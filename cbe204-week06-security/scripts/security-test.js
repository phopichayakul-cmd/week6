// Automated security test run (Week 6 Part I test matrix + extra tests).
// - uses its own temporary database (data/test-db.json), so data/db.json is untouched
// - generates random passwords at runtime (nothing hard-coded)
// - writes the results to evidence/security-test-results.md
//
//   npm run test:security

import fs from "node:fs";
import crypto from "node:crypto";

process.env.DB_FILE = "data/test-db.json";
process.env.NODE_ENV = "test";

const { config } = await import("../src/config.js");
const { reset } = await import("../src/db.js");
const { default: app } = await import("../src/app.js");
const bcrypt = (await import("bcryptjs")).default;
const jwt = (await import("jsonwebtoken")).default;

// ---------- test data ----------
const studentPw = crypto.randomBytes(9).toString("base64url");
const adminPw = crypto.randomBytes(9).toString("base64url");
const hash = (pw) => bcrypt.hashSync(pw, config.bcryptRounds);

reset({
    users: [
        { id: 101, username: "alice", passwordHash: hash(studentPw), role: "student", createdAt: new Date().toISOString() },
        { id: 102, username: "bob", passwordHash: hash(adminPw), role: "admin", createdAt: new Date().toISOString() },
        { id: 103, username: "john", passwordHash: hash(studentPw), role: "student", createdAt: new Date().toISOString() }
    ],
    tasks: [
        { id: 1, title: "Alice task", completed: false, ownerId: 101 },
        { id: 4, title: "John's private task", completed: false, ownerId: 103 }
    ],
    revokedTokens: []
});

const server = app.listen(0);
const base = `http://localhost:${server.address().port}`;

async function call(method, path, { token, body, rawBody } = {}) {
    const headers = {};
    if (token !== undefined) headers.Authorization = `Bearer ${token}`;
    if (body !== undefined || rawBody !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetch(base + path, {
        method,
        headers,
        body: rawBody ?? (body !== undefined ? JSON.stringify(body) : undefined)
    });
    let json = null;
    try { json = await res.json(); } catch { /* not json */ }
    return { status: res.status, json };
}

const results = [];
function record(id, name, request, expected, actual, pass, note = "") {
    results.push({ id, name, request, expected, actual, pass, note });
}
const expectStatus = async (id, name, request, expectedStatus, promise, extra) => {
    const r = await promise;
    const extraOk = extra ? extra(r) : true;
    record(id, name, request, String(expectedStatus), `${r.status} ${JSON.stringify(r.json)}`,
        r.status === expectedStatus && extraOk);
    return r;
};

// ---------- Part I test matrix ----------
await expectStatus("1", "Protected endpoint without login", "GET /api/protected (no token)", 401,
    call("GET", "/api/protected"));

await expectStatus("2", "Incorrect password", "POST /auth/login alice + wrong password", 401,
    call("POST", "/auth/login", { body: { username: "alice", password: "wrong-password" } }));

const aliceLogin = await expectStatus("3", "Valid login (student)", "POST /auth/login alice", 200,
    call("POST", "/auth/login", { body: { username: "alice", password: studentPw } }),
    (r) => typeof r.json?.token === "string" && !("passwordHash" in (r.json.user ?? {})));
const alice = aliceLogin.json.token;
// hide token body in the report
results.at(-1).actual = `200 {"message":"Login successful","token":"eyJ...(hidden)","user":${JSON.stringify(aliceLogin.json.user)}}`;

const bobLogin = await call("POST", "/auth/login", { body: { username: "bob", password: adminPw } });
const bob = bobLogin.json.token;
record("3b", "Valid login (admin)", "POST /auth/login bob", "200", `${bobLogin.status} (token issued, role ${bobLogin.json.user.role})`, bobLogin.status === 200);

await expectStatus("4", "Valid authenticated request", "GET /api/protected (alice token)", 200,
    call("GET", "/api/protected", { token: alice }));

await expectStatus("4b", "Get current user", "GET /auth/me (alice token)", 200,
    call("GET", "/auth/me", { token: alice }),
    (r) => r.json.user.id === 101 && !JSON.stringify(r.json).includes("passwordHash"));

await expectStatus("5", "Access another user's resource", "GET /api/users/102 (alice token)", 403,
    call("GET", "/api/users/102", { token: alice }));

await expectStatus("5b", "Access another user's task", "GET /api/tasks/4 (alice token, task owned by john)", 403,
    call("GET", "/api/tasks/4", { token: alice }));

await expectStatus("5c", "Access own user record", "GET /api/users/101 (alice token)", 200,
    call("GET", "/api/users/101", { token: alice }));

await expectStatus("6", "Student performs admin operation", "DELETE /api/users/103 (alice token)", 403,
    call("DELETE", "/api/users/103", { token: alice }));

await expectStatus("6b", "Student opens admin area", "GET /api/admin (alice token)", 403,
    call("GET", "/api/admin", { token: alice }));

await expectStatus("6c", "Admin opens admin area", "GET /api/admin (bob token)", 200,
    call("GET", "/api/admin", { token: bob }));

// 7. Modified JWT: change role in the payload to "admin", keep old signature
const [h, p, s] = alice.split(".");
const payload = JSON.parse(Buffer.from(p, "base64url").toString());
payload.role = "admin";
const tampered = `${h}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${s}`;
await expectStatus("7", "Modified JWT (role changed to admin)", "GET /api/admin (tampered token)", 401,
    call("GET", "/api/admin", { token: tampered }));

// 8. Expired JWT (correct signature, exp in the past)
const now = Math.floor(Date.now() / 1000);
const expired = jwt.sign({ role: "student", username: "alice", iat: now - 7200, exp: now - 3600 }, config.jwtSecret,
    { subject: "101", issuer: config.jwtIssuer, audience: config.jwtAudience, jwtid: crypto.randomUUID() });
await expectStatus("8", "Expired JWT", "GET /api/protected (expired token)", 401,
    call("GET", "/api/protected", { token: expired }));

await expectStatus("8b", "Malformed JWT", "GET /api/protected (Bearer not-a-jwt)", 401,
    call("GET", "/api/protected", { token: "not-a-jwt" }));

const noneToken = `${Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url")}.${Buffer.from(JSON.stringify({ sub: "102", role: "admin" })).toString("base64url")}.`;
await expectStatus("8c", "Unsigned JWT (alg: none)", "GET /api/admin (alg none token)", 401,
    call("GET", "/api/admin", { token: noneToken }));

// 10. Invalid input
await expectStatus("10", "Invalid input (too short)", 'POST /auth/register {"username":"ab","password":"short"}', 400,
    call("POST", "/auth/register", { body: { username: "ab", password: "short" } }));
await expectStatus("10b", "Invalid input (missing field)", 'POST /auth/register {"username":"carol"}', 400,
    call("POST", "/auth/register", { body: { username: "carol" } }));
await expectStatus("10c", "Invalid input (wrong type)", 'POST /auth/register {"username":123,"password":true}', 400,
    call("POST", "/auth/register", { body: { username: 123, password: true } }));
await expectStatus("10d", "Malformed JSON body", "POST /auth/login  body: {bad json", 400,
    call("POST", "/auth/login", { rawBody: "{bad json" }),
    (r) => !JSON.stringify(r.json).includes("at ")); // no stack trace
await expectStatus("10e", "Invalid ID format", "GET /api/users/abc (alice token)", 400,
    call("GET", "/api/users/abc", { token: alice }));

// Registration + role injection
const regPw = crypto.randomBytes(9).toString("base64url");
await expectStatus("R1", "Register new user", 'POST /auth/register {"username":"carol",...}', 201,
    call("POST", "/auth/register", { body: { username: "carol", password: regPw } }),
    (r) => !JSON.stringify(r.json).includes("password"));
await expectStatus("R2", "Duplicate username", 'POST /auth/register {"username":"carol"} again', 409,
    call("POST", "/auth/register", { body: { username: "carol", password: regPw } }));
await expectStatus("R3", "Client tries to choose role", 'POST /auth/register {"username":"mallory","role":"admin"}', 201,
    call("POST", "/auth/register", { body: { username: "mallory", password: regPw, role: "admin" } }),
    (r) => r.json.user.role === "student");
results.at(-1).expected = "201 with role = student";

await expectStatus("L1", "Unknown user login (same error as wrong password)", "POST /auth/login nobody", 401,
    call("POST", "/auth/login", { body: { username: "nobody", password: "whatever123" } }),
    (r) => r.json.error === "Invalid credentials");

// Brute force: 5 wrong passwords, then the 6th attempt is blocked
for (let i = 0; i < 5; i++) {
    await call("POST", "/auth/login", { body: { username: "john", password: `wrong-${i}` } });
}
await expectStatus("L2", "Brute-force protection (6th wrong login)", "POST /auth/login john x6", 429,
    call("POST", "/auth/login", { body: { username: "john", password: "wrong-again" } }));

// Password storage check
const db = JSON.parse(fs.readFileSync(config.dbFile, "utf8"));
const plaintextFound = [studentPw, adminPw, regPw].some((pw) => JSON.stringify(db).includes(pw));
const allHashed = db.users.every((u) => /^\$2[aby]\$/.test(u.passwordHash) && !("password" in u));
record("P1", "No plaintext passwords in database", "inspect data/test-db.json", "only bcrypt hashes",
    db.users.map((u) => `${u.username}: ${u.passwordHash.slice(0, 20)}...`).join("; "),
    !plaintextFound && allHashed);
const carol = db.users.find((u) => u.username === "carol");
const mallory = db.users.find((u) => u.username === "mallory");
record("P2", "Salt: same password -> different hashes", "compare carol vs mallory hashes (same password)",
    "hashes differ", carol.passwordHash === mallory.passwordHash ? "identical" : "different",
    carol.passwordHash !== mallory.passwordHash);

// 9. Logout, then reuse the same token
await expectStatus("9a", "Logout", "POST /auth/logout (alice token)", 200,
    call("POST", "/auth/logout", { token: alice }));
await expectStatus("9", "Logout then access protected resource", "GET /api/protected (same alice token)", 401,
    call("GET", "/api/protected", { token: alice }));

// Admin operation allowed
await expectStatus("6d", "Admin performs admin operation", "DELETE /api/users/103 (bob token)", 200,
    call("DELETE", "/api/users/103", { token: bob }));

server.close();

// ---------- report ----------
const passed = results.filter((r) => r.pass).length;
const esc = (s) => String(s).replace(/\|/g, "\\|");
const lines = [
    "# Week 6 Security Test Results",
    "",
    `Run: ${new Date().toLocaleString()}  |  Node ${process.version}  |  **${passed}/${results.length} passed**`,
    "",
    "Generated by `npm run test:security` against the real Express app with a temporary database.",
    "",
    "| # | Security Test | Request | Expected | Actual | Pass/Fail |",
    "|---|---|---|---|---|---|",
    ...results.map((r) => `| ${r.id} | ${esc(r.name)} | \`${esc(r.request)}\` | ${esc(r.expected)} | ${esc(r.actual)} | ${r.pass ? "PASS" : "**FAIL**"} |`)
];
fs.mkdirSync("evidence", { recursive: true });
fs.writeFileSync("evidence/security-test-results.md", lines.join("\n") + "\n");
fs.rmSync(config.dbFile, { force: true });

for (const r of results) {
    console.log(`${r.pass ? "PASS" : "FAIL"}  [${r.id}] ${r.name}  ->  ${r.actual.slice(0, 90)}`);
}
console.log(`\n${passed}/${results.length} passed. Report: evidence/security-test-results.md`);
process.exit(passed === results.length ? 0 : 1);
