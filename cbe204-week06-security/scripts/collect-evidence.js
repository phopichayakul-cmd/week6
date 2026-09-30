// Collects Part L evidence from the REAL app + data/db.json.
// Writes evidence/evidence.json (requests + responses) and evidence/db-users.json.
// Passwords in request bodies are masked. Run after `npm run seed`.
//
//   npm run evidence

import fs from "node:fs";
import crypto from "node:crypto";

process.env.NODE_ENV = "test";
const { config } = await import("../src/config.js");
const { default: app } = await import("../src/app.js");
const jwt = (await import("jsonwebtoken")).default;

const server = app.listen(0);
const base = `http://localhost:${server.address().port}`;
const items = [];

async function call(title, method, path, { token, body, tokenLabel } = {}) {
    const headers = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    if (body) headers["Content-Type"] = "application/json";
    const res = await fetch(base + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
    const json = await res.json().catch(() => null);
    const shownBody = body ? { ...body, ...(body.password ? { password: "********" } : {}) } : undefined;
    const shownJson = json && json.token ? { ...json, token: json.token.slice(0, 30) + "..." } : json;
    items.push({
        title, method, path,
        auth: token ? `Bearer ${tokenLabel ?? token.slice(0, 20) + "..."}` : "(none)",
        body: shownBody, status: res.status, response: shownJson
    });
    return json;
}

const studentPw = process.env.SEED_STUDENT_PASSWORD;
const adminPw = process.env.SEED_ADMIN_PASSWORD;
const newUser = "student_" + crypto.randomInt(10000, 99999);

await call("1. Registration", "POST", "/auth/register", { body: { username: newUser, password: "MyNewPassw0rd" } });
const alice = (await call("3. Login (student)", "POST", "/auth/login", { body: { username: "alice", password: studentPw } })).token;
const bob = (await call("3b. Login (admin)", "POST", "/auth/login", { body: { username: "bob", password: adminPw } })).token;
await call("4a. Protected endpoint WITHOUT authentication", "GET", "/api/protected");
await call("4b. Protected endpoint WITH authentication", "GET", "/api/protected", { token: alice });
await call("5a. Student tries admin operation", "DELETE", "/api/users/103", { token: alice });
await call("5b. Student reads another user's record", "GET", "/api/users/102", { token: alice });
await call("5c. Admin operation as admin", "GET", "/api/admin", { token: bob });

const [h, p, s] = alice.split(".");
const pl = JSON.parse(Buffer.from(p, "base64url").toString());
pl.role = "admin";
const tampered = `${h}.${Buffer.from(JSON.stringify(pl)).toString("base64url")}.${s}`;
await call("6a. Modified JWT (role changed to admin)", "GET", "/api/admin", { token: tampered, tokenLabel: "<alice token with role=admin, old signature>" });

const now = Math.floor(Date.now() / 1000);
const expired = jwt.sign({ role: "student", username: "alice", iat: now - 7200, exp: now - 3600 }, config.jwtSecret,
    { subject: "101", issuer: config.jwtIssuer, audience: config.jwtAudience, jwtid: crypto.randomUUID() });
await call("6b. Expired JWT", "GET", "/api/protected", { token: expired, tokenLabel: "<expired token>" });
await call("6c. Malformed JWT", "GET", "/api/protected", { token: "not-a-jwt", tokenLabel: "not-a-jwt" });
await call("6d. Wrong password", "POST", "/auth/login", { body: { username: "alice", password: "wrong-password" } });
await call("6e. Invalid input", "POST", "/auth/register", { body: { username: "ab", password: "short" } });
await call("6f. Logout", "POST", "/auth/logout", { token: alice });
await call("6g. Same token after logout", "GET", "/api/protected", { token: alice });

server.close();

// decoded token for Part D1
const decoded = {
    header: JSON.parse(Buffer.from(h, "base64url").toString()),
    payload: JSON.parse(Buffer.from(p, "base64url").toString())
};

const db = JSON.parse(fs.readFileSync(config.dbFile, "utf8"));
fs.mkdirSync("evidence", { recursive: true });
fs.writeFileSync("evidence/evidence.json", JSON.stringify({ generatedAt: new Date().toISOString(), node: process.version, items, decoded }, null, 2));
fs.writeFileSync("evidence/db-users.json", JSON.stringify(db.users, null, 2));
for (const it of items) console.log(`${it.status}  ${it.title}`);
console.log("Saved evidence/evidence.json and evidence/db-users.json");
