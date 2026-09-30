# CBE204 Week 6 — Secure Login Prototype (JWT)

This is the Week 5 **Task Manager REST API** with a security layer added. It has
user registration, login, JWT authentication, role-based and ownership-based
authorization, and a Postman security test suite.

**Authentication mechanism chosen: Option B — JWT Authentication.**

```
HTTP Request → Validate Input → Authenticate (JWT) → Authorize (role / owner) → Process → Safe Response
```

## Project structure

```
cbe204-week06-security/
├── src/
│   ├── server.js                 # starts the HTTP server
│   ├── app.js                    # Express app, routes, 404 + safe error handler
│   ├── config.js                 # reads secrets/settings from .env
│   ├── db.js                     # JSON-file database (users, tasks, revokedTokens)
│   ├── routes/
│   │   ├── auth.js               # register / login / me / logout
│   │   ├── users.js              # user records (self or admin, admin-only delete)
│   │   └── tasks.js              # Week 5 task CRUD, now owner-protected
│   └── middleware/
│       ├── auth.js               # authenticate(): verifies the Bearer JWT
│       ├── authorization.js      # requireRole(), requireSelfOrAdmin(), canAccessOwned()
│       └── validate.js           # server-side input validation
├── scripts/
│   ├── seed.js                   # resets data/db.json with demo users + tasks
│   ├── make-expired-token.js     # prints an expired JWT for the Postman test
│   └── security-test.js          # automated security test matrix → evidence/
├── postman/
│   └── CBE204-Week06-Security.postman_collection.json
├── data/db.json                  # created by `npm run seed` (password hashes only)
├── evidence/security-test-results.md   # created by `npm run test:security`
├── .env.example
└── package.json
```

## How to install and run

Requirements: Node.js 20 or newer, npm, and Postman.

```bash
npm install
cp .env.example .env          # Windows: copy .env.example .env
```

Edit `.env`:

- `JWT_SECRET` must be a long random string. Generate one with
  `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`
- `SEED_ADMIN_PASSWORD` and `SEED_STUDENT_PASSWORD` are the passwords for the demo users.

Then run:

```bash
npm run seed                  # creates data/db.json with demo users + tasks
npm start                     # http://localhost:3000
```

Demo users created by `npm run seed`:

| ID  | Username | Role    | Password                |
|-----|----------|---------|-------------------------|
| 101 | alice    | student | `SEED_STUDENT_PASSWORD` |
| 102 | bob      | admin   | `SEED_ADMIN_PASSWORD`   |
| 103 | john     | student | `SEED_STUDENT_PASSWORD` |

## API endpoints

| Method | Endpoint | Who can call it | Success | Failure cases |
|---|---|---|---|---|
| POST | /auth/register | anyone | 201 | 400 invalid input, 409 username taken |
| POST | /auth/login | anyone | 200 + JWT | 400 invalid input, 401 invalid credentials, 429 too many failures |
| GET | /auth/me | authenticated | 200 | 401 |
| POST | /auth/logout | authenticated | 200 | 401 |
| GET | /api/protected | authenticated | 200 | 401 |
| GET | /api/profile | authenticated | 200 | 401 |
| GET | /api/admin | admin | 200 | 401, 403 |
| GET | /api/users | admin | 200 | 401, 403 |
| GET | /api/users/:id | that user, or admin | 200 | 400, 401, 403, 404 |
| DELETE | /api/users/:id | admin | 200 | 400, 401, 403, 404 |
| GET | /api/tasks | authenticated (students see their own tasks, admins see all) | 200 | 401 |
| GET / PUT / DELETE | /api/tasks/:id | task owner, or admin | 200 | 400, 401, 403, 404 |
| POST | /api/tasks | authenticated (owner is taken from the token) | 201 | 400, 401 |

Protected requests send `Authorization: Bearer <token>`.

## Database / schema

`data/db.json` is a small JSON-file database. Using a file means the stored data can be opened and checked.

```
users          id (int, from 101) | username (unique) | passwordHash (bcrypt) | role ("student"|"admin") | createdAt
tasks          id | title | completed | ownerId → users.id
revokedTokens  jti (JWT ID of a logged-out token) | exp (when it would have expired anyway)
```

The `passwordHash` values look like `$2b$10$...`. There is no `password` column.

## Security design

| Requirement | How it is done |
|---|---|
| Never store plaintext passwords | `bcrypt.hash(password, BCRYPT_ROUNDS)` in `routes/auth.js`. Only the hash is saved. bcrypt adds a random salt, so two users with the same password get different hashes. |
| Verify passwords securely | `bcrypt.compare()`. For an unknown username the code compares against a dummy hash, so that case takes about as long as a wrong password. |
| Authentication on protected endpoints | The `authenticate` middleware reads the Bearer token and runs `jwt.verify` with `algorithms: ["HS256"]` plus issuer and audience checks. It also rejects expired or revoked tokens and loads the user from the DB. |
| Authorization enforced server-side | `requireRole("admin")`, `requireSelfOrAdmin()` and `canAccessOwned()`. The role is read from the database, not from the token or the request body. |
| Client cannot choose its role | `/auth/register` always creates a `student` and ignores any `role` field. |
| No password/hash in responses | Every response goes through `toPublicUser()`, which returns only `{ id, username, role }`. |
| No hardcoded secrets | `JWT_SECRET` and the seed passwords come from `.env`, which is in `.gitignore`. The server refuses to start without a secret of 32+ characters. |
| Input validation | Username: 3–20 characters, letters, digits and `_`. Password: 8–72 characters (bcrypt only uses the first 72 bytes). Type checks, ID checks, a 100-character task title limit, and a 10 kB body limit. |
| Safe errors | Clients get generic messages (`Invalid credentials`, `Invalid or expired token`, `Internal server error`). Details go to the server log only. No stack traces. `x-powered-by` is disabled. |
| JWT claims | `sub`, `role`, `username`, `iat`, `exp` (15 min), `iss`, `aud`, `jti`. There is no sensitive data in the payload, because a JWT payload is only encoded, not encrypted. |
| Logout | `/auth/logout` stores the token's `jti` in `revokedTokens`, and `authenticate` rejects it after that. |
| Brute-force protection | After 5 failed logins for the same IP + username within 15 minutes, the API returns `429`. |

## Security testing

### 1. Automated test run

```bash
npm run test:security
```

This starts the real app with a temporary database and runs the Part I test
matrix plus extra tests: alg-none token, role injection, user enumeration,
brute force, salt check and plaintext check. The results table is written to
`evidence/security-test-results.md`.

### 2. Postman

1. Import `postman/CBE204-Week06-Security.postman_collection.json`.
2. Open the collection → **Variables** and set:
   - `studentPassword` = `SEED_STUDENT_PASSWORD` from `.env`
   - `adminPassword` = `SEED_ADMIN_PASSWORD` from `.env`
   - `expiredToken` = the output of `npm run token:expired`
3. Run `npm run seed`, then `npm start`.
4. Run the folders in order (**Authentication → Protected Resources → Security Tests**), or use the Collection Runner. Every request has test scripts that check the expected status code.

| # | Security Test | Postman request | Expected |
|---|---|---|---|
| 1 | Protected endpoint without login | Security Tests / No Authentication | 401 |
| 2 | Incorrect password | Security Tests / Invalid Password | 401 |
| 3 | Valid login | Authentication / Login (student) | 200 |
| 4 | Valid authenticated request | Protected Resources / Get Protected Resource | 200 |
| 5 | Access another user's resource | Security Tests / Other User, Other User's Task | 403 |
| 6 | Student performs admin operation | Security Tests / Unauthorized Role | 403 |
| 7 | Modified JWT | Security Tests / Modified Token | 401 |
| 8 | Expired JWT | Security Tests / Expired Token | 401 |
| 9 | Logout then access protected resource | Authentication / Logout → Security Tests / After Logout | 401 |
| 10 | Invalid input | Security Tests / Invalid Input | 400 |

## Known limitations (what I would change for production)

- Use HTTPS only, because the Bearer token must never travel over plain HTTP.
- Use a real database (for example PostgreSQL with parameterized queries) instead of a JSON file.
- Keep the revoked-token list and login-attempt counters in a shared store such as Redis. The login-attempt counter is currently in memory, so it resets when the server restarts.
- Add refresh tokens with rotation, so access tokens can stay short-lived.
- Use a secret manager for `JWT_SECRET` and plan for rotating it.
- Add a stronger password policy (breached-password check) and account lockout alerts.
- Add security headers (for example with `helmet`), structured logging and monitoring.

## Relationship to Week 5

The task routes (`/api/tasks`) are the Week 5 CRUD API with the same validation
and error format (`{ "error": "message" }`). The Week 6 changes are:

- `authenticate` added to every task route
- an `ownerId` on each task, with ownership checks
- a JSON-file database instead of an in-memory array

## AI Tools Used

Development was assisted by Claude (Anthropic). It was used to implement the
authentication and authorization code, the automated security test script, the
Postman collection and this README, based on the Week 6 lab sheet and cheat
sheet. All code was run and tested (the automated security test matrix and the
Postman collection) before submission.

## Notes

- If port 3000 is already in use (for example by another demo API), set `PORT=3100` in `.env` and change the Postman collection variable `baseUrl` to `http://localhost:3100`. The screenshots in `evidence/` were taken on port 3100.
- `evidence/` holds the Postman run screenshots (`postman1-5.png`), a screenshot of `data/db.json` (`db_notepad.png`) and the automated test results (`security-test-results.md`).
