import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import { config } from "../config.js";
import { users, revokedTokens, toPublicUser } from "../db.js";
import { authenticate } from "../middleware/auth.js";
import { validateCredentials } from "../middleware/validate.js";

const router = Router();

// Used when the username doesn't exist, so a login for an unknown user
// takes about as long as a wrong password (no user-enumeration by timing).
const DUMMY_HASH = bcrypt.hashSync("dummy-password-for-timing", config.bcryptRounds);

// ---- very small brute-force protection (in memory) ----
const MAX_FAILED = 5;
const WINDOW_MS = 15 * 60 * 1000;
const failedLogins = new Map(); // key -> { count, first }

function loginKey(req, username) {
    return `${req.ip}|${username.toLowerCase()}`;
}
function isLocked(key) {
    const entry = failedLogins.get(key);
    if (!entry) return false;
    if (Date.now() - entry.first > WINDOW_MS) {
        failedLogins.delete(key);
        return false;
    }
    return entry.count >= MAX_FAILED;
}
function recordFailure(key) {
    const entry = failedLogins.get(key);
    if (!entry || Date.now() - entry.first > WINDOW_MS) {
        failedLogins.set(key, { count: 1, first: Date.now() });
    } else {
        entry.count += 1;
    }
}

function issueToken(user) {
    // Claims: only what the API needs. No password / hash / personal data,
    // because a JWT payload is only base64url-encoded, NOT encrypted.
    return jwt.sign(
        { role: user.role, username: user.username },
        config.jwtSecret,
        {
            algorithm: "HS256",
            subject: String(user.id),
            expiresIn: config.jwtExpiresIn,
            issuer: config.jwtIssuer,
            audience: config.jwtAudience,
            jwtid: crypto.randomUUID()
        }
    );
}

// POST /auth/register  -> validate -> hash -> store hash
router.post("/register", async (req, res, next) => {
    try {
        const error = validateCredentials(req.body, { strict: true });
        if (error) return res.status(400).json({ error });

        const { username, password } = req.body;

        if (users.findByUsername(username)) {
            return res.status(409).json({ error: "Username is already taken" });
        }

        const passwordHash = await bcrypt.hash(password, config.bcryptRounds);

        // Role is ALWAYS "student" on self-registration. Any "role" field
        // sent by the client is ignored - the client can't choose its role.
        const user = users.create({ username, passwordHash, role: "student" });

        res.status(201).json({ message: "User registered", user: toPublicUser(user) });
    } catch (err) {
        next(err);
    }
});

// POST /auth/login  -> find user -> bcrypt.compare -> issue JWT
router.post("/login", async (req, res, next) => {
    try {
        const error = validateCredentials(req.body, { strict: false });
        if (error) return res.status(400).json({ error });

        const { username, password } = req.body;
        const key = loginKey(req, username);

        if (isLocked(key)) {
            return res.status(429).json({ error: "Too many failed login attempts. Try again later." });
        }

        const user = users.findByUsername(username);
        const valid = await bcrypt.compare(password, user ? user.passwordHash : DUMMY_HASH);

        if (!user || !valid) {
            recordFailure(key);
            // Same message whether the user exists or not
            return res.status(401).json({ error: "Invalid credentials" });
        }

        failedLogins.delete(key);
        const token = issueToken(user);

        res.status(200).json({
            message: "Login successful",
            token,
            tokenType: "Bearer",
            expiresIn: config.jwtExpiresIn,
            user: toPublicUser(user)
        });
    } catch (err) {
        next(err);
    }
});

// GET /auth/me  -> who am I (from the verified token)
router.get("/me", authenticate, (req, res) => {
    res.status(200).json({ user: req.user });
});

// POST /auth/logout  -> revoke this token's jti so it can't be reused
router.post("/logout", authenticate, (req, res) => {
    revokedTokens.add(req.token.jti, req.token.exp);
    res.status(200).json({ message: "Logged out" });
});

export default router;
