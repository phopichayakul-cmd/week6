import jwt from "jsonwebtoken";
import { config } from "../config.js";
import { users, revokedTokens, toPublicUser } from "../db.js";

// Authentication middleware - "Who are you?"
//
// Request -> read Authorization header -> extract Bearer token
//         -> verify signature + expiry + issuer/audience
//         -> reject revoked (logged-out) tokens
//         -> load the user from the DB -> continue
export function authenticate(req, res, next) {
    const header = req.get("Authorization");

    if (!header || !header.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Authentication required" });
    }

    const token = header.slice("Bearer ".length).trim();

    let payload;
    try {
        payload = jwt.verify(token, config.jwtSecret, {
            algorithms: ["HS256"],          // never accept "none" or other algs
            issuer: config.jwtIssuer,
            audience: config.jwtAudience
        });
    } catch {
        // Same message for expired / tampered / malformed tokens,
        // so we don't leak why verification failed.
        return res.status(401).json({ error: "Invalid or expired token" });
    }

    if (!payload.jti || revokedTokens.has(payload.jti)) {
        return res.status(401).json({ error: "Invalid or expired token" });
    }

    // Look the user up on every request: if the account was deleted the
    // token stops working, and the role comes from the DB, not the token.
    const user = users.findById(Number(payload.sub));
    if (!user) {
        return res.status(401).json({ error: "Invalid or expired token" });
    }

    req.user = toPublicUser(user);
    req.token = { jti: payload.jti, exp: payload.exp };
    next();
}
