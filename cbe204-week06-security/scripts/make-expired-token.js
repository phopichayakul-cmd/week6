// Prints a correctly-signed JWT for alice (id 101) that expired 1 hour ago.
// Paste it into the Postman collection variable `expiredToken`
// to run the "Expired Token" security test.
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import { config } from "../src/config.js";

const now = Math.floor(Date.now() / 1000);

const token = jwt.sign(
    {
        role: "student",
        username: "alice",
        iat: now - 2 * 3600,
        exp: now - 3600 // already expired
    },
    config.jwtSecret,
    {
        algorithm: "HS256",
        subject: "101",
        issuer: config.jwtIssuer,
        audience: config.jwtAudience,
        jwtid: crypto.randomUUID()
    }
);

console.log(token);
