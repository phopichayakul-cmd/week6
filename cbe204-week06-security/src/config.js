import "dotenv/config";

// All secrets and security settings come from the environment (.env),
// never from source code.
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error(
        "JWT_SECRET is missing or too short (need 32+ characters). " +
        "Copy .env.example to .env and set a long random secret."
    );
}

export const config = {
    port: Number(process.env.PORT) || 3000,
    jwtSecret: JWT_SECRET,
    jwtExpiresIn: process.env.JWT_EXPIRES_IN || "15m",
    jwtIssuer: "cbe204-week06-api",
    jwtAudience: "cbe204-week06-client",
    bcryptRounds: Number(process.env.BCRYPT_ROUNDS) || 10,
    dbFile: process.env.DB_FILE || "data/db.json"
};
