// Resets data/db.json with demo users + tasks.
// Passwords come from .env (SEED_ADMIN_PASSWORD / SEED_STUDENT_PASSWORD),
// and only their bcrypt hashes are written to the database.
import bcrypt from "bcryptjs";
import { config } from "../src/config.js";
import { reset } from "../src/db.js";

const adminPw = process.env.SEED_ADMIN_PASSWORD;
const studentPw = process.env.SEED_STUDENT_PASSWORD;

if (!adminPw || !studentPw || adminPw.length < 8 || studentPw.length < 8) {
    console.error("Set SEED_ADMIN_PASSWORD and SEED_STUDENT_PASSWORD (8+ chars) in .env first.");
    process.exit(1);
}

const hash = (pw) => bcrypt.hashSync(pw, config.bcryptRounds);
const now = new Date().toISOString();

reset({
    users: [
        { id: 101, username: "alice", passwordHash: hash(studentPw), role: "student", createdAt: now },
        { id: 102, username: "bob", passwordHash: hash(adminPw), role: "admin", createdAt: now },
        { id: 103, username: "john", passwordHash: hash(studentPw), role: "student", createdAt: now }
    ],
    tasks: [
        { id: 1, title: "Study JavaScript", completed: false, ownerId: 101 },
        { id: 2, title: "Build REST API", completed: false, ownerId: 101 },
        { id: 3, title: "Review security checklist", completed: false, ownerId: 102 },
        { id: 4, title: "John's private task", completed: false, ownerId: 103 }
    ],
    revokedTokens: []
});

console.log(`Seeded ${config.dbFile}: alice (101, student), bob (102, admin), john (103, student)`);
