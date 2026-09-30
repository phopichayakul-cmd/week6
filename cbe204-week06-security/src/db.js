import fs from "node:fs";
import path from "node:path";
import { config } from "./config.js";

// A tiny JSON-file "database" so that the stored data (and the password
// hashes) can be inspected as evidence. Schema:
//
//   users         { id, username, passwordHash, role, createdAt }
//   tasks         { id, title, completed, ownerId }        (Week 5 resource)
//   revokedTokens { jti, exp }                             (logged-out JWTs)

const EMPTY = { users: [], tasks: [], revokedTokens: [] };
const dbPath = path.resolve(config.dbFile);

let data = load();

function load() {
    if (!fs.existsSync(dbPath)) return structuredClone(EMPTY);
    const parsed = JSON.parse(fs.readFileSync(dbPath, "utf8"));
    return { ...structuredClone(EMPTY), ...parsed };
}

export function save() {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    const tmp = `${dbPath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
    fs.renameSync(tmp, dbPath); // atomic replace
}

export function reset(newData) {
    data = { ...structuredClone(EMPTY), ...newData };
    save();
}

function nextId(list, start) {
    return list.reduce((max, item) => Math.max(max, item.id), start - 1) + 1;
}

// ---------- users ----------
export const users = {
    findById: (id) => data.users.find((u) => u.id === id),
    findByUsername: (username) =>
        data.users.find((u) => u.username.toLowerCase() === username.toLowerCase()),
    all: () => data.users,
    create({ username, passwordHash, role }) {
        const user = {
            id: nextId(data.users, 101),
            username,
            passwordHash,
            role,
            createdAt: new Date().toISOString()
        };
        data.users.push(user);
        save();
        return user;
    },
    remove(id) {
        const index = data.users.findIndex((u) => u.id === id);
        if (index === -1) return null;
        const [removed] = data.users.splice(index, 1);
        data.tasks = data.tasks.filter((t) => t.ownerId !== id);
        save();
        return removed;
    }
};

// ---------- tasks ----------
export const tasks = {
    all: () => data.tasks,
    byOwner: (ownerId) => data.tasks.filter((t) => t.ownerId === ownerId),
    findById: (id) => data.tasks.find((t) => t.id === id),
    create({ title, completed, ownerId }) {
        const task = { id: nextId(data.tasks, 1), title, completed, ownerId };
        data.tasks.push(task);
        save();
        return task;
    },
    update(id, changes) {
        const task = data.tasks.find((t) => t.id === id);
        Object.assign(task, changes);
        save();
        return task;
    },
    remove(id) {
        const index = data.tasks.findIndex((t) => t.id === id);
        const [removed] = data.tasks.splice(index, 1);
        save();
        return removed;
    }
};

// ---------- revoked tokens (logout) ----------
export const revokedTokens = {
    has: (jti) => data.revokedTokens.some((t) => t.jti === jti),
    add(jti, exp) {
        const now = Math.floor(Date.now() / 1000);
        // drop entries whose token has expired anyway
        data.revokedTokens = data.revokedTokens.filter((t) => t.exp > now);
        data.revokedTokens.push({ jti, exp });
        save();
    }
};

// Only these fields ever leave the server - never passwordHash.
export function toPublicUser(user) {
    return { id: user.id, username: user.username, role: user.role };
}
