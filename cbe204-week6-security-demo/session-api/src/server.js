const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { users } = require("./store");

const app = express();
const PORT = 3002;
const SESSION_SECRET = process.env.SESSION_SECRET || "LOCAL-DEMO-ONLY-change-me";

app.use(express.json());

app.use(session({
  name: "cbe204.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,      // Local HTTP lab. Use true with HTTPS in deployment.
    sameSite: "lax",
    maxAge: 15 * 60 * 1000
  }
}));

function publicUser(user) {
  return { id: user.id, username: user.username, role: user.role };
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Authentication required" });
  }
  const user = users.find(u => u.id === req.session.userId);
  if (!user) {
    return res.status(401).json({ error: "Authentication required" });
  }
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Forbidden" });
  }
  next();
}

app.get("/", (req, res) => {
  res.json({
    name: "CBE204 Week 6 Secure Session API",
    auth: "Session + Cookie",
    message: "Use Postman cookie handling to observe the session cookie."
  });
});

app.post("/auth/register", async (req, res) => {
  const { username, password } = req.body || {};

  if (typeof username !== "string" || typeof password !== "string" ||
      username.length < 3 || username.length > 50 ||
      password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: "Invalid registration input" });
  }

  if (users.some(u => u.username === username)) {
    return res.status(409).json({ error: "Username already exists" });
  }

  const user = {
    id: Math.max(...users.map(u => u.id)) + 1,
    username,
    role: "student",
    passwordHash: await bcrypt.hash(password, 12)
  };
  users.push(user);
  res.status(201).json({ user: publicUser(user) });
});

app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  const user = users.find(u => u.username === username);

  if (!user || typeof password !== "string" ||
      !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  req.session.userId = user.id;
  res.json({ message: "Login successful", user: publicUser(user) });
});

app.get("/auth/me", requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.post("/auth/logout", requireAuth, (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: "Logout failed" });
    res.clearCookie("cbe204.sid");
    res.json({ message: "Logged out" });
  });
});

app.get("/api/protected", requireAuth, (req, res) => {
  res.json({ message: "You reached a protected endpoint", user: publicUser(req.user) });
});

app.get("/api/users/:id", requireAuth, (req, res) => {
  const targetId = Number(req.params.id);

  if (req.user.role !== "admin" && req.user.id !== targetId) {
    return res.status(403).json({ error: "You cannot access another user's resource" });
  }

  const user = users.find(u => u.id === targetId);
  if (!user) return res.status(404).json({ error: "User not found" });

  res.json({ user: publicUser(user) });
});

app.delete("/api/users/:id", requireAuth, requireAdmin, (req, res) => {
  const targetId = Number(req.params.id);
  const index = users.findIndex(u => u.id === targetId);

  if (index === -1) return res.status(404).json({ error: "User not found" });

  users.splice(index, 1);
  res.json({ message: "User deleted" });
});

app.listen(PORT, () => {
  console.log(`Session API listening on http://localhost:${PORT}`);
  console.log("Use only for the local CBE204 laboratory.");
});
