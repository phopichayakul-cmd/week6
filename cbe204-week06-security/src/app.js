import express from "express";
import cors from "cors";
import authRouter from "./routes/auth.js";
import usersRouter from "./routes/users.js";
import tasksRouter from "./routes/tasks.js";
import { authenticate } from "./middleware/auth.js";
import { requireRole } from "./middleware/authorization.js";

const app = express();

// Don't advertise the framework in response headers.
app.disable("x-powered-by");

// Same frontend origins as Week 5 (Live Server).
app.use(cors({
    origin: ["http://localhost:5500", "http://127.0.0.1:5500"]
}));

// Small body limit: rejects oversized payloads early.
app.use(express.json({ limit: "10kb" }));

// Request logger - never logs bodies, so passwords don't end up in logs.
app.use((req, res, next) => {
    if (process.env.NODE_ENV !== "test") console.log(req.method, req.url);
    next();
});

app.get("/", (req, res) => {
    res.send("Welcome CBE204 Week6 - Secure Task API");
});

// ---- Authentication ----
app.use("/auth", authRouter);

// ---- Protected resources ----
app.get("/api/protected", authenticate, (req, res) => {
    res.status(200).json({
        message: `Hello ${req.user.username}, you are authenticated`,
        user: req.user
    });
});

app.get("/api/profile", authenticate, (req, res) => {
    res.status(200).json({ profile: req.user });
});

app.get("/api/admin", authenticate, requireRole("admin"), (req, res) => {
    res.status(200).json({ message: "Welcome administrator" });
});

app.use("/api/users", usersRouter);
app.use("/api/tasks", tasksRouter);

// ---- 404 ----
app.use((req, res) => {
    res.status(404).json({ error: "Route not found" });
});

// ---- Central error handler ----
// Details go to the server log only; the client gets a generic message
// (no stack traces, no file paths, no library errors).
app.use((error, req, res, next) => {
    if (error.type === "entity.parse.failed") {
        return res.status(400).json({ error: "Invalid JSON body" });
    }
    if (error.type === "entity.too.large") {
        return res.status(413).json({ error: "Request body too large" });
    }
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
});

export default app;
