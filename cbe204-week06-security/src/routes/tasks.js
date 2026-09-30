import { Router } from "express";
import { tasks } from "../db.js";
import { authenticate } from "../middleware/auth.js";
import { canAccessOwned } from "../middleware/authorization.js";
import { validateIdParam } from "../middleware/validate.js";

// Week 5 Task CRUD, now secured:
//  - every request must be authenticated
//  - each task has an ownerId (taken from the token, never from the body)
//  - students only see / change their own tasks, admins can see all

const router = Router();
router.use(authenticate);

const MAX_TITLE = 100;

function validateTitle(title) {
    return typeof title === "string" && title.trim() !== "" && title.trim().length <= MAX_TITLE;
}

// Finds the task and checks ownership. Sends 404/403 and returns null if not allowed.
function loadOwnedTask(req, res) {
    const task = tasks.findById(Number(req.params.id));
    if (!task) {
        res.status(404).json({ error: "Task not found" });
        return null;
    }
    if (!canAccessOwned(req.user, task)) {
        res.status(403).json({ error: "Forbidden" });
        return null;
    }
    return task;
}

// GET /api/tasks
router.get("/", (req, res) => {
    const list = req.user.role === "admin" ? tasks.all() : tasks.byOwner(req.user.id);
    res.status(200).json(list);
});

// GET /api/tasks/:id
router.get("/:id", validateIdParam(), (req, res) => {
    const task = loadOwnedTask(req, res);
    if (task) res.status(200).json(task);
});

// POST /api/tasks
router.post("/", (req, res) => {
    const { title, completed } = req.body ?? {};

    if (!validateTitle(title)) {
        return res.status(400).json({ error: `title is required (1-${MAX_TITLE} characters)` });
    }
    if (completed !== undefined && typeof completed !== "boolean") {
        return res.status(400).json({ error: "completed must be a boolean" });
    }

    const task = tasks.create({
        title: title.trim(),
        completed: completed ?? false,
        ownerId: req.user.id // from the verified token, not from the client
    });
    res.status(201).json(task);
});

// PUT /api/tasks/:id
router.put("/:id", validateIdParam(), (req, res) => {
    const task = loadOwnedTask(req, res);
    if (!task) return;

    const { title, completed } = req.body ?? {};

    if (title === undefined && completed === undefined) {
        return res.status(400).json({ error: "Provide at least title or completed to update" });
    }
    if (title !== undefined && !validateTitle(title)) {
        return res.status(400).json({ error: `title must be 1-${MAX_TITLE} characters` });
    }
    if (completed !== undefined && typeof completed !== "boolean") {
        return res.status(400).json({ error: "completed must be a boolean" });
    }

    const updated = tasks.update(task.id, {
        ...(title !== undefined ? { title: title.trim() } : {}),
        ...(completed !== undefined ? { completed } : {})
    });
    res.status(200).json(updated);
});

// DELETE /api/tasks/:id
router.delete("/:id", validateIdParam(), (req, res) => {
    const task = loadOwnedTask(req, res);
    if (!task) return;

    const deleted = tasks.remove(task.id);
    res.status(200).json({ message: "Task deleted", task: deleted });
});

export default router;
