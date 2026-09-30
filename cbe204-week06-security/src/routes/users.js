import { Router } from "express";
import { users, toPublicUser } from "../db.js";
import { authenticate } from "../middleware/auth.js";
import { requireRole, requireSelfOrAdmin } from "../middleware/authorization.js";
import { validateIdParam } from "../middleware/validate.js";

const router = Router();

// Every route in this file needs a logged-in user.
router.use(authenticate);

// GET /api/users  -> admin only
router.get("/", requireRole("admin"), (req, res) => {
    res.status(200).json(users.all().map(toPublicUser));
});

// GET /api/users/:id  -> yourself, or admin
router.get("/:id", validateIdParam(), requireSelfOrAdmin(), (req, res) => {
    const user = users.findById(Number(req.params.id));
    if (!user) return res.status(404).json({ error: "User not found" });
    res.status(200).json(toPublicUser(user));
});

// DELETE /api/users/:id  -> admin only
router.delete("/:id", validateIdParam(), requireRole("admin"), (req, res) => {
    const id = Number(req.params.id);
    if (id === req.user.id) {
        return res.status(400).json({ error: "Admins cannot delete their own account" });
    }
    const removed = users.remove(id);
    if (!removed) return res.status(404).json({ error: "User not found" });
    res.status(200).json({ message: "User deleted", user: toPublicUser(removed) });
});

export default router;
