// Authorization middleware - "What are you allowed to do?"
// Always used AFTER authenticate(), always enforced on the server.

// Only users whose role is in the list may continue.
export function requireRole(...allowedRoles) {
    return (req, res, next) => {
        if (!req.user || !allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ error: "Forbidden" });
        }
        next();
    };
}

// The user in the URL (:id) must be the logged-in user, unless they are admin.
// Prevents Broken Access Control / IDOR such as Alice reading /api/users/102.
export function requireSelfOrAdmin(paramName = "id") {
    return (req, res, next) => {
        const targetId = Number(req.params[paramName]);
        if (req.user.role === "admin" || req.user.id === targetId) {
            return next();
        }
        return res.status(403).json({ error: "Forbidden" });
    };
}

// Helper for resources that have an owner (e.g. tasks).
export function canAccessOwned(user, resource) {
    return user.role === "admin" || resource.ownerId === user.id;
}
