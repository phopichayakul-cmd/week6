// Server-side input validation. Client-side checks are only for UX;
// this is the real security boundary.

const USERNAME_RE = /^[a-zA-Z0-9_]{3,20}$/;

export function validateCredentials(body, { strict }) {
    const { username, password } = body ?? {};

    if (typeof username !== "string" || typeof password !== "string") {
        return "username and password are required and must be strings";
    }
    if (!strict) {
        // login: only basic sanity limits
        if (username.length === 0 || username.length > 50 || password.length === 0 || password.length > 72) {
            return "Invalid username or password format";
        }
        return null;
    }
    // register: full rules
    if (!USERNAME_RE.test(username)) {
        return "username must be 3-20 characters: letters, numbers or underscore";
    }
    if (password.length < 8 || password.length > 72) {
        // bcrypt only uses the first 72 bytes, so cap it
        return "password must be 8-72 characters";
    }
    return null;
}

// Validates :id route params as positive integers (same rule as Week 5).
export function validateIdParam(paramName = "id") {
    return (req, res, next) => {
        const id = Number(req.params[paramName]);
        if (!Number.isInteger(id) || id < 1) {
            return res.status(400).json({ error: "ID must be a positive integer" });
        }
        next();
    };
}
