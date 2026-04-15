// Demo fixture 19 — State-changing browser request with CSRF token validation
//
// Companion to 18. Browser state-changing request is guarded.

function updateEmail(req, res, db) {
    if (req.body.csrfToken !== req.session.csrfToken) {
        return res.status(403).json({ error: 'invalid csrf token' });
    }

    db.query(
        'UPDATE users SET email = ? WHERE id = ?',
        [req.body.email, req.session.userId],
    );
    return res.json({ ok: true });
}
