// Demo fixture 18 — State-changing browser request without CSRF protection
//
// Not covered by the deterministic engine today.
// This is intended as an AI-only coverage example.

function updateEmail(req, res, db) {
    db.query(
        'UPDATE users SET email = ? WHERE id = ?',
        [req.body.email, req.session.userId],
    );
    res.json({ ok: true });
}
