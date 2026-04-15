// Demo fixture 16 — Open redirect through untrusted destination
//
// Not covered by the deterministic engine today.
// This is intended as an AI-only coverage example.

function continueLogin(req, res) {
    return res.redirect(req.query.next);
}
