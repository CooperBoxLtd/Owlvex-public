// Demo fixture 11 — Session cookie hardened with httpOnly
//
// This keeps the cookie out of client-side JavaScript.
// Owlvex should stay quiet here.

function issueSessionCookie(req, res, token) {
    res.cookie('session', token, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
    });
    res.json({ ok: true });
}
