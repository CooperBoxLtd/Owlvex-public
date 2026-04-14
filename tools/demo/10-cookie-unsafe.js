// Demo fixture 10 — Session cookie without httpOnly
//
// Express defaults httpOnly to false when no options object is provided.
// Owlvex should flag this as SM-001.

function issueSessionCookie(req, res, token) {
    res.cookie('session', token);
    res.json({ ok: true });
}
