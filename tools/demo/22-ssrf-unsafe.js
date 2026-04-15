// Demo fixture 22 — Server-side request made to an untrusted destination
//
// Not covered by the deterministic engine today.
// This is intended as an AI-only coverage example.

async function fetchAvatar(req, res, fetch) {
    const response = await fetch(req.query.url);
    const body = await response.text();
    res.send(body);
}
