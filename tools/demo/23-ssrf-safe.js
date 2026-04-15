// Demo fixture 23 — Outbound request constrained to an explicit allow-list
//
// Companion to 22. The destination is parsed and restricted before use.

const ALLOWED_HOSTS = new Set(['cdn.example.com', 'images.example.com']);

async function fetchAvatar(req, res, fetch) {
    const url = new URL(req.query.url);
    if (!ALLOWED_HOSTS.has(url.hostname)) {
        res.status(400).send('invalid host');
        return;
    }

    const response = await fetch(url.toString());
    const body = await response.text();
    res.send(body);
}
