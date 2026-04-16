// Demo fixture 31 - Outbound request constrained to exact trusted hosts
//
// Companion to 30. The hostname must be present in an explicit allow-list.
// Owlvex should stay quiet here.

const TRUSTED_HOSTS = new Set(['avatars.example.com', 'images.example.com']);

async function fetchAvatar(req, res, fetch) {
    const url = new URL(req.query.url);
    if (!TRUSTED_HOSTS.has(url.hostname)) {
        res.status(400).send('invalid host');
        return;
    }

    const response = await fetch(url.toString());
    const body = await response.text();
    res.send(body);
}
