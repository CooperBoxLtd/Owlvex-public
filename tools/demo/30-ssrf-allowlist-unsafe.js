// Demo fixture 30 - Weak outbound host validation with substring matching
//
// The code tries to restrict outbound destinations, but the check is too weak.
// Owlvex should still flag this as SSRF-prone.

async function fetchAvatar(req, res, fetch) {
    const url = new URL(req.query.url);
    if (!url.hostname.includes('example.com')) {
        res.status(400).send('invalid host');
        return;
    }

    const response = await fetch(url.toString());
    const body = await response.text();
    res.send(body);
}
