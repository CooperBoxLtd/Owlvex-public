// Demo fixture 21 — Narrow CORS policy with explicit origin allow-list
//
// Companion to 20. Restricts browser origins.

const ALLOWED_ORIGINS = new Set(['https://portal.example.com']);

function enableCors(app) {
    app.use((req, res, next) => {
        const origin = req.headers.origin;
        if (origin && ALLOWED_ORIGINS.has(origin)) {
            res.setHeader('Access-Control-Allow-Origin', origin);
            res.setHeader('Access-Control-Allow-Credentials', 'true');
        }
        next();
    });
}
