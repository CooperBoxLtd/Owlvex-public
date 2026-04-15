// Demo fixture 20 — Overly permissive CORS policy
//
// Not covered by the deterministic engine today.
// Intended as an AI-only coverage example.

function enableCors(app) {
    app.use((req, res, next) => {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        next();
    });
}
