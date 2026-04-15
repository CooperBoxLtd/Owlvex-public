// Demo fixture 17 — Open redirect safely resolved through an allow-list
//
// Companion to 16. The redirect target is server-controlled.

const ALLOWED_ROUTES = new Set(['/dashboard', '/settings', '/billing']);

function continueLogin(req, res) {
    const next = ALLOWED_ROUTES.has(req.query.next) ? req.query.next : '/dashboard';
    return res.redirect(next);
}
