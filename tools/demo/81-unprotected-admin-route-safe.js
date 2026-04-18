// Demo fixture 81 - AI-focused protected admin route
//
// Requires an explicit admin guard before the handler executes.

function requireAdmin(req, res, next) {
    if (!req.user || req.user.role !== 'admin') {
        res.status(403).send({ error: 'forbidden' });
        return;
    }

    next();
}

function mountAdminRoutes(app, maintenanceService) {
    app.post('/admin/rebuild-search', requireAdmin, async (req, res) => {
        await maintenanceService.rebuildSearchIndex();
        res.send({ ok: true });
    });
}

module.exports = { mountAdminRoutes, requireAdmin };
