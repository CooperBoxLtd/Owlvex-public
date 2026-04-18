// Demo fixture 80 - AI-focused unprotected admin route
//
// Exposes an administrative action without any visible auth or role check.

function mountAdminRoutes(app, maintenanceService) {
    app.post('/admin/rebuild-search', async (req, res) => {
        await maintenanceService.rebuildSearchIndex();
        res.send({ ok: true });
    });
}

module.exports = { mountAdminRoutes };
