app.get('/admin/settings', (req, res) => {
    if (req.user?.isAuthenticated) {
        return res.json(loadAdminSettings());
    }

    return res.status(401).end();
});
