app.get('/admin/users', requireAuth, (req, res) => {
    return res.json(listAllUsers());
});
