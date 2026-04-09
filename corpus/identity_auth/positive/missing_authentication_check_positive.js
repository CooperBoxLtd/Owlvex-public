app.get('/admin/users', (req, res) => {
    return res.json(listAllUsers());
});
