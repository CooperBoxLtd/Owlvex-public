app.delete('/admin/users/:id', (req, res) => {
    if (!req.user) {
        return res.status(401).end();
    }

    deleteUser(req.params.id);
    return res.status(204).end();
});
