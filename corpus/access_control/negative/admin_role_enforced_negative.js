app.delete('/admin/users/:id', requireAdmin, (req, res) => {
    deleteUser(req.params.id);
    return res.status(204).end();
});
