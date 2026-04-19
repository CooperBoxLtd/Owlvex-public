// Demo fixture 82 - AI-focused privilege escalation example
//
// Lets any authenticated user assign a new role to another account.

async function updateUserRole(req, res, users) {
    if (!req.user) {
        res.status(401).send({ error: 'auth_required' });
        return;
    }

    await users.updateOne(
        { id: req.params.userId },
        { $set: { role: req.body.role } },
    );

    res.send({ ok: true });
}

module.exports = { updateUserRole };
