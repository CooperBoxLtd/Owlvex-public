// Demo fixture 83 - AI-focused safe role administration
//
// Requires an admin and allow-lists the roles that can be assigned.

const allowedRoles = new Set(['viewer', 'editor', 'support']);

async function updateUserRole(req, res, users) {
    if (!req.user || req.user.role !== 'admin') {
        res.status(403).send({ error: 'forbidden' });
        return;
    }

    if (!allowedRoles.has(req.body.role)) {
        res.status(400).send({ error: 'invalid_role' });
        return;
    }

    await users.updateOne(
        { id: req.params.userId },
        { $set: { role: req.body.role } },
    );

    res.send({ ok: true });
}

module.exports = { updateUserRole, allowedRoles };
