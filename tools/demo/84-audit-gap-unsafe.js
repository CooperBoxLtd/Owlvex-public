// Demo fixture 84 - AI-focused audit gap example
//
// Performs a privileged account action without any audit trail.

async function suspendAccount(req, res, accounts) {
    if (!req.user || req.user.role !== 'admin') {
        res.status(403).send({ error: 'forbidden' });
        return;
    }

    await accounts.updateOne(
        { id: req.params.accountId },
        { $set: { suspended: true } },
    );

    res.send({ ok: true });
}

module.exports = { suspendAccount };
