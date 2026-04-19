// Demo fixture 85 - AI-focused audited privileged action
//
// Records an audit event when an admin suspends an account.

async function suspendAccount(req, res, accounts, auditLogger) {
    if (!req.user || req.user.role !== 'admin') {
        res.status(403).send({ error: 'forbidden' });
        return;
    }

    await accounts.updateOne(
        { id: req.params.accountId },
        { $set: { suspended: true } },
    );

    await auditLogger.record({
        actorId: req.user.id,
        action: 'account.suspend',
        targetId: req.params.accountId,
    });

    res.send({ ok: true });
}

module.exports = { suspendAccount };
