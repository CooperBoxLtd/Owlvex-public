// Demo fixture 88 - AI-focused approval workflow bypass
//
// The comment claims only finance can approve refunds, but the code only checks authentication.

async function approveRefund(req, res, refunds) {
    // Only finance approvers should be able to mark refunds as approved.
    if (!req.user) {
        res.status(401).send({ error: 'auth_required' });
        return;
    }

    await refunds.updateOne(
        { id: req.params.refundId },
        { $set: { status: 'approved', approvedBy: req.user.id } },
    );

    res.send({ ok: true });
}

module.exports = { approveRefund };
