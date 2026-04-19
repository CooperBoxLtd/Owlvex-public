// Demo fixture 89 - AI-focused protected refund approval flow
//
// Enforces a finance-approver role before changing refund state.

async function approveRefund(req, res, refunds) {
    if (!req.user || req.user.role !== 'finance_approver') {
        res.status(403).send({ error: 'forbidden' });
        return;
    }

    await refunds.updateOne(
        { id: req.params.refundId, status: 'manager_reviewed' },
        { $set: { status: 'approved', approvedBy: req.user.id } },
    );

    res.send({ ok: true });
}

module.exports = { approveRefund };
