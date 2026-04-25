const express = require('express');
const { requireUser } = require('../middleware/auth');
const { canApproveRefund } = require('../policies/workflowPolicy');
const { auditSafe, auditUnsafe } = require('../lib/auditLogger');

function createRefundRouter(repositories) {
  const router = express.Router();

  router.post('/:refundId/approve-unsafe', requireUser, async (req, res) => {
    const refund = repositories.refunds.approve(req.params.refundId, req.user.id);
    auditUnsafe(repositories.audit, {
      type: 'refund.approved',
      actor: req.user,
      refund,
      requestBody: req.body,
    });
    res.json({ refund });
  });

  router.post('/:refundId/approve-safe', requireUser, async (req, res) => {
    const refund = repositories.refunds.findForTenant(req.params.refundId, req.user.tenantId);
    if (!canApproveRefund(req.user, refund)) {
      res.status(403).json({ error: 'forbidden' });
      return;
    }

    const approved = repositories.refunds.approveForTenant(req.params.refundId, req.user.tenantId, req.user.id);
    auditSafe(repositories.audit, {
      type: 'refund.approved',
      actorId: req.user.id,
      targetId: req.params.refundId,
      outcome: 'approved',
    });
    res.json({ refund: approved });
  });

  return router;
}

module.exports = { createRefundRouter };
