function canApproveRefund(user, refund) {
  return Boolean(
    user
    && refund
    && user.tenantId === refund.tenantId
    && (user.role === 'finance_approver' || user.permissions?.includes('refunds:approve')),
  );
}

module.exports = { canApproveRefund };
