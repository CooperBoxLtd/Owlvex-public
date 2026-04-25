const ALLOWED_ROLES = new Set(['support_agent', 'finance_approver', 'admin']);

function canReadDocument(user, document) {
  return Boolean(user && document && user.tenantId === document.tenantId);
}

function canAssignRole(actor, targetUser, nextRole) {
  return Boolean(
    actor
    && targetUser
    && actor.role === 'admin'
    && actor.tenantId === targetUser.tenantId
    && ALLOWED_ROLES.has(nextRole),
  );
}

module.exports = { ALLOWED_ROLES, canReadDocument, canAssignRole };
