function logAuthEventUnsafe(logger, session, password) {
  logger.info('login_attempt', {
    userId: session.userId,
    tenantId: session.tenantId,
    password
  });
}

function logAuthEventSafe(logger, session, password) {
  logger.info('login_attempt', {
    userId: session.userId,
    tenantId: session.tenantId,
    password: password ? '[REDACTED]' : undefined
  });
}

module.exports = {
  logAuthEventUnsafe,
  logAuthEventSafe
};
