// Demo fixture 12 — Sensitive data written to logs
//
// Logging the raw password creates a durable exposure in log systems.
// Owlvex should flag this as DP-001.

function handleLoginAttempt(username, password, logger) {
    logger.info('Login attempt', { username, password });
}
