// Demo fixture 13 — Sensitive logging fixed with redaction
//
// The log keeps operational context without storing raw secrets.
// Owlvex should stay quiet here.

function handleLoginAttempt(username, suppliedSecret, logger) {
    logger.info('Login attempt', {
        username,
        credentialSupplied: Boolean(suppliedSecret),
    });
}
