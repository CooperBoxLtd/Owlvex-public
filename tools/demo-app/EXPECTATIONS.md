# Demo App Expectations

This file is the source of truth for the repo-context validation app in `tools/demo-app/`.

Purpose:

- define what Owlvex should still detect in a small vulnerable app
- define which safe helper or route patterns should stay clean when nearby context is visible
- provide a benchmark lens for scanner normalization and model evaluation

These expectations should be read together with:

- [README.md](./README.md)
- [STABILIZATION_CONTRACT.md](../../docs/STABILIZATION_CONTRACT.md)

## Expected Unsafe Findings

These files or routes are intentionally vulnerable and should remain detectable:

| Area | Expectation |
| --- | --- |
| `src/db.js` `getDocumentById` | finding expected: broken access control / IDOR |
| `src/db.js` `findUsersByEmailUnsafe` | finding expected: SQL injection |
| `src/routes/documents.js` `/unsafe/:id` | finding expected: unsafe direct object access |
| `src/routes/browser.js` `/continue-unsafe` | finding expected: open redirect |
| `src/routes/browser.js` `/profile-unsafe` | finding expected: missing CSRF protection |
| `src/routes/integrations.js` `/fetch-unsafe` | finding expected: SSRF |
| `src/routes/uploads.js` `/unsafe` | finding expected: path traversal / unsafe file path handling |
| `src/routes/auth.js` unsafe auth path | finding expected |
| `src/routes/search.js` `/users-unsafe` | finding expected: SQL injection |
| `src/routes/logs.js` `/login-unsafe` | finding expected: sensitive logging |
| `src/lib/tokens.js` `decodeJwtWithoutVerification` | finding expected: weak JWT validation |

## Expected Clean Or Constrained Paths

These paths exist to prove that context-aware suppression is working:

| Area | Expectation |
| --- | --- |
| `src/db.js` `getDocumentForTenant` | clean: tenant-scoped helper should not be flagged as broken access control |
| `src/db.js` `findUsersByEmailSafe` | clean: parameterized query helper |
| `src/routes/documents.js` `/safe-user/:id` | clean: ownership-scoped access |
| `src/routes/documents.js` `/safe-tenant/:id` | clean: tenant-scoped access |
| `src/routes/browser.js` `/continue-safe` | clean: safe redirect resolver |
| `src/routes/integrations.js` `/fetch-safe` | clean: allowlisted outbound URL check |
| `src/routes/logs.js` `/login-safe` | clean: redacted logging path |
| `src/lib/logger.js` `logAuthEventSafe` | clean: redacted secret field must not trigger sensitive logging |
| `src/server.js` route mounts and localhost startup log | clean from shell-level overclaims; findings should come from the real route or helper file instead |

## Known Demo Tradeoffs

Some findings are still expected even though this is a demo app rather than a production deployment:

| Area | Expectation |
| --- | --- |
| `src/lib/tokens.js` hardcoded secret | finding expected |
| `src/middleware/csrf.js` hardcoded demo token | finding expected unless the contract changes |

These are intentional demo shortcuts, not accidental benchmark noise.

## Stabilization Rule

The goal of `tools/demo-app/` is not to make the entire app scan clean. The goal is to prove that Owlvex can:

- still detect real vulnerable flows
- suppress safe companion flows when the local context supports that suppression
- avoid shell-level or helper-level overclaims that misclassify the code it is actually looking at

Any future change that mutates these expectations should be reviewed explicitly against the stabilization contract rather than silently accepted.
