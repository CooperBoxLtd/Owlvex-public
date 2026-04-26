# Benchmark App Expectations

This file is the source of truth for `tools/benchmark-app/`.

## Purpose

The benchmark app should behave like a small real application so Owlvex has actual repo context:

- policies live outside route files
- routes call helper modules
- safe and unsafe workflows sit near each other
- comments express business rules only where a real team would document them
- findings should be based on code behavior, not filenames

## Expected Unsafe Findings

| Area | Expectation |
| --- | --- |
| `src/routes/documents.js` `GET /documents/:documentId/unsafe` | finding expected: missing object-level authorization / tenant scope |
| `src/routes/refunds.js` `POST /refunds/:refundId/approve-unsafe` | finding expected: broken function-level authorization |
| `src/routes/roles.js` `POST /users/:userId/role-unsafe` | finding expected: privilege escalation through role assignment |
| `src/routes/integrations.js` `POST /integrations/proxy-unsafe` | finding expected: SSRF |
| `src/routes/reports.js` `GET /reports/download-unsafe` | finding expected: path traversal |
| `src/routes/profile.js` `POST /profile/email-unsafe` | finding expected: missing CSRF protection |
| `src/routes/imports.js` `POST /imports/customer-notes-unsafe` | finding expected: code execution / unsafe deserialization-like import |
| `src/lib/tokens.js` `decodeSessionTokenWithoutVerification` | finding expected: weak JWT validation |

## Expected Clean Or Constrained Paths

| Area | Expectation |
| --- | --- |
| `src/routes/documents.js` `GET /documents/:documentId/safe` | clean: tenant-scoped repository call |
| `src/routes/refunds.js` `POST /refunds/:refundId/approve-safe` | clean: finance approval policy enforced |
| `src/routes/roles.js` `POST /users/:userId/role-safe` | clean: admin policy and allowed role validation enforced |
| `src/routes/integrations.js` `POST /integrations/proxy-safe` | clean: partner URL resolved through allow-list helper |
| `src/routes/reports.js` `GET /reports/download-safe` | clean: report ID mapped through fixed catalog |
| `src/routes/profile.js` `POST /profile/email-safe` | clean: CSRF middleware enforced |
| `src/routes/imports.js` `POST /imports/customer-notes-safe` | clean: JSON-only data import with shape validation |
| `src/lib/tokens.js` `verifySessionToken` | clean: signature, issuer, audience, and algorithm validation |

## Stabilization Rule

This app is the long-term repo-context benchmark target. The older demo app has been removed so repo-context work has one realistic source of truth.
