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

## Helper-Layer Findings

Some files contain dangerous sinks that are intentionally reusable by safe and unsafe workflows.

For helper or repository files, Owlvex should not promote a finding to Fix First only because the helper contains a risky state change. It should first resolve caller context:

| Helper area | Expected behavior |
| --- | --- |
| `src/store/repositories.js` `users.updateRole` | Possible Extra when scanned alone; Fix First only when reached from an unguarded role route |
| `src/store/repositories.js` `refunds.approve` | Possible Extra when scanned alone; Fix First only when reached from an unguarded approval workflow |
| `src/store/repositories.js` `refunds.approveForTenant` | clean/constrained when caller enforces approval policy and tenant scope |
| `src/store/repositories.js` audit writes | audit-gap findings should distinguish missing audit from unsafe caller-supplied audit identity |

Expected action gating:

- Fix First findings may offer fix preview.
- Possible Extra findings should offer caller-path investigation before fix preview.
- Finder-only helper findings should not be treated as fully proven without caller evidence.

## Fix Preview Evaluation

Fix preview tests may temporarily change the vulnerable source files. Those changes are test artifacts unless explicitly committed as product code.

After evaluating a generated fix:

- verify the anchored finding
- rescan every touched file
- record residual or newly introduced findings
- restore the unsafe benchmark baseline before future baseline scans

## Stabilization Rule

This app is the long-term repo-context benchmark target. The older demo app has been removed so repo-context work has one realistic source of truth.

## External SAST Stability Plan

Use an external SAST baseline, starting with CodeQL, to keep the benchmark stable over time.

Goals:

- confirm the intentionally unsafe routes still look unsafe to an independent scanner
- confirm the documented safe routes do not drift into obvious SAST findings
- catch benchmark edits that accidentally remove, weaken, or add security cases
- compare Owlvex findings against a non-AI baseline before changing benchmark expectations

Planned process:

1. Restore the unsafe benchmark baseline with `npm run benchmark:reset`.
2. Run CodeQL or another SAST scanner against `tools/benchmark-app`.
3. Record the SAST result summary alongside Owlvex stabilization reports.
4. Investigate any mismatch before updating `EXPECTATIONS.md` or `benchmark.expectations.json`.
5. Treat benchmark drift as a test failure unless the expectation file is deliberately updated.

This external SAST check is not the source of truth for Owlvex behavior. It is a stability guard that helps detect accidental benchmark changes and obvious false-positive or false-negative drift.
