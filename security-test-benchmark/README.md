# Owlvex Security Test Benchmark

This is a realistic, intentionally vulnerable benchmark application for Owlvex repo-context scanning.

It is not product code and must not be deployed. It is a compact customer-support and finance portal with real workflows:

- authentication and session middleware
- tenant-scoped document access
- role and permission changes
- refund approval workflow
- outbound partner integrations
- report downloads
- profile updates with CSRF protection
- import/upload paths
- audit logging

The goal is to test whether Owlvex can understand how an app works, not just whether it can match isolated unsafe snippets.

## Test Benchmark Role

Use this app when validating:

- repo-context reasoning
- authorization and workflow checks
- safe helper recognition
- unsafe/safe route pairs
- report confidence language
- fix-preview continuation on realistic code

Use isolated rule fixtures for single-pattern tests. This app is for whole-repo behavior.

## Reset Discipline

The default app state should remain intentionally vulnerable where `EXPECTATIONS.md` says a finding is expected.

When testing fix preview:

1. apply or keep the generated fix only long enough to evaluate Owlvex behavior
2. record whether the fix was correct, partial, or introduced follow-up findings
3. restore the unsafe benchmark path before the next baseline scan
4. keep good fixed code as remediation evidence, not as the default benchmark source

This prevents the benchmark from drifting into a fixed app and losing its value as a repeatable scanner test.

Commands:

- `npm run benchmark:reset:check` shows whether source files differ from the unsafe baseline.
- `npm run benchmark:reset` restores the unsafe source baseline and removes generated Owlvex reports from `src/`.

## Intentional Unsafe Workflows

- document access by ID without tenant scope
- refund approval with authentication but no finance approval check
- role assignment without admin authorization
- outbound fetch from user-controlled URL
- report download with user-controlled file path
- profile update without CSRF validation
- import payload evaluated as JavaScript
- weak JWT decode helper

## Expected Clean Workflows

- tenant-scoped document lookup
- finance-approved refund workflow
- admin-only role assignment with allowed role validation
- allow-listed partner fetch
- report download through a fixed report catalog
- profile update with CSRF validation
- JSON-only import flow
- verified JWT helper

The source of truth for expected scanner behavior is [EXPECTATIONS.md](./EXPECTATIONS.md) and [benchmark.expectations.json](./benchmark.expectations.json).
