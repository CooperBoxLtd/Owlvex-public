# Owlvex Benchmark App

This is a realistic benchmark application for Owlvex repo-context scanning.

It is not a production app. It is a compact customer-support and finance portal with real workflows:

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

## Benchmark Role

Use this app when validating:

- repo-context reasoning
- authorization and workflow checks
- safe helper recognition
- unsafe/safe route pairs
- report confidence language
- fix-preview continuation on realistic code

Keep `tools/demo/` for isolated rule fixtures. This app is for whole-repo behavior.

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
