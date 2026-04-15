# Owlvex Demo App

This is a small intentionally vulnerable training app for the next Owlvex validation stage.

Unlike `tools/demo/`, which is a fixture-level corpus made of isolated files, this folder is a mini repo with routes, middleware, auth helpers, and data-access helpers. The purpose is to test whether Owlvex can understand surrounding project context and avoid false positives that disappear when ownership checks, allow-lists, tenant scoping, or safe wrappers are visible elsewhere in the app.

## What It Contains

- Vulnerable and safe document access flows
- Vulnerable and safe redirect handling
- Vulnerable and safe outbound URL fetching
- Vulnerable and safe file upload handling
- Vulnerable and safe browser state-changing flows
- Vulnerable and safe SQL query construction
- Vulnerable and safe JWT/session validation
- Vulnerable and safe credential logging
- Shared auth, tenant, CSRF, and URL-policy helpers

## Route Map

- `GET /documents/unsafe/:id` - direct object lookup with no ownership check
- `GET /documents/safe-user/:id` - lookup scoped to the current user
- `GET /documents/safe-tenant/:id` - lookup scoped to the current tenant
- `GET /browser/continue-unsafe?next=...` - open redirect through untrusted destination
- `GET /browser/continue-safe?next=...` - redirect constrained by allow-list
- `POST /browser/profile-unsafe` - browser state change without CSRF validation
- `POST /browser/profile-safe` - browser state change protected by shared CSRF middleware
- `GET /integrations/fetch-unsafe?url=...` - privileged outbound fetch to untrusted URL
- `GET /integrations/fetch-safe?url=...` - outbound fetch constrained by allow-list
- `POST /uploads/unsafe` - file write using caller-controlled file name
- `POST /uploads/safe` - file write constrained by extension and safe name policy
- `GET /search/users-unsafe?email=...` - SQL query built from untrusted email input
- `GET /search/users-safe?email=...` - query represented with parameter binding
- `GET /auth/session-unsafe` - JWT claims trusted after decode with no signature verification
- `GET /auth/session-safe` - JWT verified with HMAC and claim checks
- `POST /logs/login-unsafe` - password written into logs
- `POST /logs/login-safe` - password redacted before logging

## Important Note

This app is for scanner evaluation and training-style demos only. It is intentionally not production-safe.

## Suggested Validation Flow

1. Scan `tools/demo/` when you want isolated single-file validation.
2. Scan `tools/demo-app/` when you want repo-context validation.
3. Compare whether Owlvex drops findings when it can see:
   - ownership checks in middleware
   - tenant scoping in data-access helpers
   - allow-lists in redirect or fetch helpers
   - CSRF validation wired through shared middleware

## Expected Shape

The app should produce a mix of:

- true positives for clearly unsafe routes
- clean results for safe companion routes
- fewer AI overclaims once surrounding helpers are visible

## Expected Validation Targets

Unsafe routes that should be flagged:

- `/documents/unsafe/:id`
- `/browser/continue-unsafe`
- `/browser/profile-unsafe`
- `/integrations/fetch-unsafe`
- `/uploads/unsafe`
- `/search/users-unsafe`
- `/auth/session-unsafe`
- `/logs/login-unsafe`

Safe companion routes that should stay clean:

- `/documents/safe-user/:id`
- `/documents/safe-tenant/:id`
- `/browser/continue-safe`
- `/browser/profile-safe`
- `/integrations/fetch-safe`
- `/uploads/safe`
- `/search/users-safe`
- `/auth/session-safe`
- `/logs/login-safe`
