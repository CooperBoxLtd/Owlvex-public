# Owlvex Production Readiness Contract

This document defines what "production ready" means for Owlvex.

It is not a deployment runbook and it is not a backlog.

It is a shipping contract:

- the conditions that must be true before we call the control plane production ready
- the boundaries that must remain true after production launch
- the verification signals required for release confidence

If this document conflicts with [IMPLEMENTATION_DESIGN.md](D:/Dev/repos/CodeScanner/docs/IMPLEMENTATION_DESIGN.md), the design document wins.

For environment setup and deployment mechanics, see [DEPLOYMENT_ENVIRONMENTS.md](D:/Dev/repos/CodeScanner/docs/DEPLOYMENT_ENVIRONMENTS.md) and [FIRST_PRODUCTION_DEPLOY.md](D:/Dev/repos/CodeScanner/docs/FIRST_PRODUCTION_DEPLOY.md).

## 1. Purpose

Owlvex is production ready only when we can operate the product safely, repeatably, and honestly within its intended model:

- local scanning
- backend control plane only
- explicit provider-direct AI calls
- benchmark-backed deterministic trust

Production readiness does not mean "the app starts in Azure".

It means:

- the system behaves according to the product boundary
- the critical extension/backend contracts are stable
- release signals are strong enough to trust changes
- operational failure modes are understood and bounded

## 2. Non-Negotiable Production Boundaries

These must be true in production at all times:

1. Owlvex backend must not require raw source code for scanning.
2. The extension and CLI remain the execution plane.
3. Deterministic scanning remains local.
4. AI calls that include source code go directly to the customer-selected provider, not through Owlvex backend.
5. User-facing findings must preserve provenance.
6. Production claims about deterministic certainty must only cover benchmark-backed behavior.

A release that violates any of the above is not production ready, even if deployment succeeds.

## 3. Production Readiness Scope

This contract covers:

- the backend control plane
- the extension/backend integration contract
- deterministic release confidence
- operational deployment safety
- minimum observability and rollback expectations

This contract does not require:

- Stripe activation on day one
- SendGrid activation on day one
- every roadmap feature to be complete
- enterprise hardening beyond the minimum controls listed here

## 4. Required Readiness Areas

## 4.1 Product Boundary Readiness

Required:

- backend request/response shapes are metadata-oriented
- backend rejects or ignores unexpected source-bearing payload fields by design
- backend logs do not include raw source
- extension settings and UI make outbound provider behavior explicit

Exit criteria:

- a code review of extension-to-backend payloads confirms metadata-only behavior
- backend route handlers that accept scan-related payloads document allowed fields
- docs explicitly describe allowed and forbidden data flows

## 4.2 Contract Readiness

Required:

- extension/backend API contracts used in production are stable and tested
- comparison payloads and prompt payloads have one canonical shape
- error responses are structured enough for the extension to surface actionable messages

Minimum production contract set:

- `/health`
- `/v1/licences/validate`
- `/v1/prompts/build`
- `/v1/scans/record`
- `/v1/scans/compare`
- `/v1/policies/evaluate`

Exit criteria:

- each production route has at least one integration test for success and one failure case
- extension rendering paths for scan, report, and comparison consume the same field names the backend returns
- contract changes are treated as release-impacting changes

## 4.3 Deterministic Trust Readiness

Required:

- every deterministic rule that is presented as proven is benchmark-backed
- product wording matches actual implementation confidence
- heuristic behavior is not labelled deterministic certainty

Exit criteria:

- aggregate deterministic benchmark gate passes
- live deterministic rule set and benchmark-covered rule set match
- any intentionally heuristic rule is either removed from deterministic claims or clearly downgraded in wording

## 4.4 Test And Release Readiness

Required:

- extension tests pass
- backend tests pass
- deterministic benchmark gate passes
- critical orchestration paths have coverage, not just isolated helpers

Minimum release gate:

1. extension unit/integration tests green
2. backend API/service tests green
3. deterministic benchmark green
4. no known contract mismatch between backend payloads and extension rendering

Exit criteria:

- CI blocks production deploy on failed tests or failed benchmark
- release notes call out any intentional schema or behavior changes
- there is one documented "go / no-go" checklist for release

## 4.5 Operational Readiness

Required:

- production backend is deployed to Azure App Service for Containers
- production database schema is versioned and repeatable
- secrets are injected securely and are not committed to the repo
- health checks exist and are meaningful

Exit criteria:

- `/health` returns success after deploy
- database initialization path is documented and repeatable
- required production secrets are enumerated
- the deployment path supports redeploy without reprovisioning everything

## 4.6 Observability Readiness

Required:

- structured logs exist for startup, shutdown, health, and major API failures
- operational logs do not leak secrets or source-bearing data
- failures can be correlated to a request, route, or component during debugging

Exit criteria:

- logs are structured enough to inspect production failures
- expected high-value events are logged
- at least one documented place exists to inspect deployment/runtime failures

## 4.7 Security Readiness

Required:

- secrets are stored in OS-backed secure storage in the extension where applicable
- backend secrets are handled through environment or secret-management mechanisms
- production CORS, auth headers, and admin-only routes are reviewed explicitly
- backend defaults do not expose development-only surfaces in production

Exit criteria:

- docs endpoints are disabled in production unless intentionally enabled
- admin operations require explicit admin credentials
- production CORS behavior is tested against the real client origin model
- no known high-severity boundary or auth flaw is open at release time

## 5. Release Blockers

The following are automatic blockers for calling Owlvex production ready:

- backend starts accepting raw source code for scanning
- deterministic rules are marketed as proven without benchmark coverage
- known extension/backend response-shape mismatch in production workflows
- release path does not run tests and benchmark before deploy
- production secrets are expected to be committed or manually edited into tracked files
- production-only behavior cannot be health-checked or rolled back

## 6. Minimum Production Checklist

A release candidate is production ready only if all items below are true:

- architecture boundary still matches [IMPLEMENTATION_DESIGN.md](D:/Dev/repos/CodeScanner/docs/IMPLEMENTATION_DESIGN.md)
- deployment model still matches [DEPLOYMENT_ENVIRONMENTS.md](D:/Dev/repos/CodeScanner/docs/DEPLOYMENT_ENVIRONMENTS.md)
- extension tests pass
- backend tests pass
- deterministic benchmark passes
- production API contracts used by the extension are verified end-to-end
- production secrets are available and not repo-stored
- `/health` succeeds after deploy
- rollback path is known
- current docs do not overclaim deterministic certainty

## 7. Recommended Verification Evidence

Before a production sign-off, capture:

- latest extension test result
- latest backend test result
- latest deterministic benchmark result
- health check result from the live production endpoint
- one manual extension smoke test against production:
  - licence validation
  - prompt build
  - single-file scan
  - scan metadata record
  - scan comparison

This evidence should be lightweight, but it must exist.

## 8. Current Gaps To Close

Based on the current codebase state, the highest-value production-readiness gaps are:

1. close extension/backend response-shape mismatches in scan comparison
2. align deterministic claims with actual rule certainty and benchmark coverage
3. raise coverage on orchestration paths in `extension.ts`, provider integration, and backend route contracts
4. verify production CORS against the real VS Code/webview/client call pattern
5. make the release gate explicit in CI and docs

## 9. Definition Of Production Ready

Owlvex is production ready when:

- it preserves the local-execution and metadata-only backend boundary
- the extension and backend agree on the contracts they use
- deterministic claims are benchmark-backed and honest
- the production control plane can be deployed, observed, and rolled back safely
- release confidence is based on repeatable signals, not manual optimism

## 10. Bottom Line

The Owlvex production-ready standard is:

> **Safe boundary, stable contract, benchmark-backed trust, repeatable release.**
