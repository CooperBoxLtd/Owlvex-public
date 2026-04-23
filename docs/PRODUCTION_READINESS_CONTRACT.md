# Owlvex Production Readiness Contract

This document defines what "production ready" means for Owlvex.

It is not a deployment runbook and it is not a backlog.

It is a shipping contract:

- the conditions that must be true before we call the control plane production ready
- the boundaries that must remain true after production launch
- the verification signals required for release confidence

If this document conflicts with [IMPLEMENTATION_DESIGN.md](D:/Dev/repos/CodeScanner/docs/IMPLEMENTATION_DESIGN.md), the design document wins.

For environment setup and deployment mechanics, see [DEPLOYMENT_ENVIRONMENTS.md](D:/Dev/repos/CodeScanner/docs/DEPLOYMENT_ENVIRONMENTS.md), [DEV_AZURE_ENVIRONMENT.md](D:/Dev/repos/CodeScanner/docs/DEV_AZURE_ENVIRONMENT.md), and [FIRST_PRODUCTION_DEPLOY.md](D:/Dev/repos/CodeScanner/docs/FIRST_PRODUCTION_DEPLOY.md).

For current customer-facing boundary wording and the current Azure secret-posture note, see [CUSTOMER_SECURITY_AND_DATA_BOUNDARY.md](D:/Dev/repos/CodeScanner/docs/CUSTOMER_SECURITY_AND_DATA_BOUNDARY.md) and [AZURE_SECRET_POSTURE_2026-04-18.md](D:/Dev/repos/CodeScanner/docs/AZURE_SECRET_POSTURE_2026-04-18.md).

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
- production is not being used as the default development environment
- customer entry, registration, and licence issuance are supportable enough that early users do not depend on ad hoc engineer intervention

For the current AI lane, production readiness also requires that corroboration posture is honest:

- deterministic proof must remain distinguishable from AI-supported claims
- multi-pass AI disagreement must reduce confidence rather than being hidden
- degraded or partial AI coverage must be surfaced clearly in user-facing reports
- AI reasoning trails, when shown, must remain clearly AI-only and must not be presented as deterministic proof

For remediation quality, production readiness also depends on a stable grounded-remediation contract:

- canonical remediation must remain the primary normalization layer for product-facing fix guidance
- canonical remediation should align with curated OWASP-style guidance closely enough that fix behavior is not driven by prompt drift alone
- fix generation quality should be evaluated through a dedicated benchmark lane rather than inferred only from detection quality

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
- Resend activation on day one
- every roadmap feature to be complete
- enterprise hardening beyond the minimum controls listed here

Current operating note:

- during the free-trial phase, billing may remain intentionally disabled
- disabled billing does not remove the need to document billing-path risks
- it does mean billing-specific production blockers can stay deferred until the product is intentionally moved into a billable phase
- before marketplace and payment automation exist, customer registration and licence issuance should still be explicit and traceable rather than anonymous

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
- demo and trial onboarding paths preserve the same metadata-only backend boundary as production

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
- AI corroboration tiers and degraded coverage wording match actual scanner behavior

Exit criteria:

- aggregate deterministic benchmark gate passes
- live deterministic rule set and benchmark-covered rule set match
- any intentionally heuristic rule is either removed from deterministic claims or clearly downgraded in wording
- user-facing confidence tiers for AI-backed findings do not overstate certainty relative to the implemented corroboration flow

## 4.3A Customer Entry Readiness

Required:

- Free and Trial entry paths are understandable to a new customer without custom engineering help
- customer registration and licence issuance are traceable to a verified identity, at minimum a verified email address
- extension onboarding can guide a user from registration through licence activation and provider setup while using the packaged backend defaults for the selected build
- manual operator steps are documented when automation is not yet complete

Exit criteria:

- early-access users can register and receive a tracked licence without ad hoc database editing
- licence recovery, resend, or plan correction has a documented runbook
- marketplace and payment may remain unfinished, but customer entry is still supportable and repeatable

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

Operational release-check command:

- `cd extension && npm run release:check`

Interpretation rule:

- `benchmark:status` is artifact-backed deterministic evidence only
- `release:check` is the current-checkout go / no-go signal
- production-readiness decisions should use the fresh combined check, not the cached benchmark artifact on its own

Exit criteria:

- CI blocks production deploy on failed tests or failed benchmark
- release notes call out any intentional schema or behavior changes
- there is one documented "go / no-go" checklist for release

## 4.5 Operational Readiness

Required:

- production backend is deployed to Azure App Service for Containers
- production and development are separated at the environment level, not just by convention
- the production backend is promoted from the validated `dev` image tag rather than rebuilt separately
- production database schema is versioned and repeatable
- secrets are injected securely and are not committed to the repo
- health checks exist and are meaningful
- production environment settings required for validated customer flows are present before release

Exit criteria:

- `/health` returns success after deploy
- database initialization path is documented and repeatable
- required production secrets are enumerated
- production and development do not share the same Azure resource group or default deploy path
- the deployment path supports redeploy without reprovisioning everything
- the exact image tag validated in `dev` is the one running in `prod`
- critical customer-entry flows validated in `dev` are not broken in `prod` by missing environment configuration

Billing-specific note:

- if billing is disabled, billing webhook idempotency is documented but not an active release-path blocker for trial-only operation
- if billing is enabled, webhook replay safety and entitlement duplication protections become production blockers

## 4.6 Observability Readiness

Required:

- structured logs exist for startup, shutdown, health, and major API failures
- operational logs do not leak secrets or source-bearing data
- failures can be correlated to a request, route, or component during debugging
- AI-backed scan behavior is observable enough to explain:
  - provider throttling
  - budget-driven truncation
  - scan duration
  - model usage totals

Exit criteria:

- logs are structured enough to inspect production failures
- expected high-value events are logged
- at least one documented place exists to inspect deployment/runtime failures
- scan/report output makes degraded AI coverage, throttling, and budget truncation visible to the user
- AI usage totals are surfaced honestly enough that users can estimate provider spend without relying on hidden backend data

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
- secret-management posture is aligned between documented infra and live infra, or any drift is explicitly tracked and accepted

## 4.8 Grounded Data Readiness

Required:

- production grounded packs are traceable to trustworthy sources
- curated remediation and policy content carries auditable provenance
- AI-assisted or generated pack content is explicitly marked and human-reviewed before release

Exit criteria:

- canonical remediation entries for promoted issue families are rich enough to support reports, sidebar guidance, chat explanation, and fix generation from the same contract
- curated OWASP-style cheat-sheet guidance is reflected through the canonical remediation layer rather than left as isolated prompt-only text
- fix-generation grounding is auditable through canonical remediation provenance

## 4.9 Remediation Benchmark Readiness

Required:

- remediation quality is measured separately from detection quality
- fix generation is evaluated against declared success properties, not anecdotal patch quality
- release confidence can state which issue families have benchmarked remediation quality and which do not

Exit criteria:

- there is a dedicated fix benchmark schema and corpus
- benchmark outputs distinguish detection score from fix score
- promoted fix flows can demonstrate issue removal, scope discipline, and code-validity preservation for the covered families

- production pack schemas require provenance fields for curated entries
- release validation fails when trusted-source metadata is missing
- pack reviewers can identify source-backed, reviewed, and draft content separately

## 5. Release Blockers

The following are automatic blockers for calling Owlvex production ready:

- backend starts accepting raw source code for scanning
- deterministic rules are marketed as proven without benchmark coverage
- known extension/backend response-shape mismatch in production workflows
- release path does not run tests and benchmark before deploy
- production secrets are expected to be committed or manually edited into tracked files
- production-only behavior cannot be health-checked or rolled back
- grounded packs ship without auditable source provenance or review state
- user-facing AI usage or cost claims are materially misleading because scan accounting omits major AI passes or hides throttling/truncation behavior

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
- current production packs meet trusted-source provenance requirements

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
  - report comparison

This evidence should be lightweight, but it must exist.

## 8. Current Gaps To Close

Based on the current codebase state, the highest-value production-readiness gaps are:

1. close extension/backend response-shape mismatches in report comparison
2. align deterministic claims with actual rule certainty and benchmark coverage
3. raise coverage on orchestration paths in `extension.ts`, provider integration, and backend route contracts
4. tighten what scan-related prompt context is persisted so the backend stores prompt identity and minimal metadata rather than broad prompt snapshots where possible
5. verify production CORS against the real VS Code/webview/client call pattern
6. make the release gate explicit in CI and docs
7. require auditable trusted-source provenance for grounded packs and remediation content
8. resolve product-contract drift such as contributed settings or advertised behaviors that are not wired end-to-end in the runtime
9. if billing is enabled later, add webhook idempotency and duplicate-entitlement protection before treating the billing path as production ready
10. add full scan-level AI usage accounting so token totals, throttling, and budget truncation are visible and cost estimation is not based on partial data

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
