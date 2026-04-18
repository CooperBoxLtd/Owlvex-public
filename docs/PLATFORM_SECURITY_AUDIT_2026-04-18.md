# Owlvex Platform Security Audit

Date: 2026-04-18

## Purpose

This note captures the first focused security review of the Owlvex platform boundary after the product became externally demoable and trialable.

The goal is not full certification.

The goal is to answer:

- what data leaves the extension
- what reaches the customer-selected model provider
- what reaches Owlvex backend
- what is currently too broad or too risky
- what should be fixed next

## Current Boundary Model

Intended product boundary:

- deterministic scanning runs locally
- source code goes directly to the customer-selected provider for AI-backed analysis
- Owlvex backend acts as a control plane for:
  - licence validation
  - prompt building
  - pack delivery
  - metadata recording
  - comparison support

This boundary is the core trust story of the product and must stay true in:

- demo
- trial
- production

## Security Review Summary

### Current operating decision

For the current demo and trial phase:

- trials remain free
- billing remains disabled by default
- the backend should be treated as a metadata-only control plane for trial use

This means the current unresolved billing-specific risks are documented, but they are not on the active trial path unless billing is deliberately enabled later.

### Immediate result

One high-priority boundary issue was identified and fixed during this audit:

- local project-context contract text was being sent to the backend prompt-build endpoint
- full prompt snapshots were being recorded back to the backend during scan recording

Those behaviors widened the backend data boundary beyond the documented metadata-only posture.

The extension now:

- keeps project-context contract text in the direct AI request path only
- stops sending `prompt_snapshot` in scan-record payloads

This is a meaningful privacy improvement for both customers and trial users.

## Current Findings

### 1. Fixed: project-context leakage to backend prompt build

Severity: High

Previous behavior:

- `scanEngine.ts` sent `projectContext.combined` as `team_context` to `/v1/prompts/build`

Why it mattered:

- project-context contracts can contain sensitive architecture notes, tenant assumptions, internal workflows, and trust-boundary details
- this contradicted the intended model that project context should follow the same default-local handling as source code

Current status:

- fixed in the extension
- backend prompt build no longer needs project-context content for normal operation

### 2. Fixed: full prompt snapshot recorded to backend

Severity: High

Previous behavior:

- `scanEngine.ts` sent `prompt_snapshot: systemPrompt` to `/v1/scans/record`

Why it mattered:

- assembled prompts can contain sensitive control-plane content
- when combined with local project context, this widened what the backend retained
- this was broader than the intended metadata-oriented scan recording contract

Current status:

- fixed in the extension
- scan recording now sends `prompt_id` only, not the full assembled prompt

### 3. Improved: scan comparison payloads are now metadata-shaped

Severity: Medium

Previous behavior:

- `/v1/scans/compare` accepted unrestricted finding dictionaries

Why it mattered:

- this still was not raw source code
- but it allowed richer security payloads than a strict metadata contract
- nested fields could drift toward source-bearing or overly detailed content

Current status:

- improved in the backend contract
- comparison findings are now constrained to a small allowed metadata shape
- unexpected nested fields are rejected

Remaining follow-up:

- review whether all currently allowed comparison fields are necessary
- keep comparison payloads aligned with the smallest useful diff contract

### 4. Open: live infra drift around secret-management model

Severity: Medium

Observed earlier in the live Azure review:

- live environment uses App Service app settings for important secrets
- repo infra model expects a stronger secret-management posture, including Key Vault

Why it matters:

- this is not necessarily broken today
- but it is a drift between documented posture and live posture
- production-readiness claims should not ignore that mismatch

Recommended next step:

- document live-vs-intended secret posture explicitly
- either align live infra with the intended model or record the accepted temporary exception

### 5. Open: backend route contract review still needed

Severity: Medium

Relevant routes:

- `/v1/licences/validate`
- `/v1/prompts/build`
- `/v1/scans/record`
- `/v1/scans/compare`
- `/v1/packs/manifest`
- `/v1/packs/{pack_id}`

Why it matters:

- the product boundary depends on these routes staying metadata-only for scan workflows
- we should not rely only on current code intent

Recommended next step:

- write an explicit allowed-fields review for each route
- add negative tests for unexpected source-bearing fields where applicable

### 6. Deferred until billing is enabled: webhook idempotency and billable-flow hardening

Severity: High when billing is enabled

Current behavior:

- Stripe webhook handling is disabled by default in the current trial posture
- if billing is enabled later, `checkout.session.completed` handling still needs explicit idempotency protection and stronger duplicate-prevention guarantees around issued licences

Why it matters:

- replayed or retried billing events should never mint multiple valid licences for the same purchase
- billing flows should not become the place where key lifecycle mistakes or entitlement duplication enter the platform

Current decision:

- document this clearly
- leave billing disabled during the free-trial phase
- treat billing enablement as blocked on explicit webhook and entitlement hardening

Required before billing enablement:

- webhook idempotency protection
- duplicate-prevention on Stripe-linked licence issuance
- billing-route tests for replay and retry behavior
- a review of secret handling and operational monitoring for the billing path

## Current Data-Flow Snapshot

### Local only

- deterministic rule execution
- file content for deterministic scanning
- project-context file loading
- fix preview and diff generation before user approval
- provider and licence secrets stored in VS Code secret storage

### Sent to customer-selected provider

- source code for AI-backed scans
- local project-context contract when included in AI reasoning
- grounded framework and remediation context
- local AI review passes:
  - finder
  - verifier
  - skeptic

### Sent to Owlvex backend

- licence validation request
- prompt-build metadata:
  - frameworks
  - language
  - model
  - severity threshold
- scan-record metadata:
  - file name
  - file hash
  - language
  - provider
  - model
  - frameworks
  - score
  - finding counts / summaries
  - prompt id
- comparison payloads
- pack manifest and pack artifact requests

### Not supposed to reach Owlvex backend

- raw source code for scanning
- local project-context contract text as normal scan input
- full assembled prompt snapshots for routine metadata recording

## Recommended Next Security Work

### Priority 1

- add backend route contract tests for metadata-only behavior on any new control-plane routes
- keep comparison payload fields under explicit review as the diff feature evolves

### Priority 2

- review live Azure secret posture against documented intended posture
- decide whether Key Vault alignment is required before broader external trials

### Priority 3

- add a customer-facing security / privacy statement that mirrors this technical boundary
- make trial and production wording use the same data-flow language

### Priority 4

- keep billing disabled until the product is intentionally moved into a billable phase
- reopen webhook-idempotency and entitlement-hardening work only when billing enablement is back on the roadmap

## Working Rule

From this point on, every onboarding, trial, AI, or backend feature should be checked against one question:

> Does this widen the backend boundary beyond metadata-only control-plane behavior?

If the answer is yes, it should either be blocked, redesigned, or explicitly approved as a product-boundary change.
