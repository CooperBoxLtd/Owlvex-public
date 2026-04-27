# Owlvex Rule Pack Delivery Contract

This document defines how Owlvex delivers grounded rule/config intelligence from the backend to the client while preserving two constraints:

- customer code never leaves client-controlled infrastructure
- Owlvex retains control over high-value grounded security data, policies, and rule metadata

This is a product and engineering contract, not just an implementation note.

If this document conflicts with [IMPLEMENTATION_DESIGN.md](D:/Dev/repos/CodeScanner/docs/IMPLEMENTATION_DESIGN.md), the design document wins.

## 1. Purpose

Owlvex should not rely on shipped extension code as the primary protection model for its security intelligence.

The extension is allowed to contain:

- local execution runtime
- baseline deterministic logic
- local merge/report/render behavior

The backend should retain ownership of:

- versioned issue packs
- framework mappings
- policy packs
- prompt templates
- grounded rule/config metadata
- release confidence metadata

The client may temporarily download that intelligence, cache what it needs, and use it locally.

The client must never send customer source code back to Owlvex in order to receive or use that intelligence.

## 2. Non-Negotiable Boundary

These rules are mandatory:

1. Raw source code must not be sent to Owlvex backend for rule-pack delivery.
2. Rule-pack requests must be metadata-only and licence-gated.
3. Rule packs must be versioned.
4. Rule packs must be integrity-verifiable.
5. Clients may cache packs locally, but Owlvex remains the authoritative source of current pack versions.
6. High-value evolving grounded intelligence should be served from the backend rather than assumed secret in the shipped extension.

## 3. What A Rule Pack Is

In Owlvex, a "rule pack" is not executable source code from the customer repository.

A rule pack is backend-served product intelligence that may include:

- canonical issue definitions
- framework mappings
- rule metadata
- severity defaults
- remediation summaries
- prompt-building inputs
- policy conditions
- supported framework catalog metadata
- release metadata such as version, issued time, and compatibility bounds

It may also include compact declarative detection metadata where appropriate.

It must not require customer code to be uploaded in order to resolve or construct the pack.

## 4. Delivery Model

The intended model is:

1. client validates licence and entitlement
2. client requests pack manifest metadata
3. backend returns versioned manifest
4. client compares local cached version to manifest
5. client downloads only required pack artifacts
6. client verifies integrity before use
7. client caches approved artifacts locally for bounded reuse

All execution against customer code still happens locally.

## 5. Pack Types

Recommended first-class pack types:

### 5.1 Issue Pack

Contains:

- canonical issue entries
- remediation summaries
- cheat sheet references
- category/family assignments
- mapping metadata
- linked cheat-sheet references or curated remediation-support metadata where available

### 5.2 Framework Pack

Contains:

- supported framework catalog
- framework versions
- framework descriptions
- entitlement visibility rules
- prompt-oriented framework guidance for AI-assisted reasoning where appropriate
- provenance and upstream source references for curated framework blobs

### 5.3 Policy Pack

Contains:

- built-in policy templates
- entitlement-aware policy metadata
- policy condition schemas

### 5.4 Prompt Pack

Contains:

- prompt templates
- template metadata
- variable requirements
- compatibility constraints

### 5.5 Rule Metadata Pack

Contains:

- deterministic rule metadata
- canonical issue links
- supported languages
- confidence and provenance metadata
- optional declarative hints used by local runtime

This pack is specifically about grounded metadata, not moving scan execution to the backend.

## 6. Manifest Contract

The backend should expose a manifest that is small, cacheable, and easy to verify.

Recommended manifest fields:

- `schema_version`
- `pack_type`
- `pack_id`
- `pack_version`
- `issued_at`
- `expires_at`
- `min_extension_version`
- `max_extension_version` or compatibility range
- `licence_scope`
- `sha256`
- `signature`
- `download_url`
- `size_bytes`

Recommended response shape:

```json
{
  "schema_version": "owlvex.rulepack.manifest.v1",
  "pack_type": "issue-pack",
  "pack_id": "owlvex.issue-pack",
  "pack_version": "2026.04.13.1",
  "issued_at": "2026-04-13T10:00:00Z",
  "expires_at": "2026-04-20T10:00:00Z",
  "min_extension_version": "0.2.0",
  "licence_scope": {
    "plan": "developer",
    "frameworks": ["OWASP", "STRIDE", "CWE"]
  },
  "sha256": "<artifact hash>",
  "signature": "<signed manifest or detached signature>",
  "download_url": "https://...",
  "size_bytes": 182340
}
```

## 7. Integrity Model

Owlvex IP protection is not the same as secrecy of client files.

We should assume pack contents can eventually be inspected on client machines.

The integrity goal is:

- the client only executes/uses authentic Owlvex-issued packs
- stale or tampered packs are rejected
- licence-ineligible packs are not treated as valid

Minimum required checks:

1. verify manifest signature or equivalent server-issued integrity proof
2. verify downloaded artifact hash matches manifest
3. verify extension compatibility before activation
4. verify licence scope before use

Current implementation status:

- manifest entries are Ed25519-signed by the backend
- the extension verifies those signatures against a pinned Owlvex public key set before caching the manifest
- the extension separately verifies the artifact `sha256` against the signed manifest entry before activating a pack

Production note:

- production should override the development signing key via `OWLVEX_PACK_SIGNING_PRIVATE_KEY_PEM`
- production should set a rotation-friendly `OWLVEX_PACK_SIGNING_KEY_ID`
- the extension should accept only pinned Owlvex public keys for known `key_id` values
- the extension should pin more than one active or upcoming public key to support non-breaking key rotation
- production must fail closed if pack signing material is not configured; silent development-key fallback is only allowed in development

If any check fails, the pack must not become active.

## 8. Cache Model

The client may cache last-known-good packs locally.

Cache rules:

- cache is keyed by pack type, pack id, version, and licence scope
- cache is bounded by TTL or explicit expiry
- cache may be reused offline until expiry if policy allows
- expired packs should not silently remain active forever
- failed refresh must not delete a valid last-known-good pack immediately
- revocation-like licence failures should clear cached pack state instead of preserving it indefinitely
- cached manifest metadata should have its own freshness TTL separate from pack expiry

Recommended client behavior:

- prefer in-memory cache for the current session
- persist only last-known-good pack artifacts and metadata needed for offline use
- avoid persisting unnecessary derived data
- bind cached packs to the entitlement scope they were fetched under and reject them when current entitlement no longer matches
- after a fresh manifest is fetched, reuse the cached artifact when pack id, type, version, hash, download path, expiry, and entitlement still match the signed manifest entry
- download a pack artifact only when the signed manifest advertises a new or changed artifact, or when no valid matching cached artifact exists
- when online, refresh stale cached manifest metadata before treating it as current control-plane state
- when offline, stale manifest metadata may inform degraded-mode messaging, but should not be presented as fresh state

## 9. Offline Behavior

Offline mode must be explicit and safe.

If backend access is unavailable:

- local deterministic scanning continues
- the client uses last-known-good packs if they are still valid
- the UI indicates degraded or offline mode
- the client does not attempt to invent new pack state

If no valid cached pack exists:

- fall back to bundled baseline behavior only
- preserve provenance so users know the result came from baseline local logic

## 10. Licence And Entitlement Behavior

Pack delivery must respect licence state.

Required:

- pack manifest requests require valid licence credentials
- backend only advertises packs allowed by the plan and framework entitlements
- cached packs should not outlive entitlement forever without revalidation

Recommended:

- embed plan/framework scope in manifest metadata
- bind locally cached pack metadata to the entitlement used to fetch it

## 11. Request Boundary

Allowed client-to-backend request data for pack delivery:

- licence key or equivalent entitlement token
- extension version
- requested pack types
- selected frameworks
- platform/runtime metadata
- cached version identifiers

Forbidden:

- source code
- code snippets
- ASTs derived from customer code
- provider-bound prompts containing customer code
- file contents for pack selection

## 12. Backend Responsibilities

The backend is responsible for:

- serving pack manifests
- enforcing entitlement
- versioning artifacts
- publishing integrity metadata
- defining pack compatibility
- keeping release metadata authoritative
- auditing manifest and artifact issuance events without logging customer source or secrets

The backend is not responsible for:

- scanning customer code
- evaluating deterministic rules against customer code
- proxying source-bearing model calls

## 13. Client Responsibilities

The extension and CLI are responsible for:

- requesting manifests
- verifying packs before activation
- caching valid packs locally
- executing scanning locally
- keeping source code out of Owlvex delivery requests
- falling back safely when the backend is unavailable

## 14. Security Goals

This delivery model should protect:

### 14.1 Customer Code

By ensuring:

- no source upload for pack delivery
- no backend scan dependency
- no source-bearing telemetry

### 14.2 Owlvex IP

By ensuring:

- high-value grounded intelligence stays centralized and updateable
- the client receives only versioned artifacts required for product behavior
- integrity and entitlement control remain backend-governed
- the VSIX carries only baseline fallback knowledge and runtime code; evolving proprietary curation should ship through signed packs first
- richer issue, mapping, remediation, framework-profile, confidence-calibration, and suppression data can be changed or withdrawn without republishing the extension

Important clarification:

This model protects Owlvex better than shipping everything statically, but it does not assume client devices are secret.

Our moat is:

- authoritative backend-served intelligence
- rapid server-side curation and entitlement control
- pack expiry, rotation, and replacement
- local execution that preserves the customer code boundary
- version control over what becomes active
- licence-gated updates
- data quality, pack quality, and product integration discipline

## 15. Recommended Initial Endpoints

Recommended first endpoints:

- `GET /v1/packs/manifest`
- `GET /v1/packs/{pack_id}`

Recommended later:

- `GET /v1/packs/compatibility`
- `POST /v1/packs/activate/report` for metadata-only activation telemetry if needed

No pack endpoint should accept raw source.

## 16. Implementation Order

Recommended order:

1. define manifest schema
2. define first issue/framework/policy pack payload shapes
3. implement backend manifest endpoint
4. implement client verification and last-known-good cache
5. add offline/degraded-mode behavior
6. add signature/integrity enforcement
7. move more high-value grounded intelligence behind the pack model

## 17. Definition Of Done

This workstream is done when:

- clients can request versioned packs without sending source code
- packs are integrity-checked before activation
- clients cache last-known-good packs locally
- offline behavior is defined and user-visible
- entitlement governs what packs can become active
- backend remains metadata-only and control-plane only

## 18. Bottom Line

The Owlvex rule-pack delivery standard is:

> **Local execution, backend-issued intelligence, integrity-verified packs, no source upload.**
