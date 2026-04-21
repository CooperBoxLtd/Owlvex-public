# Owlvex Product Map

This document is the authoritative record of what Owlvex has achieved, what its architecture is, and what remains before it can be considered a complete product.

**Current status: go-to-market ready (technical foundation complete).**

---

## Architecture

Owlvex is a deterministic security reasoning engine with three distinct layers:

### Layer 1 — Deterministic Axes (core engine)

Deep, layered reasoning pipelines. Each axis applies 5 evaluation layers: subject/trust → resource/transformation → policy/sink → context validation → final decision.

| Axis | Rule | Cases |
| --- | --- | --- |
| Execution-risk | GR-001 through GR-005 + integration | 35/35 |
| SQL query | SQ-001 through SQ-005 + integration | 22/22 |
| Access control | AC-001 through AC-005 + integration | 21/21 |

**Total gate: 19 suites, all passing.**

### Layer 2 — Conditional Rules (context-aware invariants)

Lightweight rules gated on architectural context signals. The `ConditionalRule` type (`extension/src/scanner/conditionalRule.ts`) defines the formal contract:

```
cheap gate → structural truth → deterministic output
```

Rules only activate when their prerequisite context is present in the source — this is what keeps the engine trustworthy on codebases where a rule is irrelevant.

| Rule | Condition | Context gate |
| --- | --- | --- |
| AC-T001 | Multi-tenant isolation failure | `tenantId`, `organizationId`, etc. in source |
| DP-001 | PII field passed to logger | `password`, `ssn`, `accessToken`, etc. in source |
| SM-001 | `res.cookie()` missing `httpOnly: true` | `res.cookie(` in source |
| SM-002 | Debug mode without production guard | `NODE_ENV`, `process.env`, etc. in source |

### Layer 3 — AI (coverage + flexibility)

Handles patterns that cannot be expressed as structural invariants. Findings marked `provenance: 'ai'` carry explicit confidence scores and are surfaced separately from deterministic findings.

---

## DeterministicScanner — TypeScript implementation

The `DeterministicScanner` class runs all deterministic rules inline during the scan, before AI results are requested. It covers:

- **GR-001**: command/shell injection via template literal interpolation
- **SQ-001**: SQL injection via template literal interpolation
- **SQ-005**: HTML sanitizer applied before SQL sink (context mismatch)
- **AC-001**: IDOR — caller-supplied ID in parameterized query, no auth check
- **AC-T001**: multi-tenant isolation — tenant param accepted, not in query args
- **DP-001**: PII/sensitive field in logging call
- **SM-001**: `res.cookie()` call missing `httpOnly: true`
- **SM-002**: `app.set('debug', true)` without `NODE_ENV !== 'production'` guard

**Source preprocessing**: two separate stripped views are computed before scanning —
`stripComments` (for pattern matching, preserves string literals) and `stripQuotedStrings` (for brace depth tracking). These are kept separate by design; merging them would reintroduce false positives from JSDoc examples and string content.

---

## Issue Catalog

**55 canonical issues — Wave 1 complete.**

Families: injection_execution, secrets_exposure, identity_auth, access_control, data_protection_privacy, security_misconfiguration, audit_observability, availability_resilience, crypto_randomness.

Issues carry `applicability: 'global' | 'conditional'` and `requires?: string[]` — the formal vocabulary that links the catalog to the conditional rules layer.

---

## Report Layer

The report generator (`extension/src/scanner/reportGenerator.ts`) produces enterprise-grade markdown reports with:

1. **Attack Surface Assessment** — a deterministically generated narrative paragraph synthesising total findings, deterministic confirmation count, and dominant exposure categories. No AI involved.

2. **Deterministic Detections panel** — a `⚡ rule-code | issue | file | line | severity` table that appears before AI findings, making the highest-confidence results immediately visible.

3. **Provenance per finding** — each canonical finding entry states `⚡ Deterministic (rule: GR-001) — structural invariant, confidence 100%` or `🤖 AI-assisted — confidence N%`.

4. **Enterprise-grade narratives** — all five deterministic finding types (GR-001, SQ-001/SQ-005, AC-001, AC-T001, SM-002) use analyst-quality language: what the scanner observed structurally, what an attacker can do, concrete remediation code.

---

## Benchmark gate

19 deterministic suites organized into four axis groups:

| Group | Suites | Status |
| --- | --- | --- |
| execution-risk | gr002, gr003, gr004, gr005, gr001, integration | ✅ |
| sql-query | sq002, sq003, sq004, sq005, sq001, sql-integration | ✅ |
| access-control | ac002, ac004, ac003, ac005, ac001, ac-integration | ✅ |
| conditional-rules | sm002 | ✅ |

Run `npm run benchmark:status` from `extension/` to inspect the latest recorded deterministic benchmark artifact state.

---

## Demo

`tools/demo/` contains five verified fixture files and a live demo runbook in [`docs/DEMO_RUNBOOK.md`](../../docs/DEMO_RUNBOOK.md). Each fixture produces exactly the right scanner output:

```
01-idor-unsafe.js           → ⚡ AC-001  HIGH     Insecure Direct Object Reference
02-idor-safe.js             → ✓ no findings
03-debug-unsafe.js          → ⚡ SM-002  MEDIUM   Debug Mode Active Without Production Guard
04-debug-safe.js            → ✓ no findings
05-tenant-isolation-unsafe  → ⚡ AC-T001 CRITICAL Multi-Tenant Isolation Failure
```

The demo proves three claims in sequence: the engine proves violations (not guesses), it stays silent when code is correct, and findings translate into language a CTO or security lead can act on.

Additional AI-only demo fixtures now exist for uncovered classes such as open redirect and missing CSRF protection. These are useful for demonstrating model-assisted coverage, but they are not part of the deterministic trust claim.

---

## Milestones

### ✅ Milestone 1: Second Axis (SQL)

SQL deterministic axis reaches the same maturity level as execution risk. Aggregate gate 22/22.

### ✅ Milestone 2: Product Integration

`DeterministicScanner` wired into `ScanEngine`. `Finding.provenance` exposes reasoning layer to users. Sidebar shows shield + rule code for deterministic findings.

### ✅ Milestone 3: Product Confidence

CI gate runs `benchmark:deterministic` + unit tests. `benchmark:status` reports confidence for the latest recorded deterministic artifact, not full current-checkout readiness. Axis contract documents define invariants and ownership boundaries.

### ✅ Milestone 4: Broader Coverage

Three complete reasoning axes: execution-risk, sql-query, access-control.

### ✅ Milestone 5: Issue Catalog Wave 1

Canonical issue catalog expanded from 33 → 55 issues across 9 families.

### ✅ Milestone 6: Conditional Rules Layer

`ConditionalRule` type formally defined. Four conditional rules implemented (AC-T001, DP-001, SM-001, SM-002) with corpus, evaluator, and benchmark coverage for SM-002. Source preprocessing architecture (comment-strip vs. string-strip) established and documented.

### ✅ Milestone 7: Report Language Upgrade

Attack Surface Assessment, Deterministic Detections panel, provenance indicators, and enterprise-grade finding narratives. Reports read like a professional security assessment, not a lint output.

---

## Remaining Work

### Issue Catalog Wave 2

Grow from 55 to ~80 issues. Focus on framework-specific patterns (Next.js, Express middleware, ORMs) and language-specific issues.

### Secrets Exposure Axis

Hardcoded keys, tokens, and credentials in source — a natural fourth deterministic axis. Gate on entropy + context (not just pattern matching).

### Live Product Integration

The benchmark-backed deterministic engine and the live extension scan pipeline are both complete and wired together. End-to-end integration testing against real codebases (not just corpus fixtures) is the next validation step.

### PDF Report Format

Turn the markdown report into a professionally formatted PDF suitable for sharing with security leads, auditors, and compliance teams.

---

## What Owlvex Is Now

> **A deterministic security reasoning engine that proves when code is unsafe and explains why in human terms.**

Not a vulnerability list. Not a probabilistic scanner. A system that separates what is proven from what is inferred — and makes the distinction explicit in every finding and every report.
