# Owlvex Gap Analysis

Date: 2026-04-19

This document captures the highest-signal gaps observed in the current Owlvex codebase and documentation.

It is not a replacement for the backlog. It is a reality check against the current repo state so we can separate:

- implemented and documented
- implemented but under-documented
- documented but not yet stable
- release-significant gaps that should block stronger claims

It should also be read with one important qualifier:

- not all drift is bad
- some current drift is intentional because the product UX, onboarding, and remediation experience are moving closer to the intended product shape
- scanner-quality drift is different and should be reviewed carefully before it is treated as either a regression or a success

## Scope

This pass was grounded in the current implementation under:

- `backend/`
- `extension/`
- `cli/`
- `infra/`
- `docs/`
- `.github/workflows/`

It also used the current verification signals available from this checkout:

- `npm test -- --runInBand` in `extension/`
- `npm run benchmark:status` in `extension/`
- route and command wiring in the extension and backend

## Executive Summary

Owlvex is materially further along than the top-level docs suggest: the extension already includes tracked Free/Trial onboarding, review-first fix previews, repo-context AI review, usage telemetry, admin customer operations, and backend-served pack delivery.

The biggest gaps are no longer "missing architecture." They are mostly alignment and release-discipline gaps:

1. benchmark confidence is green while the current extension test suite is not
2. orchestration-heavy product paths still have weak direct coverage
3. top-level docs understate current product capabilities and operating requirements
4. some demo/documentation links are stale or broken
5. local backend validation is not frictionless from a bare checkout

The current user experience direction appears stronger than some of the older docs imply. The more important question is not "has anything drifted?" but "which drift is intentional product improvement, and which drift changes scanner truth or trust posture?"

## Verified Current State

### Product/runtime surface that already exists

- The extension exposes guided commands for:
  - tracked registration for `free` and `trial`
  - backend configuration
  - provider/model setup
  - project-context editing
  - report comparison
  - review-first fix preview and apply
- The backend exposes real control-plane routes for:
  - licence validation
  - tracked registration and email verification
  - prompt build
  - scan record and compare
  - usage events
  - pack manifest and artifact fetch
  - admin overview, customer lookup, resend verification, deactivate licence, rotate licence
- CI already runs:
  - grounded-data validation
  - backend tests
  - extension tests
  - deterministic benchmark gate

### Verification signals observed in this checkout

- `npm run benchmark:status` reports `19/19` suites and `82/82` cases passing
- the reported benchmark artifact is dated `2026-04-11T22:25:46.557Z`, so the status signal is not obviously fresh relative to this review date
- `npm test -- --runInBand` in `extension/` currently fails with 3 failing tests across 2 suites:
  - `src/stabilityGuardrails.test.ts`
  - `src/scanner/demoRegression.test.ts`
- local backend tests were not runnable from this shell as-is because `pytest` was not installed on the path in the current environment

## Gap Register

Before the gap details below, the repo should be interpreted with this review rule:

- UX, workflow, onboarding, and remediation drift may be intentional and desirable
- scanner-quality drift must be reviewed carefully because it affects trust, provenance, demo claims, and release confidence
- when those two categories conflict, preserve scanner honesty first and then adapt the UX around it

## 1. Release-signal inconsistency

Current state:

- deterministic benchmark status is green
- extension tests are not green
- production-readiness docs describe a release gate where extension tests, backend tests, and deterministic benchmarks all need to pass

Why this matters:

- the repo can currently produce a reassuring benchmark status while still failing user-facing regression tests
- this weakens the trust story around "acceptable for release" if readers treat `benchmark:status` as a sufficient signal

Evidence:

- `extension/package.json`
- `docs/PRODUCTION_READINESS_CONTRACT.md`
- `.github/workflows/ci.yml`
- failing suites: `extension/src/stabilityGuardrails.test.ts`, `extension/src/scanner/demoRegression.test.ts`

Recommended next action:

- treat benchmark green as necessary but not sufficient in docs and release messaging
- add one short "current verification status" section to release-facing docs whenever test and benchmark signals diverge
- investigate the current deterministic/fixture drift before making stronger trust claims

## 2. Orchestration coverage gap in the extension shell

Current state:

- `extension.ts` is the main execution shell for onboarding, command wiring, usage telemetry, backend coordination, comparison, and fix-preview flows
- current Jest coverage output shows `extension.ts` at very low direct coverage

Why this matters:

- the highest-risk product regressions are likely to happen in orchestration paths, not isolated helper modules
- the current tests are much stronger around scanners and helpers than around the product shell itself

Evidence:

- `extension/src/extension.ts`
- coverage output from `npm test -- --runInBand` showed `extension.ts` at roughly `7.45%` statements / `5.18%` branches

Recommended next action:

- expand integration-style tests around:
  - registration and verification flow
  - backend/provider readiness checks
  - compare-scan flow
  - fix-preview and apply guardrails
  - project-context command flow

## 3. Deterministic-contract drift risk

Current state:

- current failing tests indicate drift in guardrail expectations and demo-regression expectations
- one failure shows project context ending in a deterministic result where the test expects AI-only posture
- another shows demo regression expectations drifting around finding ordering and extra deterministic findings

Why this matters:

- these are exactly the kinds of regressions that can blur the product contract between:
  - `PROVEN` vs `PLAUSIBLE`
  - stable demo story vs evolving scanner behavior

Important qualifier:

- this drift should not automatically be treated as bad drift
- the current code may be closer to the intended product behavior than the older tests or docs
- the risky part is not change itself; the risky part is unreviewed change in scanner truth, confidence, or provenance semantics

Evidence:

- `extension/src/stabilityGuardrails.test.ts`
- `extension/src/scanner/demoRegression.test.ts`
- `docs/PROJECT_CONTEXT_AND_SCAN_TIERS_CONTRACT.md`
- `docs/STABILIZATION_CONTRACT.md`

Recommended next action:

- review these cases as scanner-quality decisions, not only test failures
- resolve whether the code or the tests represent intended truth
- once decided, update the corresponding contract docs immediately so provenance and demo expectations stay honest
- avoid "fixing the tests" or "fixing the code" mechanically without deciding which scanner posture is actually desired

## 4. Top-level docs lag behind the real product surface

Current state:

- `README.md` and `cli/README.md` still tell a much simpler story than the current repo actually supports
- the deeper docs describe richer onboarding, scan tiers, packs, telemetry, and admin flows, but the top-level entry points do not stitch that together cleanly

Why this matters:

- new contributors or evaluators can misunderstand the actual product shape
- important product capabilities appear "hidden in implementation" rather than intentionally documented

Important qualifier:

- this is partly a healthy sign that the product experience is moving ahead of older explanatory docs
- the problem is not that the UX is changing; the problem is that the docs do not clearly distinguish intentional product evolution from scanner-contract change

Examples of underrepresented current capabilities:

- tracked Free/Trial registration and email verification
- usage-event telemetry
- backend-served pack manifest/artifact model
- repo-context AI review and explicit scan tiers
- review-first fix generation and apply safeguards
- early admin/customer-ops flows

Evidence:

- `README.md`
- `docs/PRODUCT.md`
- `backend/app/routers/`
- `extension/src/extension.ts`
- `extension/src/repoAiReview.ts`

Recommended next action:

- keep `README.md` concise, but explicitly point readers to the richer current-state docs
- maintain one current-state document that says what exists now, not only what is planned

## 5. Demo documentation drift

Current state:

- multiple docs refer to `tools/demo/DEMO-SCRIPT.md`
- that file does not exist in the current repo
- the live demo guidance is in `docs/DEMO_RUNBOOK.md`

Why this matters:

- demo prep is a high-friction moment; broken references cost time right when the repo should be easiest to use

Evidence:

- `docs/PRODUCT.md`
- `tools/demo/EXPECTATIONS.md`
- `tools/owlvex-benchmark/product-map.md`
- missing file: `tools/demo/DEMO-SCRIPT.md`

Recommended next action:

- point all demo references to `docs/DEMO_RUNBOOK.md`
- keep only one canonical live-demo runbook unless a fixture-only script is intentionally reintroduced

## 6. Local backend validation friction

Current state:

- backend dependencies for tests are documented in `backend/requirements-dev.txt`
- but a bare shell in this environment could not run `pytest` directly
- the top-level README focuses on Docker startup and does not give a compact "local backend test bootstrap" flow

Why this matters:

- backend validation should be easy for contributors and coding agents
- otherwise the extension side becomes easier to verify than the control plane it depends on

Evidence:

- `backend/requirements-dev.txt`
- `README.md`
- `backend/pytest.ini`

Recommended next action:

- add one short backend developer loop to top-level docs:
  - install deps
  - run tests
  - start API
- keep the Docker path for service startup, but make the Python test path equally visible

## 7. Benchmark-status freshness ambiguity

Current state:

- `benchmark:status` reports a passing state with a `generatedAt` timestamp from `2026-04-11`
- this review happened on `2026-04-19`

Why this matters:

- readers may interpret the command as "freshly computed current truth" when it may actually be "latest stored artifact"
- that is fine operationally if explicit, but misleading if implied to be current runtime verification

Evidence:

- `tools/owlvex-benchmark/benchmark-status.mjs`
- `tools/owlvex-benchmark/runs/`

Recommended next action:

- document whether `benchmark:status` is computed live or reads the latest saved run
- if it reads cached output, say so clearly in the benchmark docs

## Documentation Changes Made In This Pass

- added this gap-analysis document
- linked the top-level README to this analysis for current-state review
- fixed broken demo-document references to use `docs/DEMO_RUNBOOK.md`

## Recommended Priority Order

1. review the currently failing extension tests as scanner-quality decisions, not just red CI items
2. tighten the documentation around release signals so benchmark-green is not over-read
3. improve extension-shell test coverage on onboarding and command orchestration
4. make backend local test/start flows easier to discover from the top level
5. keep current-state docs and top-level docs aligned as product shape evolves

## Bottom Line

Owlvex's main gaps are now about alignment, verification clarity, and operational polish, not lack of underlying product direction.

The codebase already contains a strong product core, and the current user experience direction appears to be moving closer to the intended product.

The next step is not to eliminate all drift. It is to separate intentional product improvement from scanner-quality drift, and then make the written story, the release signals, and the tested runtime say the same thing.
