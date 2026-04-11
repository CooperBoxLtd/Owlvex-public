# Owlvex Benchmark Roadmap

This roadmap defines the next development phases for the benchmark tool and the deterministic reasoning engine it is stabilizing.

The benchmark is no longer just about making the first reasoning axis real.
It is now about maintaining correctness across multiple axes, closing coverage gaps, and aligning benchmark-backed behavior with the live product.

## Current State

Verified via:

```bash
npm run benchmark:status
```

Current deterministic gate:

- `19/19` suites passing
- `82/82` cases passing

Current release gate:

```bash
npm run benchmark:deterministic
```

Current covered groups:

1. `execution-risk`
2. `sql-query`
3. `access-control`
4. `conditional-rules`

## Next Milestone 1: Conditional-Rule Benchmark Catch-Up

Goal:

- make benchmark coverage reflect more of the conditional rules already implemented in `DeterministicScanner`

Suggested deliverables:

- corpus and runners for `AC-T001`
- corpus and runners for `DP-001`
- corpus and runners for `SM-001`
- expanded conditional-rules group in the aggregate gate

Exit criteria:

- every live deterministic conditional rule has explicit benchmark coverage

## Next Milestone 2: Product Output Alignment

Goal:

- keep benchmark-backed deterministic outputs aligned with the live scanner, report generator, and sidebar

Deliverables:

- audit deterministic finding fields used in:
  - `scanEngine.ts`
  - `reportGenerator.ts`
  - `sidebarProvider.ts`
- document intentional differences between benchmark normalized findings and extension-facing findings
- keep provenance, rule code, and severity semantics aligned

Exit criteria:

- benchmark-backed findings and product-facing findings tell the same story

## Next Milestone 3: CI and Release Discipline

Goal:

- make deterministic benchmark health part of the default shipping path

Deliverables:

- run `benchmark:deterministic` in CI
- run key extension tests alongside the benchmark gate
- publish a short release checklist referencing `benchmark:status`

Exit criteria:

- deterministic regressions are blocked before release

## Next Milestone 4: Fourth Deterministic Axis

Goal:

- widen deterministic coverage carefully without weakening the existing ownership model

Recommended candidates:

- secrets exposure
- security misconfiguration
- data protection / sensitive logging

Exit criteria:

- the next axis follows the same layered contract discipline as the existing three

## Recommended Order

1. conditional-rule benchmark catch-up
2. product output alignment
3. CI and release discipline
4. fourth deterministic axis

## Working Rule

When choosing between speed and architectural clarity, prefer clarity.

This benchmark tool is not just test infrastructure.
It is the mechanism that defines what Owlvex is allowed to claim with confidence.
