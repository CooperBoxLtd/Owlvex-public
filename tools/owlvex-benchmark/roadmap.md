# Owlvex Benchmark Roadmap

This roadmap defines the next development phases for the benchmark tool and the deterministic reasoning engine it is stabilizing.

The immediate goal is not to widen scope as fast as possible.
The immediate goal is to make the first reasoning axis complete, enforceable, and reusable as the template for future axes.

## Current State

The execution-risk axis is now implemented and gated through the deterministic pipeline:

1. `GR-002` trust propagation
2. `GR-003` trust transformation
3. `GR-004` sink shape
4. `GR-005` context validation
5. `GR-001` final policy decision

Current release gate:

```bash
npm run benchmark:deterministic
```

## Phase 1: Stabilize The Execution-Risk Axis

Goal:

- prove the current layers compose correctly end to end
- make the axis safe to evolve without architectural drift

Deliverables:

- cross-layer integration corpus under `tools/owlvex-benchmark/corpus/execution_risk_integration/`
- integration runner for end-to-end execution-risk scenarios
- deterministic gate updated to include integration cases
- documentation update to mark execution-risk v1 as complete when integration coverage passes

Suggested integration cases:

- unsafe input -> `escapeHtml(...)` -> `exec(...)` -> finding
- unsafe input -> `escapeShellArg(...)` -> `exec(...)` -> no finding
- mixed branch -> generic sanitizer -> shell sink
- wrapped sink + sanitizer + context mismatch
- aliased sink + safe sanitizer + no finding

Exit criteria:

- per-layer suites pass
- integration suite passes
- `npm run benchmark:deterministic` includes integration coverage

## Phase 2: Normalize Deterministic Engine Output

Goal:

- define one canonical finding shape for deterministic results
- make benchmark output align with future scanner output

Deliverables:

- canonical finding schema document
- deterministic runner output mapped to that schema
- benchmark assertions updated to validate normalized findings where appropriate
- compatibility notes for report generation and extension integration

Suggested schema fields:

- `id`
- `axis`
- `rule`
- `family`
- `type`
- `severity`
- `confidence`
- `sink`
- `sinkKind`
- `trustState`
- `contextValid`
- `effectiveTrustState`
- `finding`
- `explanation`

Exit criteria:

- deterministic layers emit a shared output shape
- benchmark output is easier to diff and compare across runs

## Phase 3: Improve Confidence And Benchmark Operations

Goal:

- make benchmark results more useful as release evidence
- improve repeatability and longitudinal tracking

Deliverables:

- compact aggregate report for deterministic runs
- stable result storage conventions under `tools/owlvex-benchmark/runs/`
- run history notes or metadata format
- confidence reporting guidance for deterministic and model-backed runs

Potential additions:

- per-run timestamped summaries
- per-axis pass history
- benchmark change log for corpus additions and rule semantics changes

Exit criteria:

- deterministic and model-backed runs can be compared over time
- release confidence is easier to reason about from stored artifacts

## Phase 4: Start The Second Reasoning Axis

Goal:

- reuse the execution-risk template to build the next deterministic subsystem

Recommended next axis:

- SQL and contextual query execution

Why this axis:

- it maps naturally to trust, transformation, sink, context, and policy layering
- it is a strong product-relevant complement to execution risk

Required steps:

1. contract doc
2. guardrail coverage plan
3. corpus pack
4. deterministic layer implementation
5. aggregate gate

Exit criteria:

- second axis follows the same architectural discipline as execution risk
- no layer ownership drift is introduced

## Recommended Order

1. cross-layer integration corpus
2. deterministic integration runner
3. canonical finding schema
4. run-history and confidence improvements
5. second reasoning axis

## v1 Complete Definition For The Execution-Risk Axis

The execution-risk axis should be considered v1 complete when all of the following are true:

- `GR-002`, `GR-003`, `GR-004`, `GR-005`, and `GR-001` are implemented
- all five per-layer suites pass
- cross-layer integration coverage exists and passes
- `npm run benchmark:deterministic` includes integration coverage
- `execution-risk-axis.md` remains accurate
- a canonical deterministic output schema exists

## Working Rule

When choosing between speed and architectural clarity, prefer clarity.

This benchmark tool is not just test infrastructure.
It is the mechanism that defines what Owlvex is allowed to claim with confidence.
