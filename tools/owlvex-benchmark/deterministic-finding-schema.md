# Deterministic Finding Schema

This document defines the canonical output shape for deterministic benchmark-backed findings in Owlvex.

The goal is to make deterministic engine output:

- stable
- comparable across runs
- compatible with future report generation
- consistent across reasoning axes

## Purpose

The schema is the bridge between:

- deterministic benchmark runners
- future scanner report generation
- extension and UI integration
- regression diffing and run history

This schema is not model output.
It is the normalized output of deterministic reasoning layers.

## Canonical Shape

```ts
type DeterministicFinding = {
  id: string;
  axis: string;
  rule: string;
  family: string;
  type: string;
  severity: "none" | "low" | "medium" | "high" | "critical";
  confidence: number;
  finding: boolean;
  explanation: string;
  evidence: {
    file: string;
    sink: string | null;
    sinkKind: string | null;
    sinkContext: string | null;
    expression?: string | null;
    variable?: string | null;
  };
  state: {
    trustState: string;
    transformation: string;
    sanitizer: string | null;
    transformationContext: string | null;
    contextValid: boolean;
    effectiveTrustState: string;
    dangerousInContext: boolean;
    unsafeAtSink: boolean;
  };
  provenance: {
    source: "deterministic-benchmark";
    pipeline: string[];
  };
};
```

## Field Guidance

### `id`

Stable identifier for the finding within a corpus case.

Recommended format:

```text
execution-risk:<file-base-name>:<rule>
```

### `axis`

Top-level reasoning area.

For the current pipeline:

```text
execution-risk
```

### `rule`

Primary policy rule responsible for the outcome.

For the current end-to-end axis:

```text
GR-001
```

### `family`

Broad vulnerability family.

Suggested value for this axis:

```text
injection-execution
```

### `type`

Specific deterministic interpretation.

Current recommended values:

- `safe-execution-path`
- `unsafe-shell-execution`
- `unsafe-process-execution`
- `context-mismatch-execution`

### `severity`

Severity is deterministic and derived from the final execution interpretation.

Suggested mapping for the current axis:

- `none` when `finding === false`
- `high` for shell execution findings
- `medium` for process execution findings

### `confidence`

Deterministic benchmarked findings should use:

```text
1.0
```

unless a future axis intentionally introduces bounded uncertainty.

### `finding`

Boolean final decision for the deterministic engine.

### `explanation`

Short human-readable explanation of why the final state resolved the way it did.

This should be fast to scan, not verbose.

## Invariants

- deterministic findings must not invent fields ad hoc per runner
- the schema must work for both positive and negative outcomes
- `finding: false` is still useful output and should remain representable
- `state.effectiveTrustState` is the final trust state used by policy
- `state.trustState` is the pre-context-validation trust state

## Execution-Risk v1 Mapping

Execution-risk deterministic output currently maps as follows:

- `axis` -> `execution-risk`
- `rule` -> `GR-001`
- `family` -> `injection-execution`
- `type` -> derived from sink and context outcome
- `severity` -> derived from final sink interpretation
- `state.*` -> consumed from GR-002, GR-003, GR-004, and GR-005

Current runners using this schema:

- `tools/owlvex-benchmark/engine/gr001/run-gr001-corpus.mjs`
- `tools/owlvex-benchmark/engine/execution-risk-integration/run-execution-risk-integration.mjs`

## Non-goals

This schema does not yet define:

- model-originated finding shape
- report rendering schema
- suppression or rewrite audit trails
- multi-axis aggregation format

Those should build on this schema later, not replace it.
