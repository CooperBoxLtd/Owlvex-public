# Guardrail Coverage Plan (v1)

> **Historical design document.** Coverage targets defined here were for the guardrail architecture, which was superseded by the conditional rules approach. Active benchmark coverage is tracked in `run-deterministic.mjs` and `benchmark-status.mjs`. This document is retained for design history, not as active guidance.

This document defines the required corpus coverage for each Guardrails v1 rule.

Purpose:

- establish deterministic ground truth before rule engine implementation
- ensure each rule is validated against positive, negative, and edge scenarios
- act as a release-gate input for Owlvex benchmark runs

Each rule must have:

- at least 1 positive case (true positive)
- at least 1 negative case (true negative)
- at least 1 edge case (mixed, ambiguous, or branch-dependent)

Status:

- `🔴` Not covered
- `🟡` Partial
- `🟢` Complete

## Rule-to-Corpus Matrix

## GR-001 - Injection & Execution

Status: `🟡 Partial`

Current note:

- existing benchmark coverage already exercises direct `exec(...)` detection and safe non-shell `spawn(...)` handling
- branch-sensitive trust and overwrite variants are still missing

Current coverage:

- direct execution positive case added
- sanitized negative case added
- conditional mixed edge case added
- safe overwrite negative case added
- unsafe overwrite positive case added

### Required Coverage

| Type | Description | File |
| --- | --- | --- |
| Positive | Direct user input into execution sink | `direct_exec_positive.js` |
| Negative | Properly sanitized or validated input before sink | `sanitized_exec_negative.js` |
| Edge | Conditional trust overwrite | `conditional_exec_edge.js` |
| Edge | Safe override after unsafe assignment | `safe_override_negative.js` |
| Edge | Unsafe override after safe assignment | `unsafe_override_positive.js` |

### Benchmark Dimensions

- issue accuracy
- false positives
- trust propagation

## GR-002 - Trust Propagation Integrity

Status: `🟡 Partial`

### Required Coverage

| Type | Description | File |
| --- | --- | --- |
| Positive | Unsafe input propagates through variables | `propagation_unsafe_positive.js` |
| Negative | Safe constant propagation | `propagation_safe_negative.js` |
| Edge | Mixed branch trust state | `propagation_mixed_edge.js` |
| Edge | Reassignment changes trust (unsafe wins) | `propagation_reassign_unsafe_edge.js` |
| Edge | Reassignment changes trust (safe wins) | `propagation_reassign_safe_edge.js` |
| Edge | Sanitization transition | `propagation_sanitized_edge.js` |
| Edge | Partial branch overwrite | `propagation_partial_branch_edge.js` |

### Key Intent

- variable trust must not be forgotten
- overwrites must be respected deterministically

Current coverage:

- positive case added
- negative case added
- mixed branch case added
- overwrite dominance cases added
- sanitization transition case added

### Benchmark Dimensions

- trust accuracy
- state consistency

## GR-003 - Sanitization & Validation

Status: `🟡 Partial`

### Required Coverage

| Type | Description | File |
| --- | --- | --- |
| Positive | Missing sanitization before sink | `no_sanitization_positive.js` |
| Negative | Proper validation blocks exploit | `validated_input_negative.js` |
| Edge | Partial sanitization is insufficient | `partial_sanitization_edge.js` |
| Edge | Wrong sanitizer for context | `context_mismatch_sanitization_edge.js` |

### Key Intent

- not all sanitization is equal
- context-aware validation must be enforced

Current coverage:

- missing sanitization positive case added
- registered validator negative case added
- partial sanitizer edge case added
- wrong-context sanitizer edge case added
- post-sanitization propagation edge case added

### Benchmark Dimensions

- false negatives
- context awareness

## GR-004 - Sink Execution Safety

Status: `🟡 Partial`

Current note:

- current corpus covers obvious shell vs process differences
- abstraction and wrapper depth cases are still missing

Current coverage:

- `execSync` positive case added
- `spawn(..., { shell: true })` positive case added
- safe `spawn` negative case added
- constant `exec` negative case added
- aliased sink edge case added
- wrapped sink edge case added
- dynamic `spawn` command edge case added
- constant command with unsafe args edge case added

### Required Coverage

| Type | Description | File |
| --- | --- | --- |
| Positive | Dangerous sink used with dynamic input | `dangerous_sink_positive.js` |
| Negative | Safe API usage | `safe_api_negative.js` |
| Edge | Safe wrapper around dangerous sink | `wrapped_sink_edge.js` |
| Edge | Indirect sink call | `indirect_sink_edge.js` |

### Key Intent

- identify execution sinks regardless of abstraction
- avoid naive direct-call-only detection

### Benchmark Dimensions

- detection depth
- abstraction handling

## GR-005 - Context Mismatch

Status: `🔴 Not covered`

### Required Coverage

| Type | Description | File |
| --- | --- | --- |
| Positive | SQL-safe input reused in shell context | `sql_to_shell_positive.js` |
| Negative | Proper context isolation | `context_safe_negative.js` |
| Edge | Multi-context variable reuse | `multi_context_edge.js` |
| Edge | Encoding mismatch between contexts | `encoding_mismatch_edge.js` |

### Key Intent

- data safe in one context may be unsafe in another
- cross-context flows must be detected

### Benchmark Dimensions

- context sensitivity
- multi-sink reasoning

## GR-005 Implementation Note

GR-005 now has initial partial coverage in:

- `tools/owlvex-benchmark/corpus/context_mismatch/html_to_shell_positive.js`
- `tools/owlvex-benchmark/corpus/context_mismatch/html_to_process_positive.js`
- `tools/owlvex-benchmark/corpus/context_mismatch/shell_to_shell_negative.js`
- `tools/owlvex-benchmark/corpus/context_mismatch/generic_to_shell_edge.js`
- `tools/owlvex-benchmark/corpus/context_mismatch/no_sanitization_edge.js`

This v1 pack validates:

- sanitizer context is captured explicitly from GR-002 metadata
- sink context is consumed from GR-004 output
- `generic` sanitizers remain valid across sink contexts in v1
- context mismatch overrides `SAFE`

## Coverage Requirements (v1)

Minimum per rule:

- 1 positive
- 1 negative
- 2 edge

Target total cases:

- 20-30 new corpus files

Acceptance criteria:

- all rules have at least `🟡 Partial` coverage
- benchmark detects:
  - `>=95%` issue accuracy on corpus expectations
  - `<=5%` false positives in benchmark categories
- all edge cases produce deterministic outcomes

## Sequencing Recommendation

Recommended implementation order:

1. GR-002 trust propagation integrity
2. GR-001 injection and execution refinements
3. GR-003 sanitization and validation
4. GR-004 sink execution safety
5. GR-005 context mismatch

Why GR-002 first:

- trust propagation is the backbone of the rest of the guardrail system
- overwrite and branch behavior strongly affect injection, sanitization, and context reasoning

## Release Policy

No guardrail rule should ship without corpus coverage.

That means:

- no new rule without at least one positive and one negative case
- no edge-sensitive rule without explicit edge-case coverage
- no benchmarked release without traceable expected outcomes for each rule-covered case
