# Execution Risk Axis

This document defines the canonical deterministic execution-risk pipeline inside Owlvex.

It exists to lock down ownership boundaries, data contracts, and invariants for the first complete reasoning axis in the benchmark tool.

## Layer Order

Execution-risk evaluation must flow in this order:

1. `GR-002` trust propagation
2. `GR-003` trust transformation
3. `GR-004` sink shape and execution semantics
4. `GR-005` context validation
5. `GR-001` final policy decision

Later layers may consume earlier outputs.
Earlier layers must never depend on later layers.

## Ownership

### GR-002

Owns:

- variable trust state
- assignment and overwrite behavior
- branch merge behavior
- trust findings at sinks

Does not own:

- sink semantics
- sanitizer validity for a specific sink context
- final vulnerability policy decisions

### GR-003

Owns:

- explicit trust transformations
- trusted sanitizer registry
- transformation metadata such as sanitizer name and transformation context

Does not own:

- branch merge rules
- sink interpretation
- final vulnerability policy decisions

### GR-004

Owns:

- sink identification
- sink kind such as `shell` or `process`
- argument position relevant to the sink
- dangerous-in-context determination for the sink usage form

Does not own:

- trust propagation
- trust transformation
- trust resolution
- final vulnerability policy decisions

### GR-005

Owns:

- validation of transformation context against sink context
- effective invalidation of `SAFE` when context does not match

Does not own:

- trust propagation rules
- sink identification
- final vulnerability policy decisions outside context validation

### GR-001

Owns:

- final execution-risk decision
- policy consumption of trust, sink, and context outputs

Does not own:

- trust inference
- sink discovery
- sanitizer inference
- context inference

## Data Contracts

### GR-002 output

Must provide:

- trust states per variable
- sink findings with:
  - `sink`
  - `expression`
  - `variable`
  - `trustState`
  - `transformation`
  - `sanitizer`
  - `transformationContext`

### GR-004 output

Must provide:

- `sink`
- `sinkKind`
- `argumentIndex`
- `dangerousInContext`
- `expression`
- `variable`

### GR-005 output

Must provide:

- `sinkContext`
- `contextValid`
- `effectiveTrustState`
- `unsafeAtSink`

### GR-001 input contract

GR-001 must consume:

- trust state from GR-002 and GR-003 outputs
- sink shape from GR-004 output
- context validity from GR-005 output when available

GR-001 must not reconstruct any of those from raw source strings.

## Invariants

The following invariants are mandatory for this axis.

### Trust ownership

- GR-001 must never infer trust
- GR-004 must never compute trust
- GR-005 must not mutate trust propagation rules

### Sink ownership

- sink kind is owned by GR-004
- argument relevance is owned by GR-004
- `shell: true` changes sink context at GR-004, not elsewhere

### State rules

- `MIXED` is unsafe at sinks
- `UNKNOWN` must never mask `UNSAFE`
- overwrite dominance is decided in GR-002

### Context rules

- context mismatch overrides `SAFE`
- `generic` transformation context is accepted across sink contexts in v1
- no transformation means GR-005 does not create safety on its own

### Policy rules

- GR-001 is a thin consumer
- final execution finding is a deterministic consequence of:
  - trust state
  - sink danger in context
  - context validity

## Forbidden Behavior

The following are explicitly forbidden:

- reconstructing trust from source-code strings in GR-001
- inferring sanitizer type from names outside the explicit registry
- allowing GR-004 to mark something safe by changing trust state
- allowing GR-005 to redefine propagation behavior
- mixing benchmark expectations across layers without updating corpus assertions

## Release Gate

The execution-risk axis is considered healthy only when all of these pass:

- `npm run benchmark:gr002`
- `npm run benchmark:gr003`
- `npm run benchmark:gr004`
- `npm run benchmark:gr005`
- `npm run benchmark:gr001`
- `npm run benchmark:integration`

The preferred aggregate gate is:

```bash
npm run benchmark:deterministic
```

## v1 Complete Criteria

Execution-risk v1 is complete when:

- all five deterministic rule layers exist
- all five suites pass
- integration coverage exists and passes
- the aggregate deterministic runner passes
- the contract in this document remains true
- future changes preserve ownership boundaries

## Bottom Line

This axis is the template for future Owlvex reasoning systems.

The key rule is simple:

Each layer must know exactly one kind of truth, and only consume the rest.
