# SQL Query Axis

This document defines the canonical deterministic SQL and contextual query execution axis inside Owlvex.

It is the second complete reasoning axis after execution risk.

The goal is to reuse the same layered discipline:

1. trust
2. transformation
3. sink shape
4. context validation
5. final policy decision

## Purpose

The SQL query axis exists to reason deterministically about:

- unsafe string interpolation in SQL
- safe parameterized query construction
- variable trust as it flows into query construction
- transformations that are relevant to SQL safety
- context mismatch where data is transformed for one context and reused in SQL

## Layer Order

SQL query evaluation must flow in this order:

1. `SQ-002` trust propagation
2. `SQ-003` SQL transformation
3. `SQ-004` query sink shape
4. `SQ-005` SQL context validation
5. `SQ-001` final policy decision

Later layers may consume earlier outputs.
Earlier layers must never depend on later layers.

## Ownership

### SQ-002

Owns:

- trust propagation for values used in query construction
- overwrite and branch merge behavior for SQL-bound variables

### SQ-003

Owns:

- SQL-relevant transformations
- explicit registry of SQL-safe patterns and recognized validators

### SQ-004

Owns:

- query sink identification
- query construction shape
- whether a query is parameterized or interpolated

### SQ-005

Owns:

- context validation for transformations reused in SQL
- invalidation of `SAFE` when a transformation is not valid for SQL context

### SQ-001

Owns:

- final SQL-risk decision
- deterministic policy consumption of trust, sink, and context outputs

## Invariants

- SQL policy must not infer trust on its own
- query sink detection must not compute trust
- parameterized queries must be distinguishable from interpolated queries
- `MIXED` is unsafe at SQL sinks
- context mismatch overrides `SAFE`

## Seed Sources In This Repo

The current repo already contains useful SQL fixtures:

- `corpus/injection_execution/positive/sql_injection_positive.js`
- `corpus/injection_execution/negative/parameterized_query_negative.js`

These should remain benchmark anchors for the SQL axis as it grows.

## Current Scope

This axis is now implemented and benchmarked for:

- direct string interpolation into query text
- parameterized query negatives
- trust propagation and overwrite behavior
- SQL-safe transformation handling
- query sink identification for common `db.query(...)` shapes
- context mismatch where a transformation is valid for another context but not for SQL
- end-to-end integration coverage across the SQL pipeline

## Release Gate

The SQL query axis is considered healthy only when all of these pass:

- `npm run benchmark:sq002`
- `npm run benchmark:sq003`
- `npm run benchmark:sq004`
- `npm run benchmark:sq005`
- `npm run benchmark:sq001`
- `npm run benchmark:sql-integration`

The preferred aggregate gate is:

```bash
npm run benchmark:deterministic
```

## Bottom Line

The SQL axis is no longer planned work.

It is an active deterministic reasoning subsystem with its own layered contract and release gate.
