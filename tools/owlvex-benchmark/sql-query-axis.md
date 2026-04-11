# SQL Query Axis

This document defines the planned deterministic SQL and contextual query execution axis inside Owlvex.

It is the second major reasoning axis after execution risk.

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

## Initial Layering Plan

The SQL axis should follow the same ownership model as the execution-risk axis.

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

## Initial Invariants

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

## v1 Direction

SQL v1 should start narrower than a full SQL analyzer.

It should focus on:

- direct string interpolation into query text
- parameterized query negatives
- simple propagation and overwrite behavior
- sink identification for common `db.query(...)` shapes

That keeps the axis benchmarkable and deterministic from the start.
