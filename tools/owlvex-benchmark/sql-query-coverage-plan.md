# SQL Query Coverage Plan

This document defines the initial benchmark coverage plan for the SQL and contextual query execution axis.

The aim is to establish deterministic ground truth before implementing the SQL axis engine.

## Coverage Goals

Each planned SQL rule should have:

- at least 1 positive case
- at least 1 negative case
- at least 1 edge case

## Initial Rule Matrix

## SQ-001 - Query Injection Decision

Status: `Planned`

Required coverage:

| Type | Description | File |
| --- | --- | --- |
| Positive | Direct interpolated query text | `direct_query_positive.js` |
| Negative | Parameterized query | `parameterized_query_negative.js` |
| Edge | Mixed branch into query text | `conditional_query_edge.js` |

## SQ-002 - Trust Propagation

Status: `Planned`

Required coverage:

| Type | Description | File |
| --- | --- | --- |
| Positive | Unsafe input propagated into query variable | `propagation_unsafe_query_positive.js` |
| Negative | Safe constant propagated into query variable | `propagation_safe_query_negative.js` |
| Edge | Reassignment and branch merge for query variable | `propagation_mixed_query_edge.js` |

## SQ-003 - Query Transformation

Status: `Planned`

Required coverage:

| Type | Description | File |
| --- | --- | --- |
| Positive | Missing SQL-safe handling | `no_sql_validation_positive.js` |
| Negative | Explicit parameter binding | `parameter_binding_negative.js` |
| Edge | Transformation that is not SQL-safe | `wrong_transform_query_edge.js` |

## SQ-004 - Query Sink Shape

Status: `Planned`

Required coverage:

| Type | Description | File |
| --- | --- | --- |
| Positive | `db.query` with interpolated string | `db_query_interpolated_positive.js` |
| Negative | `db.query` with text and params array | `db_query_parameterized_negative.js` |
| Edge | Wrapped query helper | `wrapped_query_edge.js` |

## SQ-005 - Query Context Mismatch

Status: `Planned`

Required coverage:

| Type | Description | File |
| --- | --- | --- |
| Positive | HTML-oriented transformation reused in SQL | `html_to_sql_positive.js` |
| Negative | SQL-safe parameter binding context | `sql_context_safe_negative.js` |
| Edge | Generic validation reused in SQL | `generic_to_sql_edge.js` |

## Initial Target

The first SQL corpus pack should prioritize:

1. direct interpolated positive case
2. parameterized negative case
3. propagation edge case
4. wrapped query edge case
5. context mismatch positive case

## Release Rule

No SQL deterministic layer should be implemented without corpus coverage for the specific behavior it claims to enforce.
