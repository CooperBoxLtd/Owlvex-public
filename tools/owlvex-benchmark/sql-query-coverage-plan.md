# SQL Query Coverage Plan

This document defines the benchmark coverage plan for the SQL and contextual query execution axis.

The SQL axis engine now exists, and this document records the coverage model it is expected to maintain.

## Coverage Goals

Each SQL rule should have:

- at least 1 positive case
- at least 1 negative case
- at least 1 edge case

## Rule Matrix

## SQ-001 - Query Injection Decision

Status: `Complete`

Required coverage:

| Type | Description | File |
| --- | --- | --- |
| Positive | Direct interpolated query text | `direct_query_positive.js` |
| Negative | Parameterized query | `parameterized_query_negative.js` |
| Edge | Mixed branch into query text | `conditional_query_edge.js` |

## SQ-002 - Trust Propagation

Status: `Complete`

Required coverage:

| Type | Description | File |
| --- | --- | --- |
| Positive | Unsafe input propagated into query variable | `propagation_unsafe_query_positive.js` |
| Negative | Safe constant propagated into query variable | `propagation_safe_query_negative.js` |
| Edge | Reassignment and branch merge for query variable | `propagation_mixed_query_edge.js` |

## SQ-003 - Query Transformation

Status: `Complete`

Required coverage:

| Type | Description | File |
| --- | --- | --- |
| Positive | Missing SQL-safe handling | `no_sql_validation_positive.js` |
| Negative | Explicit parameter binding | `parameter_binding_negative.js` |
| Edge | Transformation that is not SQL-safe | `wrong_transform_query_edge.js` |

## SQ-004 - Query Sink Shape

Status: `Complete`

Required coverage:

| Type | Description | File |
| --- | --- | --- |
| Positive | `db.query` with interpolated string | `direct_query_positive.js` |
| Negative | `db.query` with text and params array | `parameterized_query_negative.js` |
| Edge | Wrapped query helper | `wrapped_query_edge.js` |

## SQ-005 - Query Context Mismatch

Status: `Complete`

Required coverage:

| Type | Description | File |
| --- | --- | --- |
| Positive | HTML-oriented transformation reused in SQL | `html_to_sql_positive.js` |
| Negative | SQL-safe parameter binding context | `sql_context_safe_negative.js` |
| Edge | Generic validation reused in SQL | `generic_to_sql_edge.js` |

## Current Target

The current SQL deterministic gate covers:

1. propagation
2. transformation
3. sink shape
4. context mismatch
5. final decision
6. SQL integration

## Release Rule

No SQL deterministic layer should exist without corpus coverage for the specific behavior it claims to enforce.
