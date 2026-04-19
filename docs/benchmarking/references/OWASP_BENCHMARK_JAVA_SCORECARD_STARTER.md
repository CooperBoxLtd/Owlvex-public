# OWASP Benchmark Java Scorecard Starter

This is the first populated scorecard shell for the Owlvex OWASP Benchmark Java slice.

It is intentionally incomplete until a real external run is recorded.

## Benchmark Identity

- benchmark: `OWASP Benchmark Java`
- slice label: `owlvex-java-first-slice`
- benchmark version: `v1.2 target`
- Owlvex version: `current deterministic Java wave`
- run date: `pending first recorded slice run`

## Included Areas

| OWASP Benchmark Java area | Owlvex canonical issue | Owlvex rule code | Included? | Notes |
| --- | --- | --- | --- | --- |
| Command Injection | `owlvex.issue.command_injection.001` | `GR-001` | yes | supported deterministically in Java |
| Path Traversal | `owlvex.issue.path_traversal.001` | `PT-001` | yes | supported deterministically in Java |
| SQL Injection | `owlvex.issue.sql_injection.001` | `SQ-001` | yes | supported deterministically in Java |

## Deliberately Excluded Areas

| OWASP Benchmark Java area | Excluded? | Why |
| --- | --- | --- |
| Weak Cryptography | yes | not part of current mapped Java proof slice |
| Weak Hashing | yes | not part of current mapped Java proof slice |
| LDAP Injection | yes | not part of current mapped Java proof slice |
| Secure Cookie Flag | yes | Java external slice deferred for now |
| Trust Boundary Violation | yes/partial | not used as a first-slice headline category |
| Weak Randomness | yes | not part of current mapped Java proof slice |
| XPATH Injection | yes | not part of current mapped Java proof slice |
| XSS (Cross-Site Scripting) | yes | not part of current deterministic Java claim |

## Result Summary

- total included categories: `3`
- total cases reviewed: `pending`
- true positives: `pending`
- false positives: `pending`
- false negatives: `pending`
- precision: `pending`
- recall: `pending`

## Claim Boundary

Until a real external run is recorded, this file supports only this process claim:

Owlvex has a declared external Java benchmark slice with explicit included and excluded areas.

It does not yet support a numerical external benchmark claim.
