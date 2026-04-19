# OWASP Benchmark Java Scorecard Template

Use this template when Owlvex produces its first external OWASP Benchmark Java slice result.

## Benchmark Identity

- benchmark: `OWASP Benchmark Java`
- slice label:
- benchmark version:
- Owlvex version:
- run date:

## Included Areas

| OWASP Benchmark Java area | Owlvex canonical issue | Owlvex rule code | Included? | Notes |
| --- | --- | --- | --- | --- |
| Command Injection | `owlvex.issue.command_injection.001` | `GR-001` | yes |  |
| Path Traversal | `owlvex.issue.path_traversal.001` | `PT-001` | yes |  |
| SQL Injection | `owlvex.issue.sql_injection.001` | `SQ-001` | yes |  |

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

- total included categories:
- total cases reviewed:
- true positives:
- false positives:
- false negatives:
- precision:
- recall:

## Claim Boundary

This scorecard supports only this narrow claim:

Owlvex has benchmarked deterministic Java coverage on the explicitly included OWASP Benchmark Java slice above.

It does not support:

- blanket OWASP Benchmark Java coverage claims
- blanket Java-language security coverage claims
- equivalence between Owlvex AI findings and deterministic benchmark proof
