# Juliet / SARD Scorecard Template

Use this template when Owlvex records its first selective Juliet / SARD slice result.

## Benchmark Identity

- benchmark: `Juliet / SARD`
- slice label:
- corpus version:
- Owlvex version:
- run date:

## Included CWE Families

| CWE | Label | Owlvex canonical issue | Rule code | Included? | Notes |
| --- | --- | --- | --- | --- | --- |
| CWE-78 | OS Command Injection | `owlvex.issue.command_injection.001` | `GR-001` | yes |  |
| CWE-89 | SQL Injection | `owlvex.issue.sql_injection.001` | `SQ-001` | yes |  |
| CWE-22 | Path Traversal | `owlvex.issue.path_traversal.001` | `PT-001` | yes |  |
| CWE-502 | Insecure Deserialization | `owlvex.issue.insecure_deserialization.001` | `DS-001` | later |  |

## Result Summary

- total included CWE families:
- total cases reviewed:
- true positives:
- false positives:
- false negatives:
- precision:
- recall:

## Claim Boundary

This scorecard supports only a selective Juliet / SARD slice claim.

It does not support:

- blanket Juliet / SARD coverage
- blanket multi-language benchmark claims
- equivalence between AI findings and deterministic external-proof benchmarking
