# Juliet / SARD Slice Starter

## Purpose

This document defines the starter approach for using Juliet / SARD as the second external proof anchor for Owlvex.

It should remain narrower than the full Juliet universe.

## Why Juliet / SARD Is Different

Juliet is useful because it provides:

- broad CWE-oriented weakness coverage
- large corpora in C/C++ and Java
- a strong reference point for structural weakness classes

But Juliet is weaker than an Owlvex-native benchmark for:

- modern web-app semantics
- explanation-fidelity benchmarking
- scan-tier fit
- client-facing product truth

So Juliet should be used as a selective corpus, not as the whole benchmark story.

## First Recommended Owlvex-Aligned Slice

The first Juliet / SARD slice should stay narrow and use weakness classes that are already close to Owlvex's promoted deterministic families.

Recommended candidates:

| CWE family | Owlvex canonical issue | Owlvex rule code | Fit |
| --- | --- | --- | --- |
| CWE-78 OS Command Injection | `owlvex.issue.command_injection.001` | `GR-001` | strong |
| CWE-89 SQL Injection | `owlvex.issue.sql_injection.001` | `SQ-001` | strong |
| CWE-22 Path Traversal | `owlvex.issue.path_traversal.001` | `PT-001` | strong |
| CWE-502 Insecure Deserialization | `owlvex.issue.insecure_deserialization.001` | `DS-001` | useful later |

## Out Of Scope For The First Juliet Slice

Do not use the first Juliet slice for:

- broad AI-only issues
- workflow or business-logic mistakes
- issue families where Owlvex only has advisory-quality support
- a giant multi-language headline claim

## Working Rule

Juliet / SARD should support statements like:

- Owlvex has cross-checked selected deterministic families against CWE-oriented external corpora

It should not be used for statements like:

- Owlvex covers the whole Juliet universe
- Owlvex is fully benchmarked across all CWE classes and languages
