# Owlvex Corpus Benchmark Report

Generated: `2026-04-09`
Source snapshot: `corpus/last-run.json`
Corpus version: `owlvex.corpus.v1`

## Executive Summary

Owlvex now has a family-aware, adversarial benchmark corpus that measures more than raw detection. It evaluates:

- issue-level accuracy
- family-level accuracy
- false positives
- performance by difficulty tier

The current corpus contains `45` cases spanning:

- Secrets & Credential Exposure
- Injection & Execution
- Identity & Auth Failures
- Access Control & Authorization
- Data Protection & Privacy
- Cryptography & Randomness

## Current Results

### Overall

- Total cases: `45`
- Issue accuracy: `80%`
- Family accuracy: `82%`
- False positives: `5`

### By Family

| Family | Cases | Issue Accuracy | Family Accuracy | False Positives |
| --- | ---: | ---: | ---: | ---: |
| Secrets & Credential Exposure | 7 | 100% | 100% | 0 |
| Injection & Execution | 13 | 69% | 77% | 2 |
| Identity & Auth Failures | 5 | 80% | 80% | 1 |
| Access Control & Authorization | 9 | 78% | 78% | 0 |
| Data Protection & Privacy | 10 | 80% | 80% | 2 |
| Cryptography & Randomness | 1 | 100% | 100% | 0 |

### By Difficulty

| Difficulty | Cases | Issue Accuracy | Family Accuracy | False Positives |
| --- | ---: | ---: | ---: | ---: |
| easy | 20 | 100% | 100% | 0 |
| medium | 6 | 100% | 100% | 0 |
| hard | 19 | 53% | 58% | 5 |

## Interpretation

The benchmark is no longer saturated. Easy and medium cases are strong, but hard cases now expose where Owlvex still needs better judgment under ambiguity and noise.

The current hard-case misses show three main classes of weakness:

1. Noise sensitivity
   Comments, strings, and debug examples can still trigger injection and disclosure logic.

2. Cross-family overlap
   Multi-issue files create interaction pressure between injection, secrets, and data-protection findings.

3. Access-control nuance
   Auth-present-but-authz-missing patterns remain harder than straightforward ownership failures.

## Most Important Findings

### Strongest Areas

- Secrets & Credential Exposure is stable on the current corpus.
- Cryptography & Randomness is stable on the current corpus.
- Medium-difficulty family recognition is currently strong.

### Weakest Areas

- Injection & Execution has the lowest family accuracy.
- Data Protection & Privacy still suffers from overlap between verbose error disclosure and sensitive logging.
- Hard difficulty is now the real pressure test for the system.

## Why This Matters

Owlvex is no longer just detecting obvious problems. It is now being measured against ambiguous, noisy, and multi-issue inputs. That means the benchmark is testing:

- judgment, not just pattern matching
- canonical classification, not just generic “something is wrong”
- precision under pressure, not just easy wins

This is the right phase for a serious security product.

## Recommended Next Steps

1. Fix the `5` false positives in `corpus/last-run.json`
2. Add a dedicated decision/disambiguation layer separate from signal generation
3. Keep expanding hard negatives and cross-family stress cases
4. Track `missedCanonical` and `extraCanonical` per case as the main tuning loop
5. Use this corpus to compare provider quality later, not only local heuristics

## Benchmark Assets

- Corpus manifest: `corpus/manifest.json`
- Last benchmark run: `corpus/last-run.json`
- Corpus guide: `corpus/README.md`
- Runner: `extension/src/frameworks/corpusRunner.ts`

## Product Takeaway

Owlvex now has:

- a canonical issue ontology
- family-aware risk grouping
- adversarial benchmark coverage
- measurable accuracy by domain and difficulty

That moves the product from “AI-assisted scanner” toward a real security intelligence system with a repeatable quality loop.
