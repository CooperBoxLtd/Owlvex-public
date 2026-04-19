# Benchmarking Methodology

## Goal

Benchmarking in Owlvex is designed to be:

- explicit
- repeatable
- reviewable
- contestable

It is not designed to pretend that every score is objective truth.

## Benchmark Types

### 1. Deterministic proof benchmark

Measures:

- structural correctness
- safe negative discipline
- rule coverage within bounded contracts

### 2. AI product benchmark

Measures:

- unsafe recall
- safe quietness
- issue-family match
- explanation fidelity
- confidence discipline
- recommended scan-tier fit

### 3. External benchmark alignment

Measures:

- how Owlvex compares to recognized external benchmark slices

## Method Rules

### Safe / unsafe pairing

Every benchmark family should use:

- unsafe example
- safe companion

### Explanation review

Benchmark review must not stop at:

- finding present
- finding absent

It must also assess:

- whether the explanation matches the visible code
- whether the language overclaims
- whether advisory patterns were incorrectly explained as vulnerabilities

### Objective vs judgment-based signals

Objective signals:

- finding present / absent
- scan mode shown in report
- detection confidence present / absent
- detection identity fragments

Judgment-based signals:

- whether the issue family was the best fit
- whether the explanation was faithful
- whether the confidence sounded reasonable
- whether the recommended scan tier was the right product lane

Owlvex benchmarks must keep these two kinds of signals visibly separate.

## Why Internal Benchmarks Still Matter

External benchmarks do not fully measure:

- explanation honesty
- safe-pair quietness in Owlvex UX
- `STATIC` vs `TARGETED_AI` vs `REPO_AI` fit
- report quality and provenance framing

That is why Owlvex needs native benchmarks even when it uses external anchors.

## How To Handle Benchmark Disputes

When a benchmark result is disputed:

1. inspect the fixture
2. inspect the expected manifest
3. inspect the generated report
4. decide whether the fixture, expectation, or scanner behavior is wrong
