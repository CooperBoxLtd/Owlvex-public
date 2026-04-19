# Benchmarking Department Charter

## Mission

The Benchmarking Department exists to define, measure, and defend Owlvex's quality claims.

It owns the benchmark strategy for:

- deterministic proof
- AI-assisted reasoning
- scan-mode and agent-fit guidance
- release confidence
- external benchmark alignment

## Non-Negotiable Principles

1. Benchmarking must separate `proof` from `AI judgment`.
2. Safe companions matter as much as unsafe fixtures.
3. Explanations are benchmarked, not only detections.
4. A benchmark score is not truth; it is a declared and reviewable contract.
5. External benchmarks support credibility, but they do not replace Owlvex-native evaluation.

## Scope

The department owns benchmark governance across three layers:

### Layer A: Deterministic Proof Benchmarks

Purpose:

- verify structural correctness of the trusted local engine

Examples:

- `tools/owlvex-benchmark/`
- `tools/demo/benchmark.expectations.json`
- `tools/demo-app/benchmark.expectations.json`

### Layer B: AI Product Benchmarks

Purpose:

- measure unsafe-case recall, safe-case quietness, family match, explanation fidelity, and confidence discipline for the AI lane

Examples:

- `tools/demo/ai-benchmark.expectations.json`
- `tools/evaluate-ai-benchmark.mjs`

### Layer C: External Benchmark Alignment

Purpose:

- anchor Owlvex quality claims against widely known external datasets without letting external datasets define the whole product

Examples:

- OWASP Benchmark
- Juliet / SARD
- SecurityEval
- CyberSecEval / Purple Llama

## Department Output

The Benchmarking Department is responsible for:

- benchmark manifests
- benchmark methodology
- benchmark scoring rules
- benchmark documentation
- benchmark roadmap
- client-facing benchmark explanation

## Department Boundaries

The department does not:

- turn exploratory AI into proof by language alone
- combine deterministic and AI scores into a single misleading quality claim
- treat benchmark success as a substitute for product review
- silently redefine expectations without updating the declared benchmark contract

## Success Condition

The department is successful when:

- engineers know what quality bar a change must clear
- product claims match measured behavior
- clients can understand when to trust `STATIC`, `TARGETED_AI`, or `REPO_AI`
- benchmark disputes can be resolved by reading fixtures, manifests, and methodology rather than guessing
