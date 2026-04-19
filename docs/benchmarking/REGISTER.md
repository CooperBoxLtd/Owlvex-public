# Benchmark Register

This file is the authoritative register of benchmark assets owned by the Benchmarking Department.

Each entry should answer:

- what the benchmark is
- what claim it supports
- whether it is Owlvex-native or external
- whether it is live, draft, or planned

## Owlvex-Native Benchmarks

| Benchmark | Type | Source | Status | Supports Claim |
| --- | --- | --- | --- | --- |
| Deterministic engine gate | proof | `tools/owlvex-benchmark/` | live | Owlvex deterministic axes are benchmark-backed for covered suites |
| Demo stabilization benchmark | proof/product | `tools/demo/benchmark.expectations.json` | live | Unsafe/safe demo fixtures remain aligned with the trusted surface |
| Demo-app stabilization benchmark | proof/product | `tools/demo-app/benchmark.expectations.json` | live | Repo-style benchmark behavior stays aligned with the trusted surface |
| Demo AI benchmark | AI/product | `tools/demo/ai-benchmark.expectations.json` | live | AI lane can be scored on unsafe recall, safe quietness, family match, and lane fit |
| AI benchmark evaluator | AI/tooling | `tools/evaluate-ai-benchmark.mjs` | live | AI benchmark results are repeatable and reviewable |
| Baseline layout | governance | `docs/benchmarking/references/BASELINE_LAYOUT.md` | live | Every benchmark claim can point to its source and artifact location |

## External Benchmark Anchors

| Benchmark | Type | Source | Status | Supports Claim |
| --- | --- | --- | --- | --- |
| OWASP Benchmark Java slice | proof/external | OWASP Benchmark | starter | Owlvex deterministic proof can be compared to a known AppSec benchmark on mapped families |
| OWASP Benchmark Java scorecard starter | proof/external | OWASP Benchmark | starter | Owlvex external Java claim has an explicit scorecard boundary before real result numbers exist |
| Juliet / SARD slices | proof/external | NIST SARD | starter | Owlvex deterministic rules can be cross-checked against CWE-oriented corpora |
| SecurityEval references | AI/external | SecurityEval | planned | Owlvex AI behavior can be calibrated against external LLM security-eval references |
| CyberSecEval references | AI/external | Purple Llama / CyberSecEval | planned | Owlvex AI and agent-lane positioning can be compared to broader cybersecurity AI evaluation work |

## Working Rule

No benchmark should be used in product or client claims unless:

1. it appears in this register
2. its role is documented
3. its current status is explicit
