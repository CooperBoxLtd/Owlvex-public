# Benchmark Baseline Layout

This document explains where benchmark inputs, outputs, and historical artifacts live.

## Owlvex-Native Proof Benchmarks

### Deterministic engine gate

Source:

- `tools/owlvex-benchmark/`

Artifacts:

- `tools/owlvex-benchmark/runs/deterministic/`

Current baseline pointer:

- `tools/owlvex-benchmark/runs/deterministic/latest.json`
- `tools/owlvex-benchmark/runs/deterministic/latest.full.json`

### Demo stabilization benchmark

Source:

- `tools/demo/benchmark.expectations.json`
- `tools/demo/EXPECTATIONS.md`

Artifacts:

- generated markdown reports in `tools/demo/`

### Demo-app stabilization benchmark

Source:

- `tools/demo-app/benchmark.expectations.json`
- `tools/demo-app/EXPECTATIONS.md`

Artifacts:

- generated markdown reports in `tools/demo-app/`

## Owlvex-Native AI Benchmarks

### Demo AI benchmark

Source:

- `tools/demo/ai-benchmark.expectations.json`
- `tools/demo/AI_BENCHMARKING.md`

Evaluator:

- `tools/evaluate-ai-benchmark.mjs`

Artifacts:

- generated markdown reports in `tools/demo/`
- future scored snapshots should be stored in a dedicated AI results archive once the benchmark stabilizes

## External Benchmark References

Reference layer:

- `docs/benchmarking/references/`

Current starter docs:

- `OWASP_BENCHMARK_JAVA_SLICE.md`

Future imported slices or scorecards should keep:

- the benchmark source
- included categories
- excluded categories
- Owlvex mapping notes
- stored result artifacts

## Working Rule

Every benchmark claim should point to:

1. the benchmark source manifest or contract
2. the latest result artifact
3. the methodology that explains what the score means
