# Benchmark Runs

This directory stores persistent benchmark artifacts.

## Layout

- `deterministic/`: timestamped and latest summaries for the deterministic execution-risk gate
- model-specific result files can also live here when imported or generated from model runs

## Deterministic Gate Artifacts

`npm run benchmark:deterministic` writes:

- `tools/owlvex-benchmark/runs/deterministic/latest.json`
- `tools/owlvex-benchmark/runs/deterministic/<timestamp>.json`
- `tools/owlvex-benchmark/runs/deterministic/latest.full.json`
- `tools/owlvex-benchmark/runs/deterministic/<timestamp>.full.json`

Use:

- `latest.json` for compact release-gate summaries
- `latest.full.json` for detailed debugging and regression inspection

These artifacts are useful for:

- tracking deterministic benchmark health over time
- spotting regressions between commits
- building release confidence history
- comparing per-suite summaries without rerunning the full tool

## Model Run Suggestions

Suggested naming for model-backed result files:

- `qwen2.5_7b.results.json`
- `llama3.1_8b.results.json`
- `mistral_small.results.json`
