# Benchmark Runs

This directory stores persistent benchmark artifacts.

Generated run outputs are local working artifacts and should not be committed by default.

## Layout

- `deterministic/`: timestamped and latest summaries for the deterministic execution-risk gate
- `ai-evals/`: timestamped and latest summaries for the AI-only evaluation lane
- model-specific result files can also live here when imported or generated from model runs

Tracked files in this directory should generally be documentation only, such as this README.

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

## AI Eval Artifacts

`npm run benchmark:ai-evals -- <report.md> [model-tag]` writes:

- `tools/owlvex-benchmark/runs/ai-evals/latest.json`
- `tools/owlvex-benchmark/runs/ai-evals/latest.results.json`
- `tools/owlvex-benchmark/runs/ai-evals/<timestamp>.json`
- `tools/owlvex-benchmark/runs/ai-evals/<timestamp>.results.json`

Use:

- `latest.json` for compact AI-eval summaries
- `latest.results.json` for per-case checks and debugging

These artifacts are directional quality signals for AI-only coverage, not deterministic release evidence.

## Model Run Suggestions

Suggested naming for model-backed result files:

- `qwen2.5_7b.results.json`
- `llama3.1_8b.results.json`
- `mistral_small.results.json`
