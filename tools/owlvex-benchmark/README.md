# Owlvex Benchmark Tool

This tool is the dedicated home for model benchmarking and evaluation inside the CodeScanner repo.

Its purpose is to answer a focused question:

`How reliable is a model for Owlvex-style security reasoning?`

This is intentionally separate from the probe corpus itself. The benchmark tool owns:

- benchmark definitions
- scoring rules
- import and run automation
- repeatable result formats
- confidence and release guidance

The benchmark corpus lives in CodeScanner-owned paths only.

## Layout

- `manifest.json`: canonical benchmark case list and expected outcomes
- `results.template.json`: standard result format for any model run
- `score.mjs`: weighted scorer
- `import-report.mjs`: imports Owlvex markdown reports into benchmark results
- `run-ollama-ssh.mjs`: runs the benchmark against a remote Ollama host over SSH
- `run-deterministic.mjs`: aggregate deterministic gate for the execution-risk axis
- `guardrails-v1.md`: deterministic post-LLM guardrail specification
- `guardrail-coverage-plan.md`: corpus coverage plan for each v1 guardrail rule
- `execution-risk-axis.md`: architecture contract for the deterministic execution-risk pipeline
- `sql-query-axis.md`: architecture contract for the planned SQL and contextual query axis
- `deterministic-finding-schema.md`: canonical output contract for deterministic benchmark-backed findings
- `release-confidence.md`: guidance for interpreting deterministic benchmark artifacts as release evidence
- `sql-query-coverage-plan.md`: initial coverage plan for the SQL and contextual query axis
- `roadmap.md`: phased development plan for stabilizing and extending the benchmark tool
- `runs/`: recommended place for model result files

## Current Scope

Right now the tool evaluates reliability across:

- command injection detection
- non-shell remediation recognition
- user-controlled command execution
- SQL injection
- hardcoded secrets
- safe baseline handling
- benign security-shaped false-positive resistance

## Corpus

Benchmark fixtures currently come from two places:

- `corpus/`: CodeScanner's main golden corpus for family-aware benchmark cases
- `tools/owlvex-benchmark/corpus`: rule-focused deterministic benchmark expansions
  - `trust_propagation/`: GR-002 trust-state cases
  - `injection_execution/`: GR-001 execution-risk cases built on top of GR-002 output
  - `sanitization_validation/`: GR-003 explicit sanitizer and validator cases
  - `sink_execution/`: GR-004 sink-shape and dangerous-context cases
  - `context_mismatch/`: GR-005 validation of transformation context against sink context
  - `execution_risk_integration/`: end-to-end execution-risk composition cases
  - `sql_query/`: seed corpus for the SQL and contextual query execution axis

## Current Dimensions

- recall
- false-positive control
- sink classification
- taxonomy precision

## Usage

Import an Owlvex markdown report:

```bash
npm run benchmark:import -- <report.md> <results.json> <model-tag>
```

Run the benchmark directly against a remote Ollama host:

```bash
npm run benchmark:run:ssh -- <ssh-host> <model-tag> <results.json>
```

Score a completed result file:

```bash
npm run benchmark:score -- <results.json>
```

Run the full deterministic execution-risk gate:

```bash
npm run benchmark:deterministic
```

Summarize the current deterministic release status:

```bash
npm run benchmark:status
```

This command also writes a persistent summary to:

- `tools/owlvex-benchmark/runs/deterministic/latest.json`
- `tools/owlvex-benchmark/runs/deterministic/<timestamp>.json`

It also writes detailed artifacts for debugging:

- `tools/owlvex-benchmark/runs/deterministic/latest.full.json`
- `tools/owlvex-benchmark/runs/deterministic/<timestamp>.full.json`

Run the deterministic GR-002 corpus:

```bash
npm run benchmark:gr002
```

Run the deterministic GR-001 corpus:

```bash
npm run benchmark:gr001
```

Run the deterministic GR-003 corpus:

```bash
npm run benchmark:gr003
```

Run the deterministic GR-004 corpus:

```bash
npm run benchmark:gr004
```

Run the deterministic GR-005 corpus:

```bash
npm run benchmark:gr005
```

Run the execution-risk integration corpus:

```bash
npm run benchmark:integration
```

Run the first SQL sink-shape slice:

```bash
npm run benchmark:sq004
```

Run the first SQL trust-propagation slice:

```bash
npm run benchmark:sq002
```

Run the first SQL decision slice:

```bash
npm run benchmark:sq001
```

## Evolution Plan

This tool should evolve according to `roadmap.md`.

The current priorities are:

- canonical deterministic finding output
- better run history and confidence reporting
- SQL and contextual query execution as the next deterministic axis

The canonical deterministic finding schema is now emitted by:

- `npm run benchmark:gr001`
- `npm run benchmark:integration`

## Release Confidence

Use `release-confidence.md` as the interpretation guide for deterministic run artifacts.

Operational release status for the covered execution-risk axis is available through:

- `npm run benchmark:status`

In general, confidence depends on:

- number of benchmark cases
- breadth of vulnerability families
- repeatability across multiple runs
- stability of the scoring rubric
- agreement that case expectations are correct

At the moment this is a strong starting benchmark, but not yet a final release-certification suite.
