# Owlvex

Prototype VS Code extension for security scanning, AI-assisted review, and fix preview workflows.

## Current Version

`0.1.26`

## Download

- Marketplace: https://marketplace.visualstudio.com/items?itemName=owlvex.owlvex
- VSIX: [owlvex-0.1.26.vsix](releases/owlvex-0.1.26.vsix)
- SHA256: `0BD88F24C576802ECAAD2A851340C48BFD45313B96ACC8F79340763F7690D0B7`

Install from terminal:

```powershell
code --install-extension .\releases\owlvex-0.1.26.vsix --force
```

Support: [SUPPORT.md](SUPPORT.md) or info@cooperbox.co.uk

## Prototype Status

Owlvex is not a finished commercial product yet.

Current expectations:

- use it as a prototype / evaluation build
- expect rough edges and ongoing UI or backend changes
- verify important findings manually before acting on them
- expect some model-specific variation in scan quality, latency, and coverage

## What It Does

Owlvex combines:

- deterministic local checks
- safe probe verification for selected sink-driven findings
- AI-assisted targeted review
- repo-context reasoning for some workflows
- report generation
- report comparison
- fix preview and verification flows

## Security Test Benchmark

This repository also publishes `security-test-benchmark/`, a deliberately vulnerable Express application used to evaluate Owlvex against a realistic codebase.

This folder is test material. It contains intentionally unsafe routes and helpers so scanners can be compared against known expectations. It is not product code and must not be deployed.

The benchmark is public so GitHub CodeQL can scan the same source and provide an independent SAST signal.

Benchmark materials:

- [security-test-benchmark/README.md](security-test-benchmark/README.md)
- [security-test-benchmark/EXPECTATIONS.md](security-test-benchmark/EXPECTATIONS.md)
- [security-test-benchmark/benchmark.expectations.json](security-test-benchmark/benchmark.expectations.json)

CodeQL runs through `.github/workflows/codeql-benchmark.yml` and is scoped to `security-test-benchmark/`.

Supported provider paths include:

- Azure AI Foundry
- OpenAI
- Anthropic
- Gemini
- Groq
- Mistral
- Ollama
- custom OpenAI-compatible endpoints

## Model Guidance

Best results so far have come from:

- GPT-5.4
- GPT-5.4 Mini

If you are evaluating Owlvex for the first time, start with one of those models before comparing other providers or smaller models.

## Installation

### Download From GitHub

If Owlvex is being distributed through a public GitHub repository, download the latest production `.vsix` from that repository's `Releases` page.

### Install From VSIX

1. Open VS Code.
2. Open the Extensions view.
3. Open the Extensions `...` menu.
4. Choose `Install from VSIX...`.
5. Select the production Owlvex VSIX.

## First Run

Owlvex now opens with a first-run checklist in the chat panel when setup is incomplete. The goal is to make the first minute concrete:

- confirm access with `Use Free`, `Start Trial`, or `Enter Licence`
- confirm the current workspace/project context
- configure an LLM provider when you want AI review and fix previews
- run the first scan
- create a summary report after scan results exist

### 1. Open Owlvex

Use the Owlvex activity bar icon or run:

- `Owlvex: Open AI Chat`

### 2. Choose Access

Owlvex supports:

- `Use Free`
- `Start Trial`
- `Enter Licence Key`

Free and trial onboarding are email-based.

### 3. Configure Your LLM

Run:

- `Owlvex: Setup AI Connection`

For Azure AI Foundry you need:

- endpoint
- deployment name
- API key

For other providers, enter the provider-specific model and key details when prompted.

### 4. Check Setup

Run:

- `Owlvex: Test Trial Setup`

This validates:

- backend connectivity
- licence state
- LLM/provider connectivity

## Basic Usage

### Scan

Available commands:

- `Owlvex: Scan Current File`
- `Owlvex: Scan Changed Files`
- `Owlvex: Scan Selected Files`
- `Owlvex: Scan Open Editors`
- `Owlvex: Scan Workspace`

### Create A Report

Run:

- `Owlvex: Create Report`

### Compare Reports

Run:

- `Owlvex: Compare Reports`

### AI Chat

Use the Owlvex chat panel to:

- ask follow-up questions
- discuss findings
- switch providers and models
- trigger scans
- open fix previews

### Fix Preview

From findings or chat:

- choose `Preview fix`
- review the generated diff
- use `Keep fix` to apply it
- Owlvex then rescans to verify the reviewed finding outcome

## Known Limitations

### Product / Platform

- this is still a prototype
- some flows are still optimized for evaluation rather than polished customer UX
- report comparison depends on stored scan metadata and can fail on older reports created before comparison-safe IDs were stored

### Safe Probe Verification

- probe checks are side-effect blocked and only inspect whether canary input reaches an intercepted sink
- probe support is intentionally narrow and does not replace full dynamic testing
- unresolved probe residue means Owlvex found evidence that dangerous input can still reach a risky operation
- blocked probe evidence can reduce unnecessary verifier calls, but it should still be read as scoped evidence

### AI / Model Behavior

- results can vary materially by provider and model
- slower or more expensive models can change scan time a lot
- some scans may reduce AI coverage after throttling or rate-limit pressure
- verifier / skeptic coverage can be truncated when corroboration budgets are exceeded

### Azure AI Foundry

- the current Azure AI Foundry path is built around Azure OpenAI-style deployment endpoints
- deployment names are user/environment specific and must exist in Azure before use
- Anthropic / Claude partner-model support is not fully productized through the same Foundry path yet

### Findings / Reports

- some findings may be correct but mislabeled
- some AI findings may still need manual review
- deterministic and AI-backed findings do not have the same trust posture
- report wording and comparison UX are still evolving

### Reading Confidence

Owlvex separates risk from evidence confidence.

- `Confirmed by rule` means deterministic code evidence proved the issue.
- `Validated by AI review` means an AI finder result was also supported by verifier or skeptic review.
- `Finder-only AI review` means the finder reported the issue, but verifier and skeptic were not triggered or were unavailable.
- `Finder high confidence, not independently verified` means the raw AI score is high, but it is still finder-only.
- `AI signal High (96% final)` is model confidence, not proof.
- `review path finder`, `finder+verifier`, or `finder+verifier+skeptic` shows which AI passes actually ran.

For important changes, validate AI-backed findings against the code before relying on them.

## Trust Boundary

Owlvex is intended to keep:

- deterministic scanning local
- editor-side findings and fix preview logic local
- backend traffic focused on licence, usage, scan metadata, and comparison metadata

## Troubleshooting

### The provider/model switch does not seem to stick

Check for workspace-level VS Code settings overriding:

- `owlvex.provider`
- `owlvex.foundry.model`
- provider-specific model settings

Workspace settings override global settings.

### Azure AI Foundry connection fails

Check:

- endpoint URL
- deployment name
- API key
- whether the deployment actually exists in Azure

### Scan comparison fails

Possible reasons:

- one of the selected reports is too old and does not contain usable stored scan IDs
- backend/control-plane availability issue
- licence does not allow comparison

### Scans are slow

Common causes:

- model latency
- throttling or retry behavior
- repo-context AI passes
- large candidate sets causing extra corroboration work

## Recommended Evaluation Workflow

1. Install the VSIX.
2. Open Owlvex.
3. Choose `Use Free`, `Start Trial`, or `Enter Licence Key`.
4. Configure the LLM connection.
5. Run `Owlvex: Test Trial Setup`.
6. Scan a small demo file first.
7. Create a report.
8. Try a second scan and compare reports.
9. Open one finding and test the `Fix code` preview flow.

## Feedback

If a result looks wrong, collect:

- the report file
- provider and model used
- whether scan warnings mention throttling or partial AI coverage
- the file or repo scope scanned
- the exact action that failed
