# Owlvex

Prototype VS Code extension for security scanning, AI-assisted review, and fix preview workflows.

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
- AI-assisted targeted review
- repo-context reasoning for some workflows
- report generation
- report comparison
- fix preview and verification flows

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

- choose `Fix code`
- review the generated diff
- use `Keep fix` to apply it
- Owlvex then rescans to verify the reviewed finding outcome

## Known Limitations

### Product / Platform

- this is still a prototype
- some flows are still optimized for evaluation rather than polished customer UX
- report comparison depends on stored scan metadata and can fail on older reports created before comparison-safe IDs were stored

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
