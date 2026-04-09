# Owlvex Product Documentation

## Overview

Owlvex is a developer-first, AI-powered code security scanner built around a simple idea:

- keep developers inside their editor
- keep source code on the developer side
- use structured security frameworks to guide model reasoning
- turn findings into practical remediation and reports

Owlvex consists of two main parts:

- a VS Code extension that handles scanning, chat, diagnostics, comparisons, and reporting
- a backend service that validates licences, assembles framework-aware prompts, and records scan metadata without receiving source code

## Product Pitch

Owlvex is building the developer-native layer for AI-powered application security. The wedge is simple: developers already live in the editor, security reviews still arrive too late, and most existing options sit at one of two extremes:

- heavy enterprise security tooling that developers tolerate rather than love
- generic AI coding tools that are not structured enough for serious security workflows

Owlvex sits between those worlds. It gives teams framework-aware security scanning directly inside VS Code, powered by the model provider they already trust, while keeping source code off Owlvex backend services.

Short version:

**Owlvex is a developer-first AppSec product that uses AI to find, explain, and report vulnerabilities inside VS Code, using the customer's own models and framework-aware security guidance.**

Investor-style framing:

- The problem: code ships faster than traditional security review can keep up.
- The wedge: a security scanner embedded directly in the developer workflow.
- The differentiation: bring-your-own-model architecture plus framework-aware reporting.
- The expansion path: scan comparison, team policy, CI/CD, compliance packs, and multi-provider security review.

## Core Value Proposition

Owlvex is designed around four promises:

1. Framework-aware scanning  
Owlvex does not run as a generic "ask an LLM about code" experience. It grounds scans in selected security frameworks and severity thresholds.

2. Bring your own model  
Teams can use Ollama, OpenAI, Anthropic, Azure AI Foundry, Gemini, Groq, Mistral, or compatible custom endpoints.

3. Source code stays on the client side  
The backend builds prompts and records metadata, but scanned code is sent only to the selected AI provider, not to Owlvex backend services.

4. Developer-friendly workflows  
Owlvex supports file scanning, folder scanning, comparison, in-editor findings, chat assistance, and report generation from the same VS Code experience.

## Why Now

Several trends make this category timely:

- AI models are now good enough to reason about code security in a useful way
- teams increasingly want model flexibility instead of hard vendor lock-in
- developer tooling is moving earlier in the software lifecycle
- security buyers still need structured outputs, not just conversational suggestions

Owlvex is positioned to benefit from all four. It does not ask teams to choose between AI convenience and security structure.

## Who It Is For

Owlvex is intended for:

- individual developers who want faster security feedback while coding
- engineering teams that want framework-guided review without introducing a heavy platform
- security-minded teams that want local or customer-controlled model execution
- organisations evaluating AI-assisted AppSec workflows before adopting larger SAST programs

## Product Components

### VS Code Extension

The extension is the primary user experience. It provides:

- file scanning
- folder scanning
- findings sidebar
- diagnostics in the editor
- AI chat for advisory guidance
- report creation
- scan comparison
- provider/model switching

The extension lives in `extension/`.

### Backend API

The backend handles:

- licence validation
- prompt assembly
- framework and template enforcement
- metadata recording
- comparison support
- billing and plan enforcement

The backend lives in `backend/`.

### Database

The database stores:

- framework definitions
- prompt templates
- rule metadata
- licence records
- scan history metadata
- comparison metadata

The schema and seed data live under `postgres/init/`.

## How Owlvex Works

### Scan Flow

At a high level, the scan flow works like this:

1. The extension reads local settings such as provider, model, frameworks, and severity threshold.
2. The extension validates the current licence with the Owlvex backend.
3. The extension requests an assembled system prompt from the backend.
4. The extension sends the source code plus the assembled prompt to the selected AI provider.
5. The extension parses the provider's structured JSON findings.
6. The extension applies diagnostics, updates the sidebar, and records scan metadata with the backend.

### Privacy Model

Owlvex is intentionally split so that:

- source code is processed on the client/provider side
- the backend sees metadata, not the code body

Recorded metadata typically includes:

- file hash
- filename
- language
- provider
- model
- frameworks
- score
- finding counts
- duration

## Framework-Aware Scanning

Owlvex uses frameworks as first-class scan inputs, not as branding labels only.

Examples include:

- OWASP
- STRIDE
- MITRE ATT&CK
- CWE
- Clean Code
- NIST
- PCI-DSS
- HIPAA

The framework selection influences:

- prompt construction
- rule hints loaded by the backend
- severity filtering
- report structure
- final interpretation of findings

Owlvex currently defaults to:

- `OWASP`
- `STRIDE`

Owlvex should evolve from “framework selection” toward a canonical security knowledge model:

- one internal issue schema
- one curated framework catalog
- one mapping layer from canonical issues to OWASP, CWE, STRIDE, ATT&CK, CAPEC, and NIST

Reference material:

- [docs/KNOWLEDGE_MODEL.md](KNOWLEDGE_MODEL.md)
- [docs/ISSUE_EXPANSION_ROADMAP.md](ISSUE_EXPANSION_ROADMAP.md)
- [docs/schemas/issue.schema.v1.json](schemas/issue.schema.v1.json)
- [docs/schemas/framework-catalog.schema.v1.json](schemas/framework-catalog.schema.v1.json)
- [docs/schemas/issue-mapping.schema.v1.json](schemas/issue-mapping.schema.v1.json)
- [docs/data/stride/owlvex.stride.2026.1.json](data/stride/owlvex.stride.2026.1.json)
- [docs/data/issues/owlvex-issue-pack.v1.json](data/issues/owlvex-issue-pack.v1.json)
- [docs/data/issues/owlvex-issue-mappings.v1.json](data/issues/owlvex-issue-mappings.v1.json)

## Supported Providers

Owlvex currently supports one active provider at a time, chosen in the extension UI or settings.

Supported providers:

- OpenAI
- Anthropic
- Azure AI Foundry
- Ollama
- Mistral
- Google Gemini
- Groq
- Custom OpenAI-compatible endpoints

This means Owlvex is multi-provider capable, but not yet multi-provider concurrent in a single scan.

## Main User Workflows

### 1. Scan a File

The user selects a file explicitly and runs a scan. Owlvex:

- opens the file
- sends it through the framework-guided scan path
- returns findings, score, and remediation

### 2. Scan a Folder

The user selects a folder to scan recursively. Owlvex:

- finds supported source files
- skips common excluded directories
- scans each supported file
- aggregates results

### 3. Create a Report

The user can create a report from:

- the last scan
- a newly selected file
- a newly selected folder

Reports include:

- summary
- severity breakdown
- framework coverage
- riskiest files
- top findings
- detailed findings grouped by framework
- code snippets involved in the reasoning

### 4. Compare Scans

The user can compare two stored scans to see:

- new findings
- resolved findings
- score change

### 5. Advisory Chat

Owlvex also provides an assistant-style chat view. Chat is meant for:

- guidance
- triage
- explanation

## Demo And Manual Test Assets

Owlvex includes a small set of test assets to make the product loop easy to demonstrate without needing a large customer repository.

### Local single-file demo assets

The `tmp/` directory in this repo contains a fast before/after path:

- `tmp/owlvex-manual-test.js`
- `tmp/owlvex-manual-test.safe.js`
- `tmp/owlvex-manual-test.current.js`
- `tmp/use-risky-test.ps1`
- `tmp/use-safe-test.ps1`

This path is best for:

- scanner smoke testing
- report generation checks
- canonical comparison demos using one file before and after a change

### Probe folder assets

For a small repo-style scan, Owlvex also uses the probe folder in the sample app:

- `D:\Dev\repos\Morse App\src\probes\owlvex-probe-hardcoded-secret.js`
- `D:\Dev\repos\Morse App\src\probes\owlvex-probe-command-injection.js`
- `D:\Dev\repos\Morse App\src\probes\owlvex-probe-sql-injection.js`
- `D:\Dev\repos\Morse App\src\probes\owlvex-probe-safe-baseline.js`

This path is best for:

- folder scans
- canonical-first reports
- comparison screens with measurable improvement output

### Recommended Demo Loop

The simplest Owlvex demo loop is:

1. Scan a risky file or probe folder.
2. Create a report.
3. Fix or swap to a safer version.
4. Scan again.
5. Compare scans.

That flow shows the full Owlvex product loop:

`detect -> normalize -> report -> compare -> explain`
- remediation help

Chat is advisory by default. Scan-backed actions remain separate so users can distinguish:

- assistant advice
- formal scan output

## User Experience Principles

Owlvex should feel:

- clear about what is being scanned
- clear about whether output is advisory or scan-backed
- persistent enough to support follow-up actions
- fast enough to test on small probe sets
- safe enough not to overstate certainty

Important UX distinctions:

- scanning is a structured workflow
- chat is exploratory and advisory
- reports should reuse existing scan memory where possible instead of forcing rescans

## Report Philosophy

Owlvex reports are intended to be more than generic summaries.

A useful Owlvex report should include:

- severity
- score and score impact
- framework mapping
- line references
- reasoning
- threat
- remediation
- code snippets involved in the finding

This makes reports usable for:

- engineering follow-up
- security review
- demonstrations
- evaluation against framework-aligned expectations

## Product Positioning

Owlvex sits between:

- generic "chat with your code" experiences
- heavyweight enterprise SAST platforms

It is best positioned as:

- lightweight to adopt
- strong on developer workflow
- flexible on model/provider choice
- privacy-conscious in architecture
- structured enough to support security use cases beyond casual prompting

More explicitly:

- Not just an IDE chatbot
- Not just another rules-only scanner
- Not a full legacy AppSec suite on day one
- A developer-native security product with room to expand upward into platform features

## Market Narrative

Owlvex can be explained as a modern AppSec wedge:

1. Start with the individual developer workflow.
2. Win on speed, clarity, and low-friction adoption.
3. Expand into team reporting, comparison, policy, and compliance.
4. Become the intelligence layer between code, security standards, and model infrastructure.

That is what makes the product more interesting than a single VS Code feature. The extension is the entry point; the broader product is security orchestration around model-assisted review.

## Strengths

- Works inside VS Code
- Uses customer-selected AI providers
- Keeps code off the Owlvex backend
- Uses framework-aware prompt assembly
- Produces findings, reports, and comparisons
- Can run against local models like Ollama

## Current Limitations

- Only one active provider/model is used for a scan at a time
- Performance depends heavily on the chosen model
- AI scan quality is probabilistic, not perfectly deterministic
- Some orchestration and UI flows still need deeper test coverage
- Large folder scans can be slow on smaller local models

## Golden Corpus And Benchmarking

Owlvex now includes a small but meaningful family-aware benchmark set in `corpus/`.

This is not just a test fixture. It is the first internal benchmark for the Owlvex security knowledge layer:

- positive cases verify canonical issue resolution
- negative cases verify false-positive resistance
- family labels verify that Owlvex understands the correct risk domain even when issue wording varies

The first corpus version contains 20 files across:

- Secrets & Credential Exposure
- Injection & Execution
- Identity & Auth Failures
- Access Control & Authorization
- Data Protection & Privacy
- Cryptography & Randomness

This gives Owlvex a practical baseline for:

- resolver tuning
- prompt tuning
- family-level quality measurement
- future provider comparison work

The next planned catalog growth is documented in [docs/ISSUE_EXPANSION_ROADMAP.md](ISSUE_EXPANSION_ROADMAP.md).

## Security Model Summary

From a product perspective:

- Owlvex reduces backend code exposure by keeping source code off Owlvex servers
- Owlvex still depends on the trust model of the chosen AI provider
- malformed model output should fail scans rather than quietly passing
- reports and comparisons should present scan-backed output clearly

## Recommended Messaging

### Homepage / README Short Copy

Owlvex is a developer-first AppSec product that brings AI-powered, framework-aware code security scanning into VS Code using your own model stack.

### Slightly Longer Copy

Owlvex helps software teams catch vulnerabilities earlier by embedding AI-powered security review directly into the developer workflow. It combines framework-aware prompt assembly, bring-your-own-model flexibility, and structured reporting so teams can generate findings, comparisons, and reports without routing source code through Owlvex servers.

### Internal Positioning

Owlvex is not just "chat with an LLM about code." It is a developer-native security product designed to become the intelligent layer between code review, security frameworks, and model infrastructure.

## Suggested Next Product Improvements

1. Add orchestration tests for the extension command layer and chat action flows.
2. Add explicit pre-flight checks for provider availability before starting scans.
3. Add multi-provider comparison mode for the same file or folder.
4. Add stronger report templates for engineering, AppSec, and executive audiences.
5. Add clearer latency/progress feedback for slow local models.

## Repository Map

- `README.md`: setup and operational documentation
- `docs/PRODUCT.md`: product positioning and product documentation
- `extension/`: VS Code extension
- `backend/`: FastAPI backend
- `postgres/`: schema and seed data
- `tmp/`: local test/probe assets used during development
