# Owlvex Product Documentation

## Overview

Owlvex is a developer-first security product that combines:

- local deterministic code analysis (structural invariant detection, 100% confidence, no false positives)
- optional AI-assisted reasoning for patterns that can't be proven structurally
- backend-served grounded data and rule intelligence
- structured reporting with explicit provenance per finding

The product preserves two properties simultaneously:

1. customer source code stays under customer control
2. Owlvex retains meaningful control over detection intelligence and product behavior

The implementation design and architectural source of truth live in [IMPLEMENTATION_DESIGN.md](IMPLEMENTATION_DESIGN.md).

The delivery backlog for that design lives in [IMPLEMENTATION_BACKLOG.md](IMPLEMENTATION_BACKLOG.md).

---

## Product Pitch

Owlvex gives software teams a developer-first AppSec product: deterministic security validation plus AI-assisted review, inside VS Code, using the customer's own models, keeping source code off Owlvex servers.

The positioning in one line:

> **Owlvex proves when code is unsafe. It doesn't guess.**

Investor-style framing:

- The problem: code ships faster than traditional security review can keep up.
- The wedge: a security scanner embedded directly in the developer workflow.
- The differentiation: deterministic-first reasoning, bring-your-own-model, framework-aware reporting.
- The expansion path: scan comparison, team policy, CI/CD, compliance packs, multi-provider review.

---

## Core Value Proposition

1. **Deterministic-first findings** — Owlvex runs structural invariant checks locally before AI is involved. Findings marked `⚡` are proven violations, 100% confidence, no validation required before escalation.

2. **AI-assisted coverage** — For patterns that can't be structurally proven, Owlvex uses the customer-selected AI provider. AI findings carry explicit confidence scores and are surfaced separately from deterministic findings.

3. **Bring your own model** — OpenAI, Anthropic, Azure AI Foundry, Gemini, Groq, Mistral, Ollama, or any compatible custom endpoint.

4. **Source code stays on the client** — The backend builds prompts and records metadata. Code is sent only to the customer-selected AI provider, never to Owlvex backend services.

---

## Who It Is For

- Individual developers who want faster security feedback while coding
- Engineering teams that want framework-guided review without a heavy platform
- Security-minded teams that want local or customer-controlled model execution
- Organisations evaluating AI-assisted AppSec workflows before adopting full SAST programs

---

## Product Components

### VS Code Extension

The execution plane. Provides:

- local deterministic scanning (8 rules, 3 reasoning axes, 4 conditional rules)
- file and folder scanning
- findings sidebar with `⚡` / `🤖` provenance distinction
- in-editor diagnostics
- AI chat for advisory guidance
- report creation with Attack Surface Assessment
- scan comparison
- provider and model switching

Lives in `extension/`.

### Backend API

The control plane. Handles:

- licence validation and plan enforcement
- prompt assembly and framework template delivery
- issue catalog and rule metadata
- scan metadata recording (no source code)
- comparison support
- billing

Must not require raw source code in order to perform its role. Lives in `backend/`.

### Deterministic Benchmark Tool

Lives under `tools/owlvex-benchmark/`. Provides:

- corpus fixtures with expected outputs for every covered rule
- per-layer and integration evaluators for three reasoning axes
- conditional rules axis (SM-002 covered; AC-T001, DP-001, SM-001 pending — see backlog)
- aggregate gate: 19 suites, 82 cases, all passing
- confidence and status reporting

This is the mechanism that defines what Owlvex can claim with certainty. No deterministic rule ships without benchmark coverage.

---

## How Owlvex Works

### Scan Flow

1. Extension reads local settings (provider, model, frameworks, severity threshold).
2. Extension validates licence with the Owlvex backend.
3. Extension runs the deterministic scanner locally — findings are produced before any AI call.
4. Extension requests an assembled system prompt from the backend.
5. Extension sends source code plus prompt directly to the selected AI provider.
6. Extension merges AI findings with deterministic findings.
7. Extension applies diagnostics, updates the sidebar, records scan metadata with the backend.

### Privacy Model

- Source code is processed on the client side and sent directly to the customer-selected AI provider.
- The Owlvex backend sees metadata only: file hash, language, provider, model, frameworks, score, finding counts, duration.
- Deterministic analysis runs locally in the extension, with no backend involvement.

---

## Framework-Aware Scanning

Framework selection influences prompt construction, severity filtering, and report structure. Supported frameworks: OWASP, STRIDE, MITRE ATT&CK, CWE, Clean Code, NIST, PCI-DSS, HIPAA.

The longer-term direction is a canonical security knowledge model — one internal issue schema with one mapping layer to all external frameworks. Reference: [KNOWLEDGE_MODEL.md](KNOWLEDGE_MODEL.md) and [ISSUE_EXPANSION_ROADMAP.md](ISSUE_EXPANSION_ROADMAP.md).

---

## Supported AI Providers

OpenAI, Anthropic, Azure AI Foundry, Ollama, Mistral, Google Gemini, Groq, and custom OpenAI-compatible endpoints. One active provider per scan. Multi-provider concurrent scanning is a future capability.

---

## Main User Workflows

**Scan a file** — structured scan with deterministic + AI findings, score, and remediation.

**Scan a folder** — recursive scan across supported file types, aggregated results.

**Create a report** — Attack Surface Assessment paragraph, Deterministic Detections panel, per-finding narratives with provenance labels.

**Compare scans** — new findings, resolved findings, score delta between two stored scans.

**Advisory chat** — exploratory guidance; clearly distinguished from formal scan output.

---

## Demo Assets

The simplest demo path uses `tools/demo/`:

- `01-idor-unsafe.js` → `⚡ AC-001 HIGH` Insecure Direct Object Reference
- `02-idor-safe.js` → no findings
- `03-debug-unsafe.js` → `⚡ SM-002 MEDIUM` Debug Mode Without Production Guard
- `04-debug-safe.js` → no findings
- `05-tenant-isolation-unsafe.js` → `⚡ AC-T001 CRITICAL` Multi-Tenant Isolation Failure

Demo script: [tools/demo/DEMO-SCRIPT.md](../tools/demo/DEMO-SCRIPT.md)

---

## Positioning

Owlvex sits between generic "chat with your code" experiences and heavyweight enterprise SAST platforms.

- Not just an IDE chatbot
- Not just a pattern-matching rules scanner
- Not a full legacy AppSec suite on day one
- A developer-native security product with a clear expansion path into team reporting, policy, and compliance

The deterministic engine is the differentiation. It turns the product from "a scanner that finds things" into "a scanner that proves things" — a fundamentally different claim.

---

## Current Limitations

- One active AI provider per scan (multi-provider concurrent scanning not yet implemented)
- AI scan quality is probabilistic; only deterministic findings carry 100% confidence
- Conditional rules AC-T001, DP-001, SM-001 are live in the scanner but lack benchmark coverage (see backlog Workstream 4)
- Large folder scans can be slow on smaller local models
