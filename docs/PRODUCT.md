# Owlvex Product Documentation

## Overview

Owlvex is a developer-first security product that combines:

- local deterministic code analysis with benchmark-backed certainty claims
- optional AI-assisted reasoning for patterns that cannot be proven structurally
- backend-served grounded data and rule intelligence
- structured reporting with explicit provenance per finding

The product preserves two properties simultaneously:

1. customer source code stays under customer control
2. Owlvex retains meaningful control over detection intelligence and product behavior

The implementation design and architectural source of truth live in [IMPLEMENTATION_DESIGN.md](IMPLEMENTATION_DESIGN.md).

The delivery backlog for that design lives in [IMPLEMENTATION_BACKLOG.md](IMPLEMENTATION_BACKLOG.md).

The next execution-shape contract for project grounding and tiered hybrid scanning lives in [PROJECT_CONTEXT_AND_SCAN_TIERS_CONTRACT.md](PROJECT_CONTEXT_AND_SCAN_TIERS_CONTRACT.md).

---

## Product Pitch

Owlvex gives software teams a developer-first AppSec product: deterministic security validation plus AI-assisted review, inside VS Code, using the customer's own models, keeping source code off Owlvex servers.

The positioning in one line:

> **Owlvex proves when code is unsafe. It doesn't guess.**

Investor-style framing:

- The problem: code ships faster than traditional security review can keep up.
- The wedge: a security scanner embedded directly in the developer workflow.
- The differentiation: deterministic-first reasoning, bring-your-own-model, framework-aware interpretation and reporting.
- The expansion path: scan comparison, review-first remediation diffs, team policy, CI/CD, compliance packs, multi-provider review.

---

## Core Value Proposition

1. **Deterministic-first findings** - Owlvex runs structural invariant checks locally before AI is involved. Findings marked deterministic are proven violations and should not be presented as probabilistic guesses.

2. **AI-assisted coverage** - For patterns that cannot be structurally proven, Owlvex uses the customer-selected AI provider. AI findings carry explicit confidence context and remain clearly distinct from deterministic findings. The intended hybrid execution shape is being formalized into `STATIC`, `TARGETED_AI`, and `REPO_AI` scan tiers rather than one undifferentiated AI lane.

   AI-backed findings should now also carry a clearer corroboration story:

   - finder pass proposes the candidate
   - verifier pass checks whether local code supports it
   - skeptic pass tries to disprove it

   That reasoning trail belongs to AI findings only and must not blur the deterministic proof boundary.

3. **Bring your own model** - OpenAI, Anthropic, Azure AI Foundry, Gemini, Groq, Mistral, Ollama, or any compatible custom endpoint.

4. **Source code stays on the client** - The backend builds prompts, delivers grounded data, and records control-plane metadata. Code is sent only to the customer-selected AI provider, never to Owlvex backend services. The same privacy default should apply to future user-supplied project-context/TDD documents unless the user explicitly chooses otherwise.

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

- local deterministic scanning across benchmark-backed execution-risk, SQL-query, access-control, and conditional-rules groups
- file and folder scanning
- findings sidebar with explicit provenance distinction
- in-editor diagnostics
- AI chat for advisory guidance, plain-language fix explanations, and concrete replacement code when the user asks how to remediate a finding
- AI-assisted reasoning that can expand from file-level context to nearby project context when the issue or proposed fix depends on code outside the active file
- future project-context upload or paste flow so users can give Owlvex TDD-style architectural grounding, goals, and security expectations for the repo
- controlled remediation flow that can propose file changes for a finding, show a diff, and let the user decide whether to apply it
- review-scoped fix application that blocks writes when the reviewed file set no longer matches the preview target
- report creation with concise per-file findings, remediation guidance, and scan errors/warnings when present
- scan comparison
- provider and model switching
- trial and demo onboarding for:
  - backend URL configuration
  - licence entry
  - provider setup
  - trial-readiness checks
- early pricing/plan instrumentation for:
  - free
  - trial
  - developer

Lives in `extension/`.

### Backend API

The control plane. Handles:

- licence validation and plan enforcement
- usage-event ingestion for pricing, trial, and upgrade telemetry
- prompt assembly and framework template delivery
- issue catalog and rule metadata
- scan metadata recording without raw source upload
- comparison support
- billing

Must not require raw source code in order to perform its role. Lives in `backend/`.

### Grounded Data Packs

Owlvex now maintains versioned local grounded-data assets that can later become signed rule-pack artifacts. Current pack families include:

- canonical issue and mapping packs under `docs/data/issues/`
- curated framework blobs under `docs/data/frameworks/`
- raw upstream framework source mirrors under `docs/data/framework-sources/`
- curated OWASP cheat sheet guidance under `docs/data/cheatsheets/`

These packs are intended to make the AI lane more data-backed over time, especially for framework-guided interpretation and remediation guidance.

Current product direction:

- scan-time AI grounding can consume curated framework and remediation guidance
- fix preview generation is grounded first in canonical remediation and local code context
- canonical remediation now carries richer normalized fix guidance into chat and fix prompts, including:
  - recommended steps
  - validation guidance
  - unsafe alternatives
  - concise curated cheat-sheet grounding
- those richer canonical remediation fields now also surface in reports and sidebar finding detail where available
- OWASP-style cheat-sheet content should continue to flow into the product through the canonical remediation layer rather than through raw prompt stuffing by default

### Deterministic Benchmark Tool

Lives under `tools/owlvex-benchmark/`. Provides:

- corpus fixtures with expected outputs for every covered rule
- per-layer and integration evaluators for benchmarked deterministic groups
- conditional-rules coverage in the aggregate deterministic gate
- aggregate gate: `19/19` suites and `82/82` cases passing
- confidence and status reporting
- separate AI eval tooling for uncovered issue classes that are not part of the deterministic release gate
- a separate benchmarking department under `docs/benchmarking/` to govern deterministic, AI, external, and future remediation benchmarks
- a starter remediation benchmark lane under `tools/fix-benchmark/` for measuring preview quality, scope discipline, finding removal, and post-fix safety
- benchmark-mapped fixes can now auto-record a latest remediation benchmark result after `Keep fix` and a completed verification rescan
- extension-side usage instrumentation now has a dedicated backend contract for:
  - `scan_run`
  - `finding_viewed`
  - `fix_viewed`
  - `second_scan`
  - `session_return`

This is the mechanism that defines what Owlvex can claim with certainty. No deterministic rule ships without benchmark coverage.

---

## How Owlvex Works

### Scan Flow

1. Extension reads local settings such as provider, model, frameworks, and severity threshold.
2. Extension may validate backend reachability and licence state with the Owlvex backend.
3. Extension runs the deterministic scanner locally before any AI call.
4. If the AI-backed path is available, extension requests an assembled system prompt from the backend.
5. Extension may include local project-context contract data and grounded remediation or framework context when the selected scan tier benefits from architectural grounding.
6. Extension sends source code plus prompt directly to the selected AI provider.
7. AI candidates are reviewed through the current multi-pass corroboration flow:
   - finder
   - verifier
   - skeptic
8. Extension merges surviving AI findings with deterministic findings, with deterministic findings leading when there is overlap or conflict.
9. The product reports the final file posture honestly:
   - `Static proof` when only deterministic findings survive
   - AI-backed tiers only when AI findings survive into the final result
   - file-level wording may say AI review was not used for the final finding set even if background AI work was attempted
10. Extension applies diagnostics, updates the sidebar, and records scan metadata with the backend.

The current onboarding path for AI-backed use is:

1. configure backend URL
2. enter or validate licence
3. configure provider/model
4. run a trial/setup readiness check

### Privacy Model

- Source code is processed on the client side and sent directly to the customer-selected AI provider.
- The Owlvex backend sees control-plane and scan metadata such as file hash, language, provider, model, frameworks, score, finding counts, duration, and prompt identity data used for product operations.
- Deterministic analysis runs locally in the extension, with no backend involvement.
- The product should continue minimizing backend-stored scan context so the control plane stays as metadata-oriented as practical.

The same boundary applies to demo and trial users:

- backend connectivity and licence validation do not imply source upload to Owlvex backend
- project-context documents should follow the same default-local handling as source code
- trial onboarding should make backend dependence explicit without weakening the metadata-only backend contract

---

## Framework-Aware Scanning

Framework selection influences prompt construction, issue interpretation, canonical mappings, and output structure. Supported frameworks: OWASP, STRIDE, MITRE ATT&CK, CWE, Clean Code, NIST, PCI-DSS, HIPAA.

Owlvex itself remains the primary detection and reasoning engine:

- deterministic findings are grounded in Owlvex structural rules and benchmark-backed invariants
- AI findings are grounded in code context, Owlvex canonical issues, and the selected framework scope
- selected frameworks act as a lens over findings, not as independent first-class scan engines

The intended split is:

- deterministic findings are Owlvex-proven and should remain stable when framework selection changes
- AI findings may follow the selected frameworks more directly for prioritization, vocabulary, mappings, and explanation style
- framework choice should influence the AI lane more strongly than the deterministic lane
- confidence scoring and validation still gate AI output even when frameworks shape the reasoning

In practical terms, framework selection currently means:

- what external mappings should be shown
- what threat-model or compliance vocabulary should be emphasized
- what prompt context should shape AI-assisted reasoning, especially for AI-only findings
- what curated framework-pack and canonical remediation guidance can shape AI scan and remediation prompts
- what bounded candidate issues the AI lane should prefer before inventing a new label

It does **not** mean that every selected framework becomes its own separate source of detection truth.

The longer-term direction is a canonical security knowledge model: one internal issue schema with one mapping layer to external frameworks. Reference: [KNOWLEDGE_MODEL.md](KNOWLEDGE_MODEL.md) and [ISSUE_EXPANSION_ROADMAP.md](ISSUE_EXPANSION_ROADMAP.md).

---

## Supported AI Providers

OpenAI, Anthropic, Azure AI Foundry, Ollama, Mistral, Google Gemini, Groq, and custom OpenAI-compatible endpoints. One active provider per scan. Multi-provider concurrent scanning is a future capability.

---

## Main User Workflows

**Scan a file** - structured scan with deterministic and AI findings, score, and remediation.

**Scan a folder** - recursive scan across supported file types, aggregated results.

**Create a report** - concise scan artifact with summary, per-file findings, remediation guidance, and scan errors/warnings when present.

**Compare scans** - new findings, resolved findings, and score delta between two stored scans.

**Advisory chat** - exploratory guidance clearly distinguished from formal scan output. This is the place for plain-language fix explanations grounded in the active file or latest scan.

**Review-first remediation** - Owlvex can generate a candidate patch for the active finding, show the proposed diff, and apply changes only after explicit user approval.

Current remediation posture:

- fix previews are grounded in canonical remediation plus local code context
- the preview is review-only until the user chooses `Keep fix`
- Owlvex blocks apply if the reviewed file scope no longer matches the preview target
- canonical remediation is the main normalization layer for fix guidance; richer OWASP-aligned canonical content is still an active improvement track

**Context-aware AI assistance** - when file-only analysis is not enough, Owlvex should gather nearby project context such as imports, referenced helpers, and related files before presenting higher-confidence AI reasoning or code changes.

**Project-grounded AI assistance** - future workflow where users can provide a local TDD-style project context contract so the AI lane better understands goals, roles, architecture, trust boundaries, and critical flows without changing the deterministic truth boundary.

**Working-scope-controlled AI access** - the assistant's bottom scope dropdown should define both what Owlvex scans and what AI is allowed to inspect as context. `Active file`, `Selected files`, `Open editors`, and `Workspace` should act as explicit AI context boundaries rather than letting repo access become an invisible always-on mode.

**Trial onboarding** - configure backend, enter a licence, configure an LLM, and verify whether the AI-backed path is ready without editing settings files by hand.

---

## Demo Assets

The simplest demo path uses `tools/demo/`:

- `01-idor-unsafe.js` -> deterministic IDOR finding
- `02-idor-safe.js` -> no findings
- `03-debug-unsafe.js` -> deterministic debug-mode finding
- `04-debug-safe.js` -> no findings
- `05-tenant-isolation-unsafe.js` -> deterministic multi-tenant isolation finding

Additional AI-only demo fixtures:

- `16-open-redirect-unsafe.js` -> AI-only open redirect coverage example
- `17-open-redirect-safe.js` -> safe companion for redirect handling
- `18-csrf-unsafe.js` -> AI-only CSRF coverage example
- `19-csrf-safe.js` -> safe companion for CSRF handling
- `20-cors-unsafe.js` -> AI-only permissive CORS coverage example
- `21-cors-safe.js` -> safe companion for CORS handling
- `22-ssrf-unsafe.js` -> AI-only SSRF coverage example
- `23-ssrf-safe.js` -> safe companion for SSRF handling
- `24-jwt-validation-unsafe.js` -> AI-only weak JWT validation coverage example
- `25-jwt-validation-safe.js` -> safe companion for JWT validation
- `26-deserialization-unsafe.py` -> AI-only insecure deserialization coverage example
- `27-deserialization-safe.py` -> safe companion for deserialization handling

Demo script: [tools/demo/DEMO-SCRIPT.md](../tools/demo/DEMO-SCRIPT.md)

The next validation layer is `tools/demo-app/`: a small intentionally vulnerable web app with shared middleware, auth helpers, tenant scoping, outbound request helpers, and both vulnerable and safe route variants. This repo-style app exists to validate that Owlvex can use surrounding project context, not just isolated fixture files. Expected outcome: some issue candidates that look risky in single-file mode should disappear once the scanner can see the full route, helper, and authorization flow together.

Current execution rule: this benchmark layer is now governed by [STABILIZATION_CONTRACT.md](./STABILIZATION_CONTRACT.md). That contract intentionally prioritizes benchmark reliability, confidence boundaries, regression capture, and a smaller trusted issue set over rapid issue-family expansion.

---

## Positioning

Owlvex sits between generic "chat with your code" experiences and heavyweight enterprise SAST platforms.

- Not just an IDE chatbot
- Not just a pattern-matching rules scanner
- Not a full legacy AppSec suite on day one
- A developer-native security product with a clear expansion path into team reporting, policy, and compliance

The deterministic engine is the differentiation. It turns the product from "a scanner that finds things" into "a scanner that proves things" - a materially different trust claim.

The execution model should become clearer over time:

- `STATIC` for deterministic proof
- `TARGETED_AI` for bounded AI review of narrowed code targets
- `REPO_AI` for broad repo-context reasoning

That is intended to strengthen the existing hybrid scanner, not replace it.

---

## Current Limitations

- One active AI provider per scan
- AI scan quality is probabilistic; only deterministic findings carry certainty claims
- Large folder scans can be slow on smaller local models
- Framework selection is currently a reasoning and reporting lens, not a fully independent framework-native detection engine
- backend/licence/provider setup is still required for the full AI-backed experience
- platform-security and customer trust-boundary hardening now need to be treated as a first-class product workstream
- Curated framework and cheat-sheet packs are now used in runtime prompt construction, but the AI lane still needs deeper issue-targeted grounding coverage and more eval cases before it can be called fully mature
