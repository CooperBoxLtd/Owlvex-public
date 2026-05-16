# Owlvex

Owlvex is a VS Code extension for security scanning, AI-assisted review, evidence reports, and previewed code fixes.

It is built for developers who want to catch useful security issues while they are still working in the editor, not after code has already moved downstream.

## Prototype Notice

Owlvex is currently a prototype/evaluation product.

Use it to find useful security signals early, preview fixes, and validate whether the workflow helps your development process. Do not treat Owlvex output as a final security sign-off. Validate important findings, fixes, and reports before relying on them.

## Current Version

`0.1.45`

## What To Expect

Use it with these expectations:

- validate important findings before relying on them
- expect scan quality and speed to vary by provider/model
- expect some UI and report wording to keep changing
- treat AI-backed results as scoped evidence, not absolute proof

## What Owlvex Does

Owlvex combines:

- local deterministic checks
- sink and guard discovery
- safe probe verification for selected issues
- repo-context AI review
- optional TDD/spec grounding
- optional design/context grounding
- optional project-owned drift checks
- summary and full evidence reports
- report comparison
- previewed code fixes
- post-fix verification loops

Supported provider paths include:

- Azure AI Foundry
- OpenAI
- Anthropic
- Gemini
- Groq
- Mistral
- Ollama
- custom OpenAI-compatible endpoints

## First 5 Minutes

The fastest useful path is:

1. Install Owlvex.
2. Open the Owlvex activity view.
3. Choose `Use Free`, `Start Trial`, or `Enter Licence Key`.
4. Select your project root.
5. Configure an LLM provider.
6. Run a small scan: current file, selected files, or changed files.
7. Create a summary report.
8. Open one finding and preview a fix.

For daily development, prefer changed-file or selected-file scans. Use workspace scans for baselines, release checks, or deeper review.

## Installation

### Install From VSIX

1. Open VS Code.
2. Open the Extensions view.
3. Open the Extensions `...` menu.
4. Choose `Install from VSIX...`.
5. Select the Owlvex VSIX.

### Open Owlvex

Use the Owlvex activity bar icon, or run:

- `Owlvex: Open AI Chat`

## Setup

### 1. Licence Or Access

Owlvex supports:

- `Use Free`
- `Start Trial`
- `Enter Licence Key`

Free and trial onboarding are email-based.

### 2. Project Root

Set the project root so Owlvex knows the active app boundary.

This controls:

- workspace scans
- repo context
- changed-file scans
- report output
- Design Box resolution
- Drift Box resolution

Command:

- `Owlvex: Select Project Root`

### 3. LLM Provider

Command:

- `Owlvex: Setup AI Connection`

For Azure AI Foundry you need:

- endpoint
- deployment name
- API key

For other providers, enter the provider-specific model and key details when prompted.

### 4. Test Setup

Command:

- `Owlvex: Test Trial Setup`

This checks:

- backend connectivity
- licence/access state
- LLM/provider connectivity

## Scan Scopes

Owlvex supports several scan scopes:

- current file
- selected files
- changed files
- open editors
- workspace

Use changed-file scanning when you want fast review of work in progress. Owlvex uses Git when available. If Git is unavailable, use selected files or current file.

Commands:

- `Owlvex: Scan Current File`
- `Owlvex: Scan Selected Files`
- `Owlvex: Scan Changed Files`
- `Owlvex: Scan Open Editors`
- `Owlvex: Scan Workspace`

## Reports

Owlvex can create:

- Summary Report
- Full Evidence Report

The summary report is for daily developer use. It focuses on what to fix first, confidence posture, proof posture, and remaining work.

The full evidence report includes deeper scoring detail, framework mappings, AI review detail, sink/probe evidence, provider status, and audit context.

Command:

- `Owlvex: Create Report`

## Fix Preview Workflow

Owlvex does not directly overwrite code when a fix is generated.

The intended flow is:

1. Scan code.
2. Open a finding.
3. Choose `Preview fix`.
4. Review the side-by-side diff.
5. Choose `Keep fix` or `Discard fix`.
6. Owlvex verifies the changed files.
7. If findings remain, Owlvex creates a continuation queue.

The fix loop should continue until:

- findings are verified clean
- the user cancels
- a finding is explicitly left for manual review

Owlvex should reject broad or unanchored patches when a fix rewrites too much of a file for the selected finding.

## TDD Box

TDD Box lets you point Owlvex at a local Markdown or text file that describes expected product behavior.

Use it for:

- test-driven design notes
- product behavior that must not change
- API or protocol contracts
- acceptance criteria
- important implementation boundaries

TDD Box is local grounding context for scan and fix reasoning. It is not a security framework and it does not run scripts.

Supported file types:

- Markdown
- text

Setting:

- `owlvex.projectContextFile`
- `owlvex.tddBoxEnabled`

Command:

- `Owlvex: Open TDD Box`

## Design Box

Design Box lets you point Owlvex at a local design/context file so scans can understand intended system behavior.

Supported file types:

- Markdown
- text
- DOCX
- PDF, best-effort text extraction

Good Design Box inputs include:

- architecture documents
- threat models
- product workflows
- security assumptions
- trust-boundary notes
- API design notes
- data-flow documentation

Owlvex uses this as reference context during scans, especially when reviewing architecture, STRIDE, trust boundaries, roles, and data flows.

Design Box content is treated as project reference material, not as instructions to the model. The design file is read locally and included in scan context only when configured.

Setting:

- `owlvex.designContextFile`

Command:

- `Owlvex: Open Design Context`

## Drift Box

Drift Box is for project-owned behavior checks.

Use it for scripts that tell you whether important behavior still works after scans or AI-assisted fixes.

Good Drift Box checks include:

- API contract checks
- smoke tests
- login or auth-flow checks
- tenant-isolation checks
- refund/workflow checks
- generated-fix invariant checks

Do not use Drift Box for duplicate OWASP, CodeQL, Semgrep, or general SAST scans. Owlvex security scanning runs separately.

Drift Box behavior:

- runs local scripts only after user approval/configuration
- reports pass/fail/skipped/error
- does not block scans
- does not block fixes
- does not change security-clean status
- appears in reports only when configured and enabled

Settings:

- `owlvex.driftBoxFile`
- `owlvex.driftScriptsRoot`

Command:

- `Owlvex: Open Drift Box`

## Framework Selection

Framework selection is a scan lens, not a hard security-rule firewall.

Selected frameworks guide:

- AI grounding
- report emphasis
- remediation wording
- expanded mapping detail

Deterministic local evidence still runs security-first when code proves a vulnerability pattern.

A finding may still show canonical references such as CWE, OWASP, MITRE, NIST, PCI DSS, STRIDE, or Clean Code even if that framework was not selected. Those references are taxonomy mappings for the finding, not proof that every framework lens was active.

## Reading Confidence

Owlvex separates risk from evidence confidence.

- `Confirmed by rule` means deterministic code evidence proved the issue.
- `Validated by AI review` means an AI finder result was supported by verifier or skeptic review.
- `Finder-only AI review` means the finder reported the issue, but verifier/skeptic were not triggered or unavailable.
- `Finder high confidence, not independently verified` means the raw AI score is high, but still finder-only.
- `AI signal High (96% final)` is model confidence, not deterministic proof.
- `review path finder`, `finder+verifier`, or `finder+verifier+skeptic` shows which AI passes ran.

For important changes, validate AI-backed findings against the code.

## Safe Probe Verification

Safe probes are narrow, side-effect-blocked checks used for selected sink-driven findings.

They can help answer:

- can controlled input reach a risky sink?
- is there a recognized guard in the path?
- did a fix block the risky path?

Safe probes do not replace dynamic testing, penetration testing, or full runtime validation.

## Provider And Throttling Notes

Model speed and reliability depend on provider limits.

Azure AI Foundry may be paced by default because previous testing showed real 429 rate-limit behavior. Other providers normally run looser unless configured otherwise.

If a provider returns 429s, configure throttling:

- `Owlvex: Configure Provider Throttling`

## Data And Backend Boundary

Owlvex is designed so local code analysis and fix preview happen in the extension.

The backend is used for:

- licence/access state
- onboarding/account workflows
- usage metadata
- report/comparison metadata where enabled
- signed rule/remediation pack delivery where available and entitled

Customer source code should not be sent to the Owlvex Azure backend for normal scanning. LLM provider requests depend on the provider you configure.

## Troubleshooting

### Setup Loops Or Access Problems

Run:

- `Owlvex: Test Trial Setup`

Check:

- backend URL
- licence/access state
- email used for registration
- whether the extension is dev or production

### Provider/Model Does Not Stick

Check workspace-level VS Code settings overriding:

- `owlvex.provider`
- `owlvex.foundry.model`
- provider-specific model settings

Workspace settings override global settings.

### Azure AI Foundry Fails

Check:

- endpoint URL
- deployment name
- API key
- whether the deployment exists in Azure

### Scans Are Slow

Common causes:

- large workspace scope
- model latency
- provider throttling
- repo-context AI passes
- verifier/skeptic escalation
- large candidate sets

Use current-file, selected-file, or changed-file scans for faster feedback.

### Fix Preview Is Rejected

Owlvex may reject a fix if the generated patch rewrites too much code for a finding-anchored remediation.

Try:

- regenerate diff
- scan current file
- ask for a smaller finding-anchored fix

## Recommended Evaluation Workflow

1. Install the VSIX.
2. Open Owlvex.
3. Choose access: free, trial, or licence.
4. Select project root.
5. Configure provider/model.
6. Scan one current file.
7. Create a summary report.
8. Preview a fix.
9. Keep or discard the fix.
10. Review post-fix verification.
11. Try changed-file scanning during normal development.
12. Optionally configure Design Box and Drift Box for deeper project-specific review.

## Feedback

If a result looks wrong, collect:

- report file
- provider/model used
- scan scope
- selected frameworks
- Design Box file type if used
- Drift Box result if used
- scan warnings
- the exact action that failed


