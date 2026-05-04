# Design And Drift Context Plan

Owlvex needs two project-local context surfaces that help the scanner reason about intent without changing the deterministic truth boundary:

- **Design Context**: architecture, trust boundaries, roles, assets, data flows, and system invariants.
- **Drift Checks**: developer-owned scripts that prove important behavior still works after scans, fixes, or AI-assisted code changes.

Both live inside the selected Owlvex project root. Neither is uploaded to the Owlvex backend as source code. Design context may be included in local AI prompts when AI scanning is enabled. Drift checks execute locally only after explicit user consent.

## Goals

- Improve STRIDE and design-aware review by grounding AI reasoning in the app's actual architecture.
- Reduce false positives caused by invented ownership, role, or workflow assumptions.
- Catch functionality drift after generated fixes.
- Make reports explicit about which design or drift evidence was used.

## Non-Goals

- Do not turn STRIDE, OWASP, CWE, NIST, or PCI into separate scan engines.
- Do not let design context upgrade a finding to deterministic proof.
- Do not silently run arbitrary scripts.
- Do not send customer source or drift scripts to the Owlvex backend.
- Do not let Drift Checks block scan completion, clean status, fix application, or post-fix verification.

## Project Layout

Recommended layout:

```text
.owlvex/
  project-context.md
  design/
    system.md
    trust-boundaries.md
    roles-and-permissions.md
    data-flows.md
    stride-notes.md
  drift/
    owlvex-drift.json
    invariants.md
    scripts/
      check-auth-flow.mjs
      check-api-contracts.mjs
```

## Design Context

Design Context tells Owlvex what the code is meant to do.

Useful content:

- product purpose
- important actors and roles
- trust boundaries
- data ownership rules
- sensitive data and assets
- critical workflows
- authentication and authorization model
- tenant/customer scoping model
- API contracts and important side effects
- STRIDE assumptions and threat notes

When STRIDE is selected, Design Context should be treated as high-value AI context because STRIDE depends on assets, actors, boundaries, and intended flows. If STRIDE is selected and no design context exists, reports should eventually say that STRIDE review was performed with limited design grounding.

Design Context can influence:

- AI prioritization
- finding explanations
- STRIDE category mapping
- "possible design gap" notes
- remediation constraints

Design Context must not:

- create deterministic proof by itself
- override source/sink evidence
- cause a fix to invent business concepts not present in code or docs

## Drift Checks

Drift Checks are local scripts owned by the repository. They verify that important behavior has not drifted after scanning or fixing.

Example `owlvex-drift.json`:

```json
{
  "version": 1,
  "checks": [
    {
      "id": "auth-flow",
      "label": "Authentication flow still works",
      "command": "node .owlvex/drift/scripts/check-auth-flow.mjs",
      "frameworks": ["STRIDE", "OWASP"],
      "scope": ["scan", "fix-preview", "post-fix"],
      "timeoutSeconds": 30
    }
  ]
}
```

Drift results should be reported as:

- `passed`
- `failed`
- `skipped`
- `timed_out`
- `not_approved`

Drift failures are report evidence only. They should be visible in scan and post-fix reports, but they must not block a "clean" security result when security findings are gone.

## Execution Safety

Owlvex must treat drift scripts as executable code.

Rules:

- Require explicit approval before first run.
- Show command, path, and project root before execution.
- Only run commands declared inside `.owlvex/drift/owlvex-drift.json`.
- Only run scripts inside the selected project root.
- Apply a timeout to every check.
- Cap stdout/stderr captured into reports.
- Do not run scripts from dependencies, downloaded packs, temp folders, or paths outside the root.
- Do not build shell commands from AI-generated text.

## Framework Interaction

Framework selection changes interpretation, not deterministic truth.

Expected behavior:

- STRIDE selected: load design context, especially `stride-notes.md`, trust boundaries, roles, and data flows.
- OWASP selected: drift checks tagged `OWASP` may run when drift checks are enabled.
- Clean Code selected: behavior-preservation drift checks may run when tagged.
- CWE/NIST/PCI selected: use mappings and tagged checks, but do not pretend these are independent scan engines.

## Implementation Slices

### Slice 1: Documentation And Scaffolding

- Add this contract.
- Add commands to create/open Design Context and Drift Box.
- Add default `.owlvex/design` and `.owlvex/drift` templates.

### Slice 2: Design Loader

- Load bounded markdown/text files from `.owlvex/design`.
- Prioritize STRIDE files when STRIDE is selected.
- Include loaded design context in `ProjectContextInfo.combined`.
- Add summary labels so reports and chat can say design context was used.

### Slice 3: Drift Config Parser

- Parse `.owlvex/drift/owlvex-drift.json`.
- Validate schema, path safety, frameworks, scopes, and timeout.
- Report invalid checks as skipped, not executed.

Status: implemented as a non-executing parser/loader. Owlvex now reads the Drift Box from the selected project root, validates declared checks, filters by framework and lifecycle scope, and rejects unsafe command shapes or scripts outside `.owlvex/drift/scripts`.

### Slice 4: Drift Runner

- Add approval prompt and persisted approval state.
- Execute checks locally with timeout and output caps.
- Run selected checks after scan and after keep-fix verification.

Status: runner skeleton implemented and wired into scan orchestration in non-blocking mode. Owlvex can execute validated ready checks locally after approval, persist approval per Drift Box declaration, enforce timeouts, cap output, and return structured pass/fail/timeout/not-approved results. Drift execution is report-only and must remain non-blocking.

### Slice 5: Reporting

- Add a Design/Drift section to summary and full reports.
- Show design files used.
- Show drift check status and failure output summary.
- Show when STRIDE ran without design context.

Status: implemented for Design Context and Drift Box visibility. Scan results carry design metadata, Drift Box metadata, and non-blocking run results. Summary/full reports show design files used, STRIDE-without-design warnings, configured drift checks, invalid declarations, disabled checks, out-of-scope checks, and pass/fail/timeout/not-approved runtime outcomes.

### Slice 6: Fix Flow Report Context

- After keep-fix, verify:
  - original finding cleared
  - touched files rescanned
  - applicable drift checks report pass/fail status
- If drift fails, the fix state remains driven by security verification. The report should say "security finding cleared; drift check failed" without blocking the security clean result.

## First Implementation Decision

Start with Design Context loading before Drift execution. It improves context quality immediately and does not introduce local script execution risk.
