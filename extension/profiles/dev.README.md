# Owlvex Dev

Internal Owlvex development build for validating the full developer workflow before production packaging.

## Prototype Notice

Owlvex is currently a prototype/evaluation product.

This dev build is for validating behavior before production release. Do not treat scan output as a final security sign-off; validate important findings, fixes, and reports before relying on them.

Use this build to test the path a new user should experience:

`install -> register/access -> select project root -> configure provider -> scan -> report -> preview fix -> verify -> continue`

This dev build is also where we validate TDD Box, Design Box, and Drift Box before releasing them to production.

## Current Version

`{{PACKAGE_VERSION}}`

## Build Target

- extension id: `owlvex.owlvex-dev`
- config section: `owlvexDev`
- backend: Azure dev control plane
- OWASP lens: OWASP Top 10 2025
- purpose: internal validation of onboarding, scan quality, reports, TDD Box, Design Box, Drift Box, and fix preview behavior before production packaging

## Current Validation Focus

Use this build to validate:

- first-run onboarding
- project-root selection
- changed-file and selected-file scanning
- TDD Box grounding
- Design Box context loading
- Drift Box behavior checks
- report clarity
- fix preview guardrails
- post-fix continuation queues
- provider throttling behavior
- safe probe and sink evidence

## First-Run Test Path

1. Install the dev VSIX.
2. Open the Owlvex Dev activity view.
3. Confirm the extension clearly shows dev status.
4. Register access or enter a dev licence.
5. Configure provider/model.
6. Select project root.
7. Run a current-file scan.
8. Run a changed-file scan.
9. Create a summary report.
10. Preview a fix and verify the post-fix continuation message.

## TDD Box Test Path

TDD Box should load a selected local Markdown or text file and include it as scan/fix grounding context.

Test file types:

- `.md`
- `.txt`

Expected behavior:

- selected files are stored in `owlvexDev.projectContextFile`
- configured TDD files are treated as enabled by default unless explicitly disabled
- the Scan Profile picker keeps TDD Box ticked when a file is configured
- reports/chat context show the TDD file when it is active
- TDD Box does not run scripts and is not presented as a security framework

Settings:

- `owlvexDev.projectContextFile`
- `owlvexDev.tddBoxEnabled`

Command:

- `Owlvex Dev: Open TDD Box`

## Design Box Test Path

Design Box should load a local context file and include it as scan reference material.

Test file types:

- `.md`
- `.txt`
- `.docx`
- `.pdf`

Expected behavior:

- unsupported files are rejected or ignored with a warning
- extracted design context is bounded as reference context, not model instructions
- reports state whether design context was used
- STRIDE and architecture-heavy reviews use the design context to reason about trust boundaries, roles, and data flows

Setting:

- `owlvexDev.designContextFile`

Command:

- `Owlvex Dev: Open Design Context`

## Drift Box Test Path

Drift Box is for project-owned behavior, contract, smoke, and workflow scripts.

It must not be positioned as:

- OWASP scanning
- CodeQL scanning
- Semgrep scanning
- duplicate SAST

Expected behavior:

- scripts run only when configured and enabled
- scope controls when checks run: `scan`, `fix-preview`, `post-fix`
- legacy `frameworks` fields are metadata only
- reports show Drift Box only when configured and enabled
- output is pass/fail/skipped/error
- drift failures do not block scans, fixes, post-fix verification, or security-clean status

Settings:

- `owlvexDev.driftBoxFile`
- `owlvexDev.driftScriptsRoot`

Command:

- `Owlvex Dev: Open Drift Box`

## Report Checks

When validating reports, check:

- Summary Report is useful without opening the full evidence report.
- Full Evidence Report contains proof posture and source/sink/probe detail.
- Design context appears only when configured.
- Drift results appear only when configured and enabled.
- AI confidence does not read as deterministic proof.
- Finder-only findings do not say `Validated by AI review`.
- `Validated by AI review` appears only when verifier or skeptic evidence exists.
- Provider/model and throttling warnings are visible where relevant.

## Fix Preview Checks

When validating fix preview:

- generated patches should stay finding-anchored
- broad rewrites should be rejected
- fixes should not invent unsupported business models
- Keep Fix should trigger verification
- unresolved post-fix findings should appear in one continuation queue
- continuation should proceed until clean, cancelled, or left for manual review

## Framework Selection Checks

Selected frameworks should guide:

- grounding
- explanation
- remediation wording
- expanded mapping detail

They should not disable core deterministic security evidence.

Canonical references such as CWE, OWASP, MITRE, NIST, PCI DSS, STRIDE, and Clean Code may still appear as taxonomy mappings.

## Provider Checks

When testing providers, record:

- provider
- model
- scan scope
- throttling warnings
- 429s or retries
- elapsed time
- report path

Azure AI Foundry may be paced by default. Other providers should run loose unless configured or rate-limited.

## Dev/Prod Coexistence Warning

If both Owlvex and Owlvex Dev are installed in the same VS Code instance:

- verify which activity view is active
- verify the status bar label
- verify the backend URL
- verify the config section
- avoid interpreting dev and prod licence/provider state as the same environment

## Bug Report Template

Collect:

- dev VSIX version
- commit SHA
- backend URL
- provider/model
- project root
- scan scope
- selected frameworks
- report file
- Design Box file type if used
- Drift Box config if used
- exact action clicked
- expected result
- actual result
