# Owlvex UX and Workflow Code Analysis

Generated: 2026-05-15

Scope reviewed:

- VS Code extension workflow code under `extension/src/extension.ts`
- chat and action surface under `extension/src/panels/chatViewProvider.ts`
- scan orchestration under `extension/src/scanner/workspaceScanner.ts` and `extension/src/scanner/scanEngine.ts`
- report generation under `extension/src/scanner/reportGenerator.ts`
- project context, TDD, Design Box, and Drift Box support under `extension/src/projectContext.ts`, `extension/src/driftBox.ts`, and `extension/src/driftRunner.ts`
- backend customer/admin/telemetry surfaces under `backend/app/routers/admin.py`, `backend/app/routers/usage.py`, and `backend/app/static/admin-console.html`
- current product/backlog direction under `docs/PRODUCT.md` and `docs/IMPLEMENTATION_BACKLOG.md`

Related delivery plan:

- [DESIGN_MAP_AND_UX_WORKFLOW_PLAN.md](DESIGN_MAP_AND_UX_WORKFLOW_PLAN.md)

## Executive Summary

Owlvex has the right product pieces, but the workflows still feel like separate engineering features rather than one guided developer journey. The main issue is not missing buttons; it is that users can lose orientation between onboarding, scan scope, framework selection, report type, fix preview, post-fix verification, TDD context, Design Box, and Drift Box.

The strongest product path should be:

1. install
2. register or enter licence
3. configure provider
4. select project root
5. optionally configure TDD, Design Box, and Drift Box
6. create or refresh a Design Map when repo-level understanding matters
7. scan changed files or current file
8. inspect evidence
9. preview a scoped fix
10. keep/discard
11. see one consolidated post-fix state
12. generate a summary or evidence report

Today that path exists, but it is not consistently presented as one workflow. The most important UX improvements are workflow consolidation, clearer state language, fewer ambiguous counts, and stronger user-facing explanations of what happened.

## Current Product Workflows

### Onboarding

Current code shape:

- registration choices are built in `buildBackendConnectedNoLicenceChoices()`
- post-registration choices are built in `buildRegistrationCompletionChoices()`
- backend/licence/provider readiness choices are built in `buildBackendAndLicenceReadyChoices()`
- connection setup, licence entry, Free/Trial, and provider configuration are driven from VS Code command prompts

What works:

- Free, Trial, and Enter Licence are visible early
- provider setup has provider-specific helper text
- backend and provider connection tests exist
- project root can be selected explicitly

Problems:

- the user sees multiple prompt surfaces instead of a single progress path
- email verification can feel like a loop if the status is not persisted or refreshed clearly
- after onboarding, the next recommended action may be `Configure LLM`, `Scan Workspace`, or `Scan Current File`, but the product objective is really "get first meaningful scan"
- admin-side telemetry shows usage events and scans separately, but the product does not yet make the user's onboarding-to-first-scan path obvious enough

Recommended changes:

- add one "Setup Progress" state in the chat panel:
  - Backend
  - Licence
  - Provider
  - Project root
  - First scan
  - First report/fix preview
- after licence activation, bias toward `Scan changed files`, `Scan Git commit/range`, or `Scan current file`, not workspace scan
- make verification state explicit: `Verification sent`, `Code accepted`, `Licence issued`, `Extension revalidated`
- record onboarding step outcomes as structured telemetry, not only generic usage events

## Scan Scope Workflow

Current code shape:

- `WorkingScope` supports current file, selected files, changed files, Git commit/range, open editors, and workspace
- changed-files detection is Git-backed in `workspaceScanner.ts`
- non-source changed files are now classified with skip reasons
- Git commit/range scans resolve commit, branch, tag, or range targets locally through Git before reusing the multi-file scan flow
- workspace scanning has Foundry pacing rules

What works:

- changed-files scanning exists and is now closer to a daily developer workflow
- Git target scanning supports review of a specific local commit or branch range without a workspace scan
- selected-files and open-editors support useful mid-sized scans
- unsupported changed files can be explained instead of silently ignored

Problems:

- the scope selector is still just a dropdown; it does not explain tradeoffs
- changed-files scan depends on Git. If Git is unavailable or the project has no repository, the fallback state is not yet a strong UX path
- changed-files scan still scans whole files, which is technically right for security, but reports need to separate changed-line findings from pre-existing findings
- "No changed source files" is better than before, but still risks confusing users who changed docs, config, or Drift/TDD files

Recommended changes:

- make `Changed files` the default scan scope when Git changes exist
- show scope help inline:
  - Current file: fastest
  - Changed files: best daily workflow
  - Workspace: slower, broad review
- add a no-Git fallback:
  - scan open editors
  - scan recently modified files
  - scan selected files
- in reports, split findings into:
  - touched by current diff
  - pre-existing in changed files
  - wider repo findings

## Report Workflow

Current code shape:

- summary and full reports are generated by `reportGenerator.ts`
- reports include proof posture, evidence contracts, safe probes, Drift Box sections, Design Context, AI usage, and framework mappings
- report action supports summary/full variants

What works:

- reports have meaningful evidence detail
- summary report exists for daily developer use
- full report preserves evidence and audit context
- Drift Box and Design Context are conditionally reported

Problems:

- reports are still too dense for first-time users
- some counters are precise but not user-friendly, for example "AI finding funnel" and "probe quality signal"
- report type selection exists, but the user is not guided on when to choose summary vs full
- "usage" in admin console can be confused with scan usage, prompt usage, or product usage

Recommended changes:

- summary report should start with exactly three blocks:
  - What changed?
  - What should I fix now?
  - What did Owlvex prove?
- full report should be labelled "Evidence report" everywhere, not just "full"
- add a short report type picker explanation:
  - Summary: daily developer view
  - Evidence: security/review/audit view
- rename admin console `Usage events` label to `Product events` or add a tooltip:
  - product interactions, not scan count

## Fix Preview and Post-Fix Workflow

Current code shape:

- fix previews are review-scoped and can be kept or discarded
- batch previews can span multiple files
- post-fix verification runs after keep
- continuation queue exists when remaining findings are discovered
- fix benchmarking hooks exist for benchmark-mapped cases

What works:

- original files are not changed until Keep fix
- batch preview flow reduces repeated prompts
- post-fix verification prevents the old "apply fix and trust it" failure mode
- continuation requirement is the right security posture

Problems:

- post-fix continuation can still feel like a second scan surprise
- if the scanner finds new issues after a fix, users need one consolidated next-action state, not multiple independent messages
- weak-evidence fixes are still the most toxic failure mode; the benchmark case where ownership logic was invented is the warning pattern
- users need clearer labels for `fixed target finding but file still not clean`

Recommended changes:

- always produce one consolidated post-fix summary:
  - reviewed findings cleared
  - files clean
  - remaining findings
  - false-positive/manual-review candidates
  - next recommended action
- gate fix generation by proof posture:
  - proven/sink-backed: fix preview allowed
  - AI-reviewed with strong local evidence: fix preview allowed
  - weak business-rule inference: review only
- never generate authorization/domain-model code unless an ownership model exists in code or Design/TDD context

## TDD Box, Design Box, and Drift Box Workflow

Current code shape:

- TDD Box uses `projectContextFile` and grounds scan/fix prompts
- Design Box points to local context files and is especially relevant for STRIDE
- Drift Box points to a JSON config and scripts folder, then runs repository-owned checks after approval
- Drift Box is report-only and should not block scan/fix completion

What works:

- project-specific context can now be loaded locally
- Drift Box can run real repo validation like `npm run validate`
- report text can include Drift Box only when configured/enabled
- TDD/Drift can be selected from the scan profile quick pick

Problems:

- TDD Box and Design Box concepts overlap from a user's perspective
- Drift Box configuration is still too technical for a first-time user
- the scan profile selector groups security frameworks and workflow context together; this is functional but conceptually mixed
- users need clearer feedback that Drift Box ran, what command ran, and that it is report-only

Recommended changes:

- rename the profile section from `Workflow context and checks` to `Project grounding and checks`
- show configured file paths in the profile picker detail
- add a `Run Drift Check Now` command separate from scan
- make Drift Box setup wizard ask only:
  - config file
  - scripts root
  - run during scan yes/no
- show Drift Box report line only when enabled and configured, as already intended

## Design Map Workflow

New product direction:

- Design Box and TDD Box are user-provided project context.
- Drift Box is user-provided validation scripts.
- Design Map is Owlvex-generated project understanding created from code plus optional Design/TDD context.

The Design Map should explain:

- what the application does
- entrypoints and route surfaces
- middleware, services, repositories, and data stores
- authentication, authorization, tenant, and ownership boundaries
- sensitive data and external integrations
- security-relevant source/guard/sink flows
- evidence gaps and contradictions
- scanner guidance that constrains future scan/fix reasoning

UX expectation:

- chat/config should show Design Map status: missing, stale, or current
- users should be able to `Create Design Map`, `Refresh Design Map`, and `Open Design Map`
- STRIDE or repo-level scans should recommend a Design Map when none exists
- prompt answers like "what does this app do?" should prefer the Design Map over generic active-file guessing
- reports should mention Design Map only when generated or used

Trust requirement:

- every Design Map claim needs confidence such as confirmed by code, confirmed by design context, inferred, uncertain, or contradicted
- fixes must not invent domain models that are absent from the Design Map
- authorization/ownership findings should be downgraded to review when the only evidence is a client-supplied ID and no ownership model exists

## Chat and Prompt Workflow

Current code shape:

- chat state tracks active mode, working scope, last scan target, last scan, provider state, licence state, and project context summary
- local intents can trigger scan/report/review actions
- prompt context can include active editor, project context, framework pack, report summary, and finding detail

What works:

- chat can route practical commands like scan and report
- scan-backed responses are separated from advisory responses
- chat can explain scores and findings
- project root/context are visible in state

Problems:

- users expect the prompt to remember what the tool has just said and guide application use; failures here feel like product failure
- prompt answers about app/tool usage need to be grounded in latest scan/report/action state, not only active editor context
- report navigation help should be stronger; users will ask the prompt how to use Owlvex

Recommended changes:

- add a compact "latest workflow state" block to every tool-help prompt:
  - licence/provider/project root
  - selected scan scope
  - latest scan/report
  - pending fix preview
  - continuation queue
  - configured TDD/Design/Drift paths
- add canned help intents:
  - "how do I use this report?"
  - "what should I fix first?"
  - "why no findings?"
  - "did Drift run?"
  - "what does usage mean?"
- keep chat answers grounded in stored report metadata when the user asks about reports

## Admin Console Workflow

Current code shape:

- admin console shows customer directory, active licences, pending verification, usage events, scans, reports, telemetry profile, recent activity, notes, and audit history
- usage summary is generated from `usage_events`
- scan summary is generated from `scan_history`

What works:

- customer operations are possible without manual database browsing
- telemetry profile can be changed
- customer state is inspectable
- recent activity cards exist

Problems:

- "Usage" is ambiguous; it can mean setup, prompt, session, scan, fix, or report events depending on metadata
- customer usage cannot currently answer "how did this user use the platform?" unless the recent events are inspected
- scan count can be zero while usage is nonzero, which is correct but confusing
- internal/founder/test accounts need explicit segmentation before product conclusions are reliable

Recommended changes:

- rename `Usage events` to `Product events`
- add event type grouping:
  - onboarding
  - session
  - provider setup
  - scan
  - report
  - fix
  - prompt/chat
- add customer journey timeline:
  - registered
  - verified
  - licence issued
  - provider configured
  - first scan
  - first report
  - first fix preview
- mark internal/founder/bootstrap accounts explicitly

## Engineering Findings Affecting UX

### 1. Workflow State Is Split Across Too Many Places

State exists in VS Code settings, workspace state, licence cache, provider registry, scan store, report store, and chat messages. This is workable, but user-facing guidance needs one normalized "current workflow state" object.

Recommendation:

- create a lightweight `WorkflowStateSummary` builder used by chat, onboarding, and report actions
- expose the same labels in chat and UI

### 2. Naming Is Sometimes Technically Correct But Product-Weak

Examples:

- `Usage events` is technically correct but user-confusing
- `Full report` is less clear than `Evidence report`
- `Frameworks` picker also controls TDD/Drift, which are not frameworks

Recommendation:

- use product names consistently:
  - Product events
  - Evidence report
  - Scan profile
  - Project grounding

### 3. Weak-Evidence AI Fixes Need Hard Gating

This is the highest-risk trust issue. A scanner can survive being slow. It cannot survive inventing business logic as a confident fix.

Recommendation:

- require ownership/model evidence before generating authorization fixes
- downgrade unsupported object-ownership claims to manual review
- surface "why no fix preview" as a trust feature, not a limitation

## Priority Improvement Plan

### P0 - Trust and First-Use Value

1. Make changed-files scan the default when Git changes exist.
2. Add one setup progress block in chat.
3. Rename usage/admin labels to reduce ambiguity.
4. Consolidate post-fix continuation into one summary.
5. Gate weak-evidence fix generation.

### P1 - Workflow Clarity

1. Add report type explanations.
2. Add latest workflow state to prompt context.
3. Add no-Git fallback for changed-files scanning.
4. Show configured TDD/Design/Drift paths in scan profile.
5. Add first-scan guidance after provider setup.

### P2 - Product Learning

1. Segment founder/internal/test/external users in telemetry.
2. Add onboarding step outcome telemetry.
3. Add first scan/report/fix timestamps per customer.
4. Add prompt/chat event taxonomy if production policy allows it.
5. Add admin journey timeline grouped by product step.

## Acceptance Checks

Use these as concrete completion checks:

- a new user can reach a first scan without understanding every setting
- `Changed files` is the obvious daily path when Git changes exist
- no-Git users get a useful fallback instead of a dead end
- prompt can answer "how do I use this report?" using the latest report state
- admin console can distinguish product events from scans
- post-fix output is one consolidated queue
- weak ownership/business-rule findings do not generate invented domain-model fixes
- TDD, Design Box, and Drift Box show configured paths and clear enabled/disabled state
- reports clearly distinguish summary vs evidence use cases
