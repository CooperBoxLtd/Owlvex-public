# Owlvex Diagram Workflow Engineering Review

Date: 2026-05-16

Reviewed generated diagrams from `D:\Dev\repos\Morse App\.owlvex\diagrams`:

- `architecture-map.md`
- `security-evidence-map.md`
- `workflow.md`
- `tdd-diff.md`
- `threat-flow.md`
- `risk-lens.md`
- stale `fix-impact.md`

## Executive View

The current diagrams prove that Owlvex can extract useful code signals, but the diagrams are not yet strong enough as developer workflow tools.

The best current artifact is the **Architecture Map** because it shows confirmed imports clearly. The second useful artifact is the **Risk Lens** because it tries to connect scan findings with code structure. However, the Risk Lens is currently too noisy and has a label rendering bug that makes it look unpolished.

The weakest artifacts are the **Workflow Diagram** and **TDD Diff Diagram**. They look like templates rather than project-specific reasoning. From an engineer perspective, they risk reducing trust because they imply understanding that the tool has not actually demonstrated.

## High-Impact Problems

### 1. Mermaid Label Rendering Bug

Risk Lens uses `/n` in node labels:

```mermaid
Fileefbe9e71["electron/main.js/nrisk 9/10/n2 finding(s)"]
```

This should be a real Mermaid line break, preferably `<br/>`, not `/n`.

Impact:

- Makes the diagram look broken.
- Reduces confidence in the feature immediately.
- Makes dense nodes harder to read.

Fix direction:

- Replace generated `\\n` display text with `<br/>` for Mermaid labels.
- Keep markdown text plain, but Mermaid node labels should use HTML-style line breaks.

### 2. Too Many Diagram Types, Not Enough Clear Jobs

Current Diagram Box creates or exposes too many outputs:

- Architecture Map
- Security Evidence Map
- Workflow Diagram
- TDD Diff Diagram
- Threat Flow Diagram
- Risk Lens
- stale Fix Impact in existing projects

Engineers do not want seven diagrams. They want:

1. **Architecture**: how the app is wired.
2. **Threat Flow**: where trust boundaries and STRIDE concerns are.
3. **Risk Lens**: where scan findings sit in the app.

Fix direction:

- Keep generating supporting data internally.
- In the UI, surface only three primary diagrams:
  - Architecture
  - Threat Flow
  - Risk Lens
- Hide or demote Security Evidence, TDD Diff, and raw intermediate maps under "Advanced".
- Stop showing or regenerating Fix Impact.

### 3. Workflow Diagram Is Too Generic

Current Workflow Diagram says:

```text
User -> Application entrypoint or route -> Runtime -> Policy -> Work -> Store/Integration -> Response
```

For Morse App, this is not really the workflow. The actual flow is closer to:

```text
User -> RT5Terminal UI -> NetworkPanel/useNetworkSession -> preload bridge -> main process -> session host/client -> protocol parser -> peer/session state -> UI updates
```

Problems:

- It labels UI state guards like `canTransmit` and `canResendLast` as "Auth / policy guard".
- It does not show renderer/preload/main process clearly.
- It does not show session host/client direction.
- It does not explain actual product behavior.

Fix direction:

- Make workflow diagrams application-archetype aware:
  - Electron app
  - Express/API app
  - CLI
  - frontend SPA
  - worker/job service
- For Electron, prefer renderer/preload/main/session/protocol flow over generic route/policy/work labels.
- Do not call UI affordance flags "auth policy".

### 4. TDD Diff Diagram Is a Placeholder, Not a Diff

Current TDD Diff Diagram says:

```text
TDD expectation: ownership and authorization rules -> Code evidence? -> Evidence present
```

This is not a meaningful comparison between the selected TDD file and code.

Problems:

- It does not quote or reference actual TDD sections.
- It does not map requirements to files.
- It does not say which expectations are missing, partial, contradicted, or implemented.
- It can claim "Evidence present" based on broad code signals, not requirement-level matching.

Fix direction:

- Either remove TDD Diff from the main UI until it is real, or make it requirement-based:
  - Parse TDD headings / bullet requirements.
  - Match each requirement to code evidence.
  - Output status: implemented, partial, missing, contradicted, extra.
  - Include file references per requirement.

### 5. Threat Flow Is Better, But Still Too Synthetic

Threat Flow now has STRIDE sections and better Electron boundaries. That is progress.

Remaining problems:

- Entry starts at `NetworkPanel.jsx`, but product flow probably starts at `src/main.jsx` or `RT5Terminal.jsx`.
- It still uses a single guard node for multiple STRIDE categories.
- It does not map specific STRIDE risks to scan findings when findings exist.
- Repudiation says "No audit/logging module found", which may be fine, but it should be framed as a review prompt, not a finding.

Fix direction:

- Generate Threat Flow from architecture archetype plus scan findings when available.
- Keep the pre-scan Threat Flow as a design aid.
- After scan, Risk Lens should become the better threat/finding view.

### 6. Risk Lens Is the Right Idea, But Too Noisy

Risk Lens is the closest to what developers need, because it answers:

- Where are the risky files?
- What findings are attached?
- How do those files connect to nearby code?
- Which files were scanned clean versus not scanned?

Current problems:

- Node labels are too long.
- Test files appear as risk nodes, which may be valid but should be visually separated from production/runtime code.
- Every finding expands into guard and sink nodes, creating clutter.
- It does not prioritize one path first.
- It does not provide a small "fix order" cluster.
- The overlay is helpful but visually dense.

Fix direction:

- Split Risk Lens into three sections:
  1. **Fix Order**: top 3 files/findings only.
  2. **Finding Clusters**: grouped by issue family or STRIDE.
  3. **Architecture Overlay**: broader graph with risky/scanned-clean/not-scanned states.
- Collapse detailed guard/sink evidence unless the finding is high/critical.
- Add a separate class for test files.
- Add report anchors or line references in labels.

## Diagram-by-Diagram Assessment

### Architecture Map

Status: keep.

Strengths:

- Confirmed imports are useful.
- It correctly shows Electron main/preload/runtime modules.
- It is readable compared with the other diagrams.

Weaknesses:

- It does not show runtime direction strongly enough.
- `vite.config.js` appears as an inferred module, which is not useful for application understanding.
- It does not group renderer, preload, main process, network/session, and tests.

Recommended next version:

- Group into subgraphs:
  - Renderer
  - Preload boundary
  - Main process
  - Session/network
  - Shared protocol/utils
  - Tests/dev tooling
- Keep confirmed imports as solid arrows.
- Keep inferred runtime boundaries as dotted arrows.

### Security Evidence Map

Status: keep as advanced evidence, not primary UX.

Strengths:

- Useful for scanner developers and debugging why Owlvex reasoned a certain way.
- Shows guards, sinks, stores, and integrations.

Weaknesses:

- Too raw for normal developers.
- UI flags are mixed with actual security controls.
- It does not distinguish "security control" from "business/UI state guard".

Recommended next version:

- Classify guard signals:
  - auth/security guard
  - validation guard
  - workflow/business guard
  - UI state guard
- Only auth/security and validation guards should satisfy scanner guard logic.

### Workflow Diagram

Status: redesign.

This currently reads as a generic backend workflow template. For Electron apps it should be replaced with an Electron-specific workflow.

Recommended action:

- Make workflow generation archetype-specific.
- If no archetype is confidently detected, call it "Inferred Runtime Flow" and use uncertainty labels.

### TDD Diff Diagram

Status: hide or rebuild.

This should not be promoted until it compares real TDD statements to code evidence.

Recommended action:

- Move to advanced/experimental.
- Implement requirement extraction before showing it as a first-class diagram.

### Threat Flow Diagram

Status: keep, improve.

Threat Flow is useful for STRIDE, but it should be clearer that it is a threat-model prompt, not proof.

Recommended action:

- Use archetype-specific boundaries.
- Use scan findings to enrich it when available.
- Avoid assigning generic UI flags as security controls.

### Risk Lens

Status: keep, prioritize.

This should become the primary post-scan diagram.

Recommended action:

- Fix label rendering first.
- Add a "Fix Order" section.
- Separate test/dev files from runtime files.
- Collapse low/medium detail by default.
- Use Architecture Overlay as supporting context, not the first thing developers must read.

### Fix Impact

Status: remove stale artifact.

The current `fix-impact.md` is old and generic. The product now moved toward Risk Lens.

Recommended action:

- Stop generating Fix Impact.
- Optionally delete stale `.owlvex/diagrams/fix-impact.md` when Diagram Box refreshes, or mark it deprecated.

## Recommended Product Shape

The Diagram Box should be simplified:

### Primary

- **Architecture**
  - "How this app is wired."
- **Threat Flow**
  - "Where trust boundaries and STRIDE review points are."
- **Risk Lens**
  - "Where findings sit in the code and what to fix first."

### Advanced

- Security Evidence Map
- TDD Diff
- Raw Design Map JSON/Markdown

## Implementation Backlog

1. Fix Mermaid line breaks in Risk Lens labels.
2. Delete or deprecate stale Fix Impact artifacts.
3. Add runtime/test/dev file classification.
4. Add Risk Lens "Fix Order" section with top 3 findings.
5. Collapse low/medium finding details in Risk Lens.
6. Make Workflow Diagram archetype-specific.
7. Reclassify guard signals by security relevance.
8. Move TDD Diff to advanced until requirement-level matching exists.
9. Add Design Map freshness metadata to Risk Lens.
10. Add report line anchors or file/line labels into Risk Lens findings.

## Engineering Conclusion

The current diagrams are technically interesting, but only two are close to developer value:

- Architecture Map
- Risk Lens

Threat Flow is useful for STRIDE but needs stronger code-specific grounding. Workflow and TDD Diff should not be treated as mature features yet.

The next practical goal should be:

> Make Risk Lens readable and actionable enough that a developer can open it after a scan and know the top files to inspect, how those files connect, and which parts of the broader app were not scanned.

## Implementation Decision

The immediate fix is to keep the diagram surface smaller:

- Primary: Architecture Map, Threat Flow, Risk Lens.
- Advanced: Security Evidence Map.
- Deferred: Workflow Diagram and TDD Diff until they are application-archetype aware and requirement-level.

Risk Lens should now act as the post-scan developer view: fix order first, focused scan scope second, and architecture overlay third. Low/medium findings should not drown the view in evidence nodes, and generated labels must render as readable Mermaid line breaks.

Architecture Map should present runtime responsibilities and flow rather than making raw imports the main diagram. Raw imports, sinks, guards, stores, and integrations remain in the Security Evidence Map and `owlvex-design-map.json`, which preserves the security proof boundary.
