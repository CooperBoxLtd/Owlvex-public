# AGHAST vs Owlvex

## Purpose

This document compares:

- **AGHAST**: Bounce Security's "AI Guided Hybrid Application Static Testing" framework
- **Owlvex**: this repo's deterministic-first scanner and VS Code remediation product

The goal is not to decide which project is "better" in the abstract. The goal is to answer four practical questions:

1. How are the two systems different at the architecture and code-execution level?
2. What should Owlvex borrow, and what should it avoid copying?
3. Which shape has better go-to-market odds as a product?
4. What does this imply for Owlvex's next product moves?

---

## Executive Summary

Short version:

- **AGHAST** is closer to a **hybrid security check framework**.
- **Owlvex** is closer to a **developer-facing product**.

That distinction matters.

AGHAST's strongest idea is its **clean execution model**:

- `repository` checks
- `targeted` checks
- `static` checks

That model is crisp, modular, and operationally honest. It makes it easier to reason about what kind of analysis is happening and why.

Owlvex's strongest idea is its **product loop**:

- scan inside the editor
- explain the issue
- `Fix code`
- show a diff
- `Keep fix` / `Discard fix`
- re-scan to verify the outcome

That is much closer to something teams can adopt as a daily developer tool.

My conclusion:

- **AGHAST is stronger as a framework architecture**
- **Owlvex has better odds of becoming a product**

Why:

- products win on workflow, trust, and repetition in real teams
- frameworks win on flexibility, but often stop at "powerful for experts"
- Owlvex already has a clearer wedge into daily development behavior

The highest-value move for Owlvex is:

- **borrow AGHAST's execution clarity**
- **keep Owlvex's editor-native remediation identity**

---

## Sources Used

### AGHAST

- GitHub repository: <https://github.com/BounceSecurity/aghast>
- README: <https://raw.githubusercontent.com/BounceSecurity/aghast/main/README.md>
- How It Works: <https://raw.githubusercontent.com/BounceSecurity/aghast/main/docs/how-it-works.md>

### Owlvex

- [README.md](../README.md)
- [PRODUCT.md](./PRODUCT.md)
- [IMPLEMENTATION_DESIGN.md](./IMPLEMENTATION_DESIGN.md)
- [STABILIZATION_CONTRACT.md](./STABILIZATION_CONTRACT.md)
- [MODEL_SELECTION_MATRIX.md](./MODEL_SELECTION_MATRIX.md)
- [chatViewProvider.ts](../extension/src/panels/chatViewProvider.ts)
- [sidebarProvider.ts](../extension/src/panels/sidebarProvider.ts)
- [scanEngine.ts](../extension/src/scanner/scanEngine.ts)
- [reportGenerator.ts](../extension/src/scanner/reportGenerator.ts)

---

## 1. Product Shape

## AGHAST

AGHAST presents itself as a framework that lets users **define checks** for code-specific and company-specific security concerns, then run those checks with a mix of deterministic discovery and AI analysis.

The strongest signals from its public docs:

- the central abstraction is the **check**
- each check has its own status: `PASS`, `FAIL`, or `ERROR`
- the output is structured JSON or SARIF
- it is explicitly designed to blend:
  - whole-repo AI analysis
  - targeted AI analysis after discovery
  - static-only checks

This is a strong framework posture.

It is good for:

- AppSec engineers
- platform/security teams
- organizations with custom check logic
- workflows that already speak SARIF, Semgrep, or similar formats

It is less obviously good for:

- everyday developers who want a tight IDE loop
- "fix it now" remediation workflows
- lightweight adoption inside coding flow

## Owlvex

Owlvex is shaped like a product first and a framework second.

The repo's own docs position it as:

- deterministic-first local scanning
- optional AI reasoning
- explicit provenance and corroboration posture
- scan-backed chat
- side-by-side remediation diffs
- `Keep fix` / `Discard fix`
- verification re-scan after apply

That means its center of gravity is not "define arbitrary checks." It is:

> help a developer discover, understand, and fix security problems while coding

That is a fundamentally more product-like posture.

---

## 2. Execution Model Comparison

## AGHAST's strongest architectural idea

AGHAST's public docs define three execution modes:

1. **Repository checks**
   Whole-repo AI analysis with no prior discovery step.

2. **Targeted checks**
   Deterministic discovery first, then AI analyzes each target independently.

3. **Static checks**
   Deterministic discovery only, no AI at all.

This is excellent architecture for three reasons:

### 2.1 It separates cost profiles cleanly

Repo-wide AI is expensive and broad.

Targeted AI is narrower and usually higher-signal.

Static checks are cheapest and most deterministic.

That separation forces clarity.

### 2.2 It separates trust profiles cleanly

Static checks are inherently higher-trust.

Targeted AI is easier to validate because the scope is constrained.

Repo AI is the broadest and least bounded.

Again, the model is honest about what kind of reasoning is being used.

### 2.3 It makes extensibility easier

New checks fit into one of a few known execution shapes, instead of inventing custom logic every time.

---

## Owlvex's current execution model

Owlvex is not organized around formal "check types" in the same first-class way yet.

Instead, its current execution shape is:

1. run deterministic local scanner
2. run AI analysis for uncovered or broader issue classes
3. run single-model multi-pass corroboration when enabled:
   - `Finder`
   - `Verifier`
   - `Skeptic`
4. merge results into explicit postures:
   - `PROVEN`
   - `CORROBORATED`
   - `PARTIAL`
   - `UNVERIFIED`

This is good product logic, but weaker architecture language than AGHAST's explicit mode system.

Owlvex currently expresses the trust model better than the execution model.

AGHAST expresses the execution model better than the product trust model.

That is a useful lesson.

---

## 3. Code and Architecture Differentiators

## 3.1 Deterministic engine posture

### AGHAST

AGHAST supports static checks and deterministic discovery, but it does not lead with a strong product claim around "proven structural violations" in the same way Owlvex does.

Its public language is more about:

- defining checks
- blending static and AI
- structured issue output

This is flexible and practical, but less differentiated.

### Owlvex

Owlvex's local deterministic lane is a true positioning asset.

The repo explicitly claims:

- deterministic findings are `PROVEN`
- structural invariants are the basis for certainty
- benchmark gates are the release discipline

This is stronger differentiation because it creates a sharper trust boundary:

- deterministic = product truth
- AI = flexible reasoning, explicitly bounded

That is a better long-term product foundation than "AI hybrid scanner" alone.

## 3.2 AI reasoning design

### AGHAST

AGHAST's targeted mode is the more mature idea:

- use discovery to narrow where to look
- then ask AI a constrained question

That is a strong way to reduce cost and noise.

### Owlvex

Owlvex's single-model multi-pass corroboration is a stronger **trust-control** mechanism:

- one model
- three role-separated passes
- disagreement lowers confidence

That is good product thinking, but it is still operationally expensive and quota-sensitive.

In short:

- AGHAST is better at **where AI should be aimed**
- Owlvex is better at **how AI claims should be judged**

Owlvex should absolutely steal more of AGHAST's targeting discipline.

## 3.3 Remediation workflow

This is where Owlvex is clearly ahead.

AGHAST's public shape is:

- define checks
- run checks
- get JSON/SARIF

That is useful, but it stops at detection/reporting.

Owlvex already has or is actively implementing:

- scan-backed chat
- fix explanation
- `Fix code`
- diff preview
- `Keep fix`
- `Discard fix`
- verification re-scan

That is much closer to real product behavior.

It turns the scanner from:

> "tool that points at problems"

into:

> "tool that helps close the loop"

This is a significant differentiator.

## 3.4 Delivery surface

### AGHAST

Best understood as:

- CLI/framework
- structured outputs
- check definition system

### Owlvex

Best understood as:

- VS Code-first developer product
- scanner + explainer + fixer
- optional backend control plane
- optional model choice

This matters because product adoption depends on where the user experiences value.

Owlvex's surface is easier to feel.

---

## 4. What Owlvex Should Borrow

## Borrow 1: Formal check types

Owlvex should adopt a formal classification like:

- `static`
- `targeted-ai`
- `repo-ai`

That does not mean copying AGHAST wholesale. It means making Owlvex's execution model more explicit.

This would help:

- internal architecture
- benchmark design
- user trust
- pricing and quota strategy
- report posture

## Borrow 2: Discovery-first targeted AI

This is the most important AGHAST idea for Owlvex.

Instead of broad AI passes over too much code, use deterministic discovery or helper-pattern narrowing first, then apply AI to those targets.

That would likely improve:

- token cost
- rate-limit behavior
- false-positive control
- report clarity

## Borrow 3: Check-centric output model

Owlvex findings should eventually expose:

- which Owlvex check family produced the result
- whether it was static, targeted-AI, or repo-AI
- what confidence ceiling is possible for that check type

That makes the engine more explainable.

---

## 5. What Owlvex Should Not Copy

## Do not copy the framework-first identity

AGHAST's framework shape is good, but if Owlvex over-rotates into "check definition platform," it risks losing its strongest differentiator:

- developer workflow
- editor-native guidance
- remediation loop

That would be a strategic mistake.

## Do not flatten product trust into pass/fail only

AGHAST's per-check `PASS / FAIL / ERROR` model is clean, but Owlvex's richer confidence and corroboration posture is valuable.

Owlvex should keep:

- `PROVEN`
- `CORROBORATED`
- `PARTIAL`
- `UNVERIFIED`

These are not cosmetic. They are part of the trust model.

## Do not become dependent on external scanners for core identity

AGHAST is comfortable orchestrating Semgrep, OpenAnt, and SARIF-based flows.

Owlvex can integrate with such inputs later if useful, but it should not outsource its core product identity to them.

Its moat needs to remain:

- Owlvex deterministic proofs
- Owlvex corroboration and normalization
- Owlvex remediation UX

---

## 6. Go-to-Market Analysis

This is the most important section.

Technical elegance is not enough. The question is:

> which shape has the better odds of becoming a real product?

## AGHAST's go-to-market profile

### Strengths

- Clear value for security engineers and advanced teams.
- Strong fit for custom organizational checks.
- Easy story for users already living in CLI, SARIF, Semgrep, and pipeline outputs.
- Good open-source leverage as a "bring your own checks" platform.

### Weaknesses

- The likely buyer/user is narrower.
- Frameworks are powerful, but often harder to operationalize as sticky products.
- It is easier for a framework to become admired than adopted.
- The public docs frame it more as an engine/toolkit than as a daily workflow product.

### GTM implication

AGHAST looks like it can succeed as:

- an open-source framework
- a consulting-led enablement asset
- a security-engineering toolkit

It is less obviously positioned to become the default daily tool for general developers.

## Owlvex's go-to-market profile

### Strengths

- Clear wedge: developers already live in the editor.
- Immediate use case: scan, understand, fix.
- Better "felt value" because the product helps close the loop.
- Easier story for individual adoption before org-wide rollout.
- Deterministic-first trust claim is a real positioning asset if kept honest.

### Weaknesses

- Harder product burden: UX, trust, quotas, remediation safety, model selection, report clarity.
- More moving parts to make feel reliable.
- Easier to disappoint users if AI posture is sloppy.

### GTM implication

Owlvex has the better shape for becoming a product because it can wedge into repeated daily behavior.

That matters more than elegance.

Products win when users:

- come back frequently
- trust the output enough to act
- see time saved, not just signal generated

Owlvex is closer to that shape.

---

## 7. Which Has Better Odds of Becoming a Product?

My answer:

- **Owlvex has better odds of becoming a product**
- **AGHAST has better odds of being admired as an architecture**

Why Owlvex has the better product odds:

### 7.1 The workflow is closer to the developer's job

Developers do not primarily wake up wanting:

- SARIF files
- custom check definitions
- pass/fail orchestration

They want:

- what is wrong
- why
- show me the code
- help me fix it
- let me keep or discard safely

Owlvex is directly aligned with that behavior.

### 7.2 The remediation loop is a stronger wedge than the check engine

Detection matters, but the product that wins daily attention is the one that helps the user finish the task.

Owlvex's `Fix code -> diff -> Keep/Discard -> verify` loop is a much stronger product wedge than "define checks and emit issues."

### 7.3 The deterministic-first story is easier to market than generic AI hybrid scanning

"We prove covered things and clearly bound the rest" is stronger than "we use AI plus static analysis."

It is sharper, more memorable, and more defensible if the benchmarks support it.

### 7.4 The editor surface is a better adoption vector

VS Code distribution and in-flow utility give Owlvex a better productization path than a framework-first CLI posture.

That does not make the engineering easier. It makes the distribution story better.

---

## 8. Why AGHAST Still Matters Strategically

Even if Owlvex has better product odds, AGHAST is still strategically important because it exposes a weakness in Owlvex's current shape:

Owlvex's trust model is stronger than its execution taxonomy.

AGHAST has the opposite strength.

That means AGHAST is a useful reference not because Owlvex should become it, but because it highlights missing clarity in Owlvex.

Specifically, Owlvex should become better at saying:

- this was a static proof
- this was a targeted AI check
- this was a repo-level exploratory AI pass

That would improve:

- internal architecture
- UX wording
- benchmark design
- pricing and quota strategy
- enterprise credibility

---

## 9. Strategic Recommendation for Owlvex

## Recommendation

Do **not** pivot Owlvex toward being "another hybrid check framework."

Instead:

1. keep Owlvex's **developer-native product identity**
2. adopt AGHAST's **execution-mode clarity**
3. push more AI work into **targeted** rather than broad repo-level analysis
4. keep deterministic proof and remediation UX as the main moat

## Concretely

Owlvex should formalize every issue family or scan path as one of:

- `STATIC`
- `TARGETED_AI`
- `REPO_AI`

And every finding should clearly expose:

- issue family
- execution mode
- provenance
- corroboration posture
- whether `Fix code` is offered confidently or cautiously

This would combine:

- AGHAST's architectural clarity
- Owlvex's stronger product loop

That combination is stronger than either approach alone.

---

## 10. Product Odds by Scenario

### Scenario A: "Best framework"

If the goal is:

- maximum flexibility
- organization-specific checks
- check authoring
- SARIF/CLI pipelines

Then AGHAST's shape is excellent.

### Scenario B: "Best developer product"

If the goal is:

- everyday developer use
- editor-native adoption
- fix-first workflow
- product-like retention

Then Owlvex has the better shape.

### Scenario C: "Commercial product with real usage frequency"

Owlvex still has the better odds, provided it keeps improving:

- trust
- clarity
- deterministic coverage
- AI discipline
- quota handling
- remediation safety

If it fails there, the product shape advantage can still be lost.

So this is not automatic.

But the underlying product geometry is better.

---

## 11. Risks for Owlvex

To be honest, Owlvex's product advantage can still be wasted.

Main risks:

1. **AI overclaiming**
   If `PARTIAL` or `UNVERIFIED` findings feel too confident, trust erodes fast.

2. **Quota and latency pain**
   If scans degrade too often, the product loop feels unreliable even if the architecture is strong.

3. **Overfitting to demos**
   If benchmark wins are too specific, product claims will not survive real repos.

4. **Framework drift**
   If Owlvex becomes too much of a check platform, it loses its tighter product identity.

These risks do not change the conclusion. They simply define what Owlvex must get right.

---

## 12. Final Judgment

If the question is:

> which codebase currently presents the cleaner abstract architecture?

AGHAST has a compelling answer.

If the question is:

> which one has the better chance of becoming a real repeat-use product?

Owlvex has the better answer.

Why, plainly:

- AGHAST is easier to respect
- Owlvex is easier to adopt repeatedly

And repeated adoption is what makes products.

---

## 13. Recommended Next Moves for Owlvex

1. Formalize scan/check execution modes as:
   - `STATIC`
   - `TARGETED_AI`
   - `REPO_AI`

2. Reclassify current issue families and scan paths into those modes.

3. Shift more AI scanning from broad repo context into targeted deterministic-discovery flows.

4. Keep `Fix code` and the verification loop as first-class product differentiators.

5. Use benchmark evidence, not model enthusiasm, to decide whether stronger LLMs actually improve product trust.

6. Add this comparison to product strategy discussions as:
   - what to borrow
   - what to avoid
   - what Owlvex is trying to become

---

## Bottom Line

AGHAST is a very useful reference because it is disciplined about **how checks run**.

Owlvex is the more promising product because it is disciplined about **how developers act on results**.

The winning path for Owlvex is not to imitate AGHAST.

It is to:

- borrow AGHAST's execution clarity
- keep Owlvex's remediation and editor-native product loop
- and make deterministic proof the thing that remains unmistakably Owlvex.
