# Owlvex Project Context And Scan Tiers Contract

## Purpose

This document defines two closely related product directions:

1. a **Project Context Contract** that the user can provide to Owlvex
2. a **three-tier scan model** that makes the current hybrid scanner more explicit and trustworthy

The purpose is not to replace Owlvex's current hybrid architecture.

The purpose is to make that architecture:

- easier to explain
- easier to benchmark
- easier to trust
- easier to evolve without hidden assumptions

---

## Core Decision

Owlvex keeps the current hybrid scan direction.

It does **not** drop:

- local deterministic scanning
- AI-assisted reasoning
- single-model multi-pass corroboration
- the client-side privacy boundary

Instead, it formalizes that hybrid system into:

- **Project Context Contract** for better AI understanding of the codebase
- **Three explicit scan tiers** for better execution clarity

---

## Part 1: Project Context Contract

## What it is

The Project Context Contract is a user-supplied document that helps Owlvex understand a specific codebase.

This is the "uploaded TDD-style document" concept.

It is not a source of security proof.

It is a source of **project grounding**.

Its purpose is to help AI understand:

- what the system is for
- what "correct" behavior looks like
- what the important business rules are
- what the architecture boundaries are
- what security assumptions the project relies on

---

## What it is not

The Project Context Contract is **not**:

- a replacement for code analysis
- a replacement for deterministic proof
- a way to force findings into existence
- a way to suppress valid findings just because the document says the system is secure

It may improve AI interpretation.
It may not redefine truth.

---

## Why it exists

Owlvex's AI lane is strongest when it understands the project's actual intent.

Without project grounding, AI tends to over-generalize:

- it sees an untrusted input and assumes a bug class too broadly
- it misses important architectural guards because they are spread across files
- it fails to understand what a route, helper, or middleware is supposed to enforce

The Project Context Contract exists to reduce that drift.

---

## What it should contain

The Project Context Contract should support concise, structured context such as:

- product purpose
- critical user roles
- authentication model
- authorization and tenant model
- sensitive data classes
- critical workflows
- key integrations
- trust boundaries
- forbidden behaviors
- important architectural invariants
- folders or generated code that should be treated specially

Example topics:

- "all document reads must be tenant-scoped"
- "admin actions must flow through policy middleware"
- "JWT verification only happens in middleware X"
- "folder Y contains generated code and should not drive primary findings"

---

## How Owlvex should use it

The Project Context Contract should be used only as AI context for:

- `TARGETED_AI` scans
- `REPO_AI` scans
- fix generation and remediation explanation

It may also help:

- prioritize findings
- improve report wording
- reduce false positives in safe companion patterns

It must not by itself produce:

- `PROVEN` findings
- deterministic rule outcomes
- silent suppression of structurally proven defects

---

## Privacy boundary for project context

The Project Context Contract should follow the same privacy philosophy as source code:

- default to client-side use
- do not require Owlvex backend storage
- treat the content as project-sensitive unless the user explicitly chooses otherwise

Allowed:

- local storage in extension settings or workspace-scoped data
- sending it to the selected AI provider together with code when needed for that scan tier

Not allowed by default:

- uploading it to Owlvex backend as required scan input
- assuming it is safe to retain centrally

---

## Part 2: Three-Tier Scan Model

## Why the current hybrid model needs this

Owlvex already behaves like a hybrid scanner:

- deterministic local engine
- AI reasoning
- corroboration

But today that hybrid system is too implicit.

Users and developers benefit from a clearer execution taxonomy.

The three-tier model makes the current hybrid scan easier to reason about without changing its core privacy boundary.

---

## Tier 1: `STATIC`

### Definition

Local deterministic proof based on structural rules and benchmark-backed invariants.

### Typical behavior

- fully local
- no AI required
- strongest trust
- cheapest execution

### Intended output posture

- `PROVEN`

### Examples

- IDOR with absent ownership constraint
- unsafe shell command execution from direct interpolation
- SQL query construction with direct template-literal injection
- debug mode enabled without required production guard

---

## Tier 2: `TARGETED_AI`

### Definition

AI reasoning against a bounded target, narrowed first by deterministic discovery, code references, or scoped file/context selection.

### Typical behavior

- AI examines a route, function, helper, or specific code region
- surrounding local context may be included
- Project Context Contract can be included
- best practical AI tier for most issue classes

### Intended output posture

- `CORROBORATED`
- `PARTIAL`
- `UNVERIFIED`

depending on evidence and corroboration outcome

### Examples

- SSRF allowlist validation on an outbound helper
- weak JWT validation in a specific token handler
- safe-vs-unsafe tenant guard patterns where code context matters
- AI-assisted false-positive validation of a narrowed candidate

---

## Tier 3: `REPO_AI`

### Definition

Broad repo-context AI reasoning across a larger project surface when local narrowing is insufficient.

### Typical behavior

- whole-repo or broad multi-file exploration
- most expensive
- most quota-sensitive
- best for architectural or distributed logic questions
- Project Context Contract is especially valuable here

### Intended output posture

Usually no stronger than:

- `CORROBORATED`
- `PARTIAL`
- `UNVERIFIED`

unless paired with deterministic evidence

### Examples

- business-logic authorization concerns spread across routes and middleware
- architectural misuses of shared security helpers
- repo-wide review against a project-specific control objective

---

## Relationship to current corroboration model

The three tiers do not replace the current AI corroboration direction.

They sit above it.

Owlvex should still use:

- `Finder`
- `Verifier`
- `Skeptic`

especially for AI-backed tiers.

The three tiers answer:

> what kind of scan is this?

The corroboration model answers:

> how strongly did the AI lane support or dispute the claim?

These are complementary, not competing, concepts.

---

## Reporting rule

Owlvex reports should eventually show both:

- **scan tier**
- **confidence / corroboration posture**

Example:

- `Tier: STATIC | Confidence: PROVEN`
- `Tier: TARGETED_AI | Corroboration: CORROBORATED`
- `Tier: REPO_AI | Corroboration: PARTIAL`

This is more honest than flattening everything into one generic "AI finding."

---

## Privacy rule

The move to three tiers does **not** change the code boundary.

Owlvex must keep the existing rule:

- code stays on the client
- deterministic scanning runs locally
- code goes only to the customer-selected model provider
- Owlvex backend remains a control plane, not a code-processing scan plane

This contract strengthens product clarity.
It does not weaken privacy.

---

## Product implications

This model should improve:

- trust in reports
- clarity of scan behavior
- explainability of AI involvement
- ability to benchmark different scan paths
- future pricing and quota discipline

It should also make it easier to explain the product:

- deterministic proof where Owlvex can prove
- targeted AI where bounded reasoning helps
- repo AI where broad context is needed

---

## Anti-misuse rule

The Project Context Contract must not become:

- a hidden backdoor for app-specific suppressions
- a way to turn user claims into scanner truth
- a justification for overriding deterministic evidence

It is context, not proof.

Likewise, the three-tier model must not become:

- a marketing excuse to present exploratory AI as equal to deterministic proof

Tier clarity must increase honesty, not blur it.

---

## Recommended initial implementation order

1. Add this contract to the core docs.
2. Add first-class scan tier labels:
   - `STATIC`
   - `TARGETED_AI`
   - `REPO_AI`
3. Keep current hybrid engine intact while reclassifying paths into those tiers.
4. Add a simple local Project Context Contract input path.
5. Use Project Context Contract only in AI-backed tiers.
6. Expose tier + corroboration in reports and UI.

---

## Bottom Line

Owlvex should not abandon its hybrid scanner.

It should **discipline** it.

The right path is:

- keep the current local deterministic + AI model
- add a client-side Project Context Contract for better AI grounding
- formalize the hybrid scanner into `STATIC`, `TARGETED_AI`, and `REPO_AI`
- keep deterministic proof as the strongest trust boundary in the product

That makes Owlvex easier to trust without making it heavier, less private, or less product-like.
