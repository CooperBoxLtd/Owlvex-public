# Owlvex Model Selection Matrix

## Purpose

This document defines how Owlvex evaluates AI models for the stabilization phase.

It exists to stop model selection from becoming anecdotal, hype-driven, or based on one impressive scan.

The goal is not to find the "smartest" model in general.

The goal is to find the best model posture for Owlvex's actual product shape:

- deterministic-first security scanning
- single-model, multi-pass corroboration
- one selected agent executing all three reasoning roles
- explicit confidence boundaries
- benchmark-backed reliability
- acceptable client cost and operational friction

This document should be used together with:

- [STABILIZATION_CONTRACT.md](D:/Dev/repos/CodeScanner/docs/STABILIZATION_CONTRACT.md)
- [IMPLEMENTATION_BACKLOG.md](D:/Dev/repos/CodeScanner/docs/IMPLEMENTATION_BACKLOG.md)
- [tools/demo/EXPECTATIONS.md](D:/Dev/repos/CodeScanner/tools/demo/EXPECTATIONS.md)
- [tools/benchmark-app/EXPECTATIONS.md](D:/Dev/repos/CodeScanner/tools/benchmark-app/EXPECTATIONS.md)

---

## Selection Principle

Owlvex does not select models based on branding, benchmark marketing, or single-answer fluency.

Owlvex selects models based on how well they support the verification workflow.

The preferred evaluation posture is:

1. same benchmark inputs
2. same scanner pipeline
3. same expectation files
4. same report evaluator
5. compare model behavior, not model reputation

---

## Role-Oriented Evaluation

During stabilization, model selection is organized by role.

Even if the same underlying model is used for all passes, the role definitions still matter because they describe what behavior the model must support.

The default Owlvex posture is not "three different agents."

The default posture is:

- one selected provider/model
- one agent identity
- three sequential role prompts
- one merge or adjudication layer owned by Owlvex

This keeps the client setup simple while still giving the scanner multiple reasoning perspectives.

### Role 1: Primary Scanner

The primary scanner role is responsible for the initial AI finding generation.

It should be:

- good at reading code quickly
- able to propose plausible issues without missing obvious cases
- reasonably structured in output
- not excessively prone to duplicate issue variants

### Role 2: Verifier

The verifier role is responsible for confirming whether a candidate finding is supported by local code evidence.

It should be:

- conservative
- evidence-driven
- less likely to generalize "untrusted input exists" into "vulnerability exists"
- good at staying within the cited code region and nearby context

### Role 3: Skeptic

The skeptic role is responsible for falsifying a claim where contradictory evidence exists.

It should be:

- strong at spotting guards and safe companion patterns
- comfortable rejecting weak findings
- less likely to hallucinate missing danger
- good at recognizing when a cited sink or dangerous primitive is actually absent

### Role 4: Budget Fallback

The budget fallback role is not expected to be the best model.

It is expected to be:

- affordable enough for default or frequent use
- available to more customers
- good enough to stay within benchmark tolerances

### Role 5: Accessibility Fallback

The accessibility fallback role exists for clients with provider or environment constraints.

It should be:

- easy to provision
- stable under common enterprise restrictions
- acceptable for deterministic-plus-light-AI posture even if not ideal for full corroboration

---

## Evaluation Criteria

Every candidate model should be scored against the same categories.

Use a 1-5 scale per category:

- `1` unacceptable
- `2` weak
- `3` usable
- `4` strong
- `5` excellent

### A. Code Reasoning Quality

How well does the model read code and identify the real security-relevant behavior?

Look for:

- correct issue class selection
- fewer broad category errors
- less "JSON parsing equals deserialization" style drift

### B. Verification Discipline

How well does the model stay constrained when acting as verifier or skeptic?

Look for:

- willingness to reject weak claims
- ability to spot contradictory evidence
- low tendency to overclaim under sparse context

### C. Structured Output Reliability

How consistently does the model produce parseable, schema-aligned output?

Look for:

- stable field names
- low format drift
- fewer malformed responses

### D. Duplicate-Control Behavior

How often does the model produce overlapping findings for the same sink or code region?

Look for:

- fewer duplicate issue variants
- cleaner canonical issue mapping
- less repeated advice with different wording

### E. Repo-Context Behavior

How well does the model use nearby helpers, middleware, and constraints?

Look for:

- better safe companion suppression
- better interpretation of shared guards
- fewer shell-level overclaims

### F. Rate-Limit And Throughput Behavior

How operationally usable is the model under realistic repo scans?

Look for:

- fewer `429` failures
- better latency
- stable long-run behavior across many files

### G. Cost Suitability

How realistic is the model for customer-facing use?

Look for:

- price per scan
- price per corroborated scan
- whether the model can support repeated multi-pass analysis without breaking the product economics

### H. Client Accessibility

How easy is the model for customers to adopt?

Look for:

- provider availability
- enterprise compatibility
- licensing friction
- setup simplicity

---

## Benchmark Procedure

Every serious model comparison must run the same procedure.

### Required Inputs

- the latest code on the stabilization branch
- current scanner test suite
- current expectation files
- current report evaluator

### Required Commands

```bash
cd extension
npm test -- --runInBand --runTestsByPath src/scanner/demoRegression.test.ts src/scanner/scanEngine.test.ts src/scanner/workspaceScanner.test.ts src/scanner/reportGenerator.test.ts src/panels/sidebarProvider.test.ts src/scanner/stabilizationBenchmark.test.ts
npm run benchmark:stabilization
```

After generating fresh reports from the candidate model/provider setup:

```bash
cd extension
npm run benchmark:stabilization:demo
npm run benchmark:stabilization:benchmark-app
```

### Required Comparison Outputs

For each candidate, record:

- false positives against safe companions
- false negatives against expected unsafe cases
- duplicate findings
- classification errors
- degraded scan warnings
- report evaluator pass/fail

No model change should be accepted based on "the answers looked better."

It must beat the incumbent on measured outcomes or provide a clear operational advantage without regressing trust.

---

## Decision Matrix Template

Use the following table when comparing candidates.

| Candidate | Intended Role | Code Reasoning | Verification Discipline | Structured Output | Duplicate Control | Repo Context | Rate-Limit Stability | Cost | Accessibility | Benchmark Result | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Incumbent | Primary scanner | - | - | - | - | - | - | - | - | - | Baseline |
| Candidate A | Primary scanner | - | - | - | - | - | - | - | - | - |  |
| Candidate B | Verifier / Skeptic | - | - | - | - | - | - | - | - | - |  |
| Candidate C | Budget fallback | - | - | - | - | - | - | - | - | - |  |

If a candidate cannot complete the benchmark reliably, that is a real result and should be recorded as such.

---

## Current Supported-Provider Shortlist

This shortlist is derived from the providers and default models Owlvex already supports in the extension today.

It is a starting hypothesis list, not a verdict.

The current supported provider lane includes:

- OpenAI
- Anthropic
- Azure AI Foundry
- Gemini
- Mistral
- Groq
- Ollama
- custom OpenAI-compatible endpoints

The current configured defaults in the product are:

- OpenAI: `gpt-4o`
- Anthropic: `claude-opus-4-6`
- Azure AI Foundry: `gpt-4o` deployment by default
- Gemini: `gemini-1.5-pro`
- Mistral: `mistral-large-latest`
- Groq: `llama-3.3-70b-versatile`
- Ollama: `qwen2.5:7b`

### Initial Candidate Posture

These are the recommended first candidates to benchmark, based on current Owlvex support and product needs.

| Candidate | Provider | Default Model In Repo | Best Initial Role Hypothesis | Why It Makes The Shortlist |
| --- | --- | --- | --- | --- |
| Incumbent baseline | Azure AI Foundry or OpenAI | `gpt-4o` | Primary scanner baseline | This is already the main reference posture in tests and recent scanner work. |
| Reasoning-focused candidate | Anthropic | `claude-opus-4-6` | Verifier / Skeptic | Strong candidate for conservative second-pass reading and contradiction spotting. |
| Accessibility candidate | OpenAI | `gpt-4o-mini` or similar available chat model | Budget fallback | Same provider family, simpler adoption path, useful if corroboration cost needs to drop. |
| Throughput candidate | Gemini | `gemini-1.5-pro` | Primary scanner or verifier alternative | Worth testing for repo-scale scans and different reasoning profile. |
| Cost-speed candidate | Groq | `llama-3.3-70b-versatile` | Budget fallback or skeptic experiment | Useful to test fast-turnaround corroboration if output quality stays within tolerance. |
| Local/privacy candidate | Ollama | `qwen2.5:7b` | Accessibility fallback | Important for constrained clients even if it does not win on absolute quality. |

### Candidates To De-Prioritize Initially

The following are supported, but are not the first place to spend stabilization effort:

- Mistral
  Good to keep available, but not the first benchmark target unless it offers a clear cost or region advantage for a customer.
- Custom OpenAI-compatible endpoints
  These matter operationally, but they are not a single model family and should be evaluated after the core hosted baselines are understood.

---

## Recommended Experiment Order

To keep the next round disciplined, Owlvex should benchmark in this order:

1. `gpt-4o` incumbent baseline
2. `claude-opus-4-6` as the strongest verifier / skeptic candidate
3. one cheaper or faster candidate from the already supported providers
4. one accessibility-first candidate such as Ollama

For each candidate above, the intended test shape is still the same:

- the same selected agent handles `Finder`
- the same selected agent handles `Verifier`
- the same selected agent handles `Skeptic`
- Owlvex compares the three outputs using its merge rules

This order matters because it answers the most important questions first:

1. What is our measured baseline?
2. Can a stronger reasoning model improve corroboration quality?
3. Can we get acceptable quality at lower cost or higher throughput?
4. What is the minimum viable accessible fallback for constrained customers?

---

## First Comparison Sheet

Use this filled starter matrix for the next benchmark session.

| Candidate | Intended Role | Code Reasoning | Verification Discipline | Structured Output | Duplicate Control | Repo Context | Rate-Limit Stability | Cost | Accessibility | Benchmark Result | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `gpt-4o` | Incumbent baseline | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | Current benchmark reference point |
| `claude-opus-4-6` | Verifier / Skeptic candidate | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | First strong reasoning comparison |
| `gemini-1.5-pro` | Repo-scale alternative | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | Useful counter-shape to current baseline |
| `llama-3.3-70b-versatile` | Fast fallback experiment | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | Validate speed vs trust tradeoff |
| `qwen2.5:7b` | Local accessibility fallback | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` | Important even if ceiling is lower |

All `TBD` cells must be filled from measured benchmark evidence, not intuition.

---

## Adoption Rule

A model should only replace the incumbent when at least one of the following is true:

1. it materially reduces false positives without increasing false negatives
2. it materially improves verifier or skeptic quality in the multi-pass flow
3. it materially reduces operational pain such as throttling or malformed output
4. it offers similar benchmark quality at meaningfully better cost or accessibility

A model must not be adopted simply because:

- it is newer
- it is larger
- it sounds more authoritative
- it performs well on one cherry-picked scan

---

## Release Rule

Changing the preferred AI model or provider posture is a release-impacting change.

Before switching defaults, Owlvex should have:

- a recorded benchmark comparison against the incumbent
- a written summary of tradeoffs
- a decision on which role the model is best suited for
- confirmation that the new model does not weaken confidence-tier honesty

---

## Working Rule For Tomorrow's Experiment

For the next stronger-agent trial:

1. keep the current model as the incumbent baseline
2. run the same stabilization benchmark pack
3. generate fresh demo and benchmark-app reports
4. evaluate them with the report evaluator
5. fill the matrix before making any product decision

If the stronger model improves the matrix, we adopt it deliberately.

If it does not, we keep the current posture and continue stabilization work without pretending the upgrade helped.
