# Owlvex Guardrails v1 Specification

> **Historical design document.** This describes an early architecture for a post-processing guardrail layer. The active implementation uses the conditional rules approach instead (see `extension/src/scanner/conditionalRule.ts` and `deterministicScanner.ts`). This document is retained for design history, not as active guidance.

## Purpose

Owlvex Guardrails v1 defines a deterministic post-processing layer that evaluates normalized LLM findings against code context and known execution semantics before findings are reported.

The goal is not to replace model reasoning. The goal is to constrain it.

Guardrails exist to:

- suppress predictable false positives
- upgrade predictable false negatives
- enforce category discipline
- incorporate local trust-state analysis
- make final findings explainable and benchmarkable

## Design Principles

### Deterministic

Given the same normalized finding and the same analysis context, the guardrail outcome must be identical.

### Explainable

Every rule application must be visible in the finding audit trail.

### Narrow

Rules should target known failure modes, not attempt to become a second scanner.

### Benchmarkable

Each rule should correspond to one or more benchmark cases so changes can be measured.

### Non-destructive

Raw model output should be preserved for audit and comparison, even if later suppressed or rewritten.

## Finding Lifecycle

Every finding moves through four explicit states:

1. `raw_llm`
   Direct model output before canonical normalization.
2. `normalized`
   Parsed into Owlvex's internal finding structure.
3. `guardrailed`
   Evaluated by deterministic rules and possibly suppressed, downgraded, upgraded, or rewritten.
4. `reported`
   Final finding that appears in reports and product surfaces.

This lifecycle must remain explicit in both tooling and benchmark output.

## Rule Engine Contract

### Input

The rule engine receives a single normalized finding plus supporting analysis context.

```ts
type GuardrailInput = {
  finding: NormalizedFinding;
  codeSnippet: string;
  sinkMetadata: SinkMetadata | null;
  trustState: "SAFE" | "UNSAFE" | "MIXED" | "UNKNOWN";
  analysisContext?: AnalysisContext;
};
```

### Output

The rule engine returns one of four actions:

```ts
type GuardrailAction =
  | { action: "suppress"; ruleId: string; reason: string }
  | { action: "downgrade"; ruleId: string; reason: string; updates?: Partial<NormalizedFinding> }
  | { action: "upgrade"; ruleId: string; reason: string; updates?: Partial<NormalizedFinding> }
  | { action: "rewrite"; ruleId: string; reason: string; replacement: Partial<NormalizedFinding> };
```

### Notes

- `suppress` removes the finding from final reporting, but it must remain visible in audit and benchmark traces.
- `downgrade` lowers severity, confidence, or certainty.
- `upgrade` raises severity, confidence, or certainty.
- `rewrite` changes the finding family or type when the LLM chose the wrong category.

## Normalized Finding Model

```ts
type NormalizedFinding = {
  id: string;
  family: string;
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  confidence: number;
  title: string;
  summary: string;
  reasoning: string;
  evidence: {
    snippet: string;
    sink?: string;
    sourceVariables?: string[];
    commandContext?: string;
  };
  provenance: {
    stage: "raw_llm" | "normalized" | "guardrailed" | "reported";
    model?: string;
  };
  appliedRules: AppliedRule[];
};
```

```ts
type AppliedRule = {
  ruleId: string;
  action: "suppress" | "downgrade" | "upgrade" | "rewrite";
  reason: string;
  before?: Partial<NormalizedFinding>;
  after?: Partial<NormalizedFinding>;
};
```

## Supporting Context Models

### Sink Metadata

```ts
type SinkMetadata = {
  sinkType:
    | "process_execution"
    | "sql_execution"
    | "file_write"
    | "http_response"
    | "authz_check"
    | "unknown";
  apiName?: string;
  shell?: boolean | null;
  commandSource?: "constant" | "user_controlled" | "mixed" | "unknown";
};
```

### Analysis Context

```ts
type AnalysisContext = {
  hasAuthContext?: boolean;
  hasPolicyCheck?: boolean;
  hasUserControlledInput?: boolean;
  hasSecurityRelevantSink?: boolean;
  notes?: string[];
};
```

## Rule Evaluation Model

Rules should be evaluated in deterministic order.

Recommended order:

1. category correction rules
2. sink validation rules
3. trust-state rules
4. confidence and severity tuning rules

If multiple rules apply:

- all applications must be recorded
- later rules operate on the updated finding state
- `suppress` is terminal unless benchmarking mode is configured to continue for trace purposes

## Guardrail Rule Pack v1

## Rule GR-001

### Suppress command injection on safe constant spawn

Intent:
Suppress false positives where process execution is safe and does not expose shell injection risk.

Match conditions:

- finding family or type indicates command injection or command execution injection
- sink is process execution
- API resembles `spawn(...)`
- `shell: false`
- command source is constant
- arguments may vary, but command itself is not user-controlled

Example:

```ts
spawn("git", ["status"], { shell: false });
```

Action:

- `suppress`

Reason:

- constant command with `shell: false` is not command injection by itself

Benchmark tie-ins:

- negative safe spawn cases
- constant command execution cases

## Rule GR-002

### Upgrade dangerous process execution on user-controlled command

Intent:
Catch cases where the model undercalls or misses dangerous process execution when the executable itself is user-controlled.

Match conditions:

- sink is process execution
- API resembles `spawn(...)`, `exec(...)`, `execFile(...)`, or equivalent
- command source is `user_controlled` or clearly derived from untrusted input
- finding is absent, weak, or categorized incorrectly

Example:

```ts
spawn(req.body.command, [], { shell: false });
```

Action:

- `upgrade` or `rewrite` to dangerous process execution or command injection class, depending on taxonomy

Reason:

- user-controlled executable path or command selection is dangerous even without shell interpolation

Benchmark tie-ins:

- positive user-controlled command cases
- process execution with tainted command source

## Rule GR-003

### Suppress security-shaped text false positives when no sink exists

Intent:
Prevent findings triggered by words like `token`, `auth`, `password`, or `security` when there is no security-relevant operation.

Match conditions:

- reasoning depends primarily on security-shaped terms
- code snippet contains no relevant sink
- no authz, credential handling, secret storage, cryptographic use, process sink, SQL sink, or file-sensitive sink exists

Example:

```ts
const message = "security token failed";
logger.info(message);
```

Action:

- `suppress`

Reason:

- lexical resemblance to security concepts is not evidence of a vulnerability

Benchmark tie-ins:

- comment, log, and message only examples
- terminology-only false positive cases

## Rule GR-004

### Suppress access-control findings on pure process-execution examples without auth context

Intent:
Prevent family drift where process-execution examples are incorrectly labeled as broken access control.

Match conditions:

- finding family is broken access control or authorization
- primary sink is process execution
- no auth context exists
- no route guard, role check, subject or resource decision, or policy enforcement code is present

Example:

```ts
spawn(userInput, [], { shell: false });
```

Action:

- `suppress` or `rewrite` depending on evidence

Preferred behavior:

- if dangerous execution evidence exists, `rewrite` to execution-related family
- otherwise `suppress`

Reason:

- process execution alone does not imply access control failure

Benchmark tie-ins:

- broken-access-control hallucination cases
- execution-only examples

## Rule GR-005

### Trust-state correction

Intent:
Use Owlvex local analysis to correct model overclaiming where variable trust was already resolved.

Match conditions:

- finding depends on taint or injection interpretation
- trust state is available from local analysis

Behavior:

- `SAFE` -> `suppress`
- `MIXED` -> `downgrade`
- `UNSAFE` -> no suppression and may support `upgrade`
- `UNKNOWN` -> no change

Reason:

- local deterministic trust analysis should override speculative model claims where applicable

Benchmark tie-ins:

- safe override cases
- mixed branch cases
- unsafe overwrite cases

## Reporting Requirements

Every final reported finding must carry:

- current stage
- original model family and type
- final family and type
- applied rules list
- final confidence
- final severity

Example:

```json
{
  "id": "finding-12",
  "family": "dangerous_process_execution",
  "type": "user_controlled_command",
  "severity": "high",
  "confidence": 0.94,
  "appliedRules": [
    {
      "ruleId": "GR-002",
      "action": "rewrite",
      "reason": "User-controlled command source in process sink."
    }
  ]
}
```

## Benchmark Integration

Guardrails must be benchmarked as a separate layer, not hidden inside model scoring.

Each benchmark run should capture at least:

- raw model result
- normalized result
- guardrailed result
- expected result
- rules applied
- pass or fail by dimension

Recommended benchmark dimensions:

- issue accuracy
- family accuracy
- false positives
- false negatives
- rewrite correctness
- suppression correctness

This should make it possible to answer:

- Did the model get worse?
- Did the guardrails compensate?
- Did a new rule reduce false positives but create false negatives?
- Which rule changed benchmark outcomes?

## Release Gate Tie-ins

Guardrails v1 should become part of release gating.

Suggested initial gates:

- zero critical false negatives in benchmark corpus
- no increase in known false positive classes without explicit approval
- no rule causes category drift outside expected benchmark outcomes
- all final findings include `appliedRules`

## Non-goals for v1

Guardrails v1 should not:

- perform deep dataflow analysis
- replace the normalization layer
- act as a generic policy engine
- infer broad business logic
- introduce probabilistic behavior

v1 is a targeted deterministic correction layer.

## Implementation Guidance

When engine work starts, keep these boundaries:

- normalization remains separate from guardrails
- guardrails operate on normalized findings, not raw text alone
- rules are modular and individually testable
- benchmark cases should map to specific rule IDs where possible

Recommended structure:

```text
guardrails/
  rules/
    GR-001-safe-constant-spawn.ts
    GR-002-user-controlled-command.ts
    GR-003-security-shaped-text.ts
    GR-004-access-control-mismatch.ts
    GR-005-trust-state-correction.ts
  engine.ts
  types.ts
  tests/
```

## Acceptance Criteria

Guardrails v1 is ready for implementation when:

- the normalized finding model is accepted
- sink metadata and trust-state inputs are defined clearly enough for deterministic rule evaluation
- every v1 rule has at least one benchmark tie-in
- reporting requirements for `appliedRules` are accepted
- release gating semantics are agreed for benchmarked guardrail behavior

## Bottom Line

This direction makes Owlvex more deterministic, explainable, benchmarkable, and safer to evolve.

The core idea is simple:

Owlvex should not ask the model to be right by itself. It should define exactly where the model is allowed to be trusted.
