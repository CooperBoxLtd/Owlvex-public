# Engine 1.0 Roadmap

Engine 1.0 moves Owlvex from broad model review toward evidence-first security analysis.

The core rule is simple: a finding should be trusted only when Owlvex can show the source, sink, propagation path, guard state, and classification basis. AI remains useful, but it should review evidence and explain remediation rather than act as the primary oracle.

## Problem To Solve

Recent provider comparison showed the current engine can produce unstable results:

- one provider can report a file as clean while another later finds issues
- an AI finding can identify a real pattern but assign the wrong class, such as calling uncontrolled object filtering SQL injection
- confidence percentages can look more precise than the evidence supports
- post-fix verification can prove the target finding is gone while residual risks remain

Engine 1.0 must make these cases explicit and testable.

## Reliability Principle

Trust order:

1. deterministic structural proof
2. source-to-sink evidence with recognized missing guard
3. AI-reviewed finding with concrete local evidence
4. multi-provider agreement
5. unverified AI candidate requiring manual review

A clean result from one model is provider/model-scoped evidence. It is not proof that no vulnerability exists.

## Static Evidence Contract

Every actionable finding should be represented by a structured evidence contract:

```json
{
  "source": "req.query.file",
  "flow": ["req.query.file", "filePath"],
  "sink": "fs.readFileSync(filePath)",
  "guard": "none",
  "classification": "path_traversal",
  "verdict": "supported",
  "confidence": "proven",
  "evidenceLines": [39, 40]
}
```

For clean or mitigated code, the contract should also be explicit:

```json
{
  "source": "req.query.file",
  "flow": ["req.query.file", "resolveExportPath", "resolved"],
  "sink": "fs.readFileSync(resolved)",
  "guard": "path.relative boundary check and .txt filename restriction",
  "classification": "path_traversal",
  "verdict": "guarded",
  "confidence": "not_applicable",
  "evidenceLines": [32, 41, 44, 79]
}
```

## Source/Sink/Guard Model

Engine 1.0 should maintain language and framework registries for:

- sources: request query/body/params, headers, cookies, route parameters, CLI args, environment values where relevant
- sinks: filesystem reads/writes, command execution, eval/deserialization, SQL/NoSQL queries, redirects, outbound network calls, template rendering, auth/session APIs
- guards: validation, allowlists, canonicalization, boundary checks, auth middleware, ownership checks, schema validators, parameterized APIs

The initial target should be JavaScript/TypeScript Express because it drives the current extension demo and user workflows.

## First JS/TS Families

Priority families:

- path traversal
- command execution
- SQL injection
- NoSQL/uncontrolled object filtering
- SSRF/open redirect
- missing authentication or authorization around sensitive sinks
- unsafe JWT/session validation
- synchronous request-path filesystem access as availability risk

Each family needs:

- sink definitions
- source definitions
- propagation rules
- guard definitions
- positive fixtures
- safe-negative fixtures
- taxonomy mapping rules

## Classification Rules

Classification should come from evidence, not model vocabulary.

Examples:

- client object controls filter keys over records -> uncontrolled filter or mass-assignment-style query structure
- SQL text concatenates user values -> SQL injection
- request path reaches filesystem sink without canonical boundary guard -> path traversal
- route serves sensitive files without auth middleware -> missing authentication/access control
- synchronous file read in request handler -> availability/DoS risk, not access control

If the model suggests a class that contradicts the evidence graph, Engine 1.0 should mark it as misclassified or require manual review.

## AI Role

AI should be constrained to three jobs:

1. adjudicate structured evidence when deterministic proof is incomplete
2. explain impact and remediation in human terms
3. help recognize framework-specific guards not yet in the registry

AI should not be allowed to create a high-confidence finding without returning the evidence contract.

## Provider Disagreement

The engine should persist provider/model scan snapshots per file and expose disagreement:

- provider A reported clean, provider B found issues
- providers found the same issue but used different taxonomy
- provider found an issue but adjudication rejected it

Disagreement should reduce confidence or require manual review. It should not be flattened into whichever answer arrived last.

## Engine Tests

Engine 1.0 requires tests in layers:

- golden corpus tests for known vulnerable and safe fixtures
- source/sink/guard contract tests
- taxonomy tests to prevent wrong labels such as SQL injection for non-SQL filters
- provider comparison tests for recall, precision, classification, remediation, and stability
- adjudication tests for provider disagreement
- metamorphic tests that rename variables or reformat code without changing the issue
- regression tests for bugs discovered during demos

Every unsafe fixture should have a safe companion.

## Release Gates

Before packaging or publishing:

- run deterministic and corpus regression tests
- run extension release regression tests
- verify prod/dev VSIX profile identities
- fail the release if a known unsafe fixture is missed or a known safe fixture is flagged

The current `npm run test:release` gate is the start. Engine 1.0 should add source/sink/guard corpus checks to that gate.

## Milestones

### Milestone 1: Evidence Schema

- define the evidence contract TypeScript types
- include source, sink, flow, guard, verdict, and evidence lines
- add report rendering for evidence contracts

### Milestone 2: JS/TS Extractor

- parse files with the TypeScript compiler API
- extract Express routes and route middleware
- detect request sources and common sinks
- track simple local variable propagation

### Milestone 3: Guard Registry

- recognize path canonicalization and boundary guards
- recognize common auth middleware
- recognize allowlisted query/filter construction
- recognize parameterized query APIs

### Milestone 4: Corpus Gate

- build vulnerable/safe fixture pairs for priority families
- assert expected finding family, evidence lines, and remediation class
- add false-positive safe-negative assertions

### Milestone 5: AI Adjudication

- feed structured evidence to AI, not whole-file open-ended prompts
- require JSON evidence/verdict responses
- mark disagreement and misclassification explicitly

### Milestone 6: Engine 1.0 Release Bar

- no high-confidence AI finding without evidence contract
- no clean claim without provider/model scope
- no release if golden corpus recall/precision falls below agreed thresholds
- reports explain evidence confidence qualitatively, with raw model scores only as audit trace

## Bottom Line

Engine 1.0 should make Owlvex evidence-led.

The engine should prove what it can, clearly scope what it cannot prove, and use AI to review and explain structured evidence instead of asking a model to guess the security posture of a file.

