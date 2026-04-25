# Engine Evidence Proof Layer

Engine 1.0 should not promote a finding just because a model can name a framework category. A promoted finding needs a reviewable proof chain.

## Goal

Move from detection to evidence:

- attacker action
- source
- sink
- missing guard
- counter-evidence checked
- responsibility layer
- proof status

The first implementation is static proof. Runtime harnesses and sandboxes can come later.

## Proof Status

| Status | Meaning | Promotion |
| --- | --- | --- |
| `static_proven` | Deterministic or explicitly checked source/sink/guard proof | Can enter Fix First |
| `ai_plausible` | AI supplied a source/sink/guard contract, but no deterministic proof exists | Can enter Fix First when it matches benchmark/project context |
| `counter_evidence_found` | A guard or responsibility boundary defeats the exploit hypothesis | Do not promote |
| `unproven_extra` | Vague, helper-layer, or provider-disputed extra finding | Manual-review extra only |

## Responsibility Layers

Findings should be judged against the layer that owns the security decision:

- `route-policy`: route handler or policy function owns authorization/input guard
- `auth-middleware`: establishes identity, not object-level authorization
- `repository`: persistence helper, not route authorization unless explicitly in scope
- `audit`: writes audit events, not business authorization
- `parser`: parses data and owns safe parsing/validation
- `unknown`: insufficient context

## Promotion Rule

`Fix First` should prefer findings with proof:

1. deterministic/static proof
2. benchmark-expected finding with a complete source/sink/missing-guard contract
3. provider-agreed finding with a complete contract
4. otherwise manual-review extra

Known helper-layer false-positive patterns, such as auth middleware identity setup, audit helper internals, and repository storage helpers, should be downgraded unless an expectation manifest explicitly marks that layer in scope.

## Benchmark-App First Slice

For `tools/benchmark-app`, the intended promoted findings are the unsafe route workflows:

- document IDOR
- refund authorization
- role assignment privilege escalation
- SSRF
- path traversal
- missing CSRF
- eval/code execution
- weak JWT validation

Unexpected AI-only findings in `middleware/auth.js`, `lib/auditLogger.js`, or `store/repositories.js` should not outrank those workflows.
