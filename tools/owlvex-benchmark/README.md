# Owlvex Benchmark Tool

Dedicated home for deterministic engine evaluation inside the CodeScanner repo.

For benchmark governance, methodology, client explanation, and external benchmark planning, see the Benchmarking Department:

- [docs/benchmarking/README.md](D:/Dev/repos/CodeScanner/docs/benchmarking/README.md)

For the broader build contract this benchmark supports, see:

- [IMPLEMENTATION_DESIGN.md](D:/Dev/repos/CodeScanner/docs/IMPLEMENTATION_DESIGN.md)
- [IMPLEMENTATION_BACKLOG.md](D:/Dev/repos/CodeScanner/docs/IMPLEMENTATION_BACKLOG.md)

The benchmark tool answers one question:

> **Is this axis's structural reasoning correct across all covered cases?**

It is not the whole benchmarking department. It is the deterministic correctness gate inside that larger benchmark system.

For model-assisted issue classes that are **not** part of the deterministic release gate yet, see:

- `tools/owlvex-benchmark/ai-evals/`

The repo also now includes curated framework and cheat-sheet packs under `docs/data/` so the AI lane can evolve toward more explicit grounding rather than relying only on model familiarity with OWASP/CWE/NIST terminology.
The AI eval runner can also verify framework-scope expectations and wording guardrails from generated reports, not just whether a finding showed up.
Current AI-only examples include open redirect, CSRF, permissive CORS, SSRF, weak JWT validation, and insecure deserialization fixtures under `tools/demo/`.

---

## Layout

```
tools/owlvex-benchmark/
├── engine/                     Deterministic evaluators (one per suite)
│   ├── gr001/–gr005/           Execution-risk axis layers
│   ├── ac001/–ac005/           Access-control axis layers
│   ├── access-control-integration/
│   ├── sm002/                  Conditional rule: debug mode
│   └── sq001/–sq005/           SQL query axis layers
├── corpus/                     Fixture files (.js + .expected.json pairs)
│   ├── access_control_*/       AC axis corpus (subject, resource, policy, context, integration)
│   ├── debug_mode/             SM-002 conditional rule corpus
│   ├── injection_execution/    GR axis corpus
│   ├── sql_query/              SQ axis corpus
│   └── ...
├── runs/deterministic/         Gate run artifacts (latest.json, timestamped)
├── benchmark-status.mjs        Per-axis confidence report
├── run-deterministic.mjs       Aggregate gate (19 suites)
├── product-map.md              Authoritative product state and milestone tracking
├── access-control-axis.md      AC axis contract (invariants, layer ownership)
└── README.md                   This file
```

---

## Architecture

Three deterministic reasoning axes, each following the same 5-layer pipeline:

| Layer | GR (execution-risk) | SQ (SQL) | AC (access-control) |
| --- | --- | --- | --- |
| 1 Trust/Subject | GR-002 | SQ-002 | AC-002 |
| 2 Transform/Resource | GR-003 | SQ-003/SQ-004 | AC-004 |
| 3 Policy/Sink | GR-004 | SQ-004 | AC-003 |
| 4 Context Validation | GR-005 | SQ-005 | AC-005 |
| 5 Final Decision | GR-001 | SQ-001 | AC-001 |

Plus a **Conditional Rules layer** for context-sensitive invariants:

| Suite | Rule | Gate condition |
| --- | --- | --- |
| sm002 | SM-002: debug mode without production guard | env signals in source |

The live extension scanner currently implements additional conditional rules as well:

- `AC-T001` multi-tenant isolation failure
- `DP-001` PII in logger
- `SM-001` insecure cookie
- `SM-002` debug mode without production guard

Benchmark coverage for the conditional-rules group is currently partial, with `sm002` already gated and the others still to be lifted into the benchmark tool.

AI-only coverage examples are tracked separately and are intentionally **not** counted toward the deterministic suite totals.

---

## Running the gate

**Full gate (19 suites):**
```bash
npm run benchmark:deterministic    # from extension/
```

**Per-axis confidence report:**
```bash
npm run benchmark:status
```

**AI eval lane against a generated markdown report:**
```bash
npm run benchmark:ai-evals -- ../tools/demo/owlvex-scan-report-YYYYMMDD-HHMMSS.md model-tag
```

**AI eval status summary:**
```bash
npm run benchmark:ai-status
```

**Individual suites:**
```bash
npm run benchmark:gr001            # execution-risk final decision
npm run benchmark:sq001            # SQL injection final decision
npm run benchmark:ac001            # access-control IDOR final decision
npm run benchmark:ac-integration   # AC end-to-end
npm run benchmark:sm002            # debug mode conditional rule
```

All `benchmark:*` scripts are defined in `extension/package.json`.

---

## Corpus structure

Each corpus case is a `.js` fixture paired with a `.expected.json` file:

```
corpus/access_control_integration/
├── idor_direct_positive.js
├── idor_direct_positive.expected.json
├── owned_resource_safe_negative.js
├── owned_resource_safe_negative.expected.json
└── ...
```

The expected JSON declares what the evaluator should return (`finding`, `resourceShape`, `policyCheck`, etc.). The runner compares actual vs. expected field by field.

---

## Gate status

Verified via `npm run benchmark:status`:

- `19` suites passing
- `82` cases passing

Breakdown:

| Group | Suites | Cases |
| --- | --- | --- |
| execution-risk | gr002, gr003, gr004, gr005, gr001, integration | 35 |
| sql-query | sq002, sq003, sq004, sq005, sq001, sql-integration | 22 |
| access-control | ac002, ac004, ac003, ac005, ac001, ac-integration | 21 |
| conditional-rules | sm002 | 4 |

---

## Release confidence

`benchmark:status` writes JSON artifacts to `runs/deterministic/`. When all suites in an axis pass, the axis is `high-for-covered-axis`. This is the gate for releasing deterministic findings in that category.

For authoritative product state and milestone tracking, see `product-map.md`.
