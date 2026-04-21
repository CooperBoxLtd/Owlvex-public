# Owlvex AI Eval Lane

This directory tracks **AI-only coverage cases** that are intentionally outside the deterministic benchmark gate.

Use this lane for issue classes that:

- Owlvex can discuss or detect through the AI path today
- are not yet expressible as trustworthy structural invariants
- should not be marketed as deterministic coverage

This is **not** a release-certification gate like `benchmark:deterministic`.
It is a visibility and regression lane for model-assisted behavior.

Current starter cases:

- `tools/demo/16-open-redirect-unsafe.js`
- `tools/demo/17-open-redirect-safe.js`
- `tools/demo/18-csrf-unsafe.js`
- `tools/demo/19-csrf-safe.js`
- `tools/demo/20-cors-unsafe.js`
- `tools/demo/21-cors-safe.js`
- `tools/demo/22-ssrf-unsafe.js`
- `tools/demo/23-ssrf-safe.js`
- `tools/demo/24-jwt-validation-unsafe.js`
- `tools/demo/25-jwt-validation-safe.js`

The contract for this lane is:

- unsafe fixtures should be expected to produce `provenance: 'ai'`
- safe fixtures should bias toward no findings or low-severity advisory output
- confidence must remain explicit
- wording guardrails can be checked for sensitive classes like CORS
- framework scope can be asserted when a report is generated under a known framework selection
- these cases must never be counted as deterministic benchmark coverage

`tools/demo/26-deserialization-unsafe.py` and `tools/demo/27-deserialization-safe.py` were removed from this lane after insecure deserialization was promoted into deterministic coverage.

Manifest cases can also assert:

- `frameworks_in_scope`
- `must_include_text`
- `must_not_include_text`

Run the lane against a generated Owlvex markdown report from `extension/`:

```bash
npm run benchmark:ai-evals -- ../tools/demo/owlvex-scan-report-YYYYMMDD-HHMMSS.md model-tag
```

Artifacts are written to:

- `tools/owlvex-benchmark/runs/ai-evals/latest.json`
- `tools/owlvex-benchmark/runs/ai-evals/latest.results.json`

Summarize the latest AI eval run:

```bash
npm run benchmark:ai-status
```
