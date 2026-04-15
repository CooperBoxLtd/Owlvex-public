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

The contract for this lane is:

- unsafe fixtures should be expected to produce `provenance: 'ai'`
- safe fixtures should bias toward no findings or low-severity advisory output
- confidence must remain explicit
- these cases must never be counted as deterministic benchmark coverage
