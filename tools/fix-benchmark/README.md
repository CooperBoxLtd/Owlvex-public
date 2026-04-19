# Owlvex Fix Benchmark

This directory is the starter home for Owlvex remediation benchmarking.

It exists to answer a different question from detection benchmarks:

- detection benchmark: did Owlvex understand the problem?
- fix benchmark: did Owlvex remove the problem safely and cleanly?

## Current Shape

The first fix benchmark lane is intentionally property-based.

It does **not** require one exact golden patch.
It checks whether a fix attempt:

- generated a reviewable preview
- stayed within the expected file scope
- applied cleanly
- preserved syntax / basic validity
- removed the target finding
- avoided introducing new high-risk findings

## Files

- `fix-benchmark.expectations.json`
  - reviewed benchmark contract for each starter case
- `fix-benchmark.results.template.json`
  - template for recording a fix run

## How To Use

1. Generate a fix preview in Owlvex for one of the benchmark files.
2. Record the outcome in a results JSON file using the template format.
3. Evaluate it with:

```bash
node tools/evaluate-fix-benchmark.mjs path/to/results.json
```

Or from `extension/`:

```bash
npm run benchmark:fix-demo -- ..\\tools\\fix-benchmark\\fix-benchmark.results.template.json
```

## Working Rule

Fix benchmarking is separate from detection benchmarking.

Owlvex should never imply:

- "the scan was right, therefore the fix was good"

Those are different quality bars and must be scored separately.
