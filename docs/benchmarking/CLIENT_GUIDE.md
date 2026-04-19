# Client Benchmark Guide

## Why Owlvex Uses Multiple Benchmark Layers

Owlvex does not use one giant benchmark number for everything.

That is deliberate.

The product has different trust lanes:

- `STATIC`
- `TARGETED_AI`
- `REPO_AI`

## What Each Lane Is Best At

### STATIC

Best for:

- explicit structural issues
- bounded source-to-sink proof

### TARGETED_AI

Best for:

- semantic but local code judgments

### REPO_AI

Best for:

- multi-file reasoning
- workflow and business-logic understanding

## What The AI Benchmark Measures

The Owlvex AI benchmark measures:

- unsafe-case recall
- safe-case quietness
- issue-family match
- explanation fidelity
- recommended-lane fit

## What The Score Does Not Mean

An AI benchmark score does not mean:

- the AI is always correct
- every finding is proof
- every scenario is covered equally
