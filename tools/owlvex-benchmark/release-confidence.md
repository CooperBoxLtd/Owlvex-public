# Release Confidence Guide

This document explains how to interpret benchmark artifacts as release evidence for Owlvex.

It focuses on the deterministic execution-risk axis first, because that is the most complete subsystem in the benchmark tool today.

## Purpose

Release confidence is not the same as "all tests passed".

A passing deterministic gate means the current implementation still satisfies the benchmarked contract.
Release confidence asks a second question:

`How much of the behavior we care about is covered by that gate?`

## Current Sources Of Confidence

For the execution-risk axis, confidence currently comes from:

- per-layer deterministic suites
- cross-layer integration suite
- aggregate deterministic gate
- persistent run history under `tools/owlvex-benchmark/runs/deterministic/`

## Primary Artifact

Use this file as the default release indicator:

- `tools/owlvex-benchmark/runs/deterministic/latest.json`

This is the compact summary.

It answers:

- did the deterministic gate pass
- how many suites passed
- how many benchmark cases passed
- which suite failed, if any

Use this file for:

- quick release checks
- CI summaries
- commit-to-commit comparison

## Debug Artifact

Use this file when a release check fails or when deeper inspection is needed:

- `tools/owlvex-benchmark/runs/deterministic/latest.full.json`

This file includes:

- per-suite detailed summaries
- per-case detail where available
- normalized findings for schema-enabled runners

## Interpreting The Compact Summary

Example fields in `latest.json`:

- `passed`
- `totalSuites`
- `passedSuites`
- `totalCases`
- `passedCases`
- `failedSuite`

Recommended interpretation:

- `passed: true` means the deterministic execution-risk gate is green
- `passedSuites === totalSuites` means no deterministic layer or integration suite regressed
- `passedCases === totalCases` means no covered case regressed
- `failedSuite !== null` means the implementation is not release-ready for the benchmarked contract

## Current Confidence Level

Current confidence for the execution-risk axis should be treated as:

- `High` for the covered execution-risk contract
- `Not yet sufficient` for the overall product

Why:

- the axis is layered and benchmark-backed
- integration coverage exists
- persistent run history now exists
- but only one reasoning axis is complete
- and overall product coverage still extends beyond execution risk

## Suggested Release Language

When `latest.json` is fully green, the appropriate claim is:

`The deterministic execution-risk benchmark is passing for all covered suites and cases.`

Avoid claiming:

- full product security coverage
- complete scanner correctness
- release certification across non-benchmarked axes

## When Confidence Should Increase

Confidence should be increased only when one or more of these happen:

- more benchmark cases are added without weakening invariants
- more reasoning axes reach the same level of deterministic maturity
- run history shows stability over time
- deterministic outputs and report outputs fully align

## When Confidence Should Decrease

Confidence should be reduced when:

- benchmark semantics change without corresponding corpus updates
- passing suites drop in count
- total covered cases shrink
- invariants in `execution-risk-axis.md` are violated
- new unbenchmarked logic is introduced into a deterministic layer

## Practical Release Rule

For the current execution-risk axis, treat release confidence as acceptable only when:

- `npm run benchmark:deterministic` passes
- `latest.json` shows all suites passing
- `latest.json` shows all cases passing
- no unreviewed changes violate the execution-risk contract

You can operationalize this check with:

```bash
npm run benchmark:status
```

## Bottom Line

The benchmark is now strong enough to support disciplined release decisions for the covered execution-risk axis.

It is not yet the final confidence story for all of Owlvex, but it is already a real and usable one.
