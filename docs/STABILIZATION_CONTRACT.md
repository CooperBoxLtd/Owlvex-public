# Owlvex Stabilization Contract

## Purpose

This document defines the next product phase for Owlvex.

The goal of this phase is not broad feature expansion. The goal is to make a smaller, clearer scanner trustworthy enough that future improvements build on stable ground instead of creating more ambiguity.

Owlvex is currently in a stage where:

- deterministic findings are useful but limited in coverage
- AI findings add reach but still produce drift, duplication, and misclassification
- repo-context reasoning helps in some cases but is not yet reliable enough
- provider rate limits can degrade scans in ways that make results harder to trust

This contract exists to stop reactive bug chasing and replace it with benchmark-driven stabilization work.

---

## Core Principle

Owlvex must prefer honest uncertainty over misleading certainty.

During stabilization:

- proven findings must remain narrow and trustworthy
- AI findings must be clearly constrained and normalized
- partial or degraded scans must say so explicitly
- no new issue family should be added unless it has benchmark coverage and a clear trust story

---

## Product Posture

During this phase, Owlvex should behave like a developer-native security scanner with explicit confidence boundaries.

It must not present every AI hypothesis as if it were a proven SAST result.

The scanner should distinguish between:

1. `Proven`
   Deterministic, structurally verified, or otherwise strongly corroborated findings.

2. `Plausible`
   AI-supported findings that match code evidence and survive normalization, but still benefit from review.

3. `Speculative`
   Weak or context-incomplete hypotheses that should not be shown as normal findings in the main result set.

If a finding cannot survive that framing, it should be suppressed or demoted.

---

## Stabilization Scope

This phase is limited to a small trusted issue set.

The first stabilization set is:

- IDOR and tenant scoping
- SQL injection
- SSRF
- sensitive logging
- weak JWT validation
- debug and production misconfiguration
- insecure deserialization

These families were selected because they already exist in the fixture corpus, have safe and unsafe companions, and have repeatedly exposed trust gaps in the scanner.

---

## Out Of Scope

Until this contract is met, Owlvex should not prioritize:

- adding many new issue families
- broad UI feature expansion
- making AI findings sound more authoritative without stronger validation
- claiming repo-context maturity beyond what the benchmarks prove

Model upgrades are allowed, but they are not the primary plan. A stronger model may improve precision, but model quality is an amplifier, not a replacement for scanner design discipline.

---

## Benchmark Sources Of Truth

The stabilization phase is driven by two benchmark layers:

1. `tools/demo/`
   Single-file fixture corpus with explicit safe and unsafe pairs.

2. `tools/demo-app/`
   Small intentionally vulnerable repo-context app with helpers, middleware, safe companions, and route-level context.

Every stabilization change must preserve or improve outcomes against those assets.

Known failure modes already observed in these benchmarks must stay covered by regression tests, including:

- false positive on safe deserialization
- false positive on guarded debug mode
- stale chat context leaking into fresh chat
- duplicate findings for one sink
- helper-context blindness in safe repo patterns
- deterministic false positive on redacted logs
- degraded scan behavior under repeated `429` rate limits

---

## Required Engineering Rules

During stabilization:

1. No scanner behavior change ships without tests.
2. Safe companion fixtures must remain clean.
3. Unsafe companion fixtures must remain detected.
4. Duplicate findings for the same sink must be normalized or deduplicated.
5. AI-only findings must be suppressible when local code evidence contradicts them.
6. Partial AI coverage caused by provider failure must be visible to the user.
7. Regressions found in the demo corpus or demo app must become permanent test cases.

---

## Anti-Overfitting Rule

Owlvex must not be tuned to "make the demo app pass" by introducing app-shaped exceptions.

Any suppression, normalization rule, or confidence downgrade added during stabilization must satisfy all of the following:

1. It encodes a general code-semantic truth, not a filename, route name, demo string, or fixture-specific convention.
2. It reduces a class of false positives rather than muting one example.
3. It preserves a real-positive counterexample in a nearby or equivalent pattern.
4. It can be explained as "this issue class requires this code behavior" rather than "this benchmark expected no finding here."

The following kinds of logic are not acceptable:

- checks based on repo paths, filenames, or demo-only identifiers
- suppressions that rely on one specific route name or sample host name
- logic whose only justification is making a benchmark fixture go green

The following kinds of logic are acceptable:

- proving that a required dangerous primitive is absent
- proving that a cited sink is not actually present in the local code window
- proving that a guard or constraint required by the issue class is already in place
- deduplicating overlapping findings that describe the same canonical issue and code region

Every new suppression rule must be reviewed explicitly as one of:

- `generalizable`
- `borderline`
- `too app-specific`

Only `generalizable` rules should be considered stable. `Borderline` rules must be revisited and either generalized further or removed. `Too app-specific` rules must not ship.

---

## Rate Limit Policy

Provider rate limits are treated as a product reliability problem, not merely an infrastructure annoyance.

Owlvex must:

- retry transient provider rate limits with bounded backoff
- slow down repo scans after repeated `429` warnings
- respect provider `retry-after` signals when available
- degrade honestly when AI coverage is partial
- prefer deterministic-only results over pretending a degraded AI scan is complete

Future work in this area may include a repo-scan AI budget mode that intentionally switches later files to deterministic-only after repeated throttling.

---

## Model Upgrade Policy

Stronger models may be evaluated during stabilization, but only under controlled comparison.

A model upgrade must be judged against the same benchmark inputs using the same comparison bar:

- false positives
- false negatives
- duplicate findings
- issue classification quality
- repo-context suppression behavior
- degraded behavior under throttling

No model change should be treated as a release justification by itself.

---

## Exit Criteria

The stabilization phase is complete only when all of the following are true:

1. The trusted issue set behaves consistently across `tools/demo/` and `tools/demo-app/`.
2. Safe companion files and routes stay clean in automated tests.
3. Known historical false positives are locked behind regression coverage.
4. Duplicate and misclassified AI findings are materially reduced in benchmark output.
5. Degraded AI coverage is clearly communicated and no longer masquerades as a normal full-confidence scan.
6. A stronger model, if adopted, demonstrates measured benchmark improvement rather than anecdotal improvement.

---

## Working Agreement

For the next phase of Owlvex development:

- benchmark-first work takes priority over expansion
- reliability beats breadth
- explicit confidence beats implied certainty
- each painful bug should become a permanent guardrail

This contract is the source of truth for deciding whether a scanner change is progress or just more motion.
