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
- deterministic-only final outcomes must not be described as if degraded AI findings were part of the kept file result

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

During stabilization, Owlvex should prefer simple-access corroboration over heavy validation infrastructure. The chosen direction is single-model, multi-pass verification rather than mandatory active testing, multi-agent infrastructure, or external enterprise engines.

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

Within that set, the next engine-building priority is deterministic depth on the highest-leverage structural families:

- SSRF
- path traversal
- command injection
- SQL injection
- IDOR and tenant scoping

The purpose of the next phase is not to add many new families. It is to deepen proof quality on those families until more of Owlvex's important findings can honestly move into the `STATIC` lane.

After that first bounded deterministic tranche, the next stabilization priorities are:

- product hardening on the live scan / explain / fix loop
- bounded language expansion using the same proof discipline
- platform security and customer trust-boundary hardening

The next language wave should not be judged by raw language count alone.
It should be judged by whether the trusted issue families can be ported into the next language without breaking the benchmark-backed proof story.

---

## Out Of Scope

Until this contract is met, Owlvex should not prioritize:

- adding many new issue families
- broad UI feature expansion
- making AI findings sound more authoritative without stronger validation
- claiming repo-context maturity beyond what the benchmarks prove

Model upgrades are allowed, but they are not the primary plan. A stronger model may improve precision, but model quality is an amplifier, not a replacement for scanner design discipline.

That means the preferred next investment after demo-readiness work is:

- strengthen deterministic proof contracts
- expand benchmark-backed safe and unsafe coverage for the target families
- add false-positive guards before promoting new deterministic behavior

The engine should grow by deepening the trusted issue families first, not by broadening the catalog faster than the benchmarks can support.

Likewise, the product should not widen language claims faster than the rule contracts and benchmarks can support.

The recommended next deterministic language order is:

1. deeper Python coverage
2. Java
3. C#
4. Go

Those languages should be expanded only through bounded rule contracts on the existing trusted family set, not through broad unsupported language marketing.

When model comparisons are run, they must use the evaluation method defined in [MODEL_SELECTION_MATRIX.md](D:/Dev/repos/CodeScanner/docs/MODEL_SELECTION_MATRIX.md).

---

## Benchmark Sources Of Truth

The stabilization phase is driven by two benchmark layers:

1. `tools/demo/`
   Single-file fixture corpus with explicit safe and unsafe pairs.

2. `tools/benchmark-app/`
   Realistic repo-context benchmark app with policies, middleware, safe companions, and route-level workflows.

Every stabilization change must preserve or improve outcomes against those assets.

The repo-context benchmark layer is `tools/benchmark-app/`. It replaces the older demo app as the realistic application benchmark:

- `tools/demo/` remains the isolated fixture suite
- `tools/benchmark-app/` is the realistic app for context-sensitive authorization, workflow, helper, and safe-companion reasoning

The working benchmark command for this phase is:

```bash
cd extension
npm run benchmark:refresh-and-evaluate
```

That command must remain able to:

- generate fresh reports from the current scanner
- evaluate those reports against the machine-readable benchmark manifests
- fail when the current scanner behavior drifts away from the expectation files

External SAST stability is a planned companion gate for `tools/benchmark-app`, starting with CodeQL:

- reset `tools/benchmark-app` to the unsafe baseline before the SAST run
- run CodeQL or an equivalent SAST scanner against the benchmark app
- store the SAST summary beside Owlvex stabilization artifacts
- investigate mismatches before changing benchmark expectations
- treat unexpected SAST drift as benchmark instability unless `EXPECTATIONS.md` is deliberately updated

The external SAST result is a benchmark stability guard, not the product oracle. Owlvex expectations still come from the documented benchmark contract, but CodeQL helps detect accidental benchmark edits and obvious false-positive or false-negative drift.

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
8. Deterministic benchmark files must not leak irrelevant AI corroboration warnings into file-level reporting.

---

## AI Verification Direction

Owlvex adopts single-model, confidence-routed corroboration as the primary AI verification strategy for the stabilization phase.

This means:

- one selected model or agent may be reused across multiple sequential reasoning passes
- the passes must use distinct roles and instructions
- the product must reconcile agreement and disagreement explicitly rather than pretending consensus
- verifier and skeptic passes are triggered only when they can materially change the decision

The role set is:

1. `Finder`
   Propose candidate issues from the code.

2. `Verifier`
   Confirm a candidate only when local code evidence supports the claim.

3. `Skeptic`
   Attempt to disprove the candidate using contradictory local evidence, guards, safe patterns, or missing required sinks.

These roles may be implemented using the same underlying model in separate passes. Owlvex must not require customers to provision multiple models, multiple agents, or specialized infrastructure just to benefit from corroboration.

The implementation target is:

- one selected provider/model
- one agent identity
- one finder pass for AI-backed candidates
- verifier and skeptic passes only when confidence routing requires them
- one Owlvex-controlled adjudication step

When verifier or skeptic runs, the passes must remain behaviorally distinct in implementation, not just named differently in the UI.

Minimum pass contracts:

- `Finder`
  - proposes bounded candidates from visible code
  - optimizes for recall, not final truth
  - must stay tied to concrete local signals
- `Verifier`
  - confirms only when local evidence supports the claim
  - must not invent new findings
  - should prefer rejection over guesswork
- `Skeptic`
  - attempts falsification through guards, safe patterns, missing sinks, or contradictory evidence
  - should suppress or reduce confidence when stronger contradiction exists

If those role boundaries drift, the confidence story of the AI lane also drifts.

Owlvex may evolve beyond that later, but stabilization work should assume the simple default unless there is a benchmark-backed reason to add more complexity.

### Static Ownership Rule

Deterministic findings own the exact code span, sink, and issue family they prove.

That does not mean a file with deterministic findings should skip AI review entirely.

The required behavior is:

- run deterministic scanning first
- build an exclusion map from deterministic findings:
  - line range
  - canonical issue id
  - issue family
  - matched sink/source where available
- do not ask AI to re-prove or re-verify the same proven finding
- suppress AI candidates that overlap the deterministic span and family
- still allow AI to review the rest of the file for other issue families and other spans

Examples:

- if static `SQ-001` proves SQL injection at line 25, AI should not emit or corroborate another SQL injection finding for line 25
- AI may still report missing authorization, sensitive logging, weak JWT validation, or another non-overlapping issue in the same file

This preserves the product rule:

> Static proof is final for what it covers. AI explores what static proof does not cover.

### Confidence-Routed Pass Triggering

Verifier and skeptic are not default third and second opinions for every candidate.

The intended route is:

1. Finder proposes bounded candidates and gives confidence in candidate existence.
2. High-confidence finder candidates may be kept without verifier or skeptic unless policy requires extra review.
3. Low or medium finder confidence triggers verifier when the candidate is important enough to consider.
4. Very low verifier confidence drops or demotes the candidate; skeptic should not normally run.
5. Very high verifier support keeps or upgrades the candidate; skeptic should not normally run unless severity or policy requires it.
6. Skeptic runs as an arbiter when finder and verifier disagree, both are borderline, or the finding is high-impact and context-sensitive.

Initial threshold guidance:

- finder confidence `>= 0.90`: keep as AI-supported unless static duplicate, critical policy, or known false-positive family requires verifier
- finder confidence `0.70-0.89`: run verifier
- finder confidence `< 0.70`: drop unless severity, issue family, or local signals justify verifier
- verifier `support >= 0.90`: keep as corroborated
- verifier `support 0.60-0.89`: run skeptic when impact is high/critical, confidence spread is large, or family is false-positive prone
- verifier `reject >= 0.80`: drop
- verifier `unclear` or low confidence: demote to partial/manual review or run skeptic only if the candidate is high-impact and enough evidence exists

Skeptic should run when:

- finder high but verifier low
- finder low but verifier high
- verifier is borderline
- finder/verifier confidence spread is at least `0.10`
- issue is high-impact and context-sensitive
- the finding would trigger fix generation or a strong report claim

Skeptic should be skipped when:

- verifier strongly rejects the candidate
- verifier says the claim cannot be confirmed from visible evidence
- finder and verifier are both high confidence, cite the same local evidence, and the issue is not critical
- provider rate-limit pressure is active
- candidate is medium/low risk and not fix-triggering

Thresholds are starting defaults, not permanent truth. They must be tuned from recorded pass outcomes and benchmark data.

### Role-Specific Confidence Semantics

Confidence is not global. It is confidence in a role-specific verdict.

Finder confidence means:

> How confident is the finder that this candidate vulnerability exists?

Verifier confidence means:

> How confident is the verifier in its verdict?

The verifier verdict is required:

- `support` with high confidence means the verifier strongly believes local evidence supports the finding
- `reject` with high confidence means the verifier strongly believes local evidence does not support the finding
- `unclear` means the verifier cannot resolve the candidate from available evidence

Skeptic confidence means:

> How confident is the skeptic in its challenge verdict?

The skeptic verdict is required:

- `clear` with high confidence means the skeptic tried to disprove the finding and found no meaningful contradiction
- `contradict` with high confidence means the skeptic found contradictory evidence or a safe pattern strong enough to reject or downgrade the finding
- `unclear` means the skeptic cannot resolve the dispute

Reports and UI must not display ambiguous naked values such as `skeptic 95%` without the verdict. They should show `Skeptic: clear, 95%` or `Skeptic: contradicted, 95%`.

Current report wording requirements:

- report tables must show both AI signal band and final raw confidence, for example `AI signal High (96% final)`
- report tables must show the review route, for example `review path finder` or `review path finder+verifier+skeptic`
- finder-only findings must read as `Finder-only AI review` or `Finder high confidence, not independently verified`
- `Validated by AI review` must be reserved for findings with verifier or skeptic support
- `cross-checked` summary posture must not be used for finder-only findings
- high AI confidence must be described as model confidence, not proof

### Required Pass Outcome Data

Reports currently show only surviving findings. That is not enough to measure whether verifier and skeptic are saving cost or improving quality.

Owlvex should record a local or metadata-safe pass outcome event for AI candidates:

```json
{
  "candidate_id": "stable candidate id",
  "file_hash": "sha256",
  "issue_id": "owlvex.issue.example",
  "span": { "line": 12, "line_end": 18 },
  "finder": { "verdict": "candidate", "confidence": 0.78 },
  "verifier": { "verdict": "support|reject|unclear|skipped", "confidence": 0.82 },
  "skeptic": { "verdict": "clear|contradict|unclear|skipped", "confidence": 0.80 },
  "decision": "kept|dropped|partial|static_duplicate",
  "decision_reason": "short reason",
  "route": "finder|finder_verifier|finder_verifier_skeptic",
  "source": "TARGETED_AI|REPO_AI"
}
```

This record must not include raw source code. It may include hashes, issue identifiers, spans, verdicts, confidences, and bounded decision reasons.

---

## Adjudication Rule

When multi-pass AI reasoning is introduced, Owlvex must resolve results using explicit merge rules.

The intended confidence behavior is:

- deterministic proof -> `PROVEN`
- finder-only high confidence -> `UNVERIFIED` or `AI-supported`, not `CORROBORATED`
- finder plus verifier support with no meaningful contradiction -> `CORROBORATED`
- verifier reject -> suppress the claim unless routed to skeptic by high-impact policy
- one pass supports and another disputes -> confidence must be reduced or the claim suppressed
- skeptic `clear` -> the candidate survives challenge
- skeptic `contradict` -> suppress or downgrade the claim
- if AI review runs but no AI finding survives into the final file result, the file should still read as `Static proof` and may explicitly say AI review was not used for the final finding set

Owlvex may expose the multi-pass reasoning trail for AI-backed findings in reports, but that trail must remain AI-only.

- deterministic findings should continue to explain themselves through rule proof and code evidence
- AI findings may show pass scores and the reasoning trail that kept the finding alive
- degraded or incomplete passes -> downgrade confidence and state that coverage is partial

Disagreement is product signal. It must not be hidden behind one flattened answer.

Owlvex should translate agreement and disagreement into report posture rather than fake certainty.

### Safe Probe Rule

For probeable AI-only findings, sink-first verification should be preferred over another free-form model opinion.

Owlvex may use safe exploit probes when a finding has a concrete source, sink, and guard hypothesis. A safe probe replaces the dangerous sink with a recorder, sends canary input through the local path, and records whether the canary reached the sink or was blocked by a guard.

Safe probes must not:

- execute shell commands
- make network calls
- read or write real project files
- connect to real databases
- mutate user data

Probe verdicts should feed the same adjudication posture:

- `confirmed` -> stronger local evidence
- `counter_evidence` -> suppress or downgrade
- `unsupported` -> drop
- `inconclusive` -> manual review

Reports must label probe evidence as simulated and intercepted, not as live exploit execution.

The probe contract recognizes these safe detonation techniques:

- sink interception
- canary propagation
- guard verification
- counterexample probes
- static execution slices
- taint trace probes
- mutation probes
- differential probes
- fix verification probes
- multi-file context probes

The first runtime implementation may use static/intercepted evidence for some techniques. That is acceptable as long as reports do not imply live exploit execution.

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
- make provider throttling and budget-driven corroboration truncation distinguishable in user-facing warnings and reports
- expose enough scan-level AI usage data to explain why a scan was expensive or slow

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

1. The trusted issue set behaves consistently across `tools/demo/` and `tools/benchmark-app/`.
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
