# AI Benchmarking Notes

This note defines how to use the exploratory AI fixtures in `tools/demo/` as a repeatable evaluation set for Owlvex's AI lane.

## Purpose

Use these files to measure:

- unsafe-case recall for AI-only issue families
- safe-case quietness and false-positive discipline
- explanation fidelity to the visible code
- resistance to misleading comments or business-logic ambiguity

These files are intentionally outside the deterministic proof gate. They help us evaluate how good or bad the AI layer is without pretending it is static proof.

## Current AI-Focused Fixture Set

Unsafe / safe pairs:

- `76` / `77`: NoSQL injection
- `78` / `79`: Mass assignment
- `80` / `81`: Unprotected admin route
- `82` / `83`: Privilege escalation via role assignment
- `84` / `85`: Missing audit trail on privileged action
- `86` / `87`: PII overexposure in API response
- `88` / `89`: Approval workflow bypass

The machine-readable manifest for this set is:

- [ai-benchmark.expectations.json](./ai-benchmark.expectations.json)

## What To Record

For each pair, record:

- `unsafe_detected`
- `safe_quiet`
- `canonical_issue_match`
- `explanation_grounded`
- `confidence_reasonable`

Suggested scoring:

- `unsafe_detected`: `pass` if the unsafe file is surfaced with the expected family
- `safe_quiet`: `pass` if the safe file stays clean or only shows weak advisory noise that is clearly not framed as proof
- `canonical_issue_match`: `pass` if the issue family is the intended one
- `explanation_grounded`: `pass` if the explanation matches the visible code and does not invent missing flows or controls
- `confidence_reasonable`: `pass` if the confidence and wording fit the evidence shown

## Failure Modes To Watch

- the unsafe file is missed entirely
- the safe pair is flagged as if it were clearly vulnerable
- the issue family is wrong even when something real is present
- the explanation overclaims beyond the visible code
- the confidence language sounds stronger than the evidence supports

## Recommended Evaluation Flow

1. Scan each unsafe / safe pair with the same provider and profile.
2. Save the generated report.
3. Record the five checks above for each file.
4. Review explanation drift separately from raw detection.

The key rule is:

AI evaluation is not only "did it flag the bad file?" It is also "did it stay quiet on the safe companion, and did it explain the result honestly?"

## Automated Score

Use:

```bash
node tools/evaluate-ai-benchmark.mjs
```

Or point it at a specific report:

```bash
node tools/evaluate-ai-benchmark.mjs tools/demo/owlvex-scan-report-YYYYMMDD-HHMMSS.md
```

The evaluator reports:

- unsafe recall
- safe quiet rate
- issue-family match rate
- recommended-agent fit rate
- average unsafe detection confidence
- overall AI quality score

This score is not a claim of absolute correctness. It is a repeatable product-quality indicator for the current AI lane.

## Client-Facing Agent Guidance

This benchmark can also be used to explain which Owlvex lane fits which problem type:

- `STATIC`
  - best for explicit, structurally provable source-to-sink issues
  - examples: SQLi, command injection, request-derived SSRF, path traversal
- `TARGETED_AI`
  - best for semantic but still local code judgments
  - examples: NoSQL injection, mass assignment, admin route guard quality, PII response shaping
- `REPO_AI`
  - best for workflow and multi-file reasoning
  - examples: privilege escalation via role design, missing audit trails, approval workflow bypass, broader business-logic mistakes

That means the benchmark is useful both internally and externally:

- internally: measure Owlvex AI quality over time
- externally: show clients when to trust static proof versus when AI review is the right lane
