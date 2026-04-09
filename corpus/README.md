# Owlvex Golden Corpus

This corpus is the first family-aware benchmark set for Owlvex canonical resolution.

Goals:

- verify issue-level detection for high-value canonical issues
- verify family-level detection even when issue wording varies
- catch false positives as the resolver and prompts evolve

Structure:

- `family-name/positive/`
  Code that should resolve to one or more canonical issues.
- `family-name/negative/`
  Code that should stay unresolved or avoid a specific false positive.
- `manifest.json`
  Expected canonical IDs, issue family/families, and difficulty tier for each case.

Difficulty tiers:

- `easy`
  Clear single-issue cases and obvious safe negatives.
- `medium`
  Ambiguous or slightly noisy cases where family accuracy matters.
- `hard`
  Adversarial negatives, multi-issue files, or cases that deliberately stress weak families.

The current corpus is intentionally compact but adversarial:

- 76 files
- positive, negative, ambiguous, and multi-issue coverage
- decision-conflict cases covering comment noise, dead code, partial safety, and multi-family overlap
- suitable for local iteration before a larger benchmark harness exists
