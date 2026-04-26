# Owlvex Dev

Internal Owlvex development build.

## Build

- version: `0.1.23`
- target: Azure dev backend
- focus: evidence-first scanning, safe probe verification, report clarity, and fix verification loops

## Intended Use

- internal testing
- integration checks against the Azure dev control plane
- UI, scanning, onboarding, and workflow validation

## Current Engine Notes

- Safe probe verification now runs before verifier escalation when a finding can be checked without side effects.
- Probe-confirmed blocked flows skip extra AI verifier work.
- Probe residue is reported as unresolved evidence only when canary data still reaches a risky sink.
- Fix verification should continue until all findings on changed files are resolved or explicitly left for manual review.

## Notes

- this build is not intended as customer-facing documentation
- behavior can change quickly between builds
- dev and prod may differ in backend wiring, seed data, and feature validation state
- if both `Owlvex` and `Owlvex Dev` are installed in the same VS Code instance, status bar indicators and activity views can be misread as a single environment; verify which extension view is active before interpreting licence or provider state

## Internal Workflow

1. Install the dev VSIX.
2. Open the Owlvex activity view.
3. Configure a supported provider if needed.
4. Run scans, create reports, compare reports, and exercise fix preview flows.
5. Record bugs with:
   - provider/model used
   - exact command or UI flow
   - report file when relevant
   - scan warnings or throttling notes

## Report Confidence Checks

When validating reports, check that AI evidence language does not overstate the result:

- finder-only findings must not be described as `Validated by AI review`
- finder-only findings should show `review path finder`
- raw confidence should be visible as `AI signal <band> (<percent> final)`
- `Validated by AI review` should only appear when verifier or skeptic evidence exists
- high AI confidence is model confidence, not deterministic proof

## Reminder

If you need customer-facing install/use/limitations guidance, use the production package documentation instead.
