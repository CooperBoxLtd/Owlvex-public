# Owlvex Dev

Internal Owlvex development build.

## Intended Use

- internal testing
- integration checks against the Azure dev control plane
- UI, scanning, onboarding, and workflow validation

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
