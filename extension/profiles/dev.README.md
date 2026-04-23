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

## Reminder

If you need customer-facing install/use/limitations guidance, use the production package documentation instead.
