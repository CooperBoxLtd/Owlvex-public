# Deployment Log - 2026-04-28

This records the 2026-04-28 Owlvex production backend and extension release.

No secret values are recorded here.

## Summary

- Released VS Code extension version `0.1.29`.
- Published `owlvex.owlvex v0.1.29` to the VS Code Marketplace.
- Published the production VSIX to the public GitHub distribution repository.
- Promoted the dev-validated backend image to production.
- Preserved the production licence guard by keeping prod configured with `ENVIRONMENT=production`.

## Extension Release

Private repository commit:

- `1a0282c` - released extension `0.1.29`.

Version files updated:

- `extension/package.json`
- `extension/package-lock.json`
- `extension/CHANGELOG.md`
- `extension/profiles/prod.README.md`

The release gate completed successfully:

```text
npm --prefix extension run test:release
```

Release-gate result:

- `305` Jest tests passed.
- proof contracts passed `33/33`.
- evaluator tests passed.
- packaged and verified `extension/dist/owlvex-dev.vsix`.
- packaged and verified `extension/dist/owlvex-prod.vsix`.

Marketplace publication:

- extension id: `owlvex.owlvex`
- published version: `0.1.29`
- URL: `https://marketplace.visualstudio.com/items?itemName=owlvex.owlvex`

## Public Distribution

Public repository:

- `https://github.com/CooperBoxLtd/Owlvex-public`

Public repository commit:

- `1cad7de` - published Owlvex `0.1.29`.

Public distribution updates:

- added `releases/owlvex-0.1.29.vsix`.
- updated `latest.json`.
- updated `downloads/owlvex-prod.vsix.sha256`.
- updated public `README.md`, `CHANGELOG.md`, and `LICENSE.txt`.
- created GitHub Release `v0.1.29` with `owlvex-prod.vsix` and `owlvex-prod.vsix.sha256`.

## Backend Promotion

Validated dev image:

```text
owlvexdevregistry.azurecr.io/owlvex-api:dev-20260428-onboarding-05ecdb6
```

Production was promoted to that exact image tag through the `Deploy to production` GitHub Actions workflow.

Successful workflow run:

- run id: `25062556036`
- commit: `1a0282c`
- conclusion: `success`

A duplicate workflow dispatch was cancelled after the first run completed successfully:

- run id: `25062568702`

Final production Web App image:

```text
DOCKER|owlvexdevregistry.azurecr.io/owlvex-api:dev-20260428-onboarding-05ecdb6
```

Final production health response:

```json
{"status":"ok","db":"ok","environment":"production"}
```

## Licence Guard

Production remained configured as:

```text
ENVIRONMENT=production
```

That keeps the development-only same-email trial recovery path out of production.

