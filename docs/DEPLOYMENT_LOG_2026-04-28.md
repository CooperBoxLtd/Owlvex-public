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

## Dev Observability Admin Dashboard Deployment

Later on 2026-04-28, the dev backend/admin console was updated for the dev observability telemetry work.

Backend/dashboard changes deployed:

- admin customer detail now exposes an explicit Telemetry Profile callout.
- operators can apply `dev_observability` or revert to `standard` from the selected customer panel.
- metrics page now includes Dev Observability aggregates for scan, report, fix preview, fix apply/discard, post-fix scans, duration, provider/model, and failure-rate signals.
- `metrics_dev_observability` export is available.
- backend usage metadata allowlist accepts the new report/fix telemetry fields.

Validation before deploy:

```text
uv run --python C:\Users\CristianBogdan\AppData\Roaming\uv\python\cpython-3.12-windows-x86_64-none\python.exe --with-requirements requirements-dev.txt python -m pytest tests\test_api_endpoints.py -q
```

Result:

- `85 passed`

Deployment:

- branch: `dev-observability-telemetry`
- commit: `065ad26`
- built image in ACR: `owlvexdevregistry.azurecr.io/owlvex-api:dev-20260428-202459`
- deployed image to Azure dev App Service: `owlvexdev-api`
- no schema migration was required for this slice.

Final dev Web App image:

```text
DOCKER|owlvexdevregistry.azurecr.io/owlvex-api:dev-20260428-202459
```

Final dev health response:

```json
{"status":"ok","db":"ok","environment":"development"}
```

Admin verification:

- `GET https://owlvexdev-api.azurewebsites.net/v1/admin/app` returned `200`.
- served HTML contains `Dev Observability` and `Apply Dev Observability`.
- `GET /v1/admin/metrics/dev-observability?group_by=overall` returned `200` with `dev_observability` payload.

Follow-up production test:

- production still returned the duplicate-trial error for a user deleted before the hotfix.
- investigation found `5` orphan `customer_identities` rows with no matching `customers` row.
- `2` of those orphan identities still had `trial_activated_at` set and could block re-onboarding.
- cleaned the orphan identity rows in production.
- confirmed `orphan_identities=0` and `orphan_trial_blocks=0`.

Defensive backend recovery:

- commit: `1f81ca5`
- changed `backend/app/routers/licences.py` so trial registration discards an orphan customer identity if no customer row exists for that email.
- added regression coverage for orphan identity recovery.
- backend API test result: `78 passed`.

Deployment:

- built image in ACR: `owlvexdevregistry.azurecr.io/owlvex-api:dev-20260428-orphan-recovery-1f81ca5`
- deployed and health-checked Azure dev on that image.
- promoted the exact same tag to production through `Deploy to production`.
- production workflow run: `25064792040`
- conclusion: `success`

Final production Web App image:

```text
DOCKER|owlvexdevregistry.azurecr.io/owlvex-api:dev-20260428-orphan-recovery-1f81ca5
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

## Customer Deletion Re-Onboarding Hotfix

Later on 2026-04-28, production showed a customer re-onboarding issue:

- an admin deleted a customer completely.
- the extension was uninstalled and reinstalled cleanly.
- the same user could not register again in production.

Root cause:

- customer deletion removed the `customers` row and related licence/activity data.
- it did not remove the retained `customer_identities` row.
- `customer_identities.trial_activated_at` continued to block fresh trial registration in production.

Policy decision:

- licence-only deletion must not reset trial history.
- ban/unban must not reset trial history.
- complete admin customer deletion means the customer identity is purged and re-onboarding is allowed.

Backend fix:

- commit: `4322d9e`
- changed `backend/app/routers/admin.py` so `_purge_customer_tree` also deletes `CustomerIdentity` for the deleted email.
- updated `backend/tests/test_api_endpoints.py` so customer deletion allows trial re-onboarding.

Validation:

```text
uv run --python C:\Users\CristianBogdan\AppData\Roaming\uv\python\cpython-3.12-windows-x86_64-none\python.exe --with-requirements requirements-dev.txt python -m pytest tests\test_api_endpoints.py -q
```

Result:

- `77 passed`

Deployment:

- built image in ACR: `owlvexdevregistry.azurecr.io/owlvex-api:dev-20260428-reonboard-4322d9e`
- deployed and health-checked Azure dev on that image.
- promoted the exact same tag to production through `Deploy to production`.
- production workflow run: `25064052503`
- conclusion: `success`

Final production Web App image:

```text
DOCKER|owlvexdevregistry.azurecr.io/owlvex-api:dev-20260428-reonboard-4322d9e
```

Final production health response:

```json
{"status":"ok","db":"ok","environment":"production"}
```
