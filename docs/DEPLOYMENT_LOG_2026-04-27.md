# Deployment Log - 2026-04-27

This records the 2026-04-27 Owlvex release, backend promotion, and deployment-runbook repair work.

No secret values are recorded here. Secret names are listed only so the deployment path is reproducible.

## Summary

- Released VS Code extension version `0.1.28`.
- Published `owlvex.owlvex v0.1.28` to the VS Code Marketplace.
- Published the production VSIX to the public GitHub distribution repository.
- Promoted the dev-validated backend image to production.
- Preserved the production licence guard by keeping prod configured with `ENVIRONMENT=production`.
- Repaired the GitHub Actions production deployment path so it can promote the exact validated dev image tag.

## Extension Release

Private repository commits:

- `73c2a94` - clarified framework scope in reports.
- `bfe6161` - released extension `0.1.28`.

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

Both dev and prod packages were produced because `test:release` runs `package:all`.

## Report And Framework Clarity

The report wording was changed so users can distinguish selected framework lenses from canonical security evidence.

Implemented behavior:

- reports now use `Selected framework lens` instead of the ambiguous `Frameworks in scope`.
- reports explain that selected frameworks control AI grounding, report emphasis, remediation variants, and expanded mapping detail.
- reports explain that deterministic evidence rules still run security-first.
- reports explain that mappings to unselected frameworks are taxonomy references, not proof that every framework lens was active.

The scanner/report path was also hardened against a misleading title case:

- if evidence is PII, sensitive response, or overexposure, a GraphQL/introspection title is replaced with `PII or sensitive fields over-exposed in API response`.
- canonical finding resolution remaps the GraphQL finding id to the PII overexposure finding id when the evidence contract says the issue is PII/sensitive-response/overexposure.

Regression coverage was added in `extension/src/scanner/reportGenerator.test.ts`.

## Public Distribution

Public repository:

- `https://github.com/CooperBoxLtd/Owlvex-public`

Public repository commit:

- `f44dfa3` - published Owlvex `0.1.28`.

Public distribution updates:

- added `releases/owlvex-0.1.28.vsix`.
- updated `latest.json`.
- updated `downloads/owlvex-prod.vsix.sha256`.
- updated public `README.md`, `CHANGELOG.md`, and `LICENSE.txt`.

Marketplace publication:

- extension id: `owlvex.owlvex`
- published version: `0.1.28`
- URL: `https://marketplace.visualstudio.com/items?itemName=owlvex.owlvex`

## Backend Promotion

Validated dev image:

```text
owlvexdevregistry.azurecr.io/owlvex-api:dev-20260427-161420
```

Production was promoted to that exact image tag. The production Web App now reports:

```text
DOCKER|owlvexdevregistry.azurecr.io/owlvex-api:dev-20260427-161420
```

Final production health response:

```json
{"status":"ok","db":"ok","environment":"production"}
```

The promotion happened in two steps:

1. production App Service was first switched directly through Azure to restore image parity quickly.
2. the supported GitHub Actions promotion workflow was then repaired and rerun successfully with the same image tag.

The second step resolved the earlier caveat that the formal promotion workflow had not run.

## Licence Guard

The dev image contains a development-only licence recovery behavior: same-email trial reissue can be allowed when the backend environment is `development`.

That behavior was preserved as dev-only by keeping production configured as:

```text
ENVIRONMENT=production
```

Important boundaries kept during promotion:

- no dev database was copied to production.
- no dev licences were copied to production.
- production retained a separate production database.
- production remained configured to block same-email trial reissue.

## GitHub Actions Production Workflow

Workflow:

- `.github/workflows/deploy-prod.yml`
- workflow name: `Deploy to production`

The workflow was dispatched with:

```text
image_tag=dev-20260427-161420
```

Initial workflow failures showed that the production deployment path was not fully configured:

- run `25019239506` failed because Azure login secrets were incomplete and the production PostgreSQL password secret was empty.
- run `25019810050` failed because repo-level secrets did not satisfy the workflow's `production` environment.
- repo-level secrets alone were not enough because the workflow declares `environment: production`.
- the `production` GitHub Environment needed its own secrets.

Deployment identity created:

- service principal name: `github-owlvex-prod-deploy`
- role assignment: `Contributor`
- scope: subscription `c0b31fc1-52d0-4339-96ee-9915e4dfe3c4`

Secrets configured on the GitHub `production` environment:

- `AZURE_CREDENTIALS`
- `POSTGRES_ADMIN_PASSWORD_PROD`

The final production workflow run succeeded:

- run id: `25019875298`
- job: `Promote dev image to prod`
- conclusion: `success`

## Local Deployment Findings

The local machine was not a complete production-promotion environment at the time of the deploy:

- `infra/.env.prod` was intentionally absent because real production secrets are not committed.
- `psql` was not installed locally.
- Docker Desktop was installed but the Docker daemon was not running.
- WSL could see Azure CLI but not a working Docker daemon.
- running `infra/promote-to-prod.sh` from the Windows checkout hit CRLF shell parsing errors.

An additional schema issue was found:

- direct schema application stopped at `relation "frameworks" already exists`.
- this means the SQL path is not fully idempotent for an already initialized database.

Required production schema verification still passed for the current release requirements:

- table `customers`.
- table `usage_events`.
- column `customers.pending_plan`.
- column `customers.email_verified_at`.
- column `customers.verification_code_hash`.
- column `customers.verification_code_expires_at`.
- column `licences.customer_id`.

The official GitHub Actions workflow later completed successfully after the production environment secrets were corrected.

## Follow-Ups

- Make schema application idempotent or move it to explicit migrations.
- Add a `.gitattributes` rule or checkout guidance so `infra/*.sh` stays LF on Windows.
- Decide whether local production promotion is supported or whether production promotion should be GitHub Actions only.
- Narrow the deployment service principal scope from subscription-level `Contributor` once the workflow is stable.
- Keep GitHub Environment `production` secrets documented as the deployment source of truth for production workflows.
