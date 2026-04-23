# Owlvex Deployment Environments

This document defines the supported hosted environment model for Owlvex.

It exists to keep one simple operating rule in place:

- Azure `dev` is the day-to-day hosted development environment
- Azure `prod` is the market-facing trial and release environment
- local Docker or ad hoc hosts are optional developer tools, not the named shared development environment
- the extension and CLI keep scanning locally in every environment

It also establishes the release rule for the backend:

- build one backend container image per release candidate
- deploy that exact image to Azure `dev`
- validate it there
- promote the exact same image tag to Azure `prod`
- do not rebuild a separate production image from the same commit

If this document conflicts with [IMPLEMENTATION_DESIGN.md](D:/Dev/repos/CodeScanner/docs/IMPLEMENTATION_DESIGN.md), the design document wins.

## Deployment Model

Owlvex has two supported hosted environments:

1. `dev`
   - backend runs in Azure
   - used for day-to-day backend work, integration testing, and pre-release validation

2. `prod`
   - backend runs in Azure
   - used for external trials, demos, and released product behavior

The extension and CLI remain the execution plane in both environments.

## Boundary Rules

These rules do not change by environment:

- deterministic scanning runs locally
- AI provider calls are made directly by the extension or CLI
- Owlvex backend remains a control plane
- Owlvex backend must not require raw source code for scanning

Changing `dev` to `prod` must never turn Owlvex into a backend scan relay.

## Resource Group Strategy

Owlvex should use separate Azure resource groups:

- `owlvex-dev`
- `owlvex-prd`

Both environments should currently live in:

- `uksouth`

`owlvex-prd` must no longer be used for day-to-day development deploys.

## Environment Responsibilities

### Development (`owlvex-dev`)

Development Azure is the shared hosted environment for:

- backend iteration
- extension-to-backend integration testing
- dev licence and prompt-flow validation
- pricing, trial, and usage-metering validation
- safe pre-release deploy validation

Expected backend URL shape:

- `https://owlvexdev-api.azurewebsites.net`

### Production (`owlvex-prd`)

Production Azure is the market-facing environment for:

- trial and external tester access
- production-style licence validation
- prompt/template delivery
- policy evaluation
- scan metadata storage
- controlled release validation

Expected backend URL shape:

- `https://owlvex-api.azurewebsites.net`

## Azure Subscription

Hosted Azure resources must be deployed into subscription:

- `c0b31fc1-52d0-4339-96ee-9915e4dfe3c4`

Before any deploy, set the active subscription explicitly:

```bash
az login
az account set --subscription c0b31fc1-52d0-4339-96ee-9915e4dfe3c4
```

## Environment Files

Use explicit environment files instead of ad hoc shell exports.

Supported pattern:

- `infra/.env.dev`
- `infra/.env.prod`

Tracked templates:

- [infra/.env.dev.example](D:/Dev/repos/CodeScanner/infra/.env.dev.example)
- [infra/.env.prod.example](D:/Dev/repos/CodeScanner/infra/.env.prod.example)

Legacy compatibility:

- [infra/.env.azure.example](D:/Dev/repos/CodeScanner/infra/.env.azure.example) remains a production-oriented alias

These real env files must never be committed.

## Deployment Paths

### Dev Path

For full dev environment deploys:

```bash
cp infra/.env.dev.example infra/.env.dev
# edit infra/.env.dev
bash infra/deploy-dev.sh
```

This provisions or updates the shared Azure dev control plane.

On the current Windows ARM workstation, run that command from PowerShell/Windows Terminal so the deploy can use:

- Windows Azure CLI
- Docker Desktop
- normalized Windows paths for Bicep and schema mounts

For day-to-day backend iteration on the current Windows ARM machine, prefer the split flow:

1. local `linux/amd64` image build
2. push to `owlvexdevregistry`
3. update the dev Web App to a unique image tag
4. run schema verification / migration

Recommended commands:

```bash
IMAGE_TAG=dev-20260419-1234 bash infra/build-image.sh
IMAGE_TAG=dev-20260419-1234 bash infra/deploy-app.sh
bash infra/migrate-schema.sh
```

Use remote source-upload ACR builds only as fallback when local Docker is unavailable.

If PostgreSQL schema application is blocked by the server firewall, add a temporary machine-IP rule, apply/verify schema, and then remove that rule. The Web App can still be healthy even when direct local schema access is blocked.

### Prod Path

For full production environment deploys:

```bash
cp infra/.env.prod.example infra/.env.prod
# edit infra/.env.prod
bash infra/deploy-prod.sh
```

This provisions or updates the market-facing Azure control plane.

For normal promotion after dev validation, do not rebuild the image. Promote the validated tag from the shared dev registry:

```bash
IMAGE_TAG=dev-20260419-1234 bash infra/promote-to-prod.sh
```

That path:

1. switches prod App Service to the exact validated image tag stored in `owlvexdevregistry`
2. applies schema files
3. verifies required tables/columns
4. fails loudly if schema or health checks are not correct

## Environment Parity Rule

`prod` must mirror `dev` in backend code and feature-enabling environment settings unless a difference is deliberate, documented, and release-approved.

That means:

- the deployed backend container image should be identical between `dev` and `prod` for the same release candidate
- the shared backend image source of truth is `owlvexdevregistry`
- production must not be missing required feature settings that were present during `dev` validation
- customer-facing flows such as registration, verification, licence issuance, and telemetry behavior must be exercised against `dev` before promotion and expected to behave the same way in `prod`

Allowed differences are limited to environment-scoped values such as:

- backend URL
- database connection
- secrets and keys
- billing/live provider credentials
- logging and retention policy
- branding/package profile defaults

Not allowed:

- separate ad hoc backend image builds for `prod`
- shipping a feature from `dev` to `prod` without the required production environment settings to make that feature work
- relying on undocumented environment drift as normal operating practice

### Shared Deploy Engine

The common deploy engine remains:

- [main.bicep](D:/Dev/repos/CodeScanner/infra/main.bicep) - provisions ACR, PostgreSQL Flexible Server, Key Vault, Log Analytics, App Service Plan, and Web App for Containers
- [deploy.sh](D:/Dev/repos/CodeScanner/infra/deploy.sh) - shared Azure deployment engine
- [deploy-dev.sh](D:/Dev/repos/CodeScanner/infra/deploy-dev.sh) - dev wrapper
- [deploy-prod.sh](D:/Dev/repos/CodeScanner/infra/deploy-prod.sh) - prod wrapper
- [build-image.sh](D:/Dev/repos/CodeScanner/infra/build-image.sh) - image build and push
- [deploy-app.sh](D:/Dev/repos/CodeScanner/infra/deploy-app.sh) - App Service image switch and health check
- [migrate-schema.sh](D:/Dev/repos/CodeScanner/infra/migrate-schema.sh) - schema apply and required-schema verification
- [promote-to-prod.sh](D:/Dev/repos/CodeScanner/infra/promote-to-prod.sh) - promote the exact validated image tag from dev to prod

## Extension Configuration

The extension should select the backend by environment, not by changing the scan model.

Current key:

- `owlvex.apiUrl`

Expected usage:

- dev -> Azure dev App Service URL
- prod -> Azure prod App Service URL

The packaging/profile rule should stay simple:

- dev builds or dev profiles point to dev
- prod builds or release profiles point to prod

Current package outputs:

- `npm run package:dev` -> `Owlvex Dev` with Azure dev backend default
- `npm run package:prod` -> `Owlvex` with Azure prod backend default

## Recommended Operating Pattern

Use this workflow:

1. develop and validate against Azure `dev`
2. build locally as `linux/amd64` and push to ACR with a unique tag
3. switch Azure `dev` to that exact tag
4. apply schema and verify health/schema in `dev`
5. keep deterministic benchmark and extension tests green
6. promote the exact validated tag into Azure `prod`
7. keep external trials and demos pointed at `prod`

On this machine, "local build" still means a container build for Azure:

- Docker Desktop must be running
- `docker buildx` must support `linux/amd64`
- the image should be pushed to ACR before the App Service update

If Docker Desktop is stopped, local builds will fail in a way that can look like an ARM issue. Treat Docker availability as the first prerequisite check.

On this Windows ARM workstation, use the dedicated `docker-container` builder rather than the default `docker` driver builder. The default builder can remain arm64-only and fail `linux/amd64` `RUN` steps with `exec format error`.

One-time setup:

```bash
docker run --privileged --rm tonistiigi/binfmt --install amd64
docker buildx create --name owlvex-cross --driver docker-container --use
docker buildx inspect owlvex-cross --bootstrap
```

`infra/build-image.sh` now targets `owlvex-cross` automatically by default, and still falls back to ACR remote build when Docker is unavailable.

This preserves a stable market-facing environment while still keeping Azure as the shared hosted model.

## What Must Not Change

These must remain true after the environment split:

- source code is not sent to Owlvex backend for scanning
- the deterministic engine does not move into Azure
- the extension does not require Azure to parse or inspect code
- the extension remains compatible with customer-selected AI providers

## Near-Term Improvements

The next environment-hardening priorities are:

- keep dev and prod secrets fully separate
- move from raw secret injection toward Key Vault references in App Settings
- ensure pack-signing secrets are explicitly environment-scoped
- replace ACR admin credentials with managed identity where practical
- keep image promotion tag-based rather than rebuilding separately in prod
- add a dedicated dev deployment workflow when the hosted dev environment is stable

## Bottom Line

The supported hosted operating model is:

- Azure `dev` for day-to-day development
- Azure `prod` for market-facing trials and releases
- local scanning in both
- backend control plane only

That gives Owlvex a stable production target without continuing to develop directly in production.
