# Owlvex Deployment Environments

This document defines the supported deployment model for Owlvex control-plane services.

It exists to keep one simple operating model in place:

- `ml30` stays the development environment
- Azure is the production environment
- the extension and CLI keep scanning locally in both environments
- changing environment changes the backend endpoint, not the data boundary

If this document conflicts with [IMPLEMENTATION_DESIGN.md](D:/Dev/repos/CodeScanner/docs/IMPLEMENTATION_DESIGN.md), the design document wins.

## Deployment Model

Owlvex has two environments:

1. `dev`
   - backend runs on `ml30`
   - used for iteration, debugging, local QA, and development testing

2. `prod`
   - backend runs in Azure App Service for Containers
   - used for production licences, billing, prompt delivery, and metadata storage

The extension and CLI remain the execution plane in both environments.

## Boundary Rules

These rules do not change by environment:

- deterministic scanning runs locally
- AI provider calls are made directly by the extension or CLI
- Owlvex backend remains a control plane
- Owlvex backend must not require raw source code for scanning

Changing `dev` to `prod` must never turn Owlvex into a backend scan relay.

## Environment Responsibilities

### Development (`ml30`)

Development remains the fastest place to iterate.

Use it for:

- backend development
- prompt and metadata flow validation
- Docker-based local or LAN deployments
- extension integration testing
- benchmark and test debugging

Expected backend URL shape:

- `http://owlvex.ml30.local`

### Production (Azure)

Production hosts only the Owlvex control plane:

- licence validation
- prompt/template delivery
- policy evaluation
- billing and Stripe webhook handling
- scan metadata storage

Expected backend URL shape:

- `https://<app-service-hostname>`

## Azure Subscription

Production Azure resources must be deployed into subscription:

- `c0b31fc1-52d0-4339-96ee-9915e4dfe3c4`

Before any production deploy, set the active subscription explicitly:

```bash
az login
az account set --subscription c0b31fc1-52d0-4339-96ee-9915e4dfe3c4
```

## Resource Group Strategy

Production should use a dedicated resource group.

Recommended initial value:

- `owlvex-prd`

Create it once:

```bash
az group create --name owlvex-prd --location uksouth
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

- [infra/.env.azure.example](D:/Dev/repos/CodeScanner/infra/.env.azure.example) remains as a production-oriented alias for the current deploy script

These real env files must never be committed.

## Deployment Paths

### Dev Path

Development can continue to use the existing local or `ml30` flow.

Typical path:

```bash
cp backend/.env.example backend/.env
docker compose up -d
```

This keeps the dev backend on `ml30` or local Docker without touching Azure.

### Prod Bootstrap Path

The target production bootstrap path is now:

1. provision Azure infrastructure for:
   - Azure Container Registry
   - Azure Database for PostgreSQL
   - Azure Key Vault
   - Azure App Service Plan
   - Azure Web App for Containers
2. build and push the backend image to ACR
3. configure the Web App to run that image
4. initialize the PostgreSQL schema
5. verify `/health`

The exact App Service deployment scripts are not yet implemented in the repo.

### Current Repo Status

The production infrastructure is implemented and deployed. The files under `infra/` target Azure App Service for Containers:

- [main.bicep](D:/Dev/repos/CodeScanner/infra/main.bicep) — provisions ACR, PostgreSQL Flexible Server, Key Vault, Log Analytics, App Service Plan, and the Web App for Containers
- [deploy.sh](D:/Dev/repos/CodeScanner/infra/deploy.sh) — full bootstrap: provisions infra via Bicep, builds and pushes image, updates Web App, applies schema, health checks
- [deploy-prod.yml](D:/Dev/repos/CodeScanner/.github/workflows/deploy-prod.yml) — CI gate: runs tests and benchmark, then builds/pushes image and updates Web App on push to `main`

### CI Production Path

The CI production path:

- tests and benchmark gate run first
- backend image is built and pushed to ACR
- `az webapp config container set` updates the production Web App to the new image tag
- health check confirms the deployment succeeded

## Extension Configuration

The extension should select the backend by environment, not by changing the scan model.

Current key:

- `owlvex.apiUrl`

Expected usage:

- dev -> `http://owlvex.ml30.local`
- prod default -> `https://owlvex-api.azurewebsites.net`
- prod -> Azure App Service URL

This keeps the environment switch operationally simple.

The extension now supports two packaging profiles from the same source tree:

- `npm run package:dev` -> `Owlvex Dev`
- `npm run package:prod` -> `Owlvex`

These builds are intended as environment-specific package outputs, not long-term side-by-side installs.

## Recommended Operating Pattern

Use this workflow:

1. develop and test against `ml30`
2. keep deterministic benchmark and extension tests green
3. deploy the backend control plane to Azure prod
4. point production users to the Azure backend URL

This preserves the same product model in both environments.

## What Must Not Change

These must remain true after Azure production is added:

- source code is not sent to Owlvex backend for scanning
- the deterministic engine does not move into Azure
- the extension does not require Azure to parse or inspect code
- the extension remains compatible with customer-selected AI providers

## Near-Term Improvements

The production infrastructure is live. Hardening priorities:

- move from raw secret injection toward Key Vault references in App Settings
- replace ACR admin credentials with managed identity where practical
- formalize environment selection in extension settings if needed
- document backend request shapes that are allowed to carry metadata only
- add real telemetry instrumentation before reintroducing Application Insights settings

## Bottom Line

The supported operating model is:

- `ml30` for development
- Azure for production
- local scanning in both
- backend control plane only

That lets us ship production without changing the core privacy and execution boundary of Owlvex.

For the shortest Stripe-free bootstrap sequence, see [FIRST_PRODUCTION_DEPLOY.md](D:/Dev/repos/CodeScanner/docs/FIRST_PRODUCTION_DEPLOY.md).
