# Owlvex Deployment Environments

This document defines the supported hosted environment model for Owlvex.

It exists to keep one simple operating rule in place:

- Azure `dev` is the day-to-day hosted development environment
- Azure `prod` is the market-facing trial and release environment
- local Docker or ad hoc hosts are optional developer tools, not the named shared development environment
- the extension and CLI keep scanning locally in every environment

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

Deploy the hosted dev environment with:

```bash
cp infra/.env.dev.example infra/.env.dev
# edit infra/.env.dev
bash infra/deploy-dev.sh
```

This provisions or updates the shared Azure dev control plane.

### Prod Path

Deploy the hosted production environment with:

```bash
cp infra/.env.prod.example infra/.env.prod
# edit infra/.env.prod
bash infra/deploy-prod.sh
```

This provisions or updates the market-facing Azure control plane.

### Shared Deploy Engine

The common deploy engine remains:

- [main.bicep](D:/Dev/repos/CodeScanner/infra/main.bicep) - provisions ACR, PostgreSQL Flexible Server, Key Vault, Log Analytics, App Service Plan, and Web App for Containers
- [deploy.sh](D:/Dev/repos/CodeScanner/infra/deploy.sh) - shared Azure deployment engine
- [deploy-dev.sh](D:/Dev/repos/CodeScanner/infra/deploy-dev.sh) - dev wrapper
- [deploy-prod.sh](D:/Dev/repos/CodeScanner/infra/deploy-prod.sh) - prod wrapper

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
2. keep deterministic benchmark and extension tests green
3. promote intentional releases into Azure `prod`
4. keep external trials and demos pointed at `prod`

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
- add a dedicated dev deployment workflow when the hosted dev environment is stable

## Bottom Line

The supported hosted operating model is:

- Azure `dev` for day-to-day development
- Azure `prod` for market-facing trials and releases
- local scanning in both
- backend control plane only

That gives Owlvex a stable production target without continuing to develop directly in production.
