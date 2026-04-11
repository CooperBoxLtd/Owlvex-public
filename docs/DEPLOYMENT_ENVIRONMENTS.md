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
   - backend runs in Azure
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

- `https://<container-app-fqdn>`

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

- `owlvex-prod`

Create it once:

```bash
az group create --name owlvex-prod --location westeurope
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

Use this when creating or updating Azure infrastructure:

```bash
az login
az account set --subscription c0b31fc1-52d0-4339-96ee-9915e4dfe3c4
cp infra/.env.prod.example infra/.env.prod
# edit infra/.env.prod
source infra/.env.prod
bash infra/deploy.sh
```

This path:

- creates the resource group if needed
- deploys infrastructure with Bicep
- builds and pushes the backend image
- updates the Container App
- runs DB initialization

### Prod Image-Only Path

Use this for normal application-only releases after infrastructure exists:

```bash
source infra/.env.prod
IMAGE_ONLY=1 bash infra/deploy.sh
```

### CI Production Path

GitHub Actions is the normal production release path after bootstrap:

- tests and benchmark gate run first
- backend image is built and pushed
- Container App is updated to the new image

Current workflow:

- [deploy-prod.yml](D:/Dev/repos/CodeScanner/.github/workflows/deploy-prod.yml)

Important note:

The current CI workflow is an image deployment pipeline, not a full infrastructure apply pipeline.

That is intentional for now:

- infrastructure bootstrap and major infra changes are done explicitly
- normal prod releases are image deploys

## Extension Configuration

The extension should select the backend by environment, not by changing the scan model.

Current key:

- `owlvex.apiUrl`

Expected usage:

- dev -> `http://owlvex.ml30.local`
- prod -> Azure Container App URL

This keeps the environment switch operationally simple.

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

The current Azure setup is a good Phase 1 production path, but we should tighten it over time:

- move from raw secret injection toward stronger Key Vault integration
- replace ACR admin credentials with managed identity where practical
- formalize environment selection in extension settings if needed
- document backend request shapes that are allowed to carry metadata only

## Bottom Line

The supported operating model is:

- `ml30` for development
- Azure for production
- local scanning in both
- backend control plane only

That lets us ship production without changing the core privacy and execution boundary of Owlvex.
