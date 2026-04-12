# Owlvex First Production Deploy

This runbook defines the bootstrap path for the Owlvex production control plane on Azure App Service for Containers. The infrastructure is implemented and has been deployed.

It assumes:

- development continues on `ml30`
- production runs in Azure App Service for Containers
- Stripe is not being activated yet
- the extension and CLI continue scanning locally

For the full environment model, see [DEPLOYMENT_ENVIRONMENTS.md](D:/Dev/repos/CodeScanner/docs/DEPLOYMENT_ENVIRONMENTS.md).

## Goal

Bring up a working production backend that supports:

- health checks
- licence validation
- prompt delivery
- policy evaluation
- scan metadata storage

This first deploy does **not** require:

- Stripe billing
- SendGrid email
- managed identity hardening
- full Key Vault-native secret retrieval

This first deploy also does **not** depend on Azure Container Apps.

## Target Production Stack

The intended production stack is:

- Azure Container Registry
- Azure Database for PostgreSQL Flexible Server
- Azure Key Vault
- Azure App Service Plan
- Azure Web App for Containers
- Azure monitoring

## Prerequisites

You need all of the following on the machine running the deploy:

- Azure CLI
- Docker
- `psql`
- access to subscription `c0b31fc1-52d0-4339-96ee-9915e4dfe3c4`

You also need three real secret values:

- `POSTGRES_ADMIN_PASSWORD`
- `SECRET_KEY`
- `ADMIN_KEY`

## Step 1: Log Into Azure

```bash
az login
az account set --subscription c0b31fc1-52d0-4339-96ee-9915e4dfe3c4
```

Optional verification:

```bash
az account show --query "{name:name, id:id}" -o table
```

## Step 2: Create The Production Resource Group

```bash
az group create --name owlvex-prd --location uksouth
```

This is safe to run again later.

## Step 3: Prepare Production Secrets

Prepare values for:

- `POSTGRES_ADMIN_PASSWORD`
- `SECRET_KEY`
- `ADMIN_KEY`

Leave these empty for the first deploy:

- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `STRIPE_PRICE_DEVELOPER_MONTHLY`
- `STRIPE_PRICE_DEVELOPER_ANNUAL`
- `STRIPE_PRICE_TEAM_MONTHLY`
- `STRIPE_PRICE_TEAM_ANNUAL`
- `SENDGRID_API_KEY`

`FROM_EMAIL` can remain:

- `noreply@owlvex.io`

You can still store these in `infra/.env.prod` if that is operationally convenient, but that file is now just a staging convenience, not the definition of the deployment path.

## Step 4: Provision The Azure Infrastructure

Run the deploy script. It will provision:

- Azure Container Registry
- Azure Database for PostgreSQL Flexible Server
- Azure Key Vault
- Azure App Service Plan
- Azure Web App for Containers
- Log Analytics workspace

```bash
cp infra/.env.prod.example infra/.env.prod
# edit infra/.env.prod — set POSTGRES_ADMIN_PASSWORD, SECRET_KEY, ADMIN_KEY
source infra/.env.prod
bash infra/deploy.sh
```

The script handles all steps (Bicep deploy, image build/push, schema init, health check) in sequence.

To redeploy a new image without re-provisioning infrastructure:

```bash
IMAGE_ONLY=1 bash infra/deploy.sh
```

## Step 5: Build And Push The Backend Image

Handled automatically by `deploy.sh`. The script builds from [backend/Dockerfile](D:/Dev/repos/CodeScanner/backend/Dockerfile) and pushes to the ACR created in Step 4.

## Step 6: Configure The Web App For Containers

Handled automatically by `deploy.sh` via `az webapp config container set`. The Bicep template also injects all required app settings:

- `DATABASE_URL`
- `SECRET_KEY`
- `ADMIN_KEY`
- optional Stripe values
- optional SendGrid value
- `ENVIRONMENT=production`

## Step 7: Initialize The Database Schema

Handled automatically by `deploy.sh`. It applies in order:

1. `01_schema.sql`
2. `02_seed.sql`
3. `03_rules_extended.sql`

Uses `psql` if available, falls back to `docker run postgres:16`.

## Step 8: Capture The Live API URL

`deploy.sh` prints the live URL at the end:

```
API URL   : https://<app-service-hostname>
Health    : https://<app-service-hostname>/health
```

To retrieve it later:

```bash
az webapp show --name owlvex-api --resource-group owlvex-prd --query defaultHostName -o tsv
```

## Step 9: Point The Extension At Production

Set:

- `owlvex.apiUrl = https://<app-service-hostname>`

The current live production endpoint is:

- `https://owlvex-api.azurewebsites.net`

Development can continue using:

- `http://192.168.50.35:8000`

## Step 10: Verify Production Health

```bash
curl https://<app-service-hostname>/health
```

Expected result:

- HTTP `200`
- JSON response with `status`

## What Success Looks Like

The first deploy is successful when:

- Azure resources exist in subscription `c0b31fc1-52d0-4339-96ee-9915e4dfe3c4`
- the Web App is healthy
- the backend URL is reachable over HTTPS
- the extension can use that URL as `owlvex.apiUrl`
- no Stripe configuration is required for the API to start

## What To Skip For Now

Do not block production updates on:

- Stripe webhook setup
- SendGrid integration
- ACR managed identity conversion
- Key Vault reference-based secret consumption

Those are valid hardening steps, but they are not required for the production control plane to operate.

## After First Deploy

Normal application-only production updates:

```bash
IMAGE_ONLY=1 bash infra/deploy.sh
```

Or via CI: any push to `main` that touches `backend/`, `infra/`, or the workflow file triggers the deploy pipeline in `.github/workflows/deploy-prod.yml`, which builds the image, updates the Web App, and health-checks the result.

## Future Billing Activation

When you are ready to turn on Stripe later:

1. fill in the Stripe variables in `infra/.env.prod`
2. redeploy
3. set the Stripe webhook to:

```text
https://<app-service-hostname>/v1/billing/webhook/stripe
```

## Bottom Line

For the first production deploy, you only need:

- Azure login with access to subscription `c0b31fc1-52d0-4339-96ee-9915e4dfe3c4`
- `infra/.env.prod` with three real secret values
- `bash infra/deploy.sh`

All infrastructure, image build, and schema init is automated.
