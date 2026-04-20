# Owlvex First Production Deploy

This runbook defines the bootstrap path for the Owlvex production control plane on Azure App Service for Containers.

It assumes:

- Azure `dev` exists separately from production
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

## Production Role

Production is now the market-facing environment for:

- external trials
- released product behavior
- controlled demos

It should not be used for day-to-day development deploys.

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

If registration emails should work in production, `FROM_EMAIL` must be a sender address or domain that is actually verified in SendGrid. An unverified sender will cause registration to fail at delivery time.

## Step 4: Provision The Azure Infrastructure

Run the production wrapper script. It will provision:

- Azure Container Registry
- Azure Database for PostgreSQL Flexible Server
- Azure Key Vault
- Azure App Service Plan
- Azure Web App for Containers
- Log Analytics workspace

```bash
cp infra/.env.prod.example infra/.env.prod
# edit infra/.env.prod
bash infra/deploy-prod.sh
```

The wrapper delegates to the shared Azure deploy engine and stamps the environment as production.

To redeploy a new image without re-provisioning infrastructure:

```bash
IMAGE_ONLY=1 bash infra/deploy-prod.sh
```

## Step 5: Capture The Live API URL

`deploy-prod.sh` prints the live URL at the end.

To retrieve it later:

```bash
az webapp show --name owlvex-api --resource-group owlvex-prd --query defaultHostName -o tsv
```

The current live production endpoint is:

- `https://owlvex-api.azurewebsites.net`

## Step 6: Point The Extension At Production

Set:

- `owlvex.apiUrl = https://<app-service-hostname>`

Dev builds or dev profiles should stay pointed at Azure `dev`, not production.

## Step 7: Verify Production Health

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

Normal production updates:

```bash
IMAGE_ONLY=1 bash infra/deploy-prod.sh
```

## Bottom Line

For the first production deploy, you only need:

- Azure login with access to subscription `c0b31fc1-52d0-4339-96ee-9915e4dfe3c4`
- `infra/.env.prod` with three real secret values
- `bash infra/deploy-prod.sh`

All infrastructure, image build, and schema init is automated through the shared Azure deploy engine.
