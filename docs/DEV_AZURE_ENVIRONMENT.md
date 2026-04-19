# Owlvex Azure Development Environment

This runbook defines the shared hosted development environment for Owlvex.

Its purpose is simple:

- stop day-to-day development from landing in `owlvex-prd`
- give the extension and backend a stable Azure `dev` target
- keep production reserved for releases, demos, and external trials

For the higher-level environment model, see [DEPLOYMENT_ENVIRONMENTS.md](D:/Dev/repos/CodeScanner/docs/DEPLOYMENT_ENVIRONMENTS.md).

## Target Development Environment

Use:

- resource group: `owlvex-dev`
- region: `uksouth`
- prefix: `owlvexdev`

Expected hosted resource names:

- `owlvexdevregistry`
- `owlvexdev-db`
- `owlvexdev-plan`
- `owlvexdev-api`

## Step 1: Log Into Azure

```bash
az login
az account set --subscription c0b31fc1-52d0-4339-96ee-9915e4dfe3c4
```

## Step 2: Create The Dev Resource Group

```bash
az group create --name owlvex-dev --location uksouth
```

## Step 3: Prepare Dev Secrets

```bash
cp infra/.env.dev.example infra/.env.dev
```

Edit at least:

- `POSTGRES_ADMIN_PASSWORD`
- `SECRET_KEY`
- `ADMIN_KEY`

These values must be separate from production.

## Step 4: Deploy Dev

```bash
bash infra/deploy-dev.sh
```

This:

- provisions the Azure resources
- builds and pushes the backend image
- updates the dev Web App
- applies the database schema
- health-checks the result

## Step 4A: Preferred Local Build Path On Windows ARM

For this machine, the preferred dev build path is now:

1. start Docker Desktop
2. build a `linux/amd64` image locally
3. push it to Azure Container Registry
4. update the dev Web App to the new unique tag
5. run schema/migration checks

This avoids waiting on remote source-upload builds for normal iteration.

### Quick checks

Before using the local build path, verify Docker is actually running:

```bash
docker version
docker buildx ls
docker run --rm --platform linux/amd64 hello-world
```

If these fail, the problem is usually that Docker Desktop is not running, not that the machine is ARM.

### Recommended local image build

Use a unique image tag every time:

```bash
docker buildx build \
  --platform linux/amd64 \
  -t owlvexdevregistry.azurecr.io/owlvex-api:<unique-tag> \
  --push \
  .
```

Then update the dev Web App to that tag.

### Recommended split deploy commands

Use the same unique tag through the full dev validation path:

```bash
IMAGE_TAG=dev-20260419-1234 bash infra/build-image.sh
IMAGE_TAG=dev-20260419-1234 bash infra/deploy-app.sh
bash infra/migrate-schema.sh
```

This is the preferred loop for normal backend iteration.

### Promotion discipline

Once a dev image tag is validated, promote that exact tag to prod:

```bash
IMAGE_TAG=dev-20260419-1234 bash infra/promote-to-prod.sh
```

Do not rebuild the image separately for production promotion.

### Important note

Do not reuse old image tags for dev promotion if the backend code changed.

Unique tags are required so App Service clearly pulls the intended image and does not appear to "redeploy" stale code.

## Step 5: Capture The Dev API URL

The deploy script prints the URL at the end.

To retrieve it later:

```bash
az webapp show --name owlvexdev-api --resource-group owlvex-dev --query defaultHostName -o tsv
```

Expected shape:

- `https://owlvexdev-api.azurewebsites.net`

## Step 6: Use Dev Intentionally

Use Azure `dev` for:

- backend changes
- extension-to-backend integration testing
- dev licence and prompt-flow changes
- pricing, trial, and usage-event validation
- pre-release validation

Do not use Azure `prod` for these day-to-day tasks.

## Step 7: Use The Dev Extension Profile

For an internal dev build that defaults to Azure `dev`, package:

```bash
cd extension
npm run package:dev
```

That package defaults `owlvexDev.apiUrl` to:

- `https://owlvexdev-api.azurewebsites.net`

## Bottom Line

Owlvex should now have two explicit hosted targets:

- Azure `dev` for daily work
- Azure `prod` for external use

That split is required if production is going to stay stable enough for market trials.

The preferred operational rule is now:

- build once
- validate on `dev`
- promote the same image tag to `prod`
