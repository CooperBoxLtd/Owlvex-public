#!/usr/bin/env bash
# ============================================================
# infra/deploy.sh — Owlvex Azure production deployment
#
# What this does (in order):
#   1. Creates resource group
#   2. Deploys all Azure resources via Bicep (idempotent)
#   3. Builds and pushes the Docker image to ACR
#   4. Updates the Container App to the new image
#   5. Runs the Postgres schema (first deploy only — idempotent SQL)
#   6. Prints the live API URL
#
# Prerequisites:
#   - az CLI installed and logged in (az login)
#   - Docker running
#   - All required env vars set (see .env.azure.example)
#
# Usage:
#   cp infra/.env.azure.example infra/.env.azure
#   # edit infra/.env.azure — fill in all secrets
#   source infra/.env.azure
#   bash infra/deploy.sh
#
# To deploy only a new image (no infra changes):
#   IMAGE_ONLY=1 bash infra/deploy.sh
# ============================================================

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────

RESOURCE_GROUP="${RESOURCE_GROUP:-owlvex-prod}"
LOCATION="${LOCATION:-westeurope}"
PREFIX="${PREFIX:-owlvex}"
IMAGE_TAG="${IMAGE_TAG:-$(git rev-parse --short HEAD 2>/dev/null || echo 'latest')}"
IMAGE_ONLY="${IMAGE_ONLY:-0}"

# Required secrets — must be set in environment before running
: "${POSTGRES_ADMIN_PASSWORD:?POSTGRES_ADMIN_PASSWORD is required}"
: "${SECRET_KEY:?SECRET_KEY is required}"
: "${ADMIN_KEY:?ADMIN_KEY is required}"

# Optional secrets — default to empty (Stripe/SendGrid added when ready)
STRIPE_SECRET_KEY="${STRIPE_SECRET_KEY:-}"
STRIPE_WEBHOOK_SECRET="${STRIPE_WEBHOOK_SECRET:-}"
STRIPE_PRICE_DEVELOPER_MONTHLY="${STRIPE_PRICE_DEVELOPER_MONTHLY:-}"
STRIPE_PRICE_DEVELOPER_ANNUAL="${STRIPE_PRICE_DEVELOPER_ANNUAL:-}"
STRIPE_PRICE_TEAM_MONTHLY="${STRIPE_PRICE_TEAM_MONTHLY:-}"
STRIPE_PRICE_TEAM_ANNUAL="${STRIPE_PRICE_TEAM_ANNUAL:-}"
SENDGRID_API_KEY="${SENDGRID_API_KEY:-}"
FROM_EMAIL="${FROM_EMAIL:-noreply@owlvex.io}"

ACR_NAME="${PREFIX}registry"
APP_NAME="${PREFIX}-api"

# ── Derived ───────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo ""
echo "=================================================="
echo "  Owlvex — Azure deployment"
echo "  Resource group : ${RESOURCE_GROUP}"
echo "  Location       : ${LOCATION}"
echo "  Image tag      : ${IMAGE_TAG}"
echo "  Image only     : ${IMAGE_ONLY}"
echo "=================================================="
echo ""

# ── Step 1: Resource group ────────────────────────────────────────────────

if [[ "${IMAGE_ONLY}" != "1" ]]; then
  echo "→ Creating resource group (idempotent)..."
  az group create \
    --name "${RESOURCE_GROUP}" \
    --location "${LOCATION}" \
    --output none
  echo "  ✓ Resource group: ${RESOURCE_GROUP}"
fi

# ── Step 2: Bicep deployment ──────────────────────────────────────────────

if [[ "${IMAGE_ONLY}" != "1" ]]; then
  echo ""
  echo "→ Deploying Azure resources via Bicep..."
  DEPLOY_OUTPUT=$(az deployment group create \
    --resource-group "${RESOURCE_GROUP}" \
    --template-file "${SCRIPT_DIR}/main.bicep" \
    --parameters \
        prefix="${PREFIX}" \
        postgresAdminPassword="${POSTGRES_ADMIN_PASSWORD}" \
        secretKey="${SECRET_KEY}" \
        adminKey="${ADMIN_KEY}" \
        stripeSecretKey="${STRIPE_SECRET_KEY}" \
        stripeWebhookSecret="${STRIPE_WEBHOOK_SECRET}" \
        stripePriceDeveloperMonthly="${STRIPE_PRICE_DEVELOPER_MONTHLY}" \
        stripePriceDeveloperAnnual="${STRIPE_PRICE_DEVELOPER_ANNUAL}" \
        stripePriceTeamMonthly="${STRIPE_PRICE_TEAM_MONTHLY}" \
        stripePriceTeamAnnual="${STRIPE_PRICE_TEAM_ANNUAL}" \
        sendgridApiKey="${SENDGRID_API_KEY}" \
        fromEmail="${FROM_EMAIL}" \
        imageTag="${IMAGE_TAG}" \
    --output json)

  ACR_LOGIN_SERVER=$(echo "${DEPLOY_OUTPUT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['properties']['outputs']['acrLoginServer']['value'])")
  API_URL=$(echo "${DEPLOY_OUTPUT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['properties']['outputs']['apiUrl']['value'])")
  PG_HOST=$(echo "${DEPLOY_OUTPUT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['properties']['outputs']['postgresHost']['value'])")
  echo "  ✓ ACR          : ${ACR_LOGIN_SERVER}"
  echo "  ✓ Postgres     : ${PG_HOST}"
  echo "  ✓ API URL      : ${API_URL}"
else
  # IMAGE_ONLY — derive ACR login server without re-deploying
  ACR_LOGIN_SERVER=$(az acr show --name "${ACR_NAME}" --resource-group "${RESOURCE_GROUP}" --query loginServer -o tsv)
  API_URL=$(az containerapp show --name "${APP_NAME}" --resource-group "${RESOURCE_GROUP}" --query properties.configuration.ingress.fqdn -o tsv)
  API_URL="https://${API_URL}"
fi

# ── Step 3: Build and push Docker image ──────────────────────────────────

echo ""
echo "→ Building and pushing Docker image..."
az acr login --name "${ACR_NAME}" --output none

docker build \
  --tag "${ACR_LOGIN_SERVER}/owlvex-api:${IMAGE_TAG}" \
  --tag "${ACR_LOGIN_SERVER}/owlvex-api:latest" \
  --file "${REPO_ROOT}/backend/Dockerfile" \
  "${REPO_ROOT}/backend"

docker push "${ACR_LOGIN_SERVER}/owlvex-api:${IMAGE_TAG}"
docker push "${ACR_LOGIN_SERVER}/owlvex-api:latest"
echo "  ✓ Image pushed: ${ACR_LOGIN_SERVER}/owlvex-api:${IMAGE_TAG}"

# ── Step 4: Update Container App image ───────────────────────────────────

echo ""
echo "→ Updating Container App to image ${IMAGE_TAG}..."
az containerapp update \
  --name "${APP_NAME}" \
  --resource-group "${RESOURCE_GROUP}" \
  --image "${ACR_LOGIN_SERVER}/owlvex-api:${IMAGE_TAG}" \
  --output none
echo "  ✓ Container App updated"

# ── Step 5: Apply database schema (idempotent) ────────────────────────────

if [[ "${IMAGE_ONLY}" != "1" ]]; then
  echo ""
  echo "→ Applying Postgres schema..."
  # Run schema files in order. CREATE TABLE IF NOT EXISTS / INSERT OR IGNORE — safe to re-run.
  for SQL_FILE in "${REPO_ROOT}/postgres/init/01_schema.sql" \
                  "${REPO_ROOT}/postgres/init/02_seed.sql" \
                  "${REPO_ROOT}/postgres/init/03_rules_extended.sql"; do
    if [[ -f "${SQL_FILE}" ]]; then
      PGPASSWORD="${POSTGRES_ADMIN_PASSWORD}" psql \
        --host="${PG_HOST}" \
        --port=5432 \
        --username="owlvex" \
        --dbname="owlvex" \
        --file="${SQL_FILE}" \
        --no-password \
        --output /dev/null \
        2>&1 | grep -v "^$" || true
      echo "  ✓ Applied: $(basename "${SQL_FILE}")"
    fi
  done
fi

# ── Step 6: Health check ──────────────────────────────────────────────────

echo ""
echo "→ Waiting for health check..."
sleep 10

HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${API_URL}/health" || echo "000")
if [[ "${HTTP_STATUS}" == "200" ]]; then
  echo "  ✓ Health check passed (HTTP ${HTTP_STATUS})"
else
  echo "  ✗ Health check returned HTTP ${HTTP_STATUS} — check logs:"
  echo "    az containerapp logs show --name ${APP_NAME} --resource-group ${RESOURCE_GROUP} --follow"
  exit 1
fi

# ── Done ──────────────────────────────────────────────────────────────────

echo ""
echo "=================================================="
echo "  Deployment complete"
echo ""
echo "  API URL   : ${API_URL}"
echo "  Health    : ${API_URL}/health"
echo ""
echo "  Extension setting:"
echo "    owlvex.apiUrl = ${API_URL}"
echo ""
echo "  Stripe webhook URL:"
echo "    ${API_URL}/v1/billing/webhook/stripe"
echo "=================================================="
echo ""
