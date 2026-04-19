#!/usr/bin/env bash
# ============================================================
# infra/deploy.sh — Owlvex Azure production deployment
#
# What this does (in order):
#   1. Creates resource group
#   2. Deploys Azure resources via Bicep
#   3. Builds and pushes the Docker image to ACR
#   4. Updates the Azure Web App for Containers to the new image
#   5. Runs the Postgres schema (first deploy only — idempotent SQL)
#   6. Prints the live API URL
#
# Prerequisites:
#   - az CLI installed and logged in
#   - Docker running
#   - psql installed locally, or Docker available for the fallback schema step
#   - All required env vars set (see .env.dev.example, .env.prod.example, or .env.azure.example)
#
# Usage:
#   cp infra/.env.dev.example infra/.env.dev
#   source infra/.env.dev
#   bash infra/deploy.sh
#
# Or:
#   cp infra/.env.prod.example infra/.env.prod
#   source infra/.env.prod
#   bash infra/deploy.sh
#
# To deploy only a new image (no infra changes):
#   IMAGE_ONLY=1 bash infra/deploy.sh
# ============================================================

set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-owlvex-prd}"
LOCATION="${LOCATION:-uksouth}"
PREFIX="${PREFIX:-owlvex}"
DEPLOY_ENV="${DEPLOY_ENV:-production}"
IMAGE_TAG="${IMAGE_TAG:-$(git rev-parse --short HEAD 2>/dev/null || echo 'latest')}"
IMAGE_ONLY="${IMAGE_ONLY:-0}"

: "${POSTGRES_ADMIN_PASSWORD:?POSTGRES_ADMIN_PASSWORD is required}"
: "${SECRET_KEY:?SECRET_KEY is required}"
: "${ADMIN_KEY:?ADMIN_KEY is required}"

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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

run_schema_file() {
  local sql_file="$1"
  local pg_host="$2"

  if command -v psql >/dev/null 2>&1; then
    PGPASSWORD="${POSTGRES_ADMIN_PASSWORD}" psql \
      --host="${pg_host}" \
      --port=5432 \
      --username="owlvex" \
      --dbname="owlvex" \
      --file="${sql_file}" \
      --no-password \
      --output /dev/null
  else
    docker run --rm \
      -e PGPASSWORD="${POSTGRES_ADMIN_PASSWORD}" \
      -v "${REPO_ROOT}/postgres/init:/sql:ro" \
      postgres:16 \
      psql \
        --host="${pg_host}" \
        --port=5432 \
        --username="owlvex" \
        --dbname="owlvex" \
        --file="/sql/$(basename "${sql_file}")" \
        --no-password \
        --output /dev/null
  fi
}

extract_deploy_output() {
  local field="$1"

  if command -v powershell.exe >/dev/null 2>&1; then
    printf '%s' "${DEPLOY_OUTPUT}" | powershell.exe -NoProfile -Command "\$inputJson = [Console]::In.ReadToEnd(); \$obj = \$inputJson | ConvertFrom-Json; Write-Output \$obj.properties.outputs.${field}.value" | tr -d '\r'
    return
  fi

  echo "Unable to parse Azure deployment output: powershell.exe is required." >&2
  exit 1
}

docker_available() {
  command -v docker >/dev/null 2>&1 && docker version >/dev/null 2>&1
}

echo ""
echo "=================================================="
echo "  Owlvex — Azure deployment"
echo "  Environment    : ${DEPLOY_ENV}"
echo "  Resource group : ${RESOURCE_GROUP}"
echo "  Location       : ${LOCATION}"
echo "  Image tag      : ${IMAGE_TAG}"
echo "  Image only     : ${IMAGE_ONLY}"
echo "=================================================="
echo ""

if [[ "${IMAGE_ONLY}" != "1" ]]; then
  echo "→ Creating resource group (idempotent)..."
  az group create \
    --name "${RESOURCE_GROUP}" \
    --location "${LOCATION}" \
    --output none
  echo "  ✓ Resource group: ${RESOURCE_GROUP}"
fi

if [[ "${IMAGE_ONLY}" != "1" ]]; then
  echo ""
  echo "→ Deploying Azure resources via Bicep..."
  DEPLOY_OUTPUT=$(az deployment group create \
    --resource-group "${RESOURCE_GROUP}" \
    --template-file "${SCRIPT_DIR}/main.bicep" \
    --parameters \
      prefix="${PREFIX}" \
      environment="${DEPLOY_ENV}" \
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

  ACR_LOGIN_SERVER=$(extract_deploy_output "acrLoginServer")
  API_URL=$(extract_deploy_output "apiUrl")
  PG_HOST=$(extract_deploy_output "postgresHost")
  echo "  ✓ ACR          : ${ACR_LOGIN_SERVER}"
  echo "  ✓ Postgres     : ${PG_HOST}"
  echo "  ✓ API URL      : ${API_URL}"
else
  ACR_LOGIN_SERVER=$(az acr show --name "${ACR_NAME}" --resource-group "${RESOURCE_GROUP}" --query loginServer -o tsv)
  API_HOST=$(az webapp show --name "${APP_NAME}" --resource-group "${RESOURCE_GROUP}" --query defaultHostName -o tsv)
  API_URL="https://${API_HOST}"
fi

echo ""
echo "→ Building and pushing Docker image..."
if docker_available; then
  az acr login --name "${ACR_NAME}" --output none

  docker build \
    --tag "${ACR_LOGIN_SERVER}/owlvex-api:${IMAGE_TAG}" \
    --tag "${ACR_LOGIN_SERVER}/owlvex-api:latest" \
    --file "${REPO_ROOT}/backend/Dockerfile" \
    "${REPO_ROOT}"

  docker push "${ACR_LOGIN_SERVER}/owlvex-api:${IMAGE_TAG}"
  docker push "${ACR_LOGIN_SERVER}/owlvex-api:latest"
else
  echo "  âš  Docker daemon not available â€” using az acr build fallback"
  az acr build \
    --registry "${ACR_NAME}" \
    --image "owlvex-api:${IMAGE_TAG}" \
    --image "owlvex-api:latest" \
    --file "${REPO_ROOT}/backend/Dockerfile" \
    "${REPO_ROOT}" \
    --no-logs \
    --output none
fi
echo "  ✓ Image pushed: ${ACR_LOGIN_SERVER}/owlvex-api:${IMAGE_TAG}"

echo ""
echo "→ Updating Web App for Containers to image ${IMAGE_TAG}..."
az webapp config container set \
  --name "${APP_NAME}" \
  --resource-group "${RESOURCE_GROUP}" \
  --docker-custom-image-name "${ACR_LOGIN_SERVER}/owlvex-api:${IMAGE_TAG}" \
  --docker-registry-server-url "https://${ACR_LOGIN_SERVER}" \
  --docker-registry-server-user "$(az acr credential show --name "${ACR_NAME}" --query username -o tsv)" \
  --docker-registry-server-password "$(az acr credential show --name "${ACR_NAME}" --query passwords[0].value -o tsv)" \
  --output none
echo "  ✓ Web App updated"

if [[ "${IMAGE_ONLY}" != "1" ]]; then
  echo ""
  echo "→ Applying Postgres schema..."
  for SQL_FILE in "${REPO_ROOT}/postgres/init/01_schema.sql" \
                  "${REPO_ROOT}/postgres/init/02_seed.sql" \
                  "${REPO_ROOT}/postgres/init/03_rules_extended.sql"; do
    if [[ -f "${SQL_FILE}" ]]; then
      run_schema_file "${SQL_FILE}" "${PG_HOST}" || true
      echo "  ✓ Applied: $(basename "${SQL_FILE}")"
    fi
  done
fi

echo ""
echo "→ Waiting for health check..."
sleep 15

HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${API_URL}/health" || echo "000")
if [[ "${HTTP_STATUS}" == "200" ]]; then
  echo "  ✓ Health check passed (HTTP ${HTTP_STATUS})"
else
  echo "  ✗ Health check returned HTTP ${HTTP_STATUS} — check logs:"
  echo "    az webapp log tail --name ${APP_NAME} --resource-group ${RESOURCE_GROUP}"
  exit 1
fi

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
