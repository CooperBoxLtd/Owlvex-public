#!/usr/bin/env bash
# ============================================================
# infra/deploy.sh — Owlvex full environment deploy
#
# Full deploy does:
#   1. Create/update resource group
#   2. Deploy Azure resources via Bicep
#   3. Build and push the backend image
#   4. Update the Web App to that image
#   5. Apply schema files
#   6. Verify required schema and health
#
# For day-to-day iteration, prefer the split commands:
#   bash infra/build-image.sh
#   bash infra/deploy-app.sh
#   bash infra/migrate-schema.sh
#
# For promotion after dev validation, use:
#   IMAGE_TAG=<validated-tag> bash infra/promote-to-prod.sh
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "${SCRIPT_DIR}/common.sh"

ENV_FILE="${ENV_FILE:-}"
load_env_file "${ENV_FILE}"
ensure_defaults

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

extract_deploy_output() {
  local field="$1"

  if command -v powershell.exe >/dev/null 2>&1; then
    printf '%s' "${DEPLOY_OUTPUT}" | powershell.exe -NoProfile -Command "\$inputJson = [Console]::In.ReadToEnd(); \$obj = \$inputJson | ConvertFrom-Json; Write-Output \$obj.properties.outputs.${field}.value" | tr -d '\r'
    return
  fi

  echo "Unable to parse Azure deployment output: powershell.exe is required." >&2
  exit 1
}

echo ""
echo "=================================================="
echo "  Owlvex full deploy"
echo "  Environment    : ${DEPLOY_ENV}"
echo "  Resource group : ${RESOURCE_GROUP}"
echo "  Location       : ${LOCATION}"
echo "  Image tag      : ${IMAGE_TAG}"
echo "  Image only     : ${IMAGE_ONLY}"
echo "=================================================="
echo ""

if [[ "${IMAGE_ONLY}" != "1" ]]; then
  echo "-> Creating resource group (idempotent)..."
  az group create \
    --name "${RESOURCE_GROUP}" \
    --location "${LOCATION}" \
    --output none
  echo "  + Resource group: ${RESOURCE_GROUP}"

  echo ""
  echo "-> Deploying Azure resources via Bicep..."
  TEMPLATE_FILE="$(az_template_path "${SCRIPT_DIR}/main.bicep")"
  DEPLOY_OUTPUT="$(az deployment group create \
    --resource-group "${RESOURCE_GROUP}" \
    --template-file "${TEMPLATE_FILE}" \
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
    --output json)"

  echo "  + ACR      : $(extract_deploy_output "acrLoginServer")"
  echo "  + Postgres : $(extract_deploy_output "postgresHost")"
  echo "  + API URL  : $(extract_deploy_output "apiUrl")"
fi

bash "${SCRIPT_DIR}/build-image.sh"
bash "${SCRIPT_DIR}/deploy-app.sh"
bash "${SCRIPT_DIR}/migrate-schema.sh"
