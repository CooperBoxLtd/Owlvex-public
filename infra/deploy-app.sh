#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "${SCRIPT_DIR}/common.sh"

ENV_FILE="${ENV_FILE:-}"
load_env_file "${ENV_FILE}"
ensure_defaults

ACR_LOGIN_SERVER="$(resolve_acr_login_server)"
API_URL="$(resolve_api_url)"
CONTAINER_IMAGE="${ACR_LOGIN_SERVER}/owlvex-api:${IMAGE_TAG}"

echo ""
echo "=================================================="
echo "  Owlvex app deploy"
echo "  Environment    : ${DEPLOY_ENV}"
echo "  Web app        : ${APP_NAME}"
echo "  Image          : ${CONTAINER_IMAGE}"
echo "=================================================="
echo ""

if [[ "${ACR_USE_MANAGED_IDENTITY}" == "1" ]]; then
  echo "-> Enabling managed identity pull from ACR..."
  configure_managed_identity_acr_pull

  set_webapp_container_image "${CONTAINER_IMAGE}"
else
  echo "-> Updating Web App using registry credentials..."
  set_webapp_container_image "${CONTAINER_IMAGE}" \
    --docker-registry-server-user "$(az acr credential show --name "${ACR_NAME}" --query username -o tsv)" \
    --docker-registry-server-password "$(az acr credential show --name "${ACR_NAME}" --query passwords[0].value -o tsv)" \
fi

az webapp restart --name "${APP_NAME}" --resource-group "${RESOURCE_GROUP}" --output none
wait_for_health "${API_URL}"

echo ""
echo "App updated:"
echo "  ${API_URL}"
