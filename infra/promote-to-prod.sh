#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "${IMAGE_TAG:-}" ]]; then
  echo "IMAGE_TAG is required. Promote the exact dev-validated image tag to prod." >&2
  exit 1
fi

if [[ -f "${SCRIPT_DIR}/.env.prod" ]]; then
  export ENV_FILE="${SCRIPT_DIR}/.env.prod"
fi

export DEPLOY_ENV="${DEPLOY_ENV:-production}"
export RESOURCE_GROUP="${RESOURCE_GROUP:-owlvex-prd}"
export LOCATION="${LOCATION:-uksouth}"
export PREFIX="${PREFIX:-owlvex}"
export APP_NAME="${APP_NAME:-owlvex-api}"
export ACR_NAME="${ACR_NAME:-owlvexregistry}"
export PG_SERVER_NAME="${PG_SERVER_NAME:-owlvex-dbserver}"
export ACR_USE_MANAGED_IDENTITY="${ACR_USE_MANAGED_IDENTITY:-1}"

bash "${SCRIPT_DIR}/deploy-app.sh"
bash "${SCRIPT_DIR}/migrate-schema.sh"

