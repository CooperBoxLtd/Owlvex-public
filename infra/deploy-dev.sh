#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "${SCRIPT_DIR}/.env.dev" ]]; then
  export ENV_FILE="${SCRIPT_DIR}/.env.dev"
fi

export DEPLOY_ENV="${DEPLOY_ENV:-development}"
export RESOURCE_GROUP="${RESOURCE_GROUP:-owlvex-dev}"
export LOCATION="${LOCATION:-uksouth}"
export PREFIX="${PREFIX:-owlvexdev}"
export APP_NAME="${APP_NAME:-owlvexdev-api}"
export ACR_NAME="${ACR_NAME:-owlvexdevregistry}"
export PG_SERVER_NAME="${PG_SERVER_NAME:-owlvexdev-db}"
export ACR_USE_MANAGED_IDENTITY="${ACR_USE_MANAGED_IDENTITY:-1}"

bash "${SCRIPT_DIR}/deploy.sh"
