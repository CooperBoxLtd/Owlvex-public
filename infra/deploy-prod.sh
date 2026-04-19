#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "${SCRIPT_DIR}/.env.prod" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${SCRIPT_DIR}/.env.prod"
  set +a
fi

export DEPLOY_ENV="${DEPLOY_ENV:-production}"
export RESOURCE_GROUP="${RESOURCE_GROUP:-owlvex-prd}"
export LOCATION="${LOCATION:-uksouth}"
export PREFIX="${PREFIX:-owlvex}"

bash "${SCRIPT_DIR}/deploy.sh"
