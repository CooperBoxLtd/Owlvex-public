#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "${SCRIPT_DIR}/.env.dev" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${SCRIPT_DIR}/.env.dev"
  set +a
fi

export DEPLOY_ENV="${DEPLOY_ENV:-development}"
export RESOURCE_GROUP="${RESOURCE_GROUP:-owlvex-dev}"
export LOCATION="${LOCATION:-uksouth}"
export PREFIX="${PREFIX:-owlvexdev}"

bash "${SCRIPT_DIR}/deploy.sh"
