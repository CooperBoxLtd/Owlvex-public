#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "${SCRIPT_DIR}/common.sh"

ENV_FILE="${ENV_FILE:-}"
load_env_file "${ENV_FILE}"
ensure_defaults

: "${POSTGRES_ADMIN_PASSWORD:?POSTGRES_ADMIN_PASSWORD is required}"

PG_HOST="$(resolve_pg_host)"

echo ""
echo "=================================================="
echo "  Owlvex schema migration"
echo "  Environment    : ${DEPLOY_ENV}"
echo "  Resource group : ${RESOURCE_GROUP}"
echo "  Postgres host  : ${PG_HOST}"
echo "=================================================="
echo ""

apply_schema_files "${PG_HOST}"

echo ""
echo "Schema verified for ${DEPLOY_ENV}."

