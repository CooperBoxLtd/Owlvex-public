#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

trim_cr() {
  printf '%s' "${1//$'\r'/}"
}

command_supports_flag() {
  local command_name="$1"
  local flag_name="$2"
  "$command_name" --help 2>/dev/null | grep -Fq -- "${flag_name}"
}

az_template_path() {
  local path="$1"
  if command -v wslpath >/dev/null 2>&1 && command -v az >/dev/null 2>&1 && az version >/dev/null 2>&1; then
    if [[ "$(command -v az)" == *.exe ]]; then
      wslpath -w "${path}"
      return
    fi
  fi

  printf '%s\n' "${path}"
}

docker_host_path() {
  local path="$1"
  if command -v wslpath >/dev/null 2>&1; then
    wslpath -m "${path}"
    return
  fi

  printf '%s\n' "${path}"
}

load_env_file() {
  local env_file="${1:-}"
  if [[ -n "${env_file}" && -f "${env_file}" ]]; then
    if command -v python >/dev/null 2>&1; then
      while IFS= read -r -d '' key && IFS= read -r -d '' value; do
        printf -v "${key}" '%s' "${value}"
        export "${key}"
      done < <(python - "${env_file}" <<'PY'
import sys

env_file = sys.argv[1]
with open(env_file, "r", encoding="utf-8", newline="") as fh:
    for raw in fh:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        sys.stdout.write(key)
        sys.stdout.write("\0")
        sys.stdout.write(value)
        sys.stdout.write("\0")
PY
)
      return
    fi
    set -a
    # shellcheck disable=SC1090
    source "${env_file}"
    set +a
  fi
}

ensure_defaults() {
  RESOURCE_GROUP="${RESOURCE_GROUP:-owlvex-prd}"
  LOCATION="${LOCATION:-uksouth}"
  PREFIX="${PREFIX:-owlvex}"
  DEPLOY_ENV="${DEPLOY_ENV:-production}"
  IMAGE_TAG="${IMAGE_TAG:-$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo 'latest')}"
  APP_NAME="${APP_NAME:-${PREFIX}-api}"
  ACR_NAME="${ACR_NAME:-${PREFIX}registry}"
  PG_SERVER_NAME="${PG_SERVER_NAME:-${PREFIX}-db}"
  ACR_USE_MANAGED_IDENTITY="${ACR_USE_MANAGED_IDENTITY:-0}"
  FROM_EMAIL="${FROM_EMAIL:-noreply@owlvex.io}"
}

docker_available() {
  command -v docker >/dev/null 2>&1 && docker version >/dev/null 2>&1
}

resolve_acr_login_server() {
  az acr show --name "${ACR_NAME}" --resource-group "${RESOURCE_GROUP}" --query loginServer -o tsv | tr -d '\r'
}

resolve_api_url() {
  local host
  host="$(trim_cr "$(az webapp show --name "${APP_NAME}" --resource-group "${RESOURCE_GROUP}" --query defaultHostName -o tsv)")"
  printf 'https://%s\n' "${host}"
}

resolve_pg_host() {
  if [[ -n "${PG_HOST:-}" ]]; then
    printf '%s\n' "${PG_HOST}"
    return
  fi

  az postgres flexible-server show \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${PG_SERVER_NAME}" \
    --query fullyQualifiedDomainName \
    -o tsv | tr -d '\r'
}

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
  elif docker_available; then
    local sql_dir
    sql_dir="$(docker_host_path "${REPO_ROOT}/postgres/init")"
    docker run --rm \
      -e PGPASSWORD="${POSTGRES_ADMIN_PASSWORD}" \
      -v "${sql_dir}:/sql:ro" \
      postgres:16 \
      psql \
        "sslmode=require host=${pg_host} port=5432 user=owlvex dbname=owlvex" \
        --file="/sql/$(basename "${sql_file}")" \
        --no-password \
        --output /dev/null
  else
    echo "Schema step requires either psql or a working Docker daemon." >&2
    exit 1
  fi
}

run_sql_scalar() {
  local sql="$1"
  local pg_host="$2"

  if command -v psql >/dev/null 2>&1; then
    PGPASSWORD="${POSTGRES_ADMIN_PASSWORD}" psql \
      --host="${pg_host}" \
      --port=5432 \
      --username="owlvex" \
      --dbname="owlvex" \
      --command="${sql}" \
      --tuples-only \
      --no-align \
      --no-password
  elif docker_available; then
    docker run --rm \
      -e PGPASSWORD="${POSTGRES_ADMIN_PASSWORD}" \
      postgres:16 \
      psql \
        "sslmode=require host=${pg_host} port=5432 user=owlvex dbname=owlvex" \
        --command="${sql}" \
        --tuples-only \
        --no-align \
        --no-password
  else
    echo "Schema verification requires either psql or a working Docker daemon." >&2
    exit 1
  fi
}

verify_required_schema() {
  local pg_host="$1"
  local required_tables=("customers" "usage_events")
  local required_columns=(
    "customers.pending_plan"
    "customers.email_verified_at"
    "customers.verification_code_hash"
    "customers.verification_code_expires_at"
    "licences.customer_id"
  )

  echo ""
  echo "-> Verifying required schema..."

  for table_name in "${required_tables[@]}"; do
    local exists
    exists="$(run_sql_scalar "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '${table_name}');" "${pg_host}" | tr -d '\r' | xargs)"
    if [[ "${exists}" != "t" ]]; then
      echo "  x Missing required table: ${table_name}" >&2
      exit 1
    fi
    echo "  + Table present: ${table_name}"
  done

  for qualified_column in "${required_columns[@]}"; do
    local table_name="${qualified_column%%.*}"
    local column_name="${qualified_column##*.}"
    local exists
    exists="$(run_sql_scalar "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = '${table_name}' AND column_name = '${column_name}');" "${pg_host}" | tr -d '\r' | xargs)"
    if [[ "${exists}" != "t" ]]; then
      echo "  x Missing required column: ${qualified_column}" >&2
      exit 1
    fi
    echo "  + Column present: ${qualified_column}"
  done
}

apply_schema_files() {
  local pg_host="$1"
  local sql_files=(
    "${REPO_ROOT}/postgres/init/01_schema.sql"
    "${REPO_ROOT}/postgres/init/02_seed.sql"
    "${REPO_ROOT}/postgres/init/03_rules_extended.sql"
  )

  echo ""
  echo "-> Applying schema files..."
  for sql_file in "${sql_files[@]}"; do
    if [[ -f "${sql_file}" ]]; then
      run_schema_file "${sql_file}" "${pg_host}"
      echo "  + Applied: $(basename "${sql_file}")"
    fi
  done

  verify_required_schema "${pg_host}"
}

ensure_acr_pull_role() {
  local principal_id="$1"
  local acr_id="$2"
  local existing
  existing="$(az role assignment list \
    --assignee-object-id "${principal_id}" \
    --scope "${acr_id}" \
    --query "[?roleDefinitionName=='AcrPull'] | length(@)" \
    -o tsv)"

  if [[ "${existing}" == "0" ]]; then
    az role assignment create \
      --assignee-object-id "${principal_id}" \
      --assignee-principal-type ServicePrincipal \
      --scope "${acr_id}" \
      --role AcrPull \
      --output none
  fi
}

configure_managed_identity_acr_pull() {
  local acr_id
  local principal_id

  az webapp identity assign --name "${APP_NAME}" --resource-group "${RESOURCE_GROUP}" --output none
  principal_id="$(az webapp identity show --name "${APP_NAME}" --resource-group "${RESOURCE_GROUP}" --query principalId -o tsv)"
  acr_id="$(az acr show --name "${ACR_NAME}" --resource-group "${RESOURCE_GROUP}" --query id -o tsv)"

  ensure_acr_pull_role "${principal_id}" "${acr_id}"
  az webapp config set \
    --name "${APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --generic-configurations "{\"acrUseManagedIdentityCreds\":true}" \
    --output none
}

set_webapp_container_image() {
  if command_supports_flag az "--container-image-name"; then
    az webapp config container set \
      --name "${APP_NAME}" \
      --resource-group "${RESOURCE_GROUP}" \
      --container-image-name "$1" \
      --container-registry-url "https://${ACR_LOGIN_SERVER}" \
      "${@:2}" \
      --output none
    return
  fi

  az webapp config container set \
    --name "${APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --docker-custom-image-name "$1" \
    --docker-registry-server-url "https://${ACR_LOGIN_SERVER}" \
    "${@:2}" \
    --output none
}

wait_for_health() {
  local api_url="$1"
  local attempts="${2:-12}"
  local delay_seconds="${3:-10}"
  local status="000"

  echo ""
  echo "-> Waiting for health check..."

  for (( attempt=1; attempt<=attempts; attempt++ )); do
    status="$(curl -s -o /dev/null -w "%{http_code}" "${api_url}/health" || echo "000")"
    if [[ "${status}" == "200" ]]; then
      echo "  + Health check passed (HTTP ${status})"
      return 0
    fi
    echo "  ... attempt ${attempt}/${attempts}: HTTP ${status}"
    sleep "${delay_seconds}"
  done

  echo "  x Health check returned HTTP ${status} after ${attempts} attempts" >&2
  echo "    az webapp log download --name ${APP_NAME} --resource-group ${RESOURCE_GROUP} --log-file ./app-logs.zip" >&2
  exit 1
}
