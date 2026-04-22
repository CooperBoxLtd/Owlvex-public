#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "${SCRIPT_DIR}/common.sh"

ENV_FILE="${ENV_FILE:-}"
load_env_file "${ENV_FILE}"
ensure_defaults

ACR_LOGIN_SERVER="$(resolve_acr_login_server)"
BUILDX_BUILDER="${BUILDX_BUILDER:-owlvex-cross}"

ensure_cross_builder() {
  if docker buildx inspect "${BUILDX_BUILDER}" >/dev/null 2>&1; then
    docker buildx inspect "${BUILDX_BUILDER}" --bootstrap >/dev/null
    return
  fi

  echo "-> Preparing docker buildx cross builder (${BUILDX_BUILDER})..."
  docker run --privileged --rm tonistiigi/binfmt --install amd64 >/dev/null
  docker buildx create --name "${BUILDX_BUILDER}" --driver docker-container --use >/dev/null 2>&1 || docker buildx use "${BUILDX_BUILDER}" >/dev/null
  docker buildx inspect "${BUILDX_BUILDER}" --bootstrap >/dev/null
}

echo ""
echo "=================================================="
echo "  Owlvex image build"
echo "  Environment    : ${DEPLOY_ENV}"
echo "  Resource group : ${RESOURCE_GROUP}"
echo "  Registry       : ${ACR_NAME}"
echo "  Image tag      : ${IMAGE_TAG}"
echo "=================================================="
echo ""

if docker_available; then
  echo "-> Building locally with docker buildx (linux/amd64)..."
  az acr login --name "${ACR_NAME}" --output none
  ensure_cross_builder
  docker buildx build \
    --builder "${BUILDX_BUILDER}" \
    --platform linux/amd64 \
    --tag "${ACR_LOGIN_SERVER}/owlvex-api:${IMAGE_TAG}" \
    --tag "${ACR_LOGIN_SERVER}/owlvex-api:latest" \
    --file "${REPO_ROOT}/backend/Dockerfile" \
    --push \
    "${REPO_ROOT}"
else
  echo "-> Docker daemon unavailable, using az acr build fallback..."
  az acr build \
    --registry "${ACR_NAME}" \
    --image "owlvex-api:${IMAGE_TAG}" \
    --image "owlvex-api:latest" \
    --file "${REPO_ROOT}/backend/Dockerfile" \
    "${REPO_ROOT}" \
    --no-logs \
    --output none
fi

echo ""
echo "Built image:"
echo "  ${ACR_LOGIN_SERVER}/owlvex-api:${IMAGE_TAG}"
