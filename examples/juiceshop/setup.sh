#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="${SCRIPT_DIR}/juice-shop"
REPO_URL="https://github.com/juice-shop/juice-shop.git"
JUICE_SHOP_VERSION="${JUICE_SHOP_VERSION:-master}"
IMAGE_NAME="juice-shop:local"
CONTAINER_NAME="juice-shop"
HOST_PORT="${JUICE_SHOP_PORT:-3000}"

# ── Clone / update source ──────────────────────────────────────────
if [ -d "$REPO_DIR/.git" ]; then
  echo "Pulling latest changes (version: ${JUICE_SHOP_VERSION})..."
  git -C "$REPO_DIR" fetch --depth=1 origin "$JUICE_SHOP_VERSION"
  git -C "$REPO_DIR" checkout "$JUICE_SHOP_VERSION"
else
  echo "Cloning OWASP Juice Shop source..."
  git clone --depth=1 --branch "$JUICE_SHOP_VERSION" "$REPO_URL" "$REPO_DIR"
fi

# ── Build Docker image ─────────────────────────────────────────────
echo "Building Docker image (${IMAGE_NAME})..."
docker build -t "$IMAGE_NAME" "$REPO_DIR"

# ── Remove existing container ──────────────────────────────────────
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  echo "Removing existing container..."
  docker rm -f "$CONTAINER_NAME" >/dev/null
fi

# ── Run ────────────────────────────────────────────────────────────
echo "Starting OWASP Juice Shop on http://localhost:${HOST_PORT}"
docker run -d \
  --name "$CONTAINER_NAME" \
  -p "${HOST_PORT}:3000" \
  "$IMAGE_NAME"

# ── Wait for readiness ─────────────────────────────────────────────
echo "Waiting for Juice Shop to become ready..."
until curl -sf "http://localhost:${HOST_PORT}" >/dev/null 2>&1; do
  sleep 1
done
echo "Juice Shop is running at http://localhost:${HOST_PORT}"
