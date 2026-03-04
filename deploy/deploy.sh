#!/usr/bin/env bash
# ============================================================
# RobustIDPS.ai — Deploy to Hetzner Cloud
# Usage: ./deploy/deploy.sh YOUR_SERVER_IP
# ============================================================
set -euo pipefail

SERVER_IP="${1:?Usage: ./deploy/deploy.sh YOUR_SERVER_IP}"
SSH_USER="robustidps"
APP_DIR="/home/robustidps/robustidps.ai"

echo "=== Deploying to ${SERVER_IP} ==="

echo "[0/5] Generating SSL certificate (if needed)..."
bash "$(dirname "$0")/generate-ssl.sh"

echo "[1/5] Syncing project files..."
rsync -avz --progress \
    --exclude 'node_modules' \
    --exclude '.git' \
    --exclude 'frontend/dist' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    --exclude 'venv' \
    --exclude '.env' \
    ./ "${SSH_USER}@${SERVER_IP}:${APP_DIR}/"

echo "[2/5] Building Docker images on server..."
ssh "${SSH_USER}@${SERVER_IP}" "cd ${APP_DIR} && docker compose -f docker-compose.prod.yml build"

echo "[3/5] Starting services..."
ssh "${SSH_USER}@${SERVER_IP}" "cd ${APP_DIR} && docker compose -f docker-compose.prod.yml up -d"

echo "[4/5] Checking health..."
sleep 10
ssh "${SSH_USER}@${SERVER_IP}" "curl -sfk https://localhost/api/health && echo ' OK' || echo ' Backend still starting...'"

echo "[5/5] Verifying HTTPS..."
ssh "${SSH_USER}@${SERVER_IP}" "curl -sfk https://localhost/ > /dev/null && echo 'HTTPS OK' || echo 'HTTPS not yet responding'"

echo ""
echo "============================================"
echo "  Deployed! Visit: https://robustidps.ai"
echo "============================================"
