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

echo "[1/4] Syncing project files..."
rsync -avz --progress \
    --exclude 'node_modules' \
    --exclude '.git' \
    --exclude 'frontend/dist' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    --exclude 'venv' \
    --exclude '.env' \
    ./ "${SSH_USER}@${SERVER_IP}:${APP_DIR}/"

echo "[2/4] Building Docker images on server..."
ssh "${SSH_USER}@${SERVER_IP}" "cd ${APP_DIR} && docker compose -f docker-compose.prod.yml build"

echo "[3/4] Starting services..."
ssh "${SSH_USER}@${SERVER_IP}" "cd ${APP_DIR} && docker compose -f docker-compose.prod.yml up -d"

echo "[4/4] Checking health..."
sleep 10
ssh "${SSH_USER}@${SERVER_IP}" "curl -sf http://localhost/api/health && echo ' OK' || echo ' Backend still starting...'"

echo ""
echo "============================================"
echo "  Deployed! Visit: http://${SERVER_IP}"
echo "  After Cloudflare DNS: https://robustidps.ai"
echo "============================================"
