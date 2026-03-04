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

echo "[0/6] Generating SSL certificate (if needed)..."
bash "$(dirname "$0")/generate-ssl.sh"

echo "[1/6] Syncing project files..."
rsync -avz --progress \
    --exclude 'node_modules' \
    --exclude '.git' \
    --exclude 'frontend/dist' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    --exclude 'venv' \
    --exclude '.env' \
    ./ "${SSH_USER}@${SERVER_IP}:${APP_DIR}/"

echo "[2/6] Ensuring .env exists on server..."
ssh "${SSH_USER}@${SERVER_IP}" bash -s <<'REMOTE_SCRIPT'
cd /home/robustidps/robustidps.ai
if [ -f .env ]; then
    echo ".env already exists — keeping existing configuration"
    exit 0
fi
echo "Creating .env with generated secrets..."
SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))" 2>/dev/null || openssl rand -base64 48 | tr -d '\n')
PG_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))" 2>/dev/null || openssl rand -base64 24 | tr -d '\n')
cat > .env <<EOF
DATABASE_URL=postgresql://robustidps:${PG_PASS}@postgres:5432/robustidps
SECRET_KEY=${SECRET}
ACCESS_TOKEN_EXPIRE_MINUTES=480
ADMIN_EMAIL=admin@robustidps.ai
ADMIN_PASSWORD=robustidps2024
CORS_ORIGINS=https://robustidps.ai
RATE_LIMIT_DEFAULT=100/minute
RATE_LIMIT_HEAVY=10/minute
MAX_UPLOAD_SIZE_MB=100
DEVICE=cpu
MC_PASSES=20
MAX_ROWS=10000
POSTGRES_DB=robustidps
POSTGRES_USER=robustidps
POSTGRES_PASSWORD=${PG_PASS}
EOF
chmod 600 .env
echo ".env created successfully (chmod 600)"
REMOTE_SCRIPT

echo "[3/6] Building Docker images on server..."
ssh "${SSH_USER}@${SERVER_IP}" "cd ${APP_DIR} && docker compose -f docker-compose.prod.yml build"

echo "[4/6] Starting services..."
ssh "${SSH_USER}@${SERVER_IP}" "cd ${APP_DIR} && docker compose -f docker-compose.prod.yml up -d"

echo "[5/6] Checking health..."
sleep 15
ssh "${SSH_USER}@${SERVER_IP}" "curl -sfk https://localhost/api/health && echo ' OK' || echo ' Backend still starting (PostgreSQL may need a moment)...'"

echo "[6/6] Verifying HTTPS..."
ssh "${SSH_USER}@${SERVER_IP}" "curl -sfk https://localhost/ > /dev/null && echo 'HTTPS OK' || echo 'HTTPS not yet responding'"

echo ""
echo "============================================"
echo "  Deployed! Visit: https://robustidps.ai"
echo "============================================"
