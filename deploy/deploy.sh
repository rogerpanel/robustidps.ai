#!/usr/bin/env bash
# ============================================================
# RobustIDPS.ai — Deploy to Hetzner Cloud
# Usage: ./deploy/deploy.sh YOUR_SERVER_IP
# ============================================================
set -euo pipefail

SERVER_IP="${1:?Usage: ./deploy/deploy.sh YOUR_SERVER_IP}"
SSH_USER="robustidps"
APP_DIR="/home/robustidps/robustidps.ai"

# ── SSH connection multiplexing (reuse one connection for all steps) ──
SSH_CONTROL_DIR=$(mktemp -d)
SSH_CONTROL_PATH="${SSH_CONTROL_DIR}/ssh-%r@%h:%p"
SSH_OPTS="-o ControlMaster=auto -o ControlPath=${SSH_CONTROL_PATH} -o ControlPersist=300 -o ConnectTimeout=30 -o ServerAliveInterval=15 -o ServerAliveCountMax=4"
export RSYNC_RSH="ssh ${SSH_OPTS}"

cleanup_ssh() {
    ssh -O exit -o ControlPath="${SSH_CONTROL_PATH}" "${SSH_USER}@${SERVER_IP}" 2>/dev/null || true
    rm -rf "${SSH_CONTROL_DIR}"
}
trap cleanup_ssh EXIT

# Helper: ssh with multiplexing options
remote() {
    ssh ${SSH_OPTS} "${SSH_USER}@${SERVER_IP}" "$@"
}

echo "=== Deploying to ${SERVER_IP} ==="

# Pre-flight: establish the master SSH connection
echo "Establishing SSH connection..."
if ! ssh ${SSH_OPTS} -fN "${SSH_USER}@${SERVER_IP}"; then
    echo "ERROR: Cannot connect to ${SERVER_IP} via SSH."
    echo "  Check that the server is reachable and SSH is running."
    exit 1
fi
echo "  ✓ SSH connection established"

# ── Step 0: Validate SSL certificates locally ───────────────
echo "[0/7] Validating SSL certificates..."
SSL_DIR="$(dirname "$0")/ssl"

if [ ! -f "$SSL_DIR/origin.crt" ] || [ ! -f "$SSL_DIR/origin.key" ]; then
    echo ""
    echo "ERROR: SSL certificates not found!"
    echo ""
    echo "Please set up Cloudflare Origin CA certificates first:"
    echo "  1. Go to Cloudflare Dashboard → SSL/TLS → Origin Server"
    echo "  2. Click 'Create Certificate'"
    echo "  3. Save certificate to: $SSL_DIR/origin.crt"
    echo "  4. Save private key to: $SSL_DIR/origin.key"
    echo ""
    echo "Or for quick testing (shows browser warnings):"
    echo "  ./deploy/generate-ssl.sh --self-signed"
    exit 1
fi

# Validate certificate format
if ! openssl x509 -in "$SSL_DIR/origin.crt" -noout 2>/dev/null; then
    echo "ERROR: $SSL_DIR/origin.crt is not a valid PEM certificate!"
    echo ""
    echo "Make sure the file starts with '-----BEGIN CERTIFICATE-----'"
    echo "and ends with '-----END CERTIFICATE-----'"
    echo "with no extra whitespace or characters."
    exit 1
fi

# Validate private key format
if ! openssl rsa -in "$SSL_DIR/origin.key" -check -noout 2>/dev/null && \
   ! openssl ec -in "$SSL_DIR/origin.key" -check -noout 2>/dev/null; then
    echo "ERROR: $SSL_DIR/origin.key is not a valid PEM private key!"
    echo ""
    echo "Make sure the file starts with '-----BEGIN PRIVATE KEY-----'"
    echo "or '-----BEGIN RSA PRIVATE KEY-----'"
    echo "with no extra whitespace or characters."
    exit 1
fi

# Verify cert matches key
CERT_MOD=$(openssl x509 -in "$SSL_DIR/origin.crt" -modulus -noout 2>/dev/null | openssl md5)
KEY_MOD=$(openssl rsa -in "$SSL_DIR/origin.key" -modulus -noout 2>/dev/null | openssl md5)
if [ "$CERT_MOD" != "$KEY_MOD" ]; then
    echo "ERROR: Certificate and private key do not match!"
    echo "  The origin.crt and origin.key must be from the same keypair."
    exit 1
fi

# Check certificate details
ISSUER=$(openssl x509 -in "$SSL_DIR/origin.crt" -noout -issuer 2>/dev/null)
SUBJECT=$(openssl x509 -in "$SSL_DIR/origin.crt" -noout -subject 2>/dev/null)
EXPIRY=$(openssl x509 -in "$SSL_DIR/origin.crt" -noout -enddate 2>/dev/null)

if echo "$ISSUER" | grep -qi "cloudflare"; then
    echo "  ✓ Cloudflare Origin CA certificate detected"
else
    echo "  ⚠ Non-Cloudflare certificate detected (self-signed or other CA)"
    echo "    $ISSUER"
    echo "    For Full (Strict) mode, use Cloudflare Origin CA certificates."
fi
echo "  Subject: $SUBJECT"
echo "  Expires: $EXPIRY"

# Verify hostname in certificate
if ! openssl x509 -in "$SSL_DIR/origin.crt" -noout -text 2>/dev/null | grep -q "robustidps.ai"; then
    echo "  ⚠ WARNING: Certificate may not cover robustidps.ai"
    echo "    SANs in certificate:"
    openssl x509 -in "$SSL_DIR/origin.crt" -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name" || echo "    (none found)"
fi

echo "  ✓ Certificate and key are valid and match"

# ── Step 1: Sync files ──────────────────────────────────────
echo "[1/7] Syncing project files..."
rsync -avz --progress --timeout=60 \
    --exclude 'node_modules' \
    --exclude '.git' \
    --exclude 'frontend/dist' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    --exclude 'venv' \
    --exclude '.env' \
    ./ "${SSH_USER}@${SERVER_IP}:${APP_DIR}/"

# ── Step 2: Environment setup ───────────────────────────────
echo "[2/7] Ensuring .env exists on server..."
remote bash -s <<'REMOTE_SCRIPT'
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
ADMIN_PASSWORD=R1\$
CORS_ORIGINS=https://robustidps.ai,https://37.27.31.70,http://37.27.31.70
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

# ── Step 3: Build ────────────────────────────────────────────
echo "[3/7] Building Docker images on server..."
remote "cd ${APP_DIR} && docker compose -f docker-compose.prod.yml build"

# ── Step 4: Start services ───────────────────────────────────
echo "[4/7] Starting services..."
remote "cd ${APP_DIR} && docker compose -f docker-compose.prod.yml up -d"

# ── Step 5: Force-restart nginx to load new SSL certs ────────
echo "[5/7] Restarting nginx to load SSL certificates..."
remote "cd ${APP_DIR} && docker compose -f docker-compose.prod.yml restart frontend"
sleep 5

# ── Step 6: Verify SSL on origin ─────────────────────────────
echo "[6/7] Verifying SSL certificate on origin..."
remote bash -s <<'SSL_CHECK'
echo "--- Checking nginx SSL ---"
# Test that nginx is serving SSL
SSL_INFO=$(echo | openssl s_client -connect localhost:443 -servername robustidps.ai 2>/dev/null | openssl x509 -noout -issuer -subject -dates 2>/dev/null)
if [ -n "$SSL_INFO" ]; then
    echo "$SSL_INFO"
    echo "✓ SSL certificate is being served by nginx"
else
    echo "✗ Could not retrieve SSL certificate from nginx"
    echo "  Checking nginx logs for errors..."
    docker logs --tail 20 $(docker ps -q -f name=frontend) 2>&1 | grep -i "ssl\|error\|emerg" || echo "  (no SSL errors found in recent logs)"
fi

# Health check
echo ""
echo "--- Health check ---"
curl -sfk https://localhost/api/health && echo ' ✓ Backend healthy' || echo ' ✗ Backend not responding (may still be starting)'
SSL_CHECK

# ── Step 7: Final verification ────────────────────────────────
echo "[7/7] Verifying HTTPS..."
remote "curl -sfk https://localhost/ > /dev/null && echo 'HTTPS OK' || echo 'HTTPS not yet responding'"

echo ""
echo "============================================"
echo "  Deployed! Visit: https://robustidps.ai"
echo "============================================"
echo ""
echo "If you see Cloudflare Error 526:"
echo "  1. Verify SSL mode is 'Full (Strict)' in Cloudflare Dashboard"
echo "  2. Verify DNS records are Proxied (orange cloud)"
echo "  3. Check that the Origin CA cert was created for robustidps.ai"
echo "  4. Run: ssh ${SSH_USER}@${SERVER_IP} 'echo | openssl s_client -connect localhost:443 -servername robustidps.ai 2>/dev/null | openssl x509 -noout -issuer -subject'"
