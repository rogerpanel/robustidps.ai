#!/bin/bash
# ============================================================================
# RobustIDPS.ai — Cloudflare Tunnel Setup
# ============================================================================
#
# This script sets up a Cloudflare Tunnel to expose robustidps.ai through
# Cloudflare's network, providing:
#   - Bypass of network restrictions (ISP/firewall/country blocks)
#   - DDoS protection
#   - Global CDN edge caching for static assets
#   - Free SSL/TLS termination
#   - No need for users to install VPN software
#
# Prerequisites:
#   1. A Cloudflare account (free tier works)
#   2. Your domain (robustidps.ai) added to Cloudflare DNS
#   3. Run this script on your server (37.27.31.70)
#
# Usage:
#   chmod +x deploy/setup-cloudflare-tunnel.sh
#   sudo ./deploy/setup-cloudflare-tunnel.sh
#
# ============================================================================

set -euo pipefail

TUNNEL_NAME="robustidps"
DOMAIN="robustidps.ai"
BACKEND_PORT=8000
FRONTEND_PORT=443

echo "============================================"
echo " RobustIDPS.ai Cloudflare Tunnel Setup"
echo "============================================"
echo ""

# Step 1: Install cloudflared
echo "[1/5] Installing cloudflared..."
if ! command -v cloudflared &> /dev/null; then
    # Detect architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) CF_ARCH="amd64" ;;
        aarch64) CF_ARCH="arm64" ;;
        *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    curl -L "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CF_ARCH}.deb" -o /tmp/cloudflared.deb
    dpkg -i /tmp/cloudflared.deb || apt-get install -f -y
    rm -f /tmp/cloudflared.deb
    echo "  cloudflared installed successfully"
else
    echo "  cloudflared already installed: $(cloudflared --version)"
fi

# Step 2: Authenticate with Cloudflare
echo ""
echo "[2/5] Authenticating with Cloudflare..."
echo "  A browser window will open. Log in and authorize the tunnel."
echo "  If running headless, copy the URL shown and open it in your browser."
echo ""

if [ ! -f ~/.cloudflared/cert.pem ]; then
    cloudflared tunnel login
    echo "  Authentication successful"
else
    echo "  Already authenticated (cert.pem exists)"
fi

# Step 3: Create the tunnel
echo ""
echo "[3/5] Creating tunnel '${TUNNEL_NAME}'..."

EXISTING=$(cloudflared tunnel list 2>/dev/null | grep "${TUNNEL_NAME}" | awk '{print $1}' || true)
if [ -n "$EXISTING" ]; then
    TUNNEL_ID="$EXISTING"
    echo "  Tunnel already exists: ${TUNNEL_ID}"
else
    cloudflared tunnel create "${TUNNEL_NAME}"
    TUNNEL_ID=$(cloudflared tunnel list | grep "${TUNNEL_NAME}" | awk '{print $1}')
    echo "  Tunnel created: ${TUNNEL_ID}"
fi

# Step 4: Create tunnel config
echo ""
echo "[4/5] Creating tunnel configuration..."

CREDENTIALS_FILE=$(ls ~/.cloudflared/${TUNNEL_ID}.json 2>/dev/null || echo "")
if [ -z "$CREDENTIALS_FILE" ]; then
    CREDENTIALS_FILE="$HOME/.cloudflared/${TUNNEL_ID}.json"
fi

cat > ~/.cloudflared/config.yml << EOF
tunnel: ${TUNNEL_ID}
credentials-file: ${CREDENTIALS_FILE}

ingress:
  # Frontend (nginx serves on 443)
  - hostname: ${DOMAIN}
    service: https://localhost:${FRONTEND_PORT}
    originRequest:
      noTLSVerify: true

  # API (FastAPI on 8000)
  - hostname: api.${DOMAIN}
    service: http://localhost:${BACKEND_PORT}

  # WebSocket support for Live Monitor
  - hostname: ws.${DOMAIN}
    service: http://localhost:${BACKEND_PORT}
    originRequest:
      noTLSVerify: true

  # Catch-all
  - service: http_status:404
EOF

echo "  Config written to ~/.cloudflared/config.yml"

# Step 5: Set up DNS routes
echo ""
echo "[5/5] Setting up DNS routes..."
cloudflared tunnel route dns "${TUNNEL_NAME}" "${DOMAIN}" 2>/dev/null || echo "  DNS route for ${DOMAIN} already exists"
cloudflared tunnel route dns "${TUNNEL_NAME}" "api.${DOMAIN}" 2>/dev/null || echo "  DNS route for api.${DOMAIN} already exists"

echo ""
echo "============================================"
echo " Setup Complete!"
echo "============================================"
echo ""
echo " To start the tunnel manually:"
echo "   cloudflared tunnel run ${TUNNEL_NAME}"
echo ""
echo " To install as a system service (recommended):"
echo "   sudo cloudflared service install"
echo "   sudo systemctl enable cloudflared"
echo "   sudo systemctl start cloudflared"
echo ""
echo " To check tunnel status:"
echo "   cloudflared tunnel info ${TUNNEL_NAME}"
echo ""
echo " Users can now access the app at:"
echo "   https://${DOMAIN}"
echo ""
echo " No VPN required — traffic routes through Cloudflare's CDN"
echo "============================================"
