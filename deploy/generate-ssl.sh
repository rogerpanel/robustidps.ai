#!/usr/bin/env bash
# ============================================================
# Generate a self-signed SSL certificate for Cloudflare Full mode
# Cloudflare Full mode requires HTTPS on the origin but does NOT
# validate the certificate, so a self-signed cert works fine.
#
# Usage: ./deploy/generate-ssl.sh
# Output: deploy/ssl/origin.crt and deploy/ssl/origin.key
# ============================================================
set -euo pipefail

SSL_DIR="$(dirname "$0")/ssl"
mkdir -p "$SSL_DIR"

if [ -f "$SSL_DIR/origin.crt" ] && [ -f "$SSL_DIR/origin.key" ]; then
    echo "SSL certificates already exist in $SSL_DIR"
    echo "To regenerate, delete them first: rm $SSL_DIR/origin.*"
    exit 0
fi

echo "Generating self-signed SSL certificate for robustidps.ai..."

openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 \
    -keyout "$SSL_DIR/origin.key" \
    -out "$SSL_DIR/origin.crt" \
    -subj "/C=US/ST=State/L=City/O=RobustIDPS/CN=robustidps.ai" \
    -addext "subjectAltName=DNS:robustidps.ai,DNS:www.robustidps.ai"

chmod 600 "$SSL_DIR/origin.key"
chmod 644 "$SSL_DIR/origin.crt"

echo "Done! Certificates generated:"
echo "  Certificate: $SSL_DIR/origin.crt"
echo "  Private key: $SSL_DIR/origin.key"
echo ""
echo "Now set Cloudflare SSL/TLS mode to 'Full' in the dashboard."
