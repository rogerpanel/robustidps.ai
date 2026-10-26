#!/usr/bin/env bash
# ============================================================
# RobustIDPS.ai — Hetzner Cloud Server Setup Script
# Run this on a fresh Ubuntu 22.04/24.04 Hetzner Cloud server
# Usage: ssh root@YOUR_IP 'bash -s' < deploy/setup-server.sh
# ============================================================
set -euo pipefail

echo "=== [1/6] System update ==="
apt-get update && apt-get upgrade -y

echo "=== [2/6] Install Docker ==="
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
fi

echo "=== [3/6] Install Docker Compose plugin ==="
if ! docker compose version &> /dev/null; then
    apt-get install -y docker-compose-plugin
fi

echo "=== [4/6] Create app user ==="
if ! id "robustidps" &> /dev/null; then
    useradd -m -s /bin/bash -G docker robustidps
    echo "Created user 'robustidps'"
fi

echo "=== [5/6] Setup firewall ==="
apt-get install -y ufw
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

echo "=== [6/6] Setup swap (important for 8GB RAM with PyTorch) ==="
if [ ! -f /swapfile ]; then
    fallocate -l 4G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    echo "4GB swap created"
fi

echo ""
echo "============================================"
echo "  Server ready! Next steps:"
echo "  1. Clone your repo as the robustidps user"
echo "  2. Run docker compose -f docker-compose.prod.yml up -d"
echo "============================================"
