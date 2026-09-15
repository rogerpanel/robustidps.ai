#!/usr/bin/env bash
# Install (or refresh) the RobustIDPS.ai systemd units on this host.
#
# Idempotent — safe to run repeatedly. Run as root:
#   sudo bash deploy/systemd/install.sh
#
# What it does:
#   1. Verifies the agent binaries are present under
#      /home/robustidps/robustidps.ai/agent/target/release/.
#   2. Copies the unit files into /etc/systemd/system/.
#   3. Creates /etc/robustidps/ + /var/lib/robustidps/ + /var/log/robustidps/.
#   4. Installs config-file templates (edge.toml + xdp-blocks.txt) — only
#      if the operator hasn't already created their own.
#   5. Runs `systemctl daemon-reload`.
#   6. Prints the enable / start commands but does NOT auto-start the
#      units — the operator chooses when to bring them up.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run as root (sudo bash deploy/systemd/install.sh)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
RELEASE_DIR="/home/robustidps/robustidps.ai/agent/target/release"

# ── 1. Sanity check the binaries ────────────────────────────────────
echo "[1/6] Checking agent binaries are built..."
missing=0
for bin in robustidps-edge robustidps-xdp; do
    if [[ ! -x "${RELEASE_DIR}/${bin}" ]]; then
        echo "  ✗ missing: ${RELEASE_DIR}/${bin}"
        missing=1
    else
        echo "  ✓ ${bin} ($(stat -c%s "${RELEASE_DIR}/${bin}") bytes)"
    fi
done
if [[ $missing -ne 0 ]]; then
    echo "ERROR: build the agent first:"
    echo "  su - robustidps -c 'cd ~/robustidps.ai/agent && cargo build --release'"
    exit 1
fi

# ── 2. Copy unit files ──────────────────────────────────────────────
echo "[2/6] Installing systemd unit files..."
for unit in robustidps-edge.service robustidps-xdp.service; do
    install -m 0644 -o root -g root \
        "${SCRIPT_DIR}/${unit}" "/etc/systemd/system/${unit}"
    echo "  ✓ /etc/systemd/system/${unit}"
done

# ── 3. Runtime directories ──────────────────────────────────────────
echo "[3/6] Creating runtime directories..."
for d in /etc/robustidps /var/lib/robustidps /var/lib/robustidps/edge \
         /var/lib/robustidps/edge/models /var/log/robustidps; do
    install -d -m 0755 -o robustidps -g robustidps "$d"
    echo "  ✓ $d"
done

# ── 4. Config templates (only if absent) ────────────────────────────
echo "[4/6] Installing config templates (skipping if present)..."
for pair in "edge.toml:edge.toml.example" "xdp-blocks.txt:xdp-blocks.txt.example"; do
    target="${pair%%:*}"
    source="${pair##*:}"
    if [[ -f "/etc/robustidps/${target}" ]]; then
        echo "  ⊙ /etc/robustidps/${target} (already exists — not overwritten)"
    else
        install -m 0644 -o robustidps -g robustidps \
            "${SCRIPT_DIR}/${source}" "/etc/robustidps/${target}"
        echo "  ✓ /etc/robustidps/${target}"
    fi
done

# ── 5. Reload systemd ───────────────────────────────────────────────
echo "[5/6] Reloading systemd..."
systemctl daemon-reload
echo "  ✓ daemon-reload done"

# ── 6. Next-step hint ──────────────────────────────────────────────
echo "[6/6] Install complete."
cat <<HINT

Next steps (run as root):

  # Inspect the units before starting:
  systemctl cat robustidps-edge
  systemctl cat robustidps-xdp

  # Bring them up (independently or together):
  systemctl enable --now robustidps-edge
  systemctl enable --now robustidps-xdp

  # Watch the journals:
  journalctl -fu robustidps-edge
  journalctl -fu robustidps-xdp

  # Status:
  systemctl status robustidps-edge robustidps-xdp

  # If the edge unit needs ONNX model files first, drop them at:
  #   /var/lib/robustidps/edge/models/student_int8.onnx
  #   /var/lib/robustidps/edge/models/labels.json
  # (run backend/distill_student.py to generate; copy via scp or
  #  push via backend/edge_fleet.py once the unit is running.)

HINT
