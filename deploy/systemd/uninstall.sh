#!/usr/bin/env bash
# Remove the RobustIDPS.ai systemd units. Run as root.
# Config files under /etc/robustidps/ and state under /var/lib/robustidps/
# are NOT removed — wipe those manually if intended.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run as root" >&2
    exit 1
fi

for unit in robustidps-edge robustidps-xdp; do
    if systemctl is-active --quiet "$unit"; then
        echo "stopping $unit ..."
        systemctl stop "$unit"
    fi
    if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
        echo "disabling $unit ..."
        systemctl disable "$unit"
    fi
    if [[ -f "/etc/systemd/system/${unit}.service" ]]; then
        rm -f "/etc/systemd/system/${unit}.service"
        echo "removed /etc/systemd/system/${unit}.service"
    fi
done

systemctl daemon-reload
echo "done. Config + state preserved under /etc/robustidps/ and /var/lib/robustidps/"
