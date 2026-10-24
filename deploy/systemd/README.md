# systemd units for the RobustIDPS.ai Rust agents

Installs `robustidps-edge.service` and `robustidps-xdp.service` so the
two agent daemons start on boot, restart on crash, and run with exactly
the capabilities they need (no more).

## What gets installed

| Path | Purpose |
|---|---|
| `/etc/systemd/system/robustidps-edge.service` | Long-running gRPC daemon (capture → flow assembly → ONNX classifier → fleet stream) |
| `/etc/systemd/system/robustidps-xdp.service` | Kernel-level XDP fast-path drop on a configured NIC |
| `/etc/robustidps/edge.toml` | Edge-agent config (interface, model paths, gRPC bind, etc.) |
| `/etc/robustidps/xdp-blocks.txt` | XDP block list (one CIDR/IP per line, `#`-comments OK) |
| `/var/lib/robustidps/edge/models/` | Drop zone for ONNX artefacts pushed by `backend/edge_fleet.py` |
| `/var/log/robustidps/` | (Reserved — current logging goes through journald) |

## Installing

On the Hetzner box, as root:

```bash
sudo bash /home/robustidps/robustidps.ai/deploy/systemd/install.sh
```

The installer is idempotent — re-running it after a code update only
refreshes the unit files and leaves your existing `edge.toml` /
`xdp-blocks.txt` untouched.

## Bringing the services up

```bash
# Edit the configs first if you want non-defaults:
sudoedit /etc/robustidps/edge.toml
sudoedit /etc/robustidps/xdp-blocks.txt

# Start individually so you can confirm each one logs cleanly:
sudo systemctl enable --now robustidps-edge
journalctl -fu robustidps-edge       # Ctrl-C once you see "Application startup complete"

sudo systemctl enable --now robustidps-xdp
journalctl -fu robustidps-xdp        # Ctrl-C once you see "xdp attached"

# Status snapshot:
systemctl status robustidps-edge robustidps-xdp
```

## Updating the XDP block list at runtime

The unit reads `/etc/robustidps/xdp-blocks.txt` at startup. To apply a
new list:

```bash
sudoedit /etc/robustidps/xdp-blocks.txt
sudo systemctl reload-or-restart robustidps-xdp
# Brief (sub-second) detach + reattach. Use --mode skb during the
# restart window if you can't tolerate a few µs gap; otherwise the
# default --mode auto reattaches in ~100ms.
```

## Updating the ONNX model without restart

That's what the gRPC `ApplyModelUpdate` RPC is for. From the control
plane (your MacBook or the existing backend container):

```bash
~/robustidps.ai/backend/edge_proto_gen.sh    # one-time stub generation
python -m backend.edge_fleet \
  --agents 37.27.31.70:50090 \
  push-model \
  ~/robustidps.ai/agent/agent-inference/weights/student_int8.onnx \
  ~/robustidps.ai/agent/agent-inference/weights/labels.json
```

The edge daemon atomically swaps the running `OnnxClassifier` — no
service restart, no dropped flows.

## Hardening notes

Both units run as the unprivileged `robustidps` user, with
`NoNewPrivileges=yes`, `ProtectSystem=full`, `ProtectHome=read-only`,
and the minimum-needed `AmbientCapabilities`:

| Unit | Capabilities |
|---|---|
| `robustidps-edge` | `CAP_NET_RAW`, `CAP_NET_ADMIN` (drop these if running PCAP-replay only) |
| `robustidps-xdp` | `CAP_NET_ADMIN`, `CAP_BPF`, `CAP_PERFMON` (kernel ≥ 5.8 split capabilities) |

Use `systemctl edit robustidps-edge` to add an override snippet (e.g.
to drop capabilities if you're on PCAP-replay) without modifying the
shipped unit file.

## Uninstalling

```bash
sudo bash /home/robustidps/robustidps.ai/deploy/systemd/uninstall.sh
# Configs + state are kept; wipe manually if intended:
sudo rm -rf /etc/robustidps /var/lib/robustidps
```
