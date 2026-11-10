# Distil + push automation

The `distill_and_push.py` orchestrator runs end to end:

1. Invokes `backend/distill_student.py` to retrain the INT8 ONNX student
   model from the latest `SurrogateIDS` weights.
2. Verifies the new `student_int8.onnx` + `labels.json` exist and computes
   the model's SHA-256.
3. Loads the configured fleet of edge agents (from `--agents` or the
   `ROBUSTIDPS_FLEET_AGENTS` env var) and fans out the new artefact via
   the gRPC `ApplyModelUpdate` streaming RPC.
4. Calls `GetStats` on every agent after the push so the operator can
   verify the new model is running.
5. Writes a single JSON line per run to
   `/var/log/robustidps/distill_and_push.jsonl` and prints the same JSON
   to stdout for cron mailers.

## Manual run

```bash
cd /home/robustidps/robustidps.ai

# Dry-run (verifies distill + computes SHA-256 + skips the actual push):
python3 deploy/automation/distill_and_push.py --dry-run

# Push to a single agent without redoing the distill:
python3 deploy/automation/distill_and_push.py --skip-distill --agents 37.27.31.70:50090

# Full end-to-end:
python3 deploy/automation/distill_and_push.py \
    --epochs 50 --n-train 20000 \
    --agents edge1.prod:50090,edge2.prod:50090
```

## Cron install

```bash
# Edit the MAILTO + ROBUSTIDPS_FLEET_AGENTS lines first:
sudoedit /home/robustidps/robustidps.ai/deploy/automation/crontab.example

# Install for the robustidps user:
sudo -u robustidps crontab /home/robustidps/robustidps.ai/deploy/automation/crontab.example

# Verify it landed:
sudo -u robustidps crontab -l

# Tail the log after the next run:
tail -F /var/log/robustidps/distill_and_push.jsonl
```

Cron runs every Sunday at 04:00 UTC by default. Change the schedule line
in `crontab.example` to fit your maintenance window.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Distil + push + stats all succeeded on every agent |
| 1 | At least one agent rejected the push or stat-query failed |
| 2 | A pre-push step failed (distill subprocess, missing artefact, no agents) |

Non-zero exits trigger MAILTO so the on-call notices.

## Prerequisites on the deploy host

```bash
# Python deps for the orchestrator + edge_fleet client:
pip install grpcio grpcio-tools onnx onnxruntime

# One-time protobuf stub generation (writes backend/proto/edge_pb2*.py):
bash /home/robustidps/robustidps.ai/backend/edge_proto_gen.sh

# Make sure the edge agent is listening — see deploy/systemd/.
systemctl status robustidps-edge
```

## How it interacts with the systemd units

| Unit | What `distill_and_push.py` does to it |
|---|---|
| `robustidps-edge` | Receives the ONNX bytes via gRPC; hot-swaps its `OnnxClassifier` under a `RwLock`; **no restart**. In-flight `classify()` calls finish under the old classifier; subsequent calls use the new one. |
| `robustidps-xdp` | Untouched. The XDP block list is managed separately via `/etc/robustidps/xdp-blocks.txt` + `systemctl reload-or-restart robustidps-xdp`. |

If you want the cron job to *also* push an updated block list to the
edge daemon's `OnnxAdapter`, add a `--blocks` flag to the orchestrator
or call `backend.edge_fleet.EdgeFleet.push_blocks(...)` separately.
