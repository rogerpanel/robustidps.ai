#!/usr/bin/env bash
# Phase-A reproducible smoke run (chapter 6 §6.7).
# Trains CT-TGNN on SyntheticTEXBAT, evaluates against the six-family
# attack set, computes randomized-smoothing radius + Gronwall radius,
# and writes weights/uav_metrics.json.
#
# Expected wall-clock: ~5 min CPU, ~1 min GPU.
set -euo pipefail

# Find the backend root (4 levels up from this script's directory).
# Inside the prod container:  /app/plugins/uav/uav_defense/scripts/ → /app/
# On the host development tree: <repo>/backend/plugins/uav/uav_defense/scripts/ → <repo>/backend/
BACKEND_ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
cd "$BACKEND_ROOT"

echo "── Phase A: training CT-TGNN on SyntheticTEXBAT ──"
python -m plugins.uav.uav_defense.train \
  --n-samples 1024 \
  --batch-size 64 \
  --epochs 3 \
  --epsilon 0.0157 \
  --out weights/uav_ct_tgnn.pt

echo "── Phase A: evaluating against the six-family attack set ──"
python -m plugins.uav.uav_defense.evaluate \
  --checkpoint weights/uav_ct_tgnn.pt \
  --n-samples 512 \
  --out weights/uav_metrics.json

echo "Phase A complete → ${BACKEND_ROOT}/weights/uav_metrics.json"
