#!/usr/bin/env bash
# Phase-A reproducible smoke run (chapter 6 §6.7).
# Trains CT-TGNN on SyntheticTEXBAT, evaluates against the six-family
# attack set, computes randomized-smoothing radius + Gronwall radius,
# and writes weights/uav_metrics.json.
#
# Expected wall-clock: ~5 min CPU, ~1 min GPU.
set -euo pipefail

cd "$(dirname "$0")/../.." 2>/dev/null || cd "$(dirname "$0")/../../.."

python -m plugins.uav.uav_defense.train \
  --n-samples 1024 \
  --batch-size 64 \
  --epochs 3 \
  --epsilon 0.0157 \
  --out weights/uav_ct_tgnn.pt

python -m plugins.uav.uav_defense.evaluate \
  --checkpoint weights/uav_ct_tgnn.pt \
  --n-samples 512 \
  --out weights/uav_metrics.json

echo "Phase A complete -> weights/uav_metrics.json"
