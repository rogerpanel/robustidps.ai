#!/usr/bin/env bash
# Bootstrap the chapter-6 dataset curated subsets (Tier 1).
#
# Generates ~50 MB total of synthetic-shape data into sample_data/uav/
# so the UAV operator pages can run any of the 17-dataset pipelines
# without downloading the canonical 100+ GB academic corpora.
#
# Run once on the server before the defense:
#   bash scripts/bootstrap_demo_datasets.sh
#
# Re-run with --force to regenerate (e.g., to change sample counts).
set -euo pipefail

# Locate backend root regardless of where this script is invoked from.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# In production the backend runs inside docker; exec the bootstrap
# from inside the container so PYTHONPATH resolves and the sample_data
# bind-mount is the same directory the production service reads.
if command -v docker >/dev/null 2>&1 && \
   docker compose -f "$REPO_ROOT/docker-compose.prod.yml" ps backend 2>/dev/null | grep -q "Up"; then
  echo "⮕ Generating curated subsets inside the running backend container…"
  docker compose -f "$REPO_ROOT/docker-compose.prod.yml" exec -w /app backend \
    python -m plugins.uav.demo_subsets "$@"
else
  echo "⮕ Generating curated subsets locally (no running container detected)…"
  cd "$REPO_ROOT/backend"
  python -m plugins.uav.demo_subsets "$@"
fi

echo
echo "✓ Curated subsets ready in sample_data/uav/"
ls -la "$REPO_ROOT/sample_data/uav/" 2>/dev/null || true
