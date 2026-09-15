#!/usr/bin/env bash
# Deploy the working tree to robustidps.ai @ 37.27.31.70 (Hetzner).
#
# Usage:
#   scripts/deploy-hetzner.sh                       # rsync, current branch
#   scripts/deploy-hetzner.sh <branch>              # rsync, named branch
#   scripts/deploy-hetzner.sh <branch> git          # pure git-pull on server
#   scripts/deploy-hetzner.sh <branch> rsync --no-cache=false
#
# Modes:
#   rsync   push the working tree (uncommitted changes included), rebuild
#           with --no-cache by default for a clean image
#   git     skip the upload; have the server git fetch + git pull on the
#           same branch and rebuild with layer cache (faster, idempotent)
#
# Requires on the WSL/Ubuntu/macOS host:
#   - SSH key authorised on the server for user `robustidps`
#   - rsync (for rsync mode)
set -euo pipefail

DEFAULT_BRANCH="$(git -C "$(dirname "$0")/.." rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)"
BRANCH="${1:-$DEFAULT_BRANCH}"
MODE="${2:-rsync}"

HOST="${ROBUSTIDPS_HOST:-robustidps@37.27.31.70}"
REMOTE_DIR="${ROBUSTIDPS_REMOTE_DIR:-~/robustidps.ai}"
COMPOSE_FILE="docker-compose.prod.yml"

cd "$(git rev-parse --show-toplevel)"

echo "⮕ Local: pulling $BRANCH"
git pull origin "$BRANCH"

if [[ "$MODE" == "rsync" ]]; then
  echo "⮕ rsync to $HOST:$REMOTE_DIR/"
  rsync -avz --timeout=120 \
    --exclude 'node_modules' \
    --exclude '.git' \
    --exclude 'frontend/dist' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    --exclude 'backend/weights/*.pt' \
    --exclude '*.log' \
    ./ "$HOST:$REMOTE_DIR/"

  echo "⮕ Remote: rebuild --no-cache + up -d"
  ssh "$HOST" "set -e
    cd $REMOTE_DIR
    docker compose -f $COMPOSE_FILE build --no-cache
    docker compose -f $COMPOSE_FILE up -d
    docker compose -f $COMPOSE_FILE ps"

elif [[ "$MODE" == "git" ]]; then
  echo "⮕ Remote: git pull + rebuild (layer-cached) + up -d"
  ssh "$HOST" "set -e
    cd $REMOTE_DIR
    git fetch origin
    git switch $BRANCH 2>/dev/null || git checkout $BRANCH
    git pull --ff-only origin $BRANCH
    docker compose -f $COMPOSE_FILE build
    docker compose -f $COMPOSE_FILE up -d
    docker compose -f $COMPOSE_FILE ps"

else
  echo "Unknown mode: $MODE (expected rsync | git)" >&2
  exit 2
fi

echo "⮕ Verify"
curl -skf https://robustidps.ai/api/health | head -c 200 || \
  echo "  (health check failed; check 'ssh $HOST docker compose -f $REMOTE_DIR/$COMPOSE_FILE logs backend')"
echo
echo "✓ Deploy complete — https://robustidps.ai"
