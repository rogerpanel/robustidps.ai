#!/usr/bin/env bash
# Install the RobustIDPS agent into a clone of the BlueSec1 reference agent.
#   bash bluesec/install.sh /path/to/bluesec1-agent
# The reference client and agent are left untouched; ours is added as
# src/bluesec1_agent/robust/ plus one test file.
set -euo pipefail

TARGET="${1:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -z "$TARGET" ] || [ ! -f "$TARGET/src/bluesec1_agent/models.py" ]; then
  echo "Usage: bash $0 /path/to/bluesec1-agent   (a clone of the reference agent)" >&2
  exit 1
fi

rm -rf "$TARGET/src/bluesec1_agent/robust"
cp -r "$HERE/robust" "$TARGET/src/bluesec1_agent/robust"
find "$TARGET/src/bluesec1_agent/robust" -name __pycache__ -prune -exec rm -rf {} +
cp "$HERE/tests/test_robust_agent.py" "$TARGET/tests/test_robust_agent.py"

cat <<EOF
Installed into $TARGET/src/bluesec1_agent/robust

Next:
  cd $TARGET
  uv sync
  uv run --with anthropic --with jsonschema pytest            # all tests, ours included
  # add the variables from $HERE/env.robust.example to .env, then:
  uv run --with anthropic --with jsonschema --env-file .env python -m bluesec1_agent.robust.cli --mock
  uv run --with anthropic --with jsonschema --env-file .env python -m bluesec1_agent.robust.cli --arena practice
EOF
