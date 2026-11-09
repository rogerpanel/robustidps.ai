#!/usr/bin/env bash
# Run every Experiment C (RQ7) agent run in one go: both defences, both models, three repeats each.
#
#   bash scripts/run_remedy.sh /path/to/bluesec1-agent
#
# One argument: the path to your clone of the BlueSec1 reference agent (the one you pass to
# agent/install.sh). Run agent/install.sh first so the client has the --name-rule flag. The script
# writes each run straight into results/remedy/<model>-<condition>/, so nothing has to be copied or
# labelled by hand; afterwards run scripts/remedy.py (the exact command is printed at the end).
#
# Keys come from the clone's .env (ANTHROPIC_API_KEY for Claude, the OpenAI variables for GPT), exactly
# as in the single-run commands in the README. Nothing is sent anywhere else.
#
# Settings you may want to change:
#   REPEATS       number of repeats per condition (default 3)
#   MODELS        which models to run: "claude gpt", "claude", or "gpt" (default "claude gpt")
#   GPT_MODEL     the OpenAI model id as your account names it (default gpt-6-astra)
#   CONCURRENCY   tasks in flight per run (default 4)
# e.g.  REPEATS=3 MODELS="claude gpt" bash scripts/run_remedy.sh ../bluesec1-agent

set -euo pipefail

CLONE="${1:-}"
REPEATS="${REPEATS:-3}"
MODELS="${MODELS:-claude gpt}"
GPT_MODEL="${GPT_MODEL:-gpt-6-astra}"
CONCURRENCY="${CONCURRENCY:-4}"

if [ -z "$CLONE" ] || [ ! -f "$CLONE/src/bluesec1_agent/models.py" ]; then
  echo "Usage: bash scripts/run_remedy.sh /path/to/bluesec1-agent" >&2
  echo "  (the same clone you pass to agent/install.sh; run that first)" >&2
  exit 1
fi

# Absolute paths, so the script works whichever directory it is started from.
SOCGRAPH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLONE="$(cd "$CLONE" && pwd)"
PACK_CANON="$SOCGRAPH/benchmark/socgraph-21-v1.1-canon.zip"
PACK_MIMICRY="$SOCGRAPH/benchmark/socgraph-21-v1.1-mimicry.zip"
RESULTS="$SOCGRAPH/results/remedy"

if [ ! -f "$PACK_CANON" ]; then
  echo "Missing $PACK_CANON -- build the variants first:" >&2
  echo "  python3 scripts/make_variants.py --pack benchmark/socgraph-21-v1.1.zip --out benchmark" >&2
  exit 1
fi
if [ ! -f "$CLONE/.env" ]; then
  echo "No $CLONE/.env found; add your API keys there (see agent/env.robust.example)." >&2
  exit 1
fi

mkdir -p "$RESULTS"
cd "$CLONE"

# Each row: "model_tag condition provider_flags pack extra_flags"
run_one() {
  local model="$1" cond="$2" pack="$3" repeat="$4"; shift 4
  local label="${model}-${cond}-r${repeat}"
  local out="$RESULTS/${model}-${cond}"
  echo "==== ${label} ===="
  ROBUST_TRACE_DIR="$out" ROBUST_LABEL="${cond}" \
    uv run --with anthropic --with jsonschema --env-file .env \
      python -m bluesec1_agent.robust.cli --concurrency "$CONCURRENCY" --pack "$pack" "$@"
}

for model in $MODELS; do
  if [ "$model" = "claude" ]; then
    PROVIDER=(--provider anthropic)
  elif [ "$model" = "gpt" ]; then
    PROVIDER=(--provider openai --openai-api responses --model "$GPT_MODEL")
  else
    echo "unknown model '$model' (use claude and/or gpt)" >&2; exit 1
  fi
  r=1
  while [ "$r" -le "$REPEATS" ]; do
    run_one "$model" "canon"            "$PACK_CANON"   "$r" "${PROVIDER[@]}"
    run_one "$model" "namerule-mimicry" "$PACK_MIMICRY" "$r" "${PROVIDER[@]}" --name-rule
    r=$((r + 1))
  done
done

echo
echo "All runs written under $RESULTS/<model>-<condition>/."
echo "Now build the RQ7 table and macros (from $SOCGRAPH):"
cat <<EOF
  python3 scripts/remedy.py --out paper \\
      --cond "Claude Opus 5.5|v1.1|results/study/r*-full/" \\
      --cond "Claude Opus 5.5|mimicry|results/cues/*-full-mimicry/" \\
      --cond "Claude Opus 5.5|canon|results/remedy/claude-canon/*/" \\
      --cond "Claude Opus 5.5|name-rule|results/remedy/claude-namerule-mimicry/*/" \\
      --cond "GPT-6 astra|v1.1|results/models/*-gpt-6-astra-v1.1/" \\
      --cond "GPT-6 astra|mimicry|results/models/*-gpt-6-astra-mimicry/" \\
      --cond "GPT-6 astra|canon|results/remedy/gpt-canon/*/" \\
      --cond "GPT-6 astra|name-rule|results/remedy/gpt-namerule-mimicry/*/"
EOF
