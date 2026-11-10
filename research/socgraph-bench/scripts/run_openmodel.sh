#!/usr/bin/env bash
# Experiment D (RQ6, review item D): run the SAME agent with a third, open-weight model on SOCGraph-21 v1.1
# and on the mimicry variant, three repeats each, to test whether the name-shortcut effect generalises beyond
# the two closed models.
#
#   OPEN_MODEL="<model id as your endpoint names it>" bash scripts/run_openmodel.sh /path/to/bluesec1-agent
#
# This changes nothing about the agent: it is the ordinary OpenAI-compatible path (ROBUST_PROVIDER=openai,
# LLM_API=chat), pointed at an open-weight model served behind an OpenAI-compatible endpoint (vLLM, Together,
# Fireworks, OpenRouter, a local server, ...). The endpoint must support tool/function calling, since the agent
# drives the investigation through tools. No attack content is generated; this is a defensive-agent evaluation.
#
# The open model's endpoint and key come from the clone's .env (same file as the other runs):
#   LLM_BASE_URL=https://your-endpoint/v1
#   LLM_API_KEY=...                       # a real key, or a placeholder if the endpoint needs none
# (ANTHROPIC_* / the GPT LLM_* vars are not used here.)
#
# Settings you may want to change (environment variables):
#   OPEN_MODEL    REQUIRED: the model id your endpoint expects, e.g. "Qwen/Qwen3-72B-Instruct",
#                 "meta-llama/Llama-4-Scout-17B-16E-Instruct", "deepseek-ai/DeepSeek-V3.1".
#   MODEL_TAG     short filesystem-safe label used in the result folder names (default: derived from OPEN_MODEL).
#   MODEL_NAME    display name for the paper table (default: OPEN_MODEL).
#   REPEATS       repeats per condition (default 3).
#   CONCURRENCY   tasks in flight per run (default 4).
#   REASONING_EFFORT   if your endpoint accepts it, e.g. "high"; unset by default (most open endpoints ignore it).

set -euo pipefail

CLONE="${1:-}"
OPEN_MODEL="${OPEN_MODEL:-}"
REPEATS="${REPEATS:-3}"
CONCURRENCY="${CONCURRENCY:-4}"

if [ -z "$CLONE" ] || [ ! -f "$CLONE/src/bluesec1_agent/models.py" ]; then
  echo "Usage: OPEN_MODEL=... bash scripts/run_openmodel.sh /path/to/bluesec1-agent" >&2
  echo "  (the same clone you pass to agent/install.sh; run that first)" >&2
  exit 1
fi
if [ -z "$OPEN_MODEL" ]; then
  echo "Set OPEN_MODEL to the open-weight model id your endpoint expects, e.g." >&2
  echo "  OPEN_MODEL=\"Qwen/Qwen3-72B-Instruct\" bash scripts/run_openmodel.sh $CLONE" >&2
  exit 1
fi

# A filesystem-safe tag and a display name.
MODEL_TAG="${MODEL_TAG:-$(printf '%s' "$OPEN_MODEL" | tr -c 'A-Za-z0-9._-' '-' | sed 's/-\{2,\}/-/g; s/^-//; s/-$//')}"
MODEL_NAME="${MODEL_NAME:-$OPEN_MODEL}"

SOCGRAPH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLONE="$(cd "$CLONE" && pwd)"
PACK_V11="$SOCGRAPH/benchmark/socgraph-21-v1.1.zip"
PACK_MIMICRY="$SOCGRAPH/benchmark/socgraph-21-v1.1-mimicry.zip"
RESULTS="$SOCGRAPH/results/openmodel"

for p in "$PACK_V11" "$PACK_MIMICRY"; do
  if [ ! -f "$p" ]; then
    echo "Missing $p -- build the variants first:" >&2
    echo "  python3 scripts/make_variants.py --pack benchmark/socgraph-21-v1.1.zip --out benchmark" >&2
    exit 1
  fi
done
if [ ! -f "$CLONE/.env" ]; then
  echo "No $CLONE/.env found; add LLM_BASE_URL and LLM_API_KEY for your open-model endpoint." >&2
  exit 1
fi

mkdir -p "$RESULTS"
cd "$CLONE"

run_one() {
  local cond="$1" pack="$2" repeat="$3"
  local out="$RESULTS/${MODEL_TAG}-${cond}"
  echo "==== ${MODEL_TAG} ${cond} r${repeat} ===="
  ROBUST_TRACE_DIR="$out" ROBUST_LABEL="${cond}" \
    uv run --with anthropic --with jsonschema --env-file .env \
      python -m bluesec1_agent.robust.cli --concurrency "$CONCURRENCY" --pack "$pack" \
        --provider openai --openai-api chat --model "$OPEN_MODEL" \
        ${REASONING_EFFORT:+--effort "$REASONING_EFFORT"}
}

r=1
while [ "$r" -le "$REPEATS" ]; do
  run_one "v1.1"    "$PACK_V11"     "$r"
  run_one "mimicry" "$PACK_MIMICRY" "$r"
  r=$((r + 1))
done

echo
echo "All runs written under $RESULTS/${MODEL_TAG}-{v1.1,mimicry}/."
echo "Now regenerate the model-comparison table and macros with all three models (from $SOCGRAPH):"
cat <<EOF
  python3 scripts/model_compare.py --pack benchmark/socgraph-21-v1.1.zip \\
      --run "Claude Opus 5.5|v1.1|results/study/r*-full/" \\
      --run "Claude Opus 5.5|mimicry|results/cues/*-full-mimicry/" \\
      --run "GPT-6 astra|v1.1|results/models/*-gpt-6-astra-v1.1/" \\
      --run "GPT-6 astra|mimicry|results/models/*-gpt-6-astra-mimicry/" \\
      --run "${MODEL_NAME}|v1.1|results/openmodel/${MODEL_TAG}-v1.1/*/" \\
      --run "${MODEL_NAME}|mimicry|results/openmodel/${MODEL_TAG}-mimicry/*/" --out paper
EOF
