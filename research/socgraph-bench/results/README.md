# Results

| Folder | Content |
|---|---|
| `pilot-2026-10-10/` | first real-model run, 11 Windows tasks (see its README) |
| `run1-2026-10-11-v1.0/` | study run 1 as scored on v1.0 (console output); superseded, kept for the record |
| `study/` | the study runs scored on SOCGraph-21 v1.1: one folder per run (`r<repeat>-<configuration>`), each with a `summary.json` |
| `console/` | the console output the `study/` folders were built from (`scripts/console_to_runs.py`) |

## Protocol

Three repeats of the ablation suite on v1.1 (18 runs of 21 tasks). Run 1 was
made on v1.0 and is rescored; runs 2 and 3 are new.

On the server, in `~/bluesec1-agent`, after updating the agent
(`bash ~/robustidps.ai/bluesec/install.sh ~/bluesec1-agent`):

```bash
PACK=~/robustidps.ai/research/socgraph-bench/benchmark/socgraph-21-v1.1.zip

# 1. Rescore run 1 (offline, no model calls): writes <folder>-rescored-v1.1/
uv run --with anthropic --with jsonschema python -m bluesec1_agent.robust.cli \
    --pack $PACK --rescore traces/20261011-202239-local-run traces/20261011-202438-local-run \
    traces/20261011-202650-local-run traces/20261011-202900-local-run \
    traces/20261011-203105-local-run traces/20261011-203315-local-run

# 2. Runs 2 and 3
for i in 2 3; do
  uv run --with anthropic --with jsonschema --env-file .env \
      python -m bluesec1_agent.robust.cli --pack $PACK --concurrency 4 --ablation-suite
done
```

Copy into `study/`: the five rescored run-1 folders other than
`no validation` (that configuration's run 1 lost a task to the v1.0 runtime
crash described in `run1-2026-10-11-v1.0/README.md`), and the twelve run
folders of runs 2 and 3. Runs with the same configuration label are combined
as repeats. Then:

```bash
python ../scripts/results_to_tex.py --pilot pilot-2026-10-10 \
    --runs "study/*/" --baseline full --out ../paper
```

Optional extra conditions: a second model through `--provider openai`
(e.g. DeepSeek or another OpenAI-compatible model) and effort levels
(`--effort medium`, `--effort low`), each labelled with `--label`.

## Current state of `study/`

The 17 folders were built from the console output in `console/` with
`scripts/console_to_runs.py` (each repeat's per-task lines are checked
against the means it printed). Repeats 2 and 3 have per-task rows; repeat 1
(rescored on v1.1) has run-level metrics only, from its printed table, because
the rescored per-task rows are in the trace folders on the server. When the
traces arrive, replace the `r1-*` folders with the `*-rescored-v1.1` folders
(adding `"repeat": 1` to their summaries) and regenerate:

```bash
python ../scripts/results_to_tex.py --pilot pilot-2026-10-10 --runs "study/*/" \
    --baseline full --sensitivity-exclude linux-service-stopped --out ../paper
```
