# Results

| Folder | Content |
|---|---|
| `pilot-2026-10-10/` | first real-model run, 11 Windows tasks (see its README) |
| `run1-2026-10-11-v1.0/` | study run 1 as scored on v1.0 (console output); superseded, kept for the record |
| `study/` | the study runs scored on SOCGraph-21 v1.1: one folder per run (`r<repeat>-<configuration>`), each with the run's `summary.json` (repeat 1: the rescored summary) and `trace_folder` pointing into `traces/` |
| `cues/` | the full agent on the cue-controlled variants (`blind`, `mimicry`), three repeats each (RQ5) |
| `traces/` | per-call traces of every run: the 18 study runs, the six rescored run-1 folders, an extra full run made before the study (20:19, not part of the protocol), the six cue-variant runs and the pilot; one JSON per task with every tool call, its stated purpose, the result, the submission and token use |

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

## How `study/` was built

From the trace zip of the server's `bluesec1-agent/traces/`: repeat 1 uses
the `*-rescored-v1.1` summaries (rescoring reproduced here task for task),
repeats 2 and 3 the runs' own summaries; `repeat` and `trace_folder` were
added to each. The `no validation` run of repeat 1 is left out (v1.0 runtime
crash). Regenerate everything from the repository root:

```bash
python scripts/results_to_tex.py --pilot results/pilot-2026-10-10 --runs "results/study/*/" \
    --cue-runs "results/cues/*/" --baseline full --sensitivity-exclude linux-service-stopped --out paper
python scripts/trace_stats.py --pack benchmark/socgraph-21-v1.1.zip --runs "results/study/*/" --out paper
python scripts/trace_stats.py --pack benchmark/socgraph-21-v1.1.zip --runs "results/cues/*/" --out paper \
    --prefix TrCue --table cue_interface.tex --macros cue_trace_macros.tex
python scripts/sensitivity.py --pack benchmark/socgraph-21-v1.1.zip --runs "results/study/*/" --out paper
```

## Cue-controlled variants (RQ5), done 2026-10-12

Three repeats of the full agent on each variant (about 2.5 minutes per run); results in `cues/`:

```bash
B=~/robustidps.ai/research/socgraph-bench/benchmark
for v in blind mimicry; do
  for i in 1 2 3; do
    uv run --with anthropic --with jsonschema --env-file .env \
        python -m bluesec1_agent.robust.cli --pack $B/socgraph-21-v1.1-$v.zip \
        --concurrency 4 --label "full, $v"
  done
done
```
