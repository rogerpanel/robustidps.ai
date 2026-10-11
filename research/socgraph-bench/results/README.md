# Results

| Folder | Content |
|---|---|
| `pilot-2026-10-10/` | first real-model run, 11 Windows tasks (see its README) |
| `study/` | the study runs on SOCGraph-21 v1: copy each run folder from `bluesec1-agent/traces/` here |

Recommended protocol for the paper (about 18 runs of 21 tasks):

```bash
for i in 1 2 3; do
  uv run --with anthropic --with jsonschema --env-file .env \
      python -m bluesec1_agent.robust.cli --pack ../benchmark/socgraph-21-v1.zip \
      --concurrency 4 --ablation-suite
done
```

Each `--ablation-suite` writes six run folders (`full`, `no cache`,
`no validation`, `no grounding`, `no budget`, `no method`) plus an
`ablation-*.md`/`.csv` table. Runs with the same label are combined as
repeats. Then:

```bash
python ../scripts/results_to_tex.py --pilot pilot-2026-10-10 \
    --runs "study/*/" --baseline full --out ../paper
```

Optional extra conditions for the paper: a second model through
`--provider openai` (e.g. DeepSeek or another OpenAI-compatible model) and
effort levels (`--effort medium`, `--effort low`), each labelled with
`--label`.
