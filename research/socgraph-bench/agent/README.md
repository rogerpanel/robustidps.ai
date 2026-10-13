# The investigation agent

`robust/` is a Python package installed into the public BlueSec1 reference
client (<https://github.com/False-Positive-Community/bluesec1-agent>) as
`src/bluesec1_agent/robust/`. It uses that client's task and tool interfaces
unchanged; the client itself is not part of this repository.

```bash
git clone https://github.com/False-Positive-Community/bluesec1-agent.git
bash install.sh bluesec1-agent          # copies robust/ and tests/ into the clone
cd bluesec1-agent && uv sync
uv run --with anthropic --with jsonschema pytest
```

| Module | Role |
|---|---|
| `catalog.py` | builds tool definitions from each task's advertised catalog (the catalog is authoritative); inlines `$ref`s, rewrites `oneOf` to `anyOf`, presents free-text `reasoning` fields as `purpose`/`summary` and maps them back |
| `investigation.py` | executes calls: response cache, local schema validation, grounding check on the submission, soft/hard budget, deadline; records the trace |
| `drivers.py` | Claude loop (native tool use, adaptive thinking, effort, prompt caching, server-side fallback) and an OpenAI-compatible loop |
| `prompt.py` | the investigation method prompt and the minimal ablation prompt |
| `agent.py` | parallel workers with a learned runtime task limit; per-task traces; run summary with configuration and metrics |
| `metrics.py`, `table.py` | verdict accuracy, false-positive/negative rates, breakdowns; ablation table |
| `localdata/` | the local runtime: graph builder for Sysmon (Windows/Linux), scenario definitions and ground truth, practice-pack builder and loader, scorer |
| `cli.py` | entry point: `--pack`, `--local`, `--mock`, `--ablate`, `--ablation-suite`, `--concurrency`, `--deadline` |

Run options and environment variables: `env.robust.example`.
