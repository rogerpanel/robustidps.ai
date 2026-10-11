# SOCGraph: LLM agents for provenance-graph alert investigation

Code, benchmark, results and manuscript for:

> **Grounded, Budget-Aware LLM Agents for Provenance-Graph Alert Investigation:
> Design, Ablation, and a Cross-Platform Benchmark from Public Attack Telemetry**
> Roger Nick Anaedevha, 2026 (manuscript in `paper/`).

A security operations centre (SOC) analyst who receives an alert walks the
evidence behind it (which process started what, which file it wrote, where
it connected) and decides whether it is an attack, and if so what needs a
response. This repository contains:

| Folder | What it is |
|---|---|
| [`agent/`](agent/) | An LLM investigation agent that walks an evidence graph through a small tool interface (`search`, `get_entity`, `get_relation`, `finish_investigation`) under a tool-call budget. Local safeguards (response cache, schema validation, grounding check, budgets, deadline) avoid spending calls on mistakes; each can be switched off for ablation. |
| [`benchmark/`](benchmark/) | **SOCGraph-21**: 21 investigation tasks built from public attack telemetry: 11 Windows tasks from OTRF Security-Datasets and 10 Linux tasks from Splunk attack_data (Sysmon for Linux). 15 real attacks and 6 real benign look-alikes recorded on the same machines, with ground truth. One 0.55 MB zip. |
| [`results/`](results/) | The pilot run (11 Windows tasks) and, once run, the full study and ablation runs. |
| [`scripts/`](scripts/) | `results_to_tex.py`: turns run folders into the paper's tables, figure data and macros. |
| [`paper/`](paper/) | The manuscript as an Overleaf-ready LaTeX project (IEEEtran). |

## Quick start

The agent runs inside the public reference client of the BlueSec1 runtime
(<https://github.com/False-Positive-Community/bluesec1-agent>), which is not
redistributed here. Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/False-Positive-Community/bluesec1-agent.git
bash agent/install.sh bluesec1-agent
cd bluesec1-agent && uv sync
uv run --with anthropic --with jsonschema pytest            # agent tests

cp .env.example .env    # add ANTHROPIC_API_KEY (or an OpenAI-compatible LLM_*), see agent/env.robust.example
uv run --with anthropic --with jsonschema --env-file .env \
    python -m bluesec1_agent.robust.cli --pack ../benchmark/socgraph-21-v1.1.zip --concurrency 4
```

Ablation study (the full agent, then each component turned off in turn):

```bash
uv run --with anthropic --with jsonschema --env-file .env \
    python -m bluesec1_agent.robust.cli --pack ../benchmark/socgraph-21-v1.1.zip \
    --concurrency 4 --ablation-suite
```

Rescore finished runs against a revised pack, offline (no model calls):

```bash
uv run --with anthropic --with jsonschema python -m bluesec1_agent.robust.cli \
    --pack ../benchmark/socgraph-21-v1.1.zip --rescore traces/<run folder> ...
```

Copy the run folders from `bluesec1-agent/traces/` into `results/study/`
(see `results/README.md` for the protocol) and regenerate the paper's tables:

```bash
python scripts/results_to_tex.py --pilot results/pilot-2026-10-10 \
    --runs "results/study/*/" --baseline full --out paper
```

Then upload `paper/` to Overleaf (or run `latexmk -pdf main.tex` in `paper/`).

## Reproducibility notes

- The benchmark is fixed: `benchmark/SHA256SUMS` pins the zip. It can also be
  rebuilt from the original public recordings
  (`python -m bluesec1_agent.robust.localdata.fetch` then `...localdata.pack`).
- LLM runs are not deterministic. Report several repeats per configuration;
  `results_to_tex.py` reports mean ± standard deviation across repeats.
- Every run folder records the configuration (model, effort, concurrency,
  budgets, ablations), every tool call with its stated purpose, the
  submission, the score breakdown and token usage.

## Licences

Code: MIT ([`LICENSE`](LICENSE)). Benchmark data: derived from OTRF
Security-Datasets (MIT) and Splunk attack_data (Apache-2.0); see
[`DATA_LICENSES.md`](DATA_LICENSES.md). Please cite the original datasets as
well as this work ([`CITATION.cff`](CITATION.cff)).
