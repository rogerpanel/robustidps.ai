# Agent Guard: evaluation harness and paper

Reproducible evaluation of the Agent Guard safety filter (`backend/plugins/agent_guard`) and the
manuscript "Calibration Is Not Containment: A Fail-Closed Safety Filter for LLM Agent Tool Calls".

| Path | What it is |
|---|---|
| `harness/agentdojo_eval.py` | Replays AgentDojo v1.2 ground-truth tool calls (benign tasks; hijacked-agent attacks after the first exposure to injected text) through policies generated from tool descriptions. No language model. |
| `harness/internal_eval.py` | Built-in labelled suites with ablations, before/after against earlier pack versions, the predictive layer, policy authoring, and the calibrated-deferral simulation. |
| `harness/make_tables.py` | Writes every number and table used in the paper (`paper/generated/`) from `results/*.json`. |
| `data/agentdojo_trajectories.json` | The replayed trajectories (with AgentDojo version and digest), so the evaluation reruns without AgentDojo. |
| `data/frozen_policies/` | Earlier versions of the SOC and testing packs, taken from git history, for before/after comparisons. |
| `results/` | Raw results (JSON). |
| `paper/` | LaTeX sources: `main.tex` (journal) and `main-conference.tex` (anonymous, IEEE S&P). |

## Reproduce

From the repository root, with the backend's Python dependencies installed:

```bash
# 1. trajectories (needs: pip install agentdojo==0.1.35); optional, they are committed
PYTHONPATH=backend python research/agent-guard-bench/harness/agentdojo_eval.py build
# 2. evaluations (about 2 minutes in total)
PYTHONPATH=backend python research/agent-guard-bench/harness/agentdojo_eval.py evaluate
PYTHONPATH=backend python research/agent-guard-bench/harness/internal_eval.py
# 3. numbers and tables for the paper
python research/agent-guard-bench/harness/make_tables.py
# 4. paper
cd research/agent-guard-bench/paper && latexmk -pdf main.tex main-conference.tex
```

`evaluate` imports AgentDojo only for `build`; with the committed trajectories it needs just the
backend. Every policy is regenerated from the recorded tool descriptions on each run.

## Keeping the paper current

The manuscript is meant to follow development. After a change to the filter or the packs, rerun
steps 2 to 4: the macros in `paper/generated/results_macros.tex` and the tables update, and the
text quotes only those macros. When a change alters a claim in prose (not just a number),
update the section and note it in `paper/CHANGELOG.md`.
