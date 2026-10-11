# Starter agents

Four `git clone` → `pip install` → `python main.py` reference
implementations of Agent Studio templates, each wrapped with the
AegisAgents Kit so every tool call + LLM response is verdict-checked
against the RobustIDPS.ai backend.

| Folder | Template | Framework | Tier |
|---|---|---|---|
| `soc_triage/`        | SOC Triage Agent      | LangGraph | A — defender |
| `billing_copilot/`   | Billing Copilot       | LangGraph | C — productivity |
| `red_team_operator/` | Red-Team Operator     | LangGraph | B — attacker |
| `docs_qa/`           | Docs Q&A              | LangGraph | C — productivity |

## How to use

```bash
cd examples/agents/soc_triage          # or any other folder
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export ROBUSTIDPS_API_BASE="https://robustidps.ai"
export ROBUSTIDPS_API_KEY="rids_live_…"    # from /agent-studio/account
python main.py                              # runs the canonical test inputs
```

Each agent registers itself with the Deployments registry on first
run if `DEPLOY_ON_BOOT=1` is set. Telemetry then flows automatically
to `/agent-studio/runtime` keyed by the agent's `RUNTIME_AGENT_ID`.

## Production deployment

Each folder ships a `Dockerfile`, a `k8s.yaml`, and a `Modal` recipe.
Pick your runtime, set `ROBUSTIDPS_API_KEY` from your secret manager,
and ship — the agent will:

1. Wrap itself with `aegis.guard()` from the recommended framework
   wrapper.
2. POST a verdict envelope per turn to `/api/agent-studio/runtime/ingest`.
3. Surface under `/agent-studio/deployments` with live block_rate /
   latency telemetry.

See `papers/AGENT_SHIP_GUIDE.md` for the end-to-end Build → Secure →
Ship walkthrough.
