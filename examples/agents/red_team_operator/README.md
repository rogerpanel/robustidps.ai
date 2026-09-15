# Red-Team Operator starter

**AUTHORIZED ENGAGEMENTS ONLY.** This starter refuses to probe any
target without an `authorization_id` in the spec.

Orchestrates the RobustIDPS Garak adapter (`/red-team/garak`) against
a list of target agent specs, aggregates findings, returns a report.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export ROBUSTIDPS_API_KEY="rids_live_…"
export RUNTIME_AGENT_ID="red-team-operator-dev-1"
python main.py
```

Replace `TEST_TARGETS` in `main.py` with your engagement target
specs. Each target must include `authorization_id` proving the
engagement is scoped + signed.

The agent's own verdict telemetry shows up under
`/agent-studio/runtime` and `/agent-studio/deployments`. The
per-engagement Garak findings live under
`/agent-studio/red-team` history with their `run_id`.
