# SOC Triage starter

Tier-1 SOC analyst replacement: ingests an alert payload, returns a
triage envelope (severity + MITRE ATT&CK pattern + recommended action).

Wraps a minimal LangGraph state machine with `aegis.guard()` so every
turn ships a verdict envelope to your `RUNTIME_AGENT_ID` on
robustidps.ai.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export ROBUSTIDPS_API_BASE="https://robustidps.ai"
export ROBUSTIDPS_API_KEY="rids_live_…"     # /agent-studio/account
export RUNTIME_AGENT_ID="soc-triage-dev-1"
python main.py
```

## Register the deployment

After your first verdict ships, the agent shows up on
`/agent-studio/runtime`. Pin it under `/agent-studio/deployments`:

```bash
curl -sf -X POST https://robustidps.ai/api/agent-studio/deployments \
  -H "Authorization: Bearer $ROBUSTIDPS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "template_id": "soc_triage",
    "name": "soc-triage-dev-1",
    "runtime_agent_id": "soc-triage-dev-1",
    "cloud": "docker_self",
    "region": "local",
    "tier": "dev"
  }'
```

## Production

- **Docker**: `docker build -t agent-soc-triage . && docker run --rm -e ROBUSTIDPS_API_KEY=... agent-soc-triage`
- **Kubernetes**: edit `k8s.yaml`, replace the secret + image, `kubectl apply -f k8s.yaml`
- **CI gate**: add `pytest --aegis-fail-on-warn` to your pipeline (see `papers/AGENT_SHIP_GUIDE.md` §7)
