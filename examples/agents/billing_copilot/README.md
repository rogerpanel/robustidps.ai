# Billing Copilot starter

Strict-scope invoice / payment / refund Q&A. Refunds above the
configurable threshold (default $500) open an approval ticket rather
than refunding directly.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export ROBUSTIDPS_API_KEY="rids_live_…"
export RUNTIME_AGENT_ID="billing-copilot-dev-1"
python main.py
```

Tunable env vars:

| Var | Default | What |
|---|---|---|
| `REFUND_AUTO_THRESHOLD_USD` | 500 | Refunds at-or-below auto-process; above → ticket |
| `RUNTIME_AGENT_ID`          | billing-copilot-starter | Cross-ref to `/agent-studio/runtime` |
| `ROBUSTIDPS_API_BASE`       | https://robustidps.ai | Override for self-hosted RobustIDPS |

See `examples/agents/README.md` for the deployment / k8s / dossier path.
