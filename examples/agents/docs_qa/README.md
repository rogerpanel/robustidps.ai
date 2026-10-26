# Docs Q&A starter

Internal knowledge base Q&A with strict hallucination gating. Refuses
to answer when no source clears `RETRIEVAL_THRESHOLD` (default 0.70).

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export ROBUSTIDPS_API_KEY="rids_live_…"
export RUNTIME_AGENT_ID="docs-qa-dev-1"
python main.py
```

Tunable env vars:

| Var | Default | What |
|---|---|---|
| `RETRIEVAL_THRESHOLD` | 0.70 | Min embedding score before the agent will answer |
| `RUNTIME_AGENT_ID`    | docs-qa-starter | Cross-ref to `/agent-studio/runtime` |

The starter ships a 2-row demo KB inside `main.py`; swap
`_retrieve()` for your vector-store call in production.
