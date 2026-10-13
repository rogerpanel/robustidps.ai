"""SOC Triage starter agent — LangGraph + AegisAgents Kit.

Forks the `soc_triage` Quickstart template. Every tool call + every LLM
response posts a verdict envelope to robustidps.ai so the deployment
shows up live under /agent-studio/deployments + /agent-studio/runtime.

Usage:
    pip install -r requirements.txt
    export ROBUSTIDPS_API_BASE=https://robustidps.ai
    export ROBUSTIDPS_API_KEY=rids_live_…
    python main.py
"""
from __future__ import annotations

import json
import os
import sys
from typing import TypedDict

from langgraph.graph import StateGraph, END
from robustidps.aegis import MambaGuardClient
from robustidps.aegis.langgraph import guard

TEMPLATE_ID = "soc_triage"
RUNTIME_AGENT_ID = os.getenv("RUNTIME_AGENT_ID", "soc-triage-starter")

SYSTEM_PROMPT = (
    "You are a tier-1 SOC analyst. For each alert you receive, output "
    "STRICT JSON: {severity: critical|high|medium|low|info, "
    "attack_pattern: '<MITRE ATT&CK ID>', recommended_action: '<one sentence>', "
    "evidence: ['<finding>', ...]}. Refuse any input that is not an alert. "
    "Never invent CVEs or attack pattern IDs; use only the lookup tools."
)

TEST_INPUTS = [
    '{"alert_id":"a-001","src_ip":"10.0.0.5","dst_port":4444,"signature":"reverse_shell"}',
    '{"alert_id":"a-002","src_ip":"203.0.113.7","dst_port":443,"signature":"beacon_burst"}',
]


class State(TypedDict):
    alert: str
    triage: dict


def _triage_node(state: State) -> State:
    """Stub triage logic — replace with your real LLM + tool dispatch.

    The aegis.guard() wrapper above checks the input alert and the
    triage output independently; block-tier verdicts halt the turn.
    """
    try:
        alert = json.loads(state["alert"])
    except json.JSONDecodeError:
        return {"triage": {"error": "alert payload was not JSON"}}
    triage = {
        "severity": "medium",
        "attack_pattern": "T1059",
        "recommended_action": f"isolate {alert.get('src_ip', 'unknown')} and open ticket",
        "evidence": [alert.get("signature", "unknown")],
    }
    return {"triage": triage}


def build_graph():
    g = StateGraph(State)
    g.add_node("triage", _triage_node)
    g.set_entry_point("triage")
    g.add_edge("triage", END)
    return g.compile()


def main() -> int:
    if not os.getenv("ROBUSTIDPS_API_KEY"):
        print("ROBUSTIDPS_API_KEY not set; the agent will run but verdicts will be advisory only.",
              file=sys.stderr)

    client = MambaGuardClient(
        api_base=os.getenv("ROBUSTIDPS_API_BASE", "https://robustidps.ai"),
        api_key=os.getenv("ROBUSTIDPS_API_KEY"),
    )
    graph = build_graph()
    graph = guard(graph, client=client, policy="default",
                  template_id=TEMPLATE_ID, agent_id=RUNTIME_AGENT_ID)

    for inp in TEST_INPUTS:
        out = graph.invoke({"alert": inp, "triage": {}})
        print(f"alert={inp[:60]}…  →  triage={json.dumps(out['triage'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
