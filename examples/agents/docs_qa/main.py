"""Docs Q&A starter — internal knowledge base Q&A with hallucination gating.

Forks the `docs_qa` Quickstart template. Strict retrieval threshold;
refuses to answer when no source clears `RETRIEVAL_THRESHOLD`.
"""
from __future__ import annotations

import os
import sys
from typing import TypedDict

from langgraph.graph import StateGraph, END
from robustidps.aegis import MambaGuardClient
from robustidps.aegis.langgraph import guard

TEMPLATE_ID = "docs_qa"
RUNTIME_AGENT_ID = os.getenv("RUNTIME_AGENT_ID", "docs-qa-starter")
RETRIEVAL_THRESHOLD = float(os.getenv("RETRIEVAL_THRESHOLD", "0.70"))

# Minimal demo KB — real prod swaps in a vector store.
DEMO_KB = {
    "payments-oncall": {
        "url": "https://kb.example/payments/on-call",
        "section": "rota",
        "text": "Rotation Mon/Wed/Fri = Mei, Bashir, Anya.",
        "embedding_score": 0.88,
    },
    "sev-2-2026q1": {
        "url": "https://kb.example/post-mortems/2026-q1-sev2",
        "section": "summary",
        "text": "SEV-2 caused by upstream DNS provider degradation; mitigated by failover.",
        "embedding_score": 0.83,
    },
}

SYSTEM_PROMPT = (
    "You are an internal docs Q&A assistant. Answer ONLY from the indexed "
    "internal knowledge base. Cite the doc URL + section heading for every "
    "factual claim. If retrieval score < %.2f, say 'I cannot find that.' "
    "Never invent URLs, headings, or version numbers." % RETRIEVAL_THRESHOLD
)


TEST_INPUTS = [
    "What is the on-call rotation for the payments service?",
    "Where is the post-mortem for the 2026-Q1 SEV-2?",
    "What's the CEO's phone number?",        # not in KB — refuse
]


class State(TypedDict):
    question: str
    answer: str


def _retrieve(question: str) -> dict | None:
    q_low = question.lower()
    if "on-call" in q_low or "rota" in q_low:
        return DEMO_KB["payments-oncall"]
    if "post-mortem" in q_low or "sev-2" in q_low or "2026-q1" in q_low:
        return DEMO_KB["sev-2-2026q1"]
    return None


def _answer_node(state: State) -> State:
    hit = _retrieve(state["question"])
    if hit is None or hit["embedding_score"] < RETRIEVAL_THRESHOLD:
        return {"answer": "I cannot find that in the indexed docs."}
    return {"answer": f"{hit['text']} (source: {hit['url']}#{hit['section']}, "
                       f"score={hit['embedding_score']:.2f})"}


def build_graph():
    g = StateGraph(State)
    g.add_node("answer", _answer_node)
    g.set_entry_point("answer")
    g.add_edge("answer", END)
    return g.compile()


def main() -> int:
    client = MambaGuardClient(
        api_base=os.getenv("ROBUSTIDPS_API_BASE", "https://robustidps.ai"),
        api_key=os.getenv("ROBUSTIDPS_API_KEY"),
    )
    graph = build_graph()
    graph = guard(graph, client=client, policy="default",
                  template_id=TEMPLATE_ID, agent_id=RUNTIME_AGENT_ID)
    for q in TEST_INPUTS:
        out = graph.invoke({"question": q, "answer": ""})
        print(f"Q: {q}\n→ {out['answer']}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
