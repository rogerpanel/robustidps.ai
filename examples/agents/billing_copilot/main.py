"""Billing Copilot starter — strict-scope invoice / payment / refund Q&A.

Forks the `billing_copilot` Quickstart template. Aegis-checked at every
turn; refunds > $500 open a ticket rather than refunding directly.
"""
from __future__ import annotations

import os
import re
import sys
from typing import TypedDict

from langgraph.graph import StateGraph, END
from robustidps.aegis import MambaGuardClient
from robustidps.aegis.langgraph import guard

TEMPLATE_ID = "billing_copilot"
RUNTIME_AGENT_ID = os.getenv("RUNTIME_AGENT_ID", "billing-copilot-starter")
REFUND_AUTO_THRESHOLD_USD = 500

SYSTEM_PROMPT = (
    "You are a billing support agent. Only answer questions about invoices, "
    "payments, and refunds. If asked anything outside this scope, refuse "
    "politely. Always cite the invoice number. Refunds above $500 require "
    "human approval — open an approval ticket, do not refund yourself."
)

TEST_INPUTS = [
    "Why was invoice INV-1042 charged twice?",
    "I would like a $1200 refund on INV-1099.",
    "Can you delete my account?",   # out-of-scope — agent should refuse
]


class State(TypedDict):
    question: str
    answer: str


def _classify(q: str) -> tuple[str, dict]:
    """Stub classifier — real prod swaps in the LLM."""
    q_low = q.lower()
    inv = re.search(r"INV-\d+", q)
    amt = re.search(r"\$(\d+)", q)
    if not any(k in q_low for k in ("invoice", "refund", "payment", "charge")):
        return ("out_of_scope", {})
    if "refund" in q_low and amt:
        return ("refund", {"invoice": inv.group(0) if inv else "(missing)",
                            "amount_usd": int(amt.group(1))})
    return ("info", {"invoice": inv.group(0) if inv else "(unknown)"})


def _answer_node(state: State) -> State:
    kind, ctx = _classify(state["question"])
    if kind == "out_of_scope":
        return {"answer": "I can only help with invoices, payments, and refunds. "
                          "I cannot help with account deletion — please use the Account page."}
    if kind == "refund":
        amt = ctx["amount_usd"]
        inv = ctx["invoice"]
        if amt > REFUND_AUTO_THRESHOLD_USD:
            return {"answer": f"Refund of ${amt} on {inv} exceeds the auto-approval threshold "
                              f"(${REFUND_AUTO_THRESHOLD_USD}). Opening approval ticket TKT-{abs(hash(inv)) % 9999}."}
        return {"answer": f"Refund of ${amt} on {inv} processed (under auto-approval threshold)."}
    return {"answer": f"Invoice {ctx['invoice']} status: settled. If you see a duplicate, "
                      f"open a refund ticket and I'll route it for review."}


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
