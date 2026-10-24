"""Agent Guard: a fail-closed safety filter for LLM agent tool calls.

Every tool call an agent proposes is sent here before it runs. The filter
answers allow, deny, modify (with corrected arguments) or ask (a human must
approve), from a declarative policy pack. Any failure, timeout or repeat of
a denied call is a deny.

Layers (phase 0):
  L0 canonicalise   NFKC, hidden/bidi characters removed and reported,
                    rationale fields excluded from matching
  L1 policy         action tiers, scope (rules of engagement), argument
                    rules, clamps, secret redaction, per-session budgets,
                    sticky deny and escalation after repeated denials

Modules:
  contract.py   request/decision models shared by the API and adapters
  canonical.py  L0
  policy.py     policy-pack schema and the built-in packs (policies/*.json)
  engine.py     L1 evaluation, session state, fail-closed wrapper
  adapters.py   Claude-style / Hermes shell hooks, OpenHands risk levels
  client.py     stdlib client and command hook users copy into their agents
  api.py        /api/agent-guard/*
"""
from plugins.agent_guard.api import router  # noqa: F401
