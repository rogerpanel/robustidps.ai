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
  approvals.py  queue for 'ask' decisions, bound to the exact call, single use
  registry.py   tool registry: fingerprints, versions, pins, coverage (shared with the scanner)
  evidence.py   hash-chained evidence ledger (decisions, approvals, pins, evaluations)
  evaluation.py labelled suites (suites/*.json) with verifiable result digests
  db_models.py  tables for the three above
  environment.py asset inventory and redundancy groups (per tenant) for the predictive layer
  predictive.py L2: predicted effect of a call on the environment; safe if groups and limits hold
  deferral.py   calibrated deferral: Learn-then-Test threshold over the tenant's approval history
  api.py        /api/agent-guard/*
"""
from plugins.agent_guard import db_models  # noqa: F401  (registers the tables for init_db)
from plugins.agent_guard.api import router  # noqa: F401
