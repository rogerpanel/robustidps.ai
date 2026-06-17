"""Agent Studio + Agent Security plugin for RobustIDPS.ai.

Realises the venture plan's five-SKU catalog (Agent Lab, Agent Factory,
Agent Red Team, Continuous Defense, Secure-by-Design Build) on top of the
existing platform kernel. Day-one deliverable: the free MCP / agent scanner
wedge — the analogue of Lakera's Gandalf — which gathers top-of-funnel
data points without authentication.

Subpackages:
  scanner/      Free MCP / agent scanner (public, no auth)
  aegis_kit/    LangGraph / CrewAI / MCP SDK wrappers (auto-instrument)
  dossier/      Assurance-evidence generator (PDF dossier)
  billing/      Stripe / Paddle webhook handlers
  entitlement/  Community / Pro / Enterprise tier gating
"""
from plugins.agent_studio.api import router  # noqa: F401
