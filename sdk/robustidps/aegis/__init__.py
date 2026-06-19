"""AegisAgents Kit — auto-instrument LangGraph / CrewAI / MCP agents with
MambaGuard runtime monitoring against the RobustIDPS.ai backend.

Day-1 surface — three thin wrappers and a verdict client:

    from robustidps.aegis import MambaGuardClient
    from robustidps.aegis.langgraph import guard

    guard_client = MambaGuardClient(api_base="https://robustidps.ai")
    graph = guard(graph, client=guard_client, policy="default")
    # Every tool call, every LLM response, every state transition now
    # ships a verdict envelope to /api/agent-studio/scanner/run.

The wrappers degrade gracefully — if the dependent framework isn't
installed, importing the corresponding submodule raises with a clear
hint instead of pulling LangGraph / CrewAI / MCP into the user's tree.
"""
from robustidps.aegis.client import MambaGuardClient, Verdict, VerdictDecision

__all__ = ["MambaGuardClient", "Verdict", "VerdictDecision"]
__version__ = "0.2.0"
