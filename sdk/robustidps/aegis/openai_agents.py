"""OpenAI Agents SDK wrapper — verdict-check every agent run.

OpenAI's Agents SDK (March 2025) exposes an Agent + Runner abstraction
where the agent loops through tool calls until it produces a final
response. We hook into the runner's lifecycle to send each tool
invocation + final response through MambaGuard.

    from agents import Agent, Runner
    from robustidps.aegis import MambaGuardClient
    from robustidps.aegis.openai_agents import guard

    runner = Runner()
    guarded_runner = guard(runner, MambaGuardClient())
    result = guarded_runner.run(my_agent, "user query")
"""
from __future__ import annotations

import json
from typing import Any

from robustidps.aegis.client import MambaGuardClient, VerdictDecision
from robustidps.aegis.langgraph import AgentBlocked


def guard(runner: Any, client: MambaGuardClient | None = None,
          block_on_warn: bool = False) -> Any:
    """Wrap an OpenAI Agents SDK Runner so every agent run is
    verdict-checked end-to-end."""
    try:
        import agents  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "OpenAI Agents SDK not installed. `pip install openai-agents` "
            "or use one of the other AegisAgents Kit wrappers."
        ) from e
    client = client or MambaGuardClient()

    original_run = runner.run

    def _guarded_run(agent: Any, query: str, *args, **kwargs):
        # Pre-check: agent definition + query
        spec_text = json.dumps({
            "instructions": getattr(agent, "instructions", "") or "",
            "tools": [getattr(t, "name", str(t)) for t in (getattr(agent, "tools", []) or [])],
            "query": query,
        }, default=str)
        pre = client.check(spec_text, input_kind="agent_card",
                           context={"phase": "pre_run", "framework": "openai_agents"})
        if pre.blocked or (block_on_warn and pre.decision is VerdictDecision.WARN):
            raise AgentBlocked("pre_run", pre.findings)

        result = original_run(agent, query, *args, **kwargs)

        # Post-check: final response
        final_text = str(getattr(result, "final_output", result))
        post = client.check(final_text, input_kind="agent_card",
                            context={"phase": "post_run", "framework": "openai_agents"})
        if post.blocked or (block_on_warn and post.decision is VerdictDecision.WARN):
            raise AgentBlocked("post_run", post.findings)
        if hasattr(result, "__dict__") and post.decision is VerdictDecision.WARN:
            setattr(result, "_aegis_warnings", post.findings)
        return result

    runner.run = _guarded_run
    return runner
