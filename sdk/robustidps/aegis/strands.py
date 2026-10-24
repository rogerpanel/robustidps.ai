"""Strands Agents wrapper — verdict-check at agent invocation.

Strands (https://strandsagents.com) is a model-agnostic agent SDK
that organises tools + memory + reasoning around an Agent object.
We wrap the Agent's __call__ to verify the user query pre and the
response post.

    from strands import Agent
    from robustidps.aegis import MambaGuardClient
    from robustidps.aegis.strands import guard

    agent = Agent(tools=[my_tool], system_prompt="You are…")
    guarded = guard(agent, MambaGuardClient())
    result = guarded("user query")
"""
from __future__ import annotations

from typing import Any

from robustidps.aegis.client import MambaGuardClient, VerdictDecision
from robustidps.aegis.langgraph import AgentBlocked


def guard(agent: Any, client: MambaGuardClient | None = None,
          block_on_warn: bool = False) -> Any:
    """Wrap a Strands Agent so every call is verdict-checked."""
    try:
        import strands  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "Strands Agents not installed. `pip install strands-agents` — "
            "or use the LangGraph / CrewAI / OpenAI Agents wrappers."
        ) from e
    client = client or MambaGuardClient()
    original_call = agent.__call__

    def _guarded_call(query: str, *args, **kwargs):
        sp = getattr(agent, "system_prompt", "") or ""
        pre_text = f"system_prompt: {sp}\nquery: {query}"
        pre = client.check(pre_text, input_kind="agent_card",
                           context={"phase": "pre_call", "framework": "strands"})
        if pre.blocked or (block_on_warn and pre.decision is VerdictDecision.WARN):
            raise AgentBlocked("pre_call", pre.findings)

        result = original_call(query, *args, **kwargs)

        post_text = str(getattr(result, "message", None) or result)
        post = client.check(post_text, input_kind="agent_card",
                            context={"phase": "post_call", "framework": "strands"})
        if post.blocked or (block_on_warn and post.decision is VerdictDecision.WARN):
            raise AgentBlocked("post_call", post.findings)
        return result

    agent.__call__ = _guarded_call
    return agent
