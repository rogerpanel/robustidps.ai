"""HuggingFace smolagents wrapper — verdict-check the agent run.

smolagents (https://github.com/huggingface/smolagents) is HF's
small-and-simple agent framework with a CodeAgent (writes + runs
Python) and a ToolCallingAgent. We hook the run() method to verify
the task pre and the final answer post.

    from smolagents import CodeAgent, HfApiModel
    from robustidps.aegis import MambaGuardClient
    from robustidps.aegis.smolagents import guard

    agent = CodeAgent(tools=[my_tool], model=HfApiModel())
    guarded = guard(agent, MambaGuardClient())
    answer = guarded.run("Write a Python script that…")
"""
from __future__ import annotations

from typing import Any

from robustidps.aegis.client import MambaGuardClient, VerdictDecision
from robustidps.aegis.langgraph import AgentBlocked


def guard(agent: Any, client: MambaGuardClient | None = None,
          block_on_warn: bool = False) -> Any:
    """Wrap a smolagents Agent so every .run() is verdict-checked."""
    try:
        import smolagents  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "smolagents not installed. `pip install smolagents` — or use "
            "the LangGraph / CrewAI / OpenAI Agents wrappers."
        ) from e
    client = client or MambaGuardClient()
    original_run = agent.run

    def _guarded_run(task: str, *args, **kwargs):
        # Pre-check: task + tool list
        tools = getattr(agent, "tools", {}) or {}
        tool_summary = ", ".join(
            (t.name if hasattr(t, "name") else str(t))
            for t in (tools.values() if hasattr(tools, "values") else tools)
        )
        pre_text = f"task: {task}\ntools: {tool_summary}"
        pre = client.check(pre_text, input_kind="agent_card",
                           context={"phase": "pre_run", "framework": "smolagents"})
        if pre.blocked or (block_on_warn and pre.decision is VerdictDecision.WARN):
            raise AgentBlocked("pre_run", pre.findings)

        result = original_run(task, *args, **kwargs)

        post_text = str(result)
        post = client.check(post_text, input_kind="agent_card",
                            context={"phase": "post_run", "framework": "smolagents"})
        if post.blocked or (block_on_warn and post.decision is VerdictDecision.WARN):
            raise AgentBlocked("post_run", post.findings)
        return result

    agent.run = _guarded_run
    return agent
