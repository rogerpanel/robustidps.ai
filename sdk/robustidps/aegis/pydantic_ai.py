"""Pydantic AI wrapper — verdict-check typed-agent inputs + outputs.

Pydantic AI organises agents as Agent[Deps, Output] with strongly
typed dependencies and structured outputs. We hook the result_validator
to run the verdict check on every successful response before it's
returned to the caller.

    from pydantic_ai import Agent
    from robustidps.aegis import MambaGuardClient
    from robustidps.aegis.pydantic_ai import guard

    agent = Agent('openai:gpt-4o', system_prompt='You are a helpful assistant.')
    guarded = guard(agent, MambaGuardClient())
    result = await guarded.run("user query")
"""
from __future__ import annotations

from typing import Any

from robustidps.aegis.client import MambaGuardClient, VerdictDecision
from robustidps.aegis.langgraph import AgentBlocked


def guard(agent: Any, client: MambaGuardClient | None = None,
          block_on_warn: bool = False) -> Any:
    """Wrap a Pydantic AI Agent so every run is verdict-checked."""
    try:
        import pydantic_ai  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "Pydantic AI not installed. `pip install pydantic-ai` — or "
            "use the LangGraph / CrewAI / OpenAI Agents wrappers."
        ) from e
    client = client or MambaGuardClient()

    original_run = agent.run

    async def _guarded_run(prompt: str, *args, **kwargs):
        # Pre-check the prompt
        sp = getattr(agent, "system_prompt", "") or ""
        pre_text = f"system_prompt: {sp}\nprompt: {prompt}"
        pre = client.check(pre_text, input_kind="agent_card",
                           context={"phase": "pre_run", "framework": "pydantic_ai"})
        if pre.blocked or (block_on_warn and pre.decision is VerdictDecision.WARN):
            raise AgentBlocked("pre_run", pre.findings)

        result = await original_run(prompt, *args, **kwargs)

        # Post-check the structured output
        output_text = str(getattr(result, "data", None) or getattr(result, "output", None) or result)
        post = client.check(output_text, input_kind="agent_card",
                            context={"phase": "post_run", "framework": "pydantic_ai"})
        if post.blocked or (block_on_warn and post.decision is VerdictDecision.WARN):
            raise AgentBlocked("post_run", post.findings)
        return result

    agent.run = _guarded_run
    return agent
