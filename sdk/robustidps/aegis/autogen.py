"""AutoGen wrapper — verdict-check every group-chat message.

Microsoft AutoGen organises agents as a GroupChat (one agent at a
time speaks, a manager picks the next speaker). We hook into the
group manager's message broadcast to send each message through
MambaGuard before downstream agents see it.

    from autogen_agentchat.teams import RoundRobinGroupChat
    from robustidps.aegis import MambaGuardClient
    from robustidps.aegis.autogen import guard

    team = RoundRobinGroupChat([writer_agent, critic_agent])
    guarded_team = guard(team, MambaGuardClient())
    result = await guarded_team.run("draft a launch announcement")
"""
from __future__ import annotations

from typing import Any

from robustidps.aegis.client import MambaGuardClient, VerdictDecision
from robustidps.aegis.langgraph import AgentBlocked


def guard(team: Any, client: MambaGuardClient | None = None,
          block_on_warn: bool = False) -> Any:
    """Wrap an AutoGen group chat so every broadcast message is
    verdict-checked before downstream agents see it."""
    try:
        import autogen_agentchat  # noqa: F401
    except ImportError:
        try:
            import autogen  # noqa: F401
        except ImportError as e:
            raise ImportError(
                "AutoGen not installed. `pip install autogen-agentchat` "
                "(or `pyautogen`) — or use the LangGraph / CrewAI wrappers."
            ) from e
    client = client or MambaGuardClient()

    # AutoGen's broadcast hook lives on the team's run() method. We
    # wrap run() and intercept the message stream as it's produced.
    original_run = getattr(team, "run", None) or getattr(team, "run_stream", None)
    if original_run is None:
        raise TypeError("Team object has no .run() or .run_stream() method.")

    async def _guarded_run(task: str, *args, **kwargs):
        # Pre-check the task itself
        pre = client.check(task, input_kind="agent_card",
                           context={"phase": "pre_task", "framework": "autogen"})
        if pre.blocked or (block_on_warn and pre.decision is VerdictDecision.WARN):
            raise AgentBlocked("pre_task", pre.findings)

        result = await original_run(task, *args, **kwargs)

        # Post-check the assembled output (if accessible as a string)
        if result is not None:
            post = client.check(str(result), input_kind="agent_card",
                                context={"phase": "post_task", "framework": "autogen"})
            if post.blocked or (block_on_warn and post.decision is VerdictDecision.WARN):
                raise AgentBlocked("post_task", post.findings)
        return result

    setattr(team, "run", _guarded_run)
    return team
