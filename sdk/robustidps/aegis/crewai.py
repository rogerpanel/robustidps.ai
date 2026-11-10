"""CrewAI wrapper — checks every Agent's task output with MambaGuard
before the result is handed to the next agent in the crew.

    from crewai import Agent, Task, Crew
    from robustidps.aegis import MambaGuardClient
    from robustidps.aegis.crewai import guard

    crew = Crew(agents=[a1, a2], tasks=[t1, t2])
    guarded = guard(crew, MambaGuardClient())
    result = guarded.kickoff()
"""
from __future__ import annotations

from typing import Any

from robustidps.aegis.client import MambaGuardClient, VerdictDecision
from robustidps.aegis.langgraph import AgentBlocked


def guard(crew: Any, client: MambaGuardClient | None = None,
          block_on_warn: bool = False) -> Any:
    try:
        import crewai  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "CrewAI is not installed. `pip install crewai` or use the LangGraph "
            "wrapper instead: from robustidps.aegis.langgraph import guard."
        ) from e
    client = client or MambaGuardClient()
    tasks = getattr(crew, "tasks", None)
    if tasks is None:
        raise TypeError("Object does not look like a CrewAI Crew (no .tasks attribute).")

    for task in tasks:
        original = getattr(task, "callback", None)

        def _make_cb(orig, task_name):
            def _cb(output):
                text = getattr(output, "raw", str(output))
                verdict = client.check(text, input_kind="agent_card",
                                       context={"task": task_name, "framework": "crewai"})
                if verdict.blocked or (block_on_warn and verdict.decision is VerdictDecision.WARN):
                    raise AgentBlocked(task_name, verdict.findings)
                if orig is not None:
                    return orig(output)
                return output
            return _cb

        task.callback = _make_cb(original, getattr(task, "description", "task"))
    return crew
