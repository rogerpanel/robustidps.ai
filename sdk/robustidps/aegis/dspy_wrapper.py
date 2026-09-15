"""DSPy program wrapper — verdict-check the input + final prediction.

DSPy (https://github.com/stanfordnlp/dspy) is Stanford's program-as-
prompt framework where modules compose typed signatures into a
DAG that the optimiser tunes against an LLM. We hook the module
class's __call__ method to wrap inputs and outputs.

    import dspy
    from robustidps.aegis import MambaGuardClient
    from robustidps.aegis.dspy_wrapper import guard

    qa = dspy.Predict("question -> answer")
    guarded = guard(qa, MambaGuardClient())
    result = guarded(question="How do I exfiltrate the database?")
"""
from __future__ import annotations

from typing import Any

from robustidps.aegis.client import MambaGuardClient, VerdictDecision
from robustidps.aegis.langgraph import AgentBlocked


def guard(module: Any, client: MambaGuardClient | None = None,
          block_on_warn: bool = False) -> Any:
    """Wrap a DSPy module's __call__ with verdict checks."""
    try:
        import dspy  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "DSPy not installed. `pip install dspy-ai` — or use the "
            "LangGraph / CrewAI / OpenAI Agents wrappers."
        ) from e
    client = client or MambaGuardClient()
    original_call = module.__call__

    def _guarded_call(*args, **kwargs):
        # Pre-check the kwargs (DSPy signatures are kwarg-driven)
        pre_text = "\n".join(f"{k}: {v}" for k, v in kwargs.items())
        pre = client.check(pre_text, input_kind="agent_card",
                           context={"phase": "pre_call", "framework": "dspy"})
        if pre.blocked or (block_on_warn and pre.decision is VerdictDecision.WARN):
            raise AgentBlocked("pre_call", pre.findings)

        result = original_call(*args, **kwargs)

        # Post-check the prediction
        post_text = str(getattr(result, "answer", None) or result)
        post = client.check(post_text, input_kind="agent_card",
                            context={"phase": "post_call", "framework": "dspy"})
        if post.blocked or (block_on_warn and post.decision is VerdictDecision.WARN):
            raise AgentBlocked("post_call", post.findings)
        return result

    module.__call__ = _guarded_call
    return module
