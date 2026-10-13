"""LangGraph wrapper — auto-instruments every node transition with a
MambaGuard verdict check.

    from langgraph.graph import StateGraph
    from robustidps.aegis import MambaGuardClient
    from robustidps.aegis.langgraph import guard

    graph = StateGraph(MyState)
    graph.add_node("respond", respond_node)
    guarded = guard(graph, MambaGuardClient(), block_on_warn=False)
    app = guarded.compile()

Blocked verdicts raise `AgentBlocked`; warn verdicts are appended to the
state under `_aegis_warnings` if the state is dict-like.
"""
from __future__ import annotations

from typing import Any, Callable

from robustidps.aegis.client import MambaGuardClient, VerdictDecision


class AgentBlocked(RuntimeError):
    def __init__(self, node: str, findings: list[dict[str, Any]]):
        super().__init__(f"Aegis blocked node '{node}': {len(findings)} finding(s)")
        self.node = node
        self.findings = findings


def _serialise_state(state: Any) -> str:
    if isinstance(state, str):
        return state
    if isinstance(state, dict):
        return "\n".join(f"{k}: {v}" for k, v in state.items())
    return repr(state)[:50_000]


def _wrap_node(name: str, fn: Callable, client: MambaGuardClient,
               block_on_warn: bool) -> Callable:
    def _wrapped(state: Any, *args, **kwargs):
        result = fn(state, *args, **kwargs)
        verdict = client.check(
            _serialise_state(result),
            input_kind="agent_card",
            context={"node": name, "framework": "langgraph"},
        )
        if verdict.blocked or (block_on_warn and verdict.decision is VerdictDecision.WARN):
            raise AgentBlocked(name, verdict.findings)
        if isinstance(result, dict) and verdict.decision is VerdictDecision.WARN:
            warnings = result.setdefault("_aegis_warnings", [])
            warnings.append({"node": name, "findings": verdict.findings})
        return result
    _wrapped.__name__ = f"aegis_guarded_{name}"
    return _wrapped


def guard(graph: Any, client: MambaGuardClient | None = None,
          block_on_warn: bool = False) -> Any:
    """In-place wrap every node of a LangGraph StateGraph with a verdict check.

    Returns the same graph for chaining.
    """
    try:
        import langgraph  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "LangGraph is not installed. `pip install langgraph` or use the MCP "
            "wrapper instead: from robustidps.aegis.mcp import guard."
        ) from e
    client = client or MambaGuardClient()
    nodes = getattr(graph, "nodes", None)
    if nodes is None:
        raise TypeError("Object does not look like a LangGraph StateGraph (no .nodes attribute).")
    for name in list(nodes.keys()):
        nodes[name] = _wrap_node(name, nodes[name], client, block_on_warn)
    return graph
