"""Translate between the decision contract and agent harness hook formats.

Claude-style PreToolUse command hooks (Claude Code; Hermes Agent shell hooks
accept the same JSON) send {"session_id", "tool_name", "tool_input", ...} on
stdin and read a JSON answer on stdout:
    {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                            "permissionDecision": "allow" | "deny" | "ask",
                            "permissionDecisionReason": "...",
                            "updatedInput": {...}}}
A "modify" verdict becomes "allow" with updatedInput.

OpenHands security analyzers return a risk level; its confirmation policy
pauses for approval on HIGH. "ask" and "deny" both map to HIGH (OpenHands has
no separate deny), "modify" to MEDIUM because the analyzer cannot rewrite the
action.
"""
from __future__ import annotations

from typing import Any

from plugins.agent_guard.contract import Decision, ProposedCall

_CLAUDE_VERDICT = {"allow": "allow", "modify": "allow", "ask": "ask", "deny": "deny"}
_OPENHANDS_RISK = {"allow": "LOW", "modify": "MEDIUM", "ask": "HIGH", "deny": "HIGH"}


def call_from_claude_hook(payload: dict[str, Any], framework: str = "claude") -> ProposedCall:
    """Raises ValueError/TypeError on a malformed payload (the API turns that into a deny)."""
    tool = payload.get("tool_name")
    if not isinstance(tool, str) or not tool:
        raise ValueError("tool_name missing")
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        raise TypeError("tool_input must be an object")
    return ProposedCall(
        session_id=str(payload.get("session_id") or "claude-hook")[:128],
        tool_name=tool, args=tool_input, framework=framework,
        agent_id=str(payload.get("agent_id") or "")[:128],
    )


def claude_hook_response(decision: Decision) -> dict[str, Any]:
    out: dict[str, Any] = {
        "hookEventName": "PreToolUse",
        "permissionDecision": _CLAUDE_VERDICT[decision.decision],
        "permissionDecisionReason": "Agent Guard: " + " ".join(decision.reasons)[:1000],
    }
    if decision.modified_args is not None and decision.decision in ("modify", "ask"):
        out["updatedInput"] = decision.modified_args
    return {"hookSpecificOutput": out}


def claude_hook_deny(reason: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": f"Agent Guard: {reason}"}}


def openhands_risk(decision: Decision) -> str:
    return _OPENHANDS_RISK[decision.decision]
