"""Agent Guard for the Claude Agent SDK (Python): a PreToolUse hook callback.

Put this file next to agent_guard_client.py:

    from claude_agent_sdk import ClaudeAgentOptions, HookMatcher, query
    from agent_guard_client import GuardClient
    from claude_sdk_guard import agent_guard_hook

    guard = GuardClient("https://robustidps.ai", token="rids_live_...", policy_id="mcp-general")
    options = ClaudeAgentOptions(hooks={
        "PreToolUse": [HookMatcher(matcher=None, hooks=[agent_guard_hook(guard)], timeout=90)],
    })

Why a hook and not can_use_tool: the SDK does not call can_use_tool for tool
calls that allowed_tools, the permission mode or settings already allow, so
it cannot see every call. A PreToolUse hook runs for every call.

Verdicts:
  allow   no decision, so Claude's own permission rules still apply (the
          guard only takes permissions away); grant_on_allow=True answers
          "allow" instead
  modify  "allow" with updatedInput: the call runs with the guard's
          corrected arguments
  ask     "deny" with the approval id: a person approves it on the Safety
          Filter page and the agent repeats the same call (the guard uses the
          approval once). With GuardClient(approval_wait=...) the hook waits
          for the person instead. ask_as="ask" hands the call to Claude's own
          permission prompt (or can_use_tool) instead of the guard's queue
  deny    "deny" with the guard's reasons
  error   "deny": a failure, a timeout of the guard (deadline_s) or a
          malformed input never lets the call through

Keep HookMatcher(timeout=...) above deadline_s (default: three request
timeouts plus the approval wait plus 5 seconds), so the guard's own deadline,
not the SDK's, decides.

Each hook instance uses its own session prefix, so budgets, data labels and
repeated-denial rules apply per Claude session and do not carry over between
runs. `checker(tool, args) -> verdict dict` replaces the HTTP client for
offline experiments.
"""
from __future__ import annotations

import asyncio
import copy
import uuid
from typing import Any, Callable


def _deny(reason: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": f"Agent Guard: {reason}"[:2000]}}


def agent_guard_hook(guard: Any = None, *, checker: Callable[[str, dict], dict] | None = None,
                     session_prefix: str | None = None, grant_on_allow: bool = False, ask_as: str = "deny",
                     deadline_s: float | None = None) -> Callable:
    if guard is None and checker is None:
        raise ValueError("pass a GuardClient or a checker")
    if ask_as not in ("deny", "ask"):
        raise ValueError("ask_as must be 'deny' or 'ask'")
    prefix = session_prefix or f"claude-sdk:{uuid.uuid4().hex[:8]}:"
    if deadline_s is None:
        deadline_s = (3 * float(getattr(guard, "timeout", 5.0)) + float(getattr(guard, "approval_wait", 0.0)) + 5.0
                      if guard is not None else 30.0)
    decisions: list[dict] = []

    def judge(tool: str, args: dict, session: str) -> dict:
        if checker is not None:
            return checker(tool, args)
        g = copy.copy(guard)          # same settings and approval memory, this Claude session's guard session
        g.session_id = session
        g.framework = "claude-agent-sdk"
        g.agent_id = g.agent_id or session
        return g.check(tool, args)

    async def hook(input_data: dict[str, Any], tool_use_id: str | None, context: Any) -> dict[str, Any]:
        try:
            if input_data.get("hook_event_name") != "PreToolUse":
                return {}
            tool = input_data.get("tool_name")
            args = input_data.get("tool_input") or {}
            if not isinstance(tool, str) or not tool or not isinstance(args, dict):
                return _deny("malformed tool call; failing closed")
            session = f"{prefix}{input_data.get('session_id') or 'default'}"[:128]
            verdict = await asyncio.wait_for(asyncio.to_thread(judge, tool, args, session), timeout=deadline_s)
            decision = verdict.get("decision")
            reasons = " ".join(verdict.get("reasons") or []) or str(decision)
            decisions.append({"tool": tool, "decision": decision, "tool_use_id": tool_use_id,
                              "approval_id": verdict.get("approval_id")})
            if decision == "allow":
                if not grant_on_allow:
                    return {}
                return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                                               "permissionDecisionReason": f"Agent Guard: {reasons}"[:2000]}}
            if decision == "modify" and isinstance(verdict.get("modified_args"), dict):
                return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                                               "permissionDecisionReason": f"Agent Guard: {reasons}"[:2000],
                                               "updatedInput": verdict["modified_args"]}}
            if decision == "ask":
                if ask_as == "ask":
                    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                                   "permissionDecisionReason": f"Agent Guard: {reasons}"[:2000]}}
                aid = verdict.get("approval_id")
                return _deny(f"needs a person's approval ({reasons})."
                             + (f" Approval request {aid}: approve it on the Safety Filter page, then repeat "
                                "exactly the same call." if aid else ""))
            return _deny(reasons)
        except asyncio.TimeoutError:
            return _deny(f"no verdict within {deadline_s:g} s; failing closed")
        except Exception as exc:  # noqa: BLE001 — every failure blocks
            return _deny(f"guard unreachable or invalid ({type(exc).__name__}); failing closed")

    hook.decisions = decisions  # type: ignore[attr-defined]
    return hook
