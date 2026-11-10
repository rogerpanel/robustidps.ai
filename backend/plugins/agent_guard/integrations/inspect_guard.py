"""Agent Guard for Inspect (inspect_ai): an approver.

    from inspect_ai import Task, task
    from inspect_ai.approval import ApprovalPolicy, human_approver
    from inspect_guard import agent_guard

    @task
    def my_task():
        return Task(..., approval=[
            ApprovalPolicy(agent_guard(url="https://robustidps.ai", token="...", policy="mcp-general"), "*"),
            ApprovalPolicy(human_approver(), "*"),      # receives the calls the guard escalates
        ])

Or in an approval YAML file (import this module in your task file so the
approver is registered):

    approvers:
      - name: agent_guard
        tools: "*"
        policy: mcp-general
      - name: human
        tools: "*"

Verdict mapping:
  allow  -> approve
  modify -> modify (the guard's corrected arguments)
  ask    -> escalate (the next approver decides, e.g. a human); "reject" if
            ask_as="reject" or no other approver follows
  deny   -> reject, or terminate the sample with deny_as="terminate"
Any guard failure is a reject. URL and token default to AGENT_GUARD_URL and
AGENT_GUARD_TOKEN. Each sample (by its first user message) gets its own
guard session. Verified against inspect_ai 0.3.283.
"""
from __future__ import annotations

import dataclasses
import hashlib
import os
import uuid
from typing import Any, Callable, Literal

import anyio
from inspect_ai.approval import Approval, Approver, approver
from inspect_ai.model import ChatMessage
from inspect_ai.tool import ToolCall, ToolCallView

try:  # the downloaded client file
    from agent_guard_client import GuardClient
except ImportError:  # running inside the robustidps.ai repository
    from plugins.agent_guard.client import GuardClient

Checker = Callable[[str, dict[str, Any]], dict[str, Any]]


def _session(history: list[ChatMessage], prefix: str) -> str:
    """One guard session per sample run: the sample's uuid, else a digest of its first user message."""
    try:
        from inspect_ai.solver._task_state import sample_state  # not a public API; fallback below
        state = sample_state()
        if state is not None:
            return f"{prefix}-{state.uuid}"
    except Exception:  # noqa: BLE001
        pass
    first = next((m for m in history if getattr(m, "role", "") == "user"), None)
    text = first.text if first is not None else ""
    return f"{prefix}-{hashlib.sha256(text.encode()).hexdigest()[:12]}"


@approver(name="agent_guard")
def agent_guard(url: str | None = None, token: str | None = None, policy: str = "soc-triage",
                ask_as: Literal["escalate", "reject"] = "escalate",
                deny_as: Literal["reject", "terminate"] = "reject",
                approval_wait: float = 0.0, session_prefix: str | None = None,
                checker: Checker | None = None) -> Approver:
    """Approve, modify, escalate or reject each tool call with Agent Guard.

    Args:
        url: robustidps.ai base URL (default AGENT_GUARD_URL).
        token: platform token or rids_live_ API key (default AGENT_GUARD_TOKEN).
        policy: guard policy pack id.
        ask_as: what an 'ask' verdict becomes.
        deny_as: what a 'deny' verdict becomes.
        approval_wait: seconds to wait for a person to approve an 'ask' on the Safety Filter page.
        session_prefix: prefix of the per-sample guard session id (a fresh one per approver instance
            by default, so repeated evaluations do not share budgets or repeated-denial state).
        checker: optional checker(tool, args) -> verdict, instead of the HTTP client.
    """
    session_prefix = session_prefix or f"inspect-{uuid.uuid4().hex[:8]}"
    client = None if checker is not None else GuardClient(
        url or os.environ.get("AGENT_GUARD_URL", "http://localhost:8000"),
        token if token is not None else os.environ.get("AGENT_GUARD_TOKEN", ""),
        policy_id=policy, approval_wait=approval_wait, framework="inspect")

    def check(session: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if checker is not None:
            return checker(tool, args)
        client.session_id = session
        return client.check(tool, args)

    async def approve(message: str, call: ToolCall, view: ToolCallView,
                      history: list[ChatMessage]) -> Approval:
        try:
            verdict = await anyio.to_thread.run_sync(
                check, _session(history, session_prefix), call.function, dict(call.arguments or {}))
        except Exception as exc:  # noqa: BLE001 — fail closed
            return Approval(decision="reject", explanation=f"Agent Guard failed ({type(exc).__name__}); failing closed")
        decision = verdict.get("decision")
        reasons = "; ".join(verdict.get("reasons") or [])
        meta = {"agent_guard": {k: verdict.get(k) for k in ("decision", "risk", "tier", "approval_id", "policy_id")}}
        if decision == "allow":
            return Approval(decision="approve", explanation=f"Agent Guard: {reasons}", metadata=meta)
        if decision == "modify" and verdict.get("modified_args") is not None:
            return Approval(decision="modify", modified=dataclasses.replace(call, arguments=dict(verdict["modified_args"])),
                            explanation=f"Agent Guard: {reasons}", metadata=meta)
        if decision == "ask":
            return Approval(decision=ask_as, explanation=f"Agent Guard asks for approval: {reasons}", metadata=meta)
        return Approval(decision=deny_as if decision == "deny" else "reject",
                        explanation=f"Agent Guard ({decision}): {reasons}", metadata=meta)

    return approve
