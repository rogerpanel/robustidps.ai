"""FastAPI router: /api/agent-guard/*.

Identity uses the Agent Studio layers (platform JWT, rids_live_ API key, or
demo mode), so the same tokens work for the scanner, red team and the guard.
Session state and the decision log are scoped to the caller's customer id.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, ValidationError

from plugins.agent_guard.adapters import (
    call_from_claude_hook, claude_hook_deny, claude_hook_response, openhands_risk,
)
from plugins.agent_guard.contract import FILTER_VERSION, Decision, ProposedCall
from plugins.agent_guard.engine import DecisionLog, SessionStore, decide, deny_decision
from plugins.agent_guard.policy import Policy, builtin_policies, parse_policy, validation_errors
from plugins.agent_studio.auth import require_api_key

try:
    from main import limiter
except Exception:  # pragma: no cover — keeps the plugin importable in tests
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    limiter = Limiter(key_func=get_remote_address)

logger = logging.getLogger("agent_guard")

RATE_CHECK = os.getenv("AGENT_GUARD_RATE", "600/minute")
MAX_ARGS_BYTES = 100_000
MAX_POLICY_BYTES = 200_000

router = APIRouter(prefix="/api/agent-guard", tags=["Agent Guard"])
STORE = SessionStore()
LOG = DecisionLog()


def _timeout() -> float:
    return float(os.getenv("AGENT_GUARD_TIMEOUT_S", "2.0"))


class CheckRequest(ProposedCall):
    policy_id: str = Field("soc-triage", max_length=64)
    policy: dict[str, Any] | None = Field(None, description="Inline policy pack (testing); overrides policy_id")


class PolicyBody(BaseModel):
    policy: dict[str, Any]


def _resolve_policy(policy_id: str, inline: dict | None) -> Policy:
    if inline is not None:
        if len(json.dumps(inline, default=str)) > MAX_POLICY_BYTES:
            raise HTTPException(413, "Policy too large")
        try:
            return parse_policy(inline)
        except ValidationError as exc:
            raise HTTPException(422, {"policy_errors": validation_errors(inline), "count": exc.error_count()})
    policy = builtin_policies().get(policy_id)
    if policy is None:
        raise HTTPException(404, f"Unknown policy '{policy_id}'")
    return policy


async def _decide(call: ProposedCall, policy: Policy, customer: dict) -> Decision:
    customer_id = str(customer.get("customer_id") or customer.get("email") or "anonymous")
    started = time.perf_counter()
    if len(json.dumps(call.args, default=str)) > MAX_ARGS_BYTES:
        decision = deny_decision(call, policy, "Arguments too large to inspect; failing closed.",
                                 "args-too-large", started)
    else:
        try:
            decision = await asyncio.wait_for(
                run_in_threadpool(decide, call, policy, STORE, customer_id), timeout=_timeout())
        except asyncio.TimeoutError:
            decision = deny_decision(call, policy, "The filter timed out; failing closed.", "filter-timeout", started)
    LOG.add(customer_id, {
        "t": time.time(), "session_id": call.session_id, "agent_id": call.agent_id,
        "framework": call.framework, "tool_name": call.tool_name, "args": call.args,
        **decision.model_dump(exclude={"tool_name"}),
    })
    _to_runtime_monitor(call, decision)
    return decision


def _to_runtime_monitor(call: ProposedCall, decision: Decision) -> None:
    """Feed the asynchronous runtime monitor (allow / warn / block analytics)."""
    try:
        from plugins.agent_studio.runtime_monitor import ingest
        ingest(call.agent_id or f"guard:{call.session_id}", call.framework or "agent_guard",
               {"allow": "allow", "modify": "warn", "ask": "warn", "deny": "block"}[decision.decision],
               [f.rule_id for f in decision.findings if f.verdict != "allow"], decision.latency_ms,
               kind="tool_call")
    except Exception:  # noqa: BLE001 — monitoring must never change a decision
        logger.debug("runtime monitor ingest failed", exc_info=True)


@router.get("/info")
def info() -> dict:
    return {
        "filter_version": FILTER_VERSION,
        "timeout_s": _timeout(),
        "policies": [{"id": p.id, "version": p.version, "name": p.name} for p in builtin_policies().values()],
        "verdicts": ["allow", "modify", "ask", "deny"],
        "fail_closed": ["filter error", "timeout", "repeat of a denied call", "concurrent check",
                        "arguments too large", "malformed hook payload"],
        "adapters": ["/api/agent-guard/check", "/api/agent-guard/hooks/claude"],
    }


@router.get("/client.py")
def client_script() -> PlainTextResponse:
    """The stdlib client / command hook, for users to copy into their agents."""
    path = Path(__file__).with_name("client.py")
    return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/x-python",
                             headers={"Content-Disposition": 'attachment; filename="agent_guard_client.py"'})


@router.get("/policies")
def list_policies() -> list[dict]:
    return [p.model_dump() for p in builtin_policies().values()]


@router.get("/policies/{policy_id}")
def get_policy(policy_id: str) -> dict:
    return _resolve_policy(policy_id, None).model_dump()


@router.post("/policies/validate")
def validate_policy(body: PolicyBody) -> dict:
    errors = validation_errors(body.policy)
    return {"valid": not errors, "errors": errors}


@router.post("/check", response_model=Decision)
@limiter.limit(RATE_CHECK)
async def check(request: Request, req: CheckRequest, customer: dict = Depends(require_api_key)) -> Decision:
    policy = _resolve_policy(req.policy_id, req.policy)
    call = ProposedCall(**req.model_dump(include=set(ProposedCall.model_fields)))
    decision = await _decide(call, policy, customer)
    return decision


@router.post("/hooks/claude")
@limiter.limit(RATE_CHECK)
async def claude_hook(request: Request, policy_id: str = "soc-triage",
                      customer: dict = Depends(require_api_key)) -> dict:
    """Claude-style PreToolUse hook endpoint (also Hermes shell hooks). Never errors: bad input is a deny."""
    try:
        payload = await request.json()
        call = call_from_claude_hook(payload)
        policy = _resolve_policy(policy_id, None)
    except HTTPException as exc:
        return claude_hook_deny(f"{exc.detail}; failing closed")
    except Exception:  # noqa: BLE001
        return claude_hook_deny("malformed hook payload; failing closed")
    decision = await _decide(call, policy, customer)
    response = claude_hook_response(decision)
    response["agentGuard"] = {"decision": decision.decision, "risk": decision.risk,
                              "openhands_risk": openhands_risk(decision)}
    return response


@router.get("/decisions")
def decisions(session_id: str | None = None, limit: int = 100,
              customer: dict = Depends(require_api_key)) -> list[dict]:
    customer_id = str(customer.get("customer_id") or customer.get("email") or "anonymous")
    return LOG.list(customer_id, session_id, max(1, min(limit, 500)))


@router.post("/sessions/{session_id}/reset")
def reset_session(session_id: str, customer: dict = Depends(require_api_key)) -> dict:
    """Human decision to clear a session's budget, denials and escalation."""
    customer_id = str(customer.get("customer_id") or customer.get("email") or "anonymous")
    return {"reset": STORE.reset(customer_id, session_id), "session_id": session_id}
