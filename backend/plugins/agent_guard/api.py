"""FastAPI router: /api/agent-guard/*.

Identity uses the Agent Studio layers (platform login, rids_live_ API key,
admin, demo mode). Everything is scoped to a tenant: the e-mail behind the
identity, so an agent running on a user's API key and the user signed in on
the website share sessions, approvals, the tool registry and the evidence
ledger. Approvals can only be decided by a signed-in person, never by an API
key, so an agent cannot approve its own calls.
"""

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.orm import Session

from database import SessionLocal, get_db
from plugins.agent_guard import approvals, deferral, environment, evidence, registry
from plugins.agent_guard import flow as flowmod
from plugins.agent_guard.adapters import (
    call_from_claude_hook, claude_hook_deny, claude_hook_response, openhands_risk,
)
from plugins.agent_guard.contract import FILTER_VERSION, Decision, Finding, ProposedCall
from plugins.agent_guard.engine import (
    DecisionLog, SessionStore, budget_room, canonicalize, charge_budgets, commit_let_through, commit_prediction,
    decide, deny_decision,
)
from plugins.agent_guard.evaluation import Suite, builtin_suites, compare as compare_suite, run as run_suite
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
MAX_TOOLSET_BYTES = 1_000_000

ENV_ENABLED = True
router = APIRouter(prefix="/api/agent-guard", tags=["Agent Guard"])
STORE = SessionStore()
LOG = DecisionLog()


def _timeout() -> float:
    return float(os.getenv("AGENT_GUARD_TIMEOUT_S", "2.0"))


def tenant(customer: dict) -> str:
    email = str(customer.get("email") or "").strip().lower()
    if email and customer.get("source") in ("platform_jwt", "api_key", "env_bypass"):
        return email
    return str(customer.get("customer_id") or "anonymous")


def _actor(customer: dict) -> str:
    return str(customer.get("email") or customer.get("customer_id") or "unknown")


def _require_person(customer: dict) -> None:
    if customer.get("source") == "api_key":
        raise HTTPException(403, "Approvals and pins must be made by a signed-in person, not an API key.")


# ── schemas ───────────────────────────────────────────────────────────

class CheckRequest(ProposedCall):
    policy_id: str = Field("soc-triage", max_length=64)
    policy: dict[str, Any] | None = Field(None, description="Inline policy pack (testing); overrides policy_id")
    approval_id: str | None = Field(None, max_length=64, description="Repeat an approved call with its approval id")


class PolicyBody(BaseModel):
    policy: dict[str, Any]


class DecideBody(BaseModel):
    decision: Literal["approve", "deny"]
    note: str = Field("", max_length=2000)


class ToolsetBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    text: str = Field(..., min_length=2, max_length=MAX_TOOLSET_BYTES)


class VerifyBody(BaseModel):
    tools: Any


class CoverageBody(BaseModel):
    policy_id: str = "soc-triage"
    policy: dict[str, Any] | None = None
    version: int | None = None


class EvaluateBody(BaseModel):
    suite_id: str | None = Field(None, description="Built-in suite; or pass `suite`")
    suite: dict[str, Any] | None = None
    policy_id: str | None = None
    policy: dict[str, Any] | None = None


# ── helpers ───────────────────────────────────────────────────────────

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


def _record(db: Session, tid: str, call: ProposedCall, decision: Decision) -> None:
    """Non-allow decisions go to the evidence ledger; allows only to the in-memory log."""
    if decision.decision == "allow":
        return
    try:
        evidence.append(db, tid, "guard_decision", {
            "session_id": call.session_id, "agent_id": call.agent_id, "framework": call.framework,
            "tool_name": call.tool_name, "decision": decision.decision, "risk": decision.risk,
            "rules": [f.rule_id for f in decision.findings if f.verdict == decision.decision],
            "call_key": decision.call_key, "approval_id": decision.approval_id,
            **({"flow_labels": decision.flow.get("session_after", [])} if decision.flow else {}),
            "policy": f"{decision.policy_id} v{decision.policy_version}", "filter_version": decision.filter_version,
        }, f"{decision.decision.upper()} {call.tool_name} ({call.session_id})")
    except Exception:  # noqa: BLE001 — the ledger must not change a decision
        logger.warning("evidence append failed", exc_info=True)


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


def _approved(call: ProposedCall, policy: Policy, tid: str, approval_id: str, db: Session) -> Decision:
    started = time.perf_counter()
    c = canonicalize(call, policy)
    state = STORE.get(tid, call.session_id)
    row = approvals.get(db, tid, approval_id)
    charges = (row.request or {}).get("budget_charges") if row is not None else None
    if row is not None and row.status == "approved" and row.session_id == call.session_id and row.call_key == c.key:
        # Re-check budgets at use time: other calls may have spent them since the request. The approval is kept.
        why = budget_room(state, policy, charges)
        if why:
            return deny_decision(call, policy, why, "approval-budget-spent", started).model_copy(
                update={"call_key": c.key, "approval_id": approval_id})
    ok, reason, approved_args = approvals.consume(db, tid, approval_id, call.session_id, c.key)
    if not ok:
        return deny_decision(call, policy, reason, "approval-not-valid", started).model_copy(
            update={"call_key": c.key, "approval_id": approval_id})
    state.calls += 1
    charge_budgets(state, charges)
    commit_prediction(state, approvals.approved_prediction(db, tid, approval_id))  # the approved effect happens
    flow_report = None
    if policy.flow is not None:  # the approved call's data labels now belong to the session
        env = _env_for(db, tid)
        run_args = approved_args if approved_args is not None else c.args
        flow_report = flowmod.check(c.tool, run_args, policy, env.internal if env else None, state.labels).report
        flowmod.commit(state.labels, flow_report, state.calls)
    return Decision(decision="allow", risk="MEDIUM", reasons=[reason],
                    findings=[Finding(rule_id="human-approved", verdict="allow", reason=reason)],
                    tool_name=call.tool_name, canonical_tool=c.tool, hidden_characters=c.hidden,
                    session_calls=state.calls, policy_id=policy.id, policy_version=policy.version,
                    call_key=c.key, approval_id=approval_id, flow=flow_report,
                    modified_args=approved_args if approved_args is not None and approved_args != call.args else None,
                    latency_ms=round((time.perf_counter() - started) * 1000, 3))


def _deferral(call: ProposedCall, policy: Policy, tid: str, decision: Decision, db: Session) -> tuple[Decision, dict]:
    """Score an 'ask' and apply the tenant's calibrated-deferral mode (off / shadow / auto)."""
    state = STORE.get(tid, call.session_id)
    feats = deferral.features(decision, policy, state.denied_attempts)
    score = deferral.risk_score(feats)
    ok, why = deferral.eligible(decision, policy)
    info = {"score": score, "eligible": ok, "reason": why, "features": feats}
    settings = deferral.load_settings(db, tid)
    info["mode"] = settings.mode
    if settings.mode == "off" or not ok:
        return decision, info
    calib = deferral.calibrate(*deferral.calibration_data(db, tid), settings.alpha, settings.min_samples,
                               settings.delta)
    would = bool(calib["ready"] and score <= calib["threshold"])
    info.update({"threshold": calib["threshold"], "alpha": settings.alpha, "would_auto_approve": would})
    if settings.mode == "auto" and would:
        reason = (f"Auto-approved by calibrated deferral: risk score {score} <= threshold {calib['threshold']} "
                  f"(at most {settings.alpha:.0%} of auto-approvals would have been denied, "
                  f"with {1 - settings.delta:.0%} confidence).")
        decision = decision.model_copy(update={
            "decision": "allow", "risk": "MEDIUM", "reasons": [reason],
            "findings": [*decision.findings, Finding(rule_id="calibrated-auto-approval", verdict="allow", reason=reason)]})
        commit_let_through(state, decision)
        evidence.append(db, tid, "auto_approval",
                        {"session_id": call.session_id, "tool_name": call.tool_name, "call_key": decision.call_key,
                         "score": score, "threshold": calib["threshold"], "alpha": settings.alpha, "n": calib["n"]},
                        f"Auto-approved {call.tool_name} ({call.session_id}): score {score} <= {calib['threshold']}")
    return decision, info


def _finish(call: ProposedCall, policy: Policy, tid: str, decision: Decision, db: Session) -> Decision:
    """Apply calibrated deferral, queue an approval for 'ask', then log, ledger and monitor the decision."""
    if decision.decision == "ask" and not decision.approval_id:
        try:
            decision, info = _deferral(call, policy, tid, decision, db)
        except Exception:  # noqa: BLE001 — deferral is an optimisation; on failure the ask stays an ask
            logger.warning("deferral failed", exc_info=True)
            info = {"score": None, "eligible": False, "reason": "deferral failed", "mode": "error"}
        decision = decision.model_copy(update={"deferral": info})
    if decision.decision == "ask" and not decision.approval_id:
        try:
            run_args = decision.modified_args if decision.modified_args is not None else canonicalize(call, policy).args
            info = decision.deferral or {}
            row = approvals.create(db, tid, call, policy, decision, decision.call_key, run_args,
                                   extra={"budget_charges": decision.budget_charges,
                                          "risk_score": info.get("score"),
                                          "deferral_eligible": info.get("eligible"), "deferral": info})
            decision = decision.model_copy(update={"approval_id": row.id})
        except Exception:  # noqa: BLE001 — no approval record means no way to approve: deny
            logger.warning("approval create failed", exc_info=True)
            decision = deny_decision(call, policy, "Could not queue the approval; failing closed.",
                                     "approval-queue-error")
    LOG.add(tid, {"t": time.time(), "session_id": call.session_id, "agent_id": call.agent_id,
                  "framework": call.framework, "tool_name": call.tool_name, "args": call.args,
                  **decision.model_dump(exclude={"tool_name"})})
    _record(db, tid, call, decision)
    _to_runtime_monitor(call, decision)
    return decision


def _env_for(db: Session, tid: str):
    """The tenant's environment model for the predictive layer (None if none is defined or it cannot load)."""
    if not ENV_ENABLED:
        return None
    try:
        return environment.load(db, tid)[0]
    except Exception:  # noqa: BLE001 — without a model the layer is inactive; the rule layers still apply
        logger.warning("environment load failed", exc_info=True)
        return None


def _too_large(call: ProposedCall) -> bool:
    return len(json.dumps(call.args, default=str)) > MAX_ARGS_BYTES


async def guard_call(call: ProposedCall, policy: Policy, tid: str, approval_id: str | None,
                     db: Session) -> Decision:
    """API entry point: decide (with the timeout), then record."""
    started = time.perf_counter()
    if _too_large(call):
        decision = deny_decision(call, policy, "Arguments too large to inspect; failing closed.",
                                 "args-too-large", started)
    elif approval_id:
        decision = await run_in_threadpool(_approved, call, policy, tid, approval_id, db)
    else:
        try:
            env = await run_in_threadpool(_env_for, db, tid)
            decision = await asyncio.wait_for(run_in_threadpool(decide, call, policy, STORE, tid, env),
                                              timeout=_timeout())
        except asyncio.TimeoutError:
            decision = deny_decision(call, policy, "The filter timed out; failing closed.",
                                     "filter-timeout", started)
    return await run_in_threadpool(_finish, call, policy, tid, decision, db)


def guard_call_sync(call: ProposedCall, policy: Policy, tid: str, approval_id: str | None = None) -> Decision:
    """In-process entry point for agents running in worker threads (e.g. the SOC Investigator)."""
    db = SessionLocal()
    try:
        if _too_large(call):
            decision = deny_decision(call, policy, "Arguments too large to inspect; failing closed.",
                                     "args-too-large")
        elif approval_id:
            decision = _approved(call, policy, tid, approval_id, db)
        else:
            decision = decide(call, policy, STORE, tid, _env_for(db, tid))
        return _finish(call, policy, tid, decision, db)
    except Exception:  # noqa: BLE001
        logger.warning("in-process guard failed", exc_info=True)
        return deny_decision(call, policy, "The filter failed; failing closed.", "filter-error")
    finally:
        db.close()


# ── info, policies, client ────────────────────────────────────────────

@router.get("/info")
def info() -> dict:
    return {
        "filter_version": FILTER_VERSION,
        "timeout_s": _timeout(),
        "approval_ttl_min": approvals.ttl_minutes(),
        "policies": [{"id": p.id, "version": p.version, "name": p.name} for p in builtin_policies().values()],
        "suites": [{"id": s.id, "version": s.version, "policy_id": s.policy_id, "cases": len(s.cases)}
                   for s in builtin_suites().values()],
        "verdicts": ["allow", "modify", "ask", "deny"],
        "fail_closed": ["filter error", "timeout", "repeat of a denied call", "concurrent check",
                        "arguments too large", "malformed hook payload", "approval missing, pending, "
                        "expired, used or for another call"],
    }


@router.get("/client.py")
def client_script() -> PlainTextResponse:
    """The stdlib client, command hook and MCP gateway, for users to copy into their agents."""
    path = Path(__file__).with_name("client.py")
    return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/x-python",
                             headers={"Content-Disposition": 'attachment; filename="agent_guard_client.py"'})


INTEGRATIONS = {"agentdojo": "agentdojo_guard.py", "inspect": "inspect_guard.py", "selftest": "selftest.py"}


@router.get("/integrations/{name}")
def integration_script(name: str) -> PlainTextResponse:
    """Connector files for AgentDojo (GuardedToolsExecutor) and Inspect (agent_guard approver)."""
    filename = INTEGRATIONS.get(name)
    if filename is None:
        raise HTTPException(404, f"Unknown integration; available: {', '.join(INTEGRATIONS)}")
    path = Path(__file__).parent / "integrations" / filename
    download = "agent_guard_selftest.py" if name == "selftest" else filename
    return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/x-python",
                             headers={"Content-Disposition": f'attachment; filename="{download}"'})


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


# ── checks ────────────────────────────────────────────────────────────

@router.post("/check", response_model=Decision)
@limiter.limit(RATE_CHECK)
async def check(request: Request, req: CheckRequest, customer: dict = Depends(require_api_key),
                db: Session = Depends(get_db)) -> Decision:
    policy = _resolve_policy(req.policy_id, req.policy)
    call = ProposedCall(**req.model_dump(include=set(ProposedCall.model_fields)))
    return await guard_call(call, policy, tenant(customer), req.approval_id, db)


@router.post("/hooks/claude")
@limiter.limit(RATE_CHECK)
async def claude_hook(request: Request, policy_id: str = "soc-triage",
                      customer: dict = Depends(require_api_key), db: Session = Depends(get_db)) -> dict:
    """Claude-style PreToolUse hook endpoint (also Hermes shell hooks). Never errors: bad input is a deny.

    Hooks cannot wait for a person, so 'ask' is returned as 'ask' (Claude Code asks its user) and the
    approval is also queued here for review."""
    try:
        payload = await request.json()
        call = call_from_claude_hook(payload)
        policy = _resolve_policy(policy_id, None)
    except HTTPException as exc:
        return claude_hook_deny(f"{exc.detail}; failing closed")
    except Exception:  # noqa: BLE001
        return claude_hook_deny("malformed hook payload; failing closed")
    decision = await guard_call(call, policy, tenant(customer), None, db)
    response = claude_hook_response(decision)
    response["agentGuard"] = {"decision": decision.decision, "risk": decision.risk,
                              "openhands_risk": openhands_risk(decision), "approval_id": decision.approval_id}
    return response


@router.get("/decisions")
def decisions(session_id: str | None = None, limit: int = 100,
              customer: dict = Depends(require_api_key)) -> list[dict]:
    return LOG.list(tenant(customer), session_id, max(1, min(limit, 500)))


@router.get("/sessions/{session_id}")
def session_state(session_id: str, customer: dict = Depends(require_api_key)) -> dict:
    """What the guard holds for a session: call count, denials, budgets used, assets taken down, data labels."""
    state = STORE.peek(tenant(customer), session_id)
    if state is None:
        return {"session_id": session_id, "exists": False, "calls": 0, "denied_attempts": 0,
                "budget_used": {}, "unavailable": [], "blast": 0, "labels": {}}
    return {"session_id": session_id, "exists": True, "calls": state.calls, "denied_attempts": state.denied_attempts,
            "budget_used": dict(state.budget_used), "unavailable": sorted(state.unavailable), "blast": state.blast,
            "labels": {k: dict(v) for k, v in sorted(state.labels.items())}}


@router.post("/sessions/{session_id}/reset")
def reset_session(session_id: str, customer: dict = Depends(require_api_key), db: Session = Depends(get_db)) -> dict:
    """A person clears a session's budget, denials and escalation."""
    _require_person(customer)
    done = STORE.reset(tenant(customer), session_id)
    evidence.append(db, tenant(customer), "session_reset", {"session_id": session_id, "by": _actor(customer)},
                    f"Session {session_id} reset by {_actor(customer)}")
    return {"reset": done, "session_id": session_id}


# ── approvals ─────────────────────────────────────────────────────────

@router.get("/approvals")
def list_approvals(status: str | None = None, customer: dict = Depends(require_api_key),
                   db: Session = Depends(get_db)) -> list[dict]:
    return approvals.listing(db, tenant(customer), status)


@router.get("/approvals/{approval_id}")
def get_approval(approval_id: str, customer: dict = Depends(require_api_key), db: Session = Depends(get_db)) -> dict:
    row = approvals.get(db, tenant(customer), approval_id)
    if row is None:
        raise HTTPException(404, "Approval not found")
    return approvals.as_dict(row)


@router.post("/approvals/{approval_id}/decide")
def decide_approval(approval_id: str, body: DecideBody, customer: dict = Depends(require_api_key),
                    db: Session = Depends(get_db)) -> dict:
    _require_person(customer)
    tid = tenant(customer)
    try:
        row = approvals.decide(db, tid, approval_id, body.decision == "approve", _actor(customer), body.note)
    except LookupError:
        raise HTTPException(404, "Approval not found")
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    if row.status == "denied":
        STORE.get(tid, row.session_id).denied_keys.add(row.call_key)  # the same call stays denied
    return approvals.as_dict(row)


# ── tool registry (shared with the scanner and the MCP gateway) ───────

@router.get("/toolsets")
def list_toolsets(customer: dict = Depends(require_api_key), db: Session = Depends(get_db)) -> list[dict]:
    return registry.listing(db, tenant(customer))


@router.post("/toolsets")
def register_toolset(body: ToolsetBody, customer: dict = Depends(require_api_key),
                     db: Session = Depends(get_db)) -> dict:
    try:
        return registry.register(db, tenant(customer), body.name.strip(), body.text)
    except registry.RegistryError as exc:
        raise HTTPException(422, str(exc))


@router.get("/toolsets/{name}")
def get_toolset(name: str, version: int | None = None, customer: dict = Depends(require_api_key),
                db: Session = Depends(get_db)) -> dict:
    row = registry.get(db, tenant(customer), name, version)
    if row is None:
        raise HTTPException(404, "Toolset not found")
    return registry._row(row)


@router.post("/toolsets/{name}/pin")
def pin_toolset(name: str, version: int, customer: dict = Depends(require_api_key),
                db: Session = Depends(get_db)) -> dict:
    _require_person(customer)
    try:
        return registry.pin(db, tenant(customer), name, version, _actor(customer))
    except registry.RegistryError as exc:
        raise HTTPException(422, str(exc))


@router.post("/toolsets/{name}/verify")
def verify_toolset(name: str, body: VerifyBody, customer: dict = Depends(require_api_key),
                   db: Session = Depends(get_db)) -> dict:
    """Used by the MCP gateway on every tools/list: only 'ok' tools reach the agent."""
    try:
        result = registry.verify(db, tenant(customer), name, body.tools)
    except registry.RegistryError as exc:
        raise HTTPException(422, str(exc))
    flagged = [t for t in result["tools"] if t["status"] not in ("ok",)]
    if flagged and result.get("pinned_version"):
        evidence.append(db, tenant(customer), "toolset_drift",
                        {"toolset": name, "pinned_version": result["pinned_version"], "flagged": flagged},
                        f"{len(flagged)} tool(s) of {name} differ from the pinned version")
    return result


@router.post("/toolsets/{name}/coverage")
def toolset_coverage(name: str, body: CoverageBody, customer: dict = Depends(require_api_key),
                     db: Session = Depends(get_db)) -> dict:
    row = registry.get(db, tenant(customer), name, body.version)
    if row is None:
        raise HTTPException(404, "Toolset not found")
    policy = _resolve_policy(body.policy_id, body.policy)
    return {**registry.coverage(row.tools, policy),
            "generated_policy": registry.generated_policy(row.tools, policy, name)}


# ── evaluation (verifiable results) ───────────────────────────────────

@router.get("/suites")
def list_suites() -> list[dict]:
    return [s.model_dump() for s in builtin_suites().values()]


@router.post("/evaluate")
def evaluate(body: EvaluateBody, customer: dict = Depends(require_api_key), db: Session = Depends(get_db)) -> dict:
    if body.suite is not None:
        if len(json.dumps(body.suite, default=str)) > MAX_POLICY_BYTES * 5:
            raise HTTPException(413, "Suite too large")
        try:
            suite = Suite.model_validate(body.suite)
        except ValidationError as exc:
            raise HTTPException(422, {"suite_errors": [f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}"
                                                       for e in exc.errors()][:20]})
    else:
        suite = builtin_suites().get(body.suite_id or "")
        if suite is None:
            raise HTTPException(404, f"Unknown suite '{body.suite_id}'")
    policy = _resolve_policy(body.policy_id or suite.policy_id or "soc-triage", body.policy)
    result = run_suite(suite, policy)
    tid = tenant(customer)
    same_inputs = [p for p in evidence.payloads(db, tid, "evaluation")
                   if p.get("suite_digest") == result["suite_digest"]
                   and p.get("policy_digest") == result["policy_digest"]
                   and p.get("filter_version") == result["filter_version"]]
    rec = evidence.append(db, tid, "evaluation",
                          {"summary": result["summary"], "suite_digest": result["suite_digest"],
                           "policy_digest": result["policy_digest"], "result_digest": result["result_digest"],
                           "filter_version": result["filter_version"]},
                          f"Evaluated {result['summary']['policy']} on {result['summary']['suite']}: "
                          f"accuracy {result['summary']['exact_accuracy']}")
    result["evidence"] = {"seq": rec.seq, "hash": rec.hash}
    result["reproduction"] = {
        "earlier_runs_same_inputs": len(same_inputs),
        "all_match": all(p.get("result_digest") == result["result_digest"] for p in same_inputs)
        if same_inputs else None,
    }
    return result


def _suite_from(body: EvaluateBody) -> Suite:
    if body.suite is not None:
        if len(json.dumps(body.suite, default=str)) > MAX_POLICY_BYTES * 5:
            raise HTTPException(413, "Suite too large")
        try:
            return Suite.model_validate(body.suite)
        except ValidationError as exc:
            raise HTTPException(422, {"suite_errors": [f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}"
                                                       for e in exc.errors()][:20]})
    suite = builtin_suites().get(body.suite_id or "")
    if suite is None:
        raise HTTPException(404, f"Unknown suite '{body.suite_id}'")
    return suite


@router.post("/evaluate/compare")
def evaluate_compare(body: EvaluateBody, customer: dict = Depends(require_api_key),
                     db: Session = Depends(get_db)) -> dict:
    """The policy against single-layer ablations and trivial baselines, with bootstrap 95% intervals."""
    suite = _suite_from(body)
    policy = _resolve_policy(body.policy_id or suite.policy_id or "soc-triage", body.policy)
    result = compare_suite(suite, policy)
    rec = evidence.append(db, tenant(customer), "evaluation_compare",
                          {"suite_digest": result["suite_digest"], "policy_digest": result["policy_digest"],
                           "filter_version": result["filter_version"],
                           "comparison_digest": result["comparison_digest"],
                           "table": [{k: r[k] for k in ("name", "kind", "exact_accuracy", "stop_recall",
                                                        "false_stop_rate")} for r in result["table"]]},
                          f"Compared {result['policy']} on {result['suite']} against "
                          f"{len(result['table']) - 1} ablations and baselines")
    result["evidence"] = {"seq": rec.seq, "hash": rec.hash}
    return result


# ── environment model (predictive layer) ──────────────────────────────

class EnvironmentBody(BaseModel):
    environment: dict[str, Any]


@router.get("/environment")
def get_environment(customer: dict = Depends(require_api_key), db: Session = Depends(get_db)) -> dict:
    env, version = environment.load(db, tenant(customer))
    return {"version": version, "environment": json.loads(env.model_dump_json()) if env else None,
            "example": environment.EXAMPLE}


@router.post("/environment/validate")
def validate_environment(body: EnvironmentBody) -> dict:
    try:
        env = environment.Environment.model_validate(body.environment)
    except ValidationError as exc:
        return {"valid": False, "errors": [f"{'.'.join(str(p) for p in e['loc']) or 'environment'}: {e['msg']}"
                                           for e in exc.errors()][:20]}
    return {"valid": True, "errors": [], "assets": len(env.assets), "groups": len(env.groups)}


@router.put("/environment")
def put_environment(body: EnvironmentBody, customer: dict = Depends(require_api_key),
                    db: Session = Depends(get_db)) -> dict:
    """Replace the tenant's asset inventory (a person only: it decides what the guard protects)."""
    _require_person(customer)
    if len(json.dumps(body.environment, default=str)) > MAX_TOOLSET_BYTES * 2:
        raise HTTPException(413, "Environment too large")
    try:
        env = environment.Environment.model_validate(body.environment)
    except ValidationError as exc:
        raise HTTPException(422, {"environment_errors": [f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}"
                                                         for e in exc.errors()][:20]})
    tid = tenant(customer)
    version = environment.save(db, tid, env, _actor(customer))
    evidence.append(db, tid, "environment_update",
                    {"version": version, "assets": len(env.assets), "groups": sorted(env.groups),
                     "digest": evidence.digest(json.loads(env.model_dump_json())), "by": _actor(customer)},
                    f"Environment model v{version} saved ({len(env.assets)} assets) by {_actor(customer)}")
    return {"version": version, "assets": len(env.assets), "groups": len(env.groups)}


# ── calibrated deferral ──────────────────────────────────────────────

@router.get("/deferral")
def get_deferral(customer: dict = Depends(require_api_key), db: Session = Depends(get_db)) -> dict:
    tid = tenant(customer)
    settings = deferral.load_settings(db, tid)
    calib = deferral.calibrate(*deferral.calibration_data(db, tid), settings.alpha, settings.min_samples,
                               settings.delta)
    return {"settings": settings.model_dump(), "calibration": calib}


@router.put("/deferral")
def put_deferral(body: deferral.DeferralSettings, customer: dict = Depends(require_api_key),
                 db: Session = Depends(get_db)) -> dict:
    """Change the deferral mode or target (a person only: 'auto' lets calls run without review)."""
    _require_person(customer)
    tid = tenant(customer)
    deferral.save_settings(db, tid, body, _actor(customer))
    evidence.append(db, tid, "deferral_settings", {**body.model_dump(), "by": _actor(customer)},
                    f"Calibrated deferral set to {body.mode} (alpha {body.alpha}) by {_actor(customer)}")
    return get_deferral(customer, db)


# ── evidence ledger ───────────────────────────────────────────────────

@router.get("/evidence")
def list_evidence(kind: str | None = None, limit: int = 100, customer: dict = Depends(require_api_key),
                  db: Session = Depends(get_db)) -> list[dict]:
    return evidence.listing(db, tenant(customer), kind, max(1, min(limit, 500)))


@router.get("/evidence/verify")
def verify_evidence(customer: dict = Depends(require_api_key), db: Session = Depends(get_db)) -> dict:
    return evidence.verify(db, tenant(customer))


@router.get("/evidence/summary")
def evidence_summary(customer: dict = Depends(require_api_key), db: Session = Depends(get_db)) -> dict:
    return evidence.summary(db, tenant(customer))


@router.get("/evidence/export")
def export_evidence(customer: dict = Depends(require_api_key), db: Session = Depends(get_db)) -> dict:
    return evidence.export(db, tenant(customer))
