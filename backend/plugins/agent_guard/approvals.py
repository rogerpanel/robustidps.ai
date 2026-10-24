"""Approval queue for calls the guard answered with 'ask'.

Flow: /check returns decision 'ask' with an approval_id. A human reviews the
preview (tool, cleaned arguments, targets, tier, reversibility, hidden
characters, reasons) and approves or denies. The agent polls the approval;
once approved it repeats the same call with that approval_id and gets 'allow'
exactly once. The approval is bound to the session and to the canonical call,
so it cannot authorise different arguments. A denial makes the call sticky-
denied in its session; an approval nobody decides expires (deny).
"""
from __future__ import annotations

import datetime
import os
import uuid
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from plugins.agent_guard.contract import Decision, ProposedCall
from plugins.agent_guard.db_models import GuardApproval
from plugins.agent_guard.evidence import append
from plugins.agent_guard.policy import Policy


def ttl_minutes() -> int:
    return max(1, min(int(os.getenv("AGENT_GUARD_APPROVAL_TTL_MIN", "15")), 24 * 60))


def _now() -> datetime.datetime:
    return datetime.datetime.utcnow()


def preview(call: ProposedCall, policy: Policy, decision: Decision, clean_args: dict[str, Any]) -> dict:
    tier = policy.tiers.get(decision.tier)
    targets = []
    keys = set(policy.scope.target_args) if policy.scope else set()
    keys |= {"host", "hosts", "ip", "target", "targets", "url", "user", "account", "path", "domain"}
    for k in sorted(keys):
        v = clean_args.get(k)
        for item in (v if isinstance(v, list) else [v]):
            if isinstance(item, (str, int, float)) and not isinstance(item, bool) and str(item).strip():
                targets.append({"arg": k, "value": str(item)})
    return {
        "tool": call.tool_name, "canonical_tool": decision.canonical_tool, "args": clean_args,
        "tier": decision.tier, "tier_description": tier.description if tier else "",
        "reversible": tier.reversible if tier else None,
        "targets": targets, "n_targets": len(targets),
        "hidden_characters": decision.hidden_characters, "reasons": decision.reasons,
        "risk": decision.risk, "agent_id": call.agent_id, "framework": call.framework,
        "policy": f"{policy.id} v{policy.version}",
    }


def create(db: Session, customer_id: str, call: ProposedCall, policy: Policy, decision: Decision,
           call_key: str, clean_args: dict[str, Any]) -> GuardApproval:
    row = GuardApproval(
        id=uuid.uuid4().hex, customer_id=customer_id, session_id=call.session_id, call_key=call_key,
        status="pending", expires_at=_now() + datetime.timedelta(minutes=ttl_minutes()),
        request={"tool_name": call.tool_name, "args": clean_args, "policy_id": policy.id,
                 "policy_version": policy.version, "agent_id": call.agent_id, "framework": call.framework},
        preview=preview(call, policy, decision, clean_args))
    db.add(row)
    db.commit()
    return row


def expire_stale(db: Session) -> None:
    db.execute(update(GuardApproval).where(GuardApproval.status == "pending", GuardApproval.expires_at < _now())
               .values(status="expired"))
    db.commit()


def get(db: Session, customer_id: str, approval_id: str) -> GuardApproval | None:
    expire_stale(db)
    return db.execute(select(GuardApproval).where(GuardApproval.id == approval_id,
                                                  GuardApproval.customer_id == customer_id)).scalar_one_or_none()


def listing(db: Session, customer_id: str, status: str | None = None, limit: int = 100) -> list[dict]:
    expire_stale(db)
    q = select(GuardApproval).where(GuardApproval.customer_id == customer_id)
    if status:
        q = q.where(GuardApproval.status == status)
    return [as_dict(r) for r in db.execute(q.order_by(GuardApproval.created_at.desc()).limit(limit)).scalars()]


def as_dict(r: GuardApproval) -> dict:
    return {"id": r.id, "session_id": r.session_id, "status": r.status,
            "created_at": r.created_at.isoformat() + "Z", "expires_at": r.expires_at.isoformat() + "Z",
            "decided_at": r.decided_at.isoformat() + "Z" if r.decided_at else None,
            "decided_by": r.decided_by, "note": r.note, "request": r.request, "preview": r.preview}


def decide(db: Session, customer_id: str, approval_id: str, approve: bool, actor: str, note: str = "") -> GuardApproval:
    row = get(db, customer_id, approval_id)
    if row is None:
        raise LookupError("approval not found")
    if row.status != "pending":
        raise ValueError(f"approval is already {row.status}")
    row.status = "approved" if approve else "denied"
    row.decided_at = _now()
    row.decided_by = actor[:255]
    row.note = note[:2000]
    db.commit()
    append(db, customer_id, "approval",
           {"approval_id": row.id, "status": row.status, "by": row.decided_by, "note": row.note,
            "session_id": row.session_id, "call_key": row.call_key, "tool_name": row.request.get("tool_name"),
            "policy": row.preview.get("policy")},
           f"{row.status.capitalize()} {row.request.get('tool_name')} ({row.session_id}) by {row.decided_by}")
    return row


def consume(db: Session, customer_id: str, approval_id: str, session_id: str, call_key: str) -> tuple[bool, str]:
    """Use an approval for this exact call. Returns (allowed, reason)."""
    row = get(db, customer_id, approval_id)
    if row is None:
        return False, "Unknown approval."
    if row.session_id != session_id or row.call_key != call_key:
        return False, "The approval was granted for a different call."
    if row.status == "pending":
        return False, "The approval is still pending."
    if row.status != "approved":
        return False, f"The approval is {row.status}."
    # Single use, atomically: only one caller can move it from approved to used.
    done = db.execute(update(GuardApproval).where(GuardApproval.id == row.id, GuardApproval.status == "approved")
                      .values(status="used"))
    db.commit()
    if done.rowcount != 1:
        return False, "The approval was already used."
    return True, f"Approved by {row.decided_by or 'a reviewer'}."
