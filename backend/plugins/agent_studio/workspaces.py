"""Workspaces — server-side per-user saved build state.

Lets a user pause work mid-wizard, navigate anywhere on the platform,
log out, log back in on a different device, and resume. Strict
per-user isolation; admin override.

State is opaque to the backend — a JSON blob the BuildWizard packs
(step, specJson, envJson, sessionId, snippetIdx, etc.). Backend's job
is identity scoping + audit columns.

Three lifecycle operations:
  save   — upsert by (owner_id, template_id, name)
  load   — fetch (self or admin only)
  delete — soft-archive (admin-only hard-delete elsewhere)

Plus:
  export — serialise to JSON for the user to download
  import — restore from uploaded JSON (with owner re-stamped to caller)
"""
from __future__ import annotations

import datetime
import secrets
from typing import Any

from sqlalchemy.orm import Session

from plugins.agent_studio.db_models import AgentStudioWorkspace, scoped


def _now() -> datetime.datetime:
    return datetime.datetime.utcnow()


def _serialize(w: AgentStudioWorkspace) -> dict:
    return {
        "workspace_id": w.workspace_id,
        "owner_id": w.owner_id,
        "owner_email": w.owner_email,
        "template_id": w.template_id,
        "name": w.name,
        "state": w.state,
        "created_at": w.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if w.created_at else None,
        "updated_at": w.updated_at.strftime("%Y-%m-%dT%H:%M:%SZ") if w.updated_at else None,
        "archived_at": (w.archived_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                         if w.archived_at else None),
        "note": w.note or "",
    }


def _resolve_owner(customer: dict) -> tuple[str, str]:
    """Compute (owner_id, owner_email) for the calling user."""
    return (customer.get("customer_id") or "unknown",
            customer.get("email") or "unknown@local")


def save_workspace(db: Session, customer: dict, template_id: str, name: str,
                   state: dict[str, Any], note: str = "",
                   workspace_id: str | None = None) -> dict:
    """Upsert — if workspace_id given AND owned by caller, update;
    otherwise create. Demo mode is refused at the API layer."""
    owner_id, owner_email = _resolve_owner(customer)

    if workspace_id:
        existing = db.get(AgentStudioWorkspace, workspace_id)
        if existing and (existing.owner_id == owner_id
                          or customer.get("role") == "admin"):
            existing.name = name
            existing.state = state
            existing.note = note
            existing.archived_at = None
            db.commit()
            return _serialize(existing)

    rec = AgentStudioWorkspace(
        workspace_id=f"ws_{secrets.token_urlsafe(10)}",
        owner_id=owner_id, owner_email=owner_email,
        template_id=template_id, name=name,
        state=state, note=note,
        created_at=_now(), updated_at=_now(),
    )
    db.add(rec)
    db.commit()
    return _serialize(rec)


def list_workspaces(db: Session, customer: dict | None,
                    template_id: str | None = None,
                    include_archived: bool = False) -> list[dict]:
    q = db.query(AgentStudioWorkspace)
    q = scoped(q, AgentStudioWorkspace, customer, customer_id_col="owner_id")
    if template_id:
        q = q.filter(AgentStudioWorkspace.template_id == template_id)
    if not include_archived:
        q = q.filter(AgentStudioWorkspace.archived_at.is_(None))
    q = q.order_by(AgentStudioWorkspace.updated_at.desc())
    return [_serialize(w) for w in q.all()]


def get_workspace(db: Session, workspace_id: str, customer: dict) -> dict | None:
    w = db.get(AgentStudioWorkspace, workspace_id)
    if w is None:
        return None
    if w.owner_id != customer.get("customer_id") and \
       customer.get("role") != "admin":
        return None
    return _serialize(w)


def archive_workspace(db: Session, workspace_id: str, customer: dict) -> dict:
    w = db.get(AgentStudioWorkspace, workspace_id)
    if w is None:
        return {"ok": False, "error": "unknown workspace_id"}
    if w.owner_id != customer.get("customer_id") and \
       customer.get("role") != "admin":
        return {"ok": False, "error": "not yours"}
    w.archived_at = _now()
    db.commit()
    return {"ok": True, "workspace_id": workspace_id,
            "archived_at": w.archived_at.strftime("%Y-%m-%dT%H:%M:%SZ")}


def delete_workspace(db: Session, workspace_id: str, customer: dict) -> dict:
    w = db.get(AgentStudioWorkspace, workspace_id)
    if w is None:
        return {"ok": False, "error": "unknown workspace_id"}
    if w.owner_id != customer.get("customer_id") and \
       customer.get("role") != "admin":
        return {"ok": False, "error": "not yours"}
    db.delete(w)
    db.commit()
    return {"ok": True, "workspace_id": workspace_id, "deleted": True}


def import_workspace(db: Session, customer: dict, payload: dict[str, Any]) -> dict:
    """Restore from a user-uploaded export. Caller becomes the owner
    regardless of what's in the file — defends against sharing a JSON
    dump that would otherwise re-own to its original creator."""
    template_id = str(payload.get("template_id") or "blank")
    name = str(payload.get("name") or "Imported workspace")
    state = payload.get("state") or {}
    note = str(payload.get("note") or "")
    if not isinstance(state, dict):
        state = {}
    return save_workspace(db, customer, template_id, name, state, note=note)


def stats(db: Session) -> dict:
    items = db.query(AgentStudioWorkspace).all()
    active = [w for w in items if w.archived_at is None]
    by_owner: dict[str, int] = {}
    by_template: dict[str, int] = {}
    for w in active:
        by_owner[w.owner_id] = by_owner.get(w.owner_id, 0) + 1
        by_template[w.template_id] = by_template.get(w.template_id, 0) + 1
    return {
        "n_total": len(items), "n_active": len(active),
        "n_archived": len(items) - len(active),
        "by_owner": by_owner, "by_template": by_template,
    }
