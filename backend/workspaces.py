"""
Multi-Tenant Project Workspaces
=================================

Provides project-scoped isolation for multi-researcher labs:
  - Create/manage project workspaces
  - Invite members with per-project roles (owner, editor, viewer)
  - Project-scoped experiments, datasets, and jobs
  - Collaborative annotations and comment threads
  - Per-project audit trails
"""

import datetime
import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc
from sqlalchemy.orm import Session

from auth import require_auth
from database import get_db

logger = logging.getLogger("robustidps.workspaces")

router = APIRouter(prefix="/api/workspaces", tags=["Workspaces"])


# ── In-memory store (production: migrate to DB tables) ───────────────────

_workspaces: dict[str, dict] = {}     # workspace_id -> workspace data
_memberships: dict[str, list] = {}     # workspace_id -> [{user_id, role, joined_at}]
_annotations: dict[str, list] = {}     # workspace_id -> [{id, user_email, target_type, target_id, text, created_at}]


# ── Schemas ──────────────────────────────────────────────────────────────

class WorkspaceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str = ""
    tags: list[str] = []


class WorkspaceUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[list[str]] = None


class MemberInvite(BaseModel):
    user_id: int
    role: str = "editor"  # owner | editor | viewer


class AnnotationCreate(BaseModel):
    target_type: str = Field(..., description="experiment | dataset | job | model")
    target_id: str = Field(..., description="ID of the target resource")
    text: str = Field(..., min_length=1, max_length=2000)


# ── Helpers ──────────────────────────────────────────────────────────────

def _user_workspaces(user_id: int) -> list[str]:
    """Get workspace IDs where user is a member."""
    result = []
    for ws_id, members in _memberships.items():
        if any(m["user_id"] == user_id for m in members):
            result.append(ws_id)
    return result


def _user_role(workspace_id: str, user_id: int) -> Optional[str]:
    """Get user's role in a workspace."""
    members = _memberships.get(workspace_id, [])
    for m in members:
        if m["user_id"] == user_id:
            return m["role"]
    return None


def _require_member(workspace_id: str, user_id: int, min_role: str = "viewer") -> str:
    """Verify user is a member with sufficient role. Returns their role."""
    role = _user_role(workspace_id, user_id)
    if role is None:
        raise HTTPException(403, "Not a member of this workspace")

    role_order = {"viewer": 0, "editor": 1, "owner": 2}
    if role_order.get(role, 0) < role_order.get(min_role, 0):
        raise HTTPException(403, f"Requires '{min_role}' role (you have '{role}')")
    return role


# ── Workspace CRUD ──────────────────────────────────────────────────────

@router.post("", summary="Create a new project workspace")
def create_workspace(body: WorkspaceCreate, user=Depends(require_auth)):
    ws_id = uuid.uuid4().hex[:10]
    workspace = {
        "workspace_id": ws_id,
        "name": body.name,
        "description": body.description,
        "tags": body.tags,
        "created_by": user.id,
        "created_at": datetime.datetime.utcnow().isoformat(),
        "updated_at": datetime.datetime.utcnow().isoformat(),
    }
    _workspaces[ws_id] = workspace
    _memberships[ws_id] = [{"user_id": user.id, "role": "owner", "joined_at": datetime.datetime.utcnow().isoformat()}]
    _annotations[ws_id] = []

    logger.info("Workspace %s created by user %d: %s", ws_id, user.id, body.name)
    return workspace


@router.get("", summary="List workspaces the current user belongs to")
def list_workspaces(user=Depends(require_auth)):
    ws_ids = _user_workspaces(user.id)
    result = []
    for ws_id in ws_ids:
        ws = _workspaces.get(ws_id)
        if ws:
            ws_copy = dict(ws)
            ws_copy["member_count"] = len(_memberships.get(ws_id, []))
            ws_copy["my_role"] = _user_role(ws_id, user.id)
            ws_copy["annotation_count"] = len(_annotations.get(ws_id, []))
            result.append(ws_copy)
    return {"workspaces": result, "total": len(result)}


@router.get("/{workspace_id}", summary="Get workspace details")
def get_workspace(workspace_id: str, user=Depends(require_auth)):
    if workspace_id not in _workspaces:
        raise HTTPException(404, "Workspace not found")
    _require_member(workspace_id, user.id)

    ws = dict(_workspaces[workspace_id])
    ws["members"] = _memberships.get(workspace_id, [])
    ws["my_role"] = _user_role(workspace_id, user.id)
    return ws


@router.patch("/{workspace_id}", summary="Update workspace details")
def update_workspace(workspace_id: str, body: WorkspaceUpdate, user=Depends(require_auth)):
    if workspace_id not in _workspaces:
        raise HTTPException(404, "Workspace not found")
    _require_member(workspace_id, user.id, "editor")

    ws = _workspaces[workspace_id]
    if body.name is not None:
        ws["name"] = body.name
    if body.description is not None:
        ws["description"] = body.description
    if body.tags is not None:
        ws["tags"] = body.tags
    ws["updated_at"] = datetime.datetime.utcnow().isoformat()
    return ws


@router.delete("/{workspace_id}", summary="Delete a workspace")
def delete_workspace(workspace_id: str, user=Depends(require_auth)):
    if workspace_id not in _workspaces:
        raise HTTPException(404, "Workspace not found")
    _require_member(workspace_id, user.id, "owner")

    del _workspaces[workspace_id]
    _memberships.pop(workspace_id, None)
    _annotations.pop(workspace_id, None)
    return {"ok": True}


# ── Members ──────────────────────────────────────────────────────────────

@router.post("/{workspace_id}/members", summary="Invite a user to the workspace")
def add_member(workspace_id: str, body: MemberInvite, user=Depends(require_auth)):
    if workspace_id not in _workspaces:
        raise HTTPException(404, "Workspace not found")
    _require_member(workspace_id, user.id, "owner")

    members = _memberships.setdefault(workspace_id, [])
    # Check not already a member
    if any(m["user_id"] == body.user_id for m in members):
        raise HTTPException(400, "User is already a member")

    members.append({
        "user_id": body.user_id,
        "role": body.role,
        "joined_at": datetime.datetime.utcnow().isoformat(),
    })
    return {"ok": True, "members": len(members)}


@router.delete("/{workspace_id}/members/{user_id}", summary="Remove a member")
def remove_member(workspace_id: str, user_id: int, user=Depends(require_auth)):
    if workspace_id not in _workspaces:
        raise HTTPException(404, "Workspace not found")
    _require_member(workspace_id, user.id, "owner")

    members = _memberships.get(workspace_id, [])
    _memberships[workspace_id] = [m for m in members if m["user_id"] != user_id]
    return {"ok": True}


@router.patch("/{workspace_id}/members/{user_id}/role", summary="Change a member's role")
def change_member_role(workspace_id: str, user_id: int, role: str = Query(...), user=Depends(require_auth)):
    if workspace_id not in _workspaces:
        raise HTTPException(404, "Workspace not found")
    _require_member(workspace_id, user.id, "owner")

    if role not in ("owner", "editor", "viewer"):
        raise HTTPException(400, "Role must be owner, editor, or viewer")

    members = _memberships.get(workspace_id, [])
    for m in members:
        if m["user_id"] == user_id:
            m["role"] = role
            return {"ok": True}
    raise HTTPException(404, "Member not found")


# ── Annotations / Comments ──────────────────────────────────────────────

@router.post("/{workspace_id}/annotations", summary="Add an annotation to a resource")
def add_annotation(workspace_id: str, body: AnnotationCreate, user=Depends(require_auth)):
    if workspace_id not in _workspaces:
        raise HTTPException(404, "Workspace not found")
    _require_member(workspace_id, user.id, "editor")

    annotation = {
        "id": uuid.uuid4().hex[:8],
        "user_id": user.id,
        "user_email": user.email,
        "target_type": body.target_type,
        "target_id": body.target_id,
        "text": body.text,
        "created_at": datetime.datetime.utcnow().isoformat(),
    }
    _annotations.setdefault(workspace_id, []).append(annotation)
    return annotation


@router.get("/{workspace_id}/annotations", summary="List annotations in workspace")
def list_annotations(
    workspace_id: str,
    target_type: Optional[str] = Query(None),
    target_id: Optional[str] = Query(None),
    user=Depends(require_auth),
):
    if workspace_id not in _workspaces:
        raise HTTPException(404, "Workspace not found")
    _require_member(workspace_id, user.id)

    notes = _annotations.get(workspace_id, [])
    if target_type:
        notes = [n for n in notes if n["target_type"] == target_type]
    if target_id:
        notes = [n for n in notes if n["target_id"] == target_id]

    return {"annotations": notes, "total": len(notes)}


@router.delete("/{workspace_id}/annotations/{annotation_id}", summary="Delete an annotation")
def delete_annotation(workspace_id: str, annotation_id: str, user=Depends(require_auth)):
    if workspace_id not in _workspaces:
        raise HTTPException(404, "Workspace not found")
    role = _require_member(workspace_id, user.id, "editor")

    notes = _annotations.get(workspace_id, [])
    for i, n in enumerate(notes):
        if n["id"] == annotation_id:
            # Only the author or an owner can delete
            if n["user_id"] != user.id and role != "owner":
                raise HTTPException(403, "Can only delete your own annotations")
            notes.pop(i)
            return {"ok": True}
    raise HTTPException(404, "Annotation not found")


# ── Workspace-scoped experiment linking ──────────────────────────────────

@router.post("/{workspace_id}/experiments/{experiment_id}", summary="Link an experiment to this workspace")
def link_experiment(workspace_id: str, experiment_id: str, user=Depends(require_auth), db: Session = Depends(get_db)):
    if workspace_id not in _workspaces:
        raise HTTPException(404, "Workspace not found")
    _require_member(workspace_id, user.id, "editor")

    from database import Experiment
    exp = db.query(Experiment).filter(
        Experiment.experiment_id == experiment_id,
        Experiment.user_id == user.id,
    ).first()
    if not exp:
        raise HTTPException(404, "Experiment not found")

    # Store workspace_id in experiment tags
    tags = exp.tags or []
    ws_tag = f"ws:{workspace_id}"
    if ws_tag not in tags:
        tags.append(ws_tag)
        exp.tags = tags
        db.commit()

    return {"ok": True, "experiment_id": experiment_id, "workspace_id": workspace_id}


@router.get("/{workspace_id}/experiments", summary="List experiments linked to this workspace")
def list_workspace_experiments(workspace_id: str, user=Depends(require_auth), db: Session = Depends(get_db)):
    if workspace_id not in _workspaces:
        raise HTTPException(404, "Workspace not found")
    _require_member(workspace_id, user.id)

    from database import Experiment
    # Get all experiments for members of this workspace that have the ws tag
    member_ids = [m["user_id"] for m in _memberships.get(workspace_id, [])]
    ws_tag = f"ws:{workspace_id}"

    experiments = db.query(Experiment).filter(
        Experiment.user_id.in_(member_ids),
    ).order_by(desc(Experiment.created_at)).all()

    # Filter by workspace tag
    result = []
    for exp in experiments:
        tags = exp.tags or []
        if ws_tag in tags:
            result.append({
                "experiment_id": exp.experiment_id,
                "name": exp.name,
                "task_type": exp.task_type,
                "model_used": exp.model_used,
                "metrics": exp.metrics or {},
                "tags": [t for t in tags if not t.startswith("ws:")],
                "created_at": exp.created_at.isoformat() if exp.created_at else None,
            })

    return {"experiments": result, "total": len(result)}
