"""HTTP surface for BlueSec Runs: store and review agent run traces.

Runs belong to the user who saved them. Uploads arrive as parsed JSON
documents from the browser. Admins can also import a run folder straight
from the agent's trace directory on the server, mounted read-only into the
container at BLUESEC_TRACES_DIR.
"""

import datetime
import json
import os
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth import User, require_auth, require_role
from database import get_db

from .db_models import BlueSecRun
from .traces import TraceError, build_run, started_at_from_folder

try:
    from main import limiter
except Exception:  # pragma: no cover — keeps the plugin importable in tests
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    limiter = Limiter(key_func=get_remote_address)

TRACES_DIR = Path(os.getenv("BLUESEC_TRACES_DIR", "/app/bluesec_traces"))
RATE_SAVE = os.getenv("BLUESEC_RATE_SAVE", "30/minute")
MAX_PAYLOAD_BYTES = 25 * 1024 * 1024
MAX_FOLDER_FILES = 600

router = APIRouter(prefix="/api/bluesec-runs", tags=["BlueSec Runs"])


class UploadBody(BaseModel):
    name: str = Field("", max_length=255)
    notes: str = Field("", max_length=5000)
    folder: str = Field("", max_length=255)     # the run folder's name, when known
    documents: list[Any] = Field(..., min_length=1, max_length=MAX_FOLDER_FILES)


class ImportBody(BaseModel):
    folder: str = Field(..., min_length=1, max_length=255)
    name: str = Field("", max_length=255)


class UpdateBody(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    notes: str | None = Field(None, max_length=5000)


def _meta(run: BlueSecRun) -> dict[str, Any]:
    return {
        "id": run.id, "name": run.name, "notes": run.notes or "", "source": run.source,
        "pt_run_id": run.pt_run_id, "agent_model": run.agent_model,
        "started_at": run.started_at.isoformat() + "Z" if run.started_at else None,
        "created_at": run.created_at.isoformat() + "Z",
        "n_tasks": run.n_tasks, "n_completed": run.n_completed,
        "mean_quality": run.mean_quality, "mean_efficiency": run.mean_efficiency,
        "mean_reward": run.mean_reward, "mean_tool_calls": run.mean_tool_calls,
    }


def _save(db: Session, user: User, built: dict[str, Any], *, name: str, notes: str,
          source: str, folder: str) -> BlueSecRun:
    payload = {"tasks": built["tasks"], "aggregates": built["aggregates"]}
    if len(json.dumps(payload, default=str)) > MAX_PAYLOAD_BYTES:
        raise HTTPException(413, "This run is larger than 25 MB.")
    agg = built["aggregates"]
    started = started_at_from_folder(folder) if folder else None
    default_name = folder or (f"Run {built['pt_run_id'][:12]}" if built["pt_run_id"] else "Run")
    run = BlueSecRun(
        id=uuid.uuid4().hex, user_id=user.id, name=(name or default_name)[:255],
        notes=notes, source=source[:300], pt_run_id=built["pt_run_id"],
        agent_model=built["agent_model"], started_at=started,
        n_tasks=agg["n_tasks"], n_completed=agg["n_completed"],
        mean_quality=agg["mean_quality"], mean_efficiency=agg["mean_efficiency"],
        mean_reward=agg["mean_reward"], mean_tool_calls=agg["mean_tool_calls"],
        payload=payload,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _owned(db: Session, user: User, run_id: str) -> BlueSecRun:
    run = db.query(BlueSecRun).filter(BlueSecRun.id == run_id,
                                      BlueSecRun.user_id == user.id).first()
    if run is None:
        raise HTTPException(404, "Run not found")
    return run


@router.get("")
def list_runs(user: User = Depends(require_auth), db: Session = Depends(get_db)):
    runs = (db.query(BlueSecRun).filter(BlueSecRun.user_id == user.id)
            .order_by(BlueSecRun.created_at.desc()).limit(500).all())
    return {"runs": [_meta(r) for r in runs]}


@router.post("")
@limiter.limit(RATE_SAVE)
def upload_run(request: Request, body: UploadBody, user: User = Depends(require_auth),
               db: Session = Depends(get_db)):
    try:
        built = build_run(body.documents)
    except TraceError as exc:
        raise HTTPException(400, str(exc)) from None
    folder = Path(body.folder).name if body.folder else ""
    run = _save(db, user, built, name=body.name, notes=body.notes, source="upload",
                folder=folder)
    return {**_meta(run), "ignored_files": built["ignored_files"]}


@router.get("/server")
def server_folders(user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    if not TRACES_DIR.is_dir():
        return {"enabled": False, "folders": []}
    imported = {s for (s,) in db.query(BlueSecRun.source)
                .filter(BlueSecRun.user_id == user.id, BlueSecRun.source.like("server:%"))}
    folders = []
    for d in TRACES_DIR.iterdir():
        if not d.is_dir():
            continue
        files = list(d.glob("*.json"))
        if not files:
            continue
        folders.append({
            "name": d.name,
            "n_files": len(files),
            "has_summary": (d / "summary.json").is_file(),
            "modified": datetime.datetime.utcfromtimestamp(d.stat().st_mtime).isoformat() + "Z",
            "imported": f"server:{d.name}" in imported,
        })
    folders.sort(key=lambda f: f["modified"], reverse=True)
    return {"enabled": True, "folders": folders}


@router.post("/server/import")
@limiter.limit(RATE_SAVE)
def server_import(request: Request, body: ImportBody,
                  user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    folder = (TRACES_DIR / body.folder).resolve()
    if folder.parent != TRACES_DIR.resolve() or not folder.is_dir():
        raise HTTPException(404, "Folder not found")
    files = sorted(folder.glob("*.json"))[:MAX_FOLDER_FILES]
    documents = []
    for f in files:
        if f.stat().st_size > MAX_PAYLOAD_BYTES:
            continue
        try:
            documents.append(json.loads(f.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    try:
        built = build_run(documents)
    except TraceError as exc:
        raise HTTPException(400, str(exc)) from None
    run = _save(db, user, built, name=body.name, notes="", source=f"server:{folder.name}",
                folder=folder.name)
    return {**_meta(run), "ignored_files": built["ignored_files"]}


@router.get("/{run_id}")
def get_run(run_id: str, user: User = Depends(require_auth), db: Session = Depends(get_db)):
    run = _owned(db, user, run_id)
    return {**_meta(run), **run.payload}


@router.patch("/{run_id}")
def update_run(run_id: str, body: UpdateBody, user: User = Depends(require_auth),
               db: Session = Depends(get_db)):
    run = _owned(db, user, run_id)
    if body.name is not None:
        run.name = body.name
    if body.notes is not None:
        run.notes = body.notes
    db.commit()
    return _meta(run)


@router.delete("/{run_id}")
def delete_run(run_id: str, user: User = Depends(require_auth), db: Session = Depends(get_db)):
    run = _owned(db, user, run_id)
    db.delete(run)
    db.commit()
    return {"deleted": run_id}
