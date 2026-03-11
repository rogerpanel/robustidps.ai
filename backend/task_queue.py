"""
Async Job Queue — background task runner with DB-backed state.
===============================================================

Provides a lightweight in-process task queue using asyncio + threading
so that long-running operations (ablation, red-team, federated, XAI)
run in the background while the user polls for progress.

Usage:
    from task_queue import router as task_queue_router, submit_task
    app.include_router(task_queue_router)

    task_id = submit_task(db, user_id, "redteam", params_dict, run_fn, run_kwargs)
    # Client polls GET /api/tasks/{task_id}
"""

import asyncio
import datetime
import logging
import threading
import traceback
import uuid
from typing import Any, Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc
from sqlalchemy.orm import Session

from auth import require_auth
from database import get_db, SessionLocal

logger = logging.getLogger("robustidps.taskqueue")

router = APIRouter(prefix="/api/tasks", tags=["Task Queue"])


# ── In-memory progress tracker (supplements DB for real-time %) ──────────

_progress: dict[str, dict] = {}  # task_id -> {"progress": 0-100, "message": "..."}


def update_progress(task_id: str, progress: int, message: str = ""):
    """Called from within a running task to report progress."""
    _progress[task_id] = {"progress": min(progress, 100), "message": message}


# ── Task execution ───────────────────────────────────────────────────────

def _run_task_sync(task_id: str, fn: Callable, kwargs: dict):
    """Execute a task function in a background thread, updating DB on completion."""
    from database import BackgroundTask
    db = SessionLocal()
    try:
        # Mark as running
        task = db.query(BackgroundTask).filter(BackgroundTask.task_id == task_id).first()
        if task:
            task.status = "running"
            task.started_at = datetime.datetime.utcnow()
            db.commit()

        update_progress(task_id, 0, "Starting...")

        # Run the actual work
        result = fn(task_id=task_id, **kwargs)

        # Mark as completed
        task = db.query(BackgroundTask).filter(BackgroundTask.task_id == task_id).first()
        if task:
            task.status = "completed"
            task.result = result
            task.progress = 100
            task.completed_at = datetime.datetime.utcnow()
            db.commit()

        update_progress(task_id, 100, "Done")
        logger.info("Task %s completed successfully", task_id)

    except Exception as e:
        logger.exception("Task %s failed: %s", task_id, e)
        task = db.query(BackgroundTask).filter(BackgroundTask.task_id == task_id).first()
        if task:
            task.status = "failed"
            task.error = f"{type(e).__name__}: {e}"
            task.completed_at = datetime.datetime.utcnow()
            db.commit()
        update_progress(task_id, -1, str(e))
    finally:
        _progress.pop(task_id, None)
        db.close()


def submit_task(
    db: Session,
    user_id: int,
    task_type: str,
    params: dict,
    fn: Callable,
    fn_kwargs: dict,
    name: str = "",
) -> str:
    """Submit a new background task. Returns the task_id."""
    from database import BackgroundTask
    task_id = uuid.uuid4().hex[:12]
    task = BackgroundTask(
        task_id=task_id,
        user_id=user_id,
        task_type=task_type,
        name=name or f"{task_type} job",
        status="queued",
        params=params,
        progress=0,
    )
    db.add(task)
    db.commit()

    # Launch in background thread
    thread = threading.Thread(
        target=_run_task_sync,
        args=(task_id, fn, fn_kwargs),
        daemon=True,
        name=f"task-{task_id}",
    )
    thread.start()
    logger.info("Task %s (%s) submitted by user %d", task_id, task_type, user_id)
    return task_id


# ── API Endpoints ────────────────────────────────────────────────────────

class TaskSummary(BaseModel):
    task_id: str
    task_type: str
    name: str
    status: str
    progress: int
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None


class TaskDetail(TaskSummary):
    params: dict
    result: Optional[Any] = None


@router.get("", summary="List background tasks for current user")
def list_tasks(
    status: Optional[str] = Query(None, description="Filter by status: queued|running|completed|failed"),
    task_type: Optional[str] = Query(None, description="Filter by task type"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user=Depends(require_auth),
    db: Session = Depends(get_db),
):
    from database import BackgroundTask
    q = db.query(BackgroundTask).filter(BackgroundTask.user_id == user.id)
    if status:
        q = q.filter(BackgroundTask.status == status)
    if task_type:
        q = q.filter(BackgroundTask.task_type == task_type)
    total = q.count()
    tasks = q.order_by(desc(BackgroundTask.created_at)).offset(offset).limit(limit).all()

    items = []
    for t in tasks:
        live = _progress.get(t.task_id, {})
        items.append({
            "task_id": t.task_id,
            "task_type": t.task_type,
            "name": t.name,
            "status": t.status,
            "progress": live.get("progress", t.progress),
            "progress_message": live.get("message", ""),
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "started_at": t.started_at.isoformat() if t.started_at else None,
            "completed_at": t.completed_at.isoformat() if t.completed_at else None,
            "error": t.error,
        })

    return {"tasks": items, "total": total}


@router.get("/{task_id}", summary="Get task details including result")
def get_task(
    task_id: str,
    user=Depends(require_auth),
    db: Session = Depends(get_db),
):
    from database import BackgroundTask
    task = db.query(BackgroundTask).filter(
        BackgroundTask.task_id == task_id,
        BackgroundTask.user_id == user.id,
    ).first()
    if not task:
        raise HTTPException(404, "Task not found")

    live = _progress.get(task_id, {})
    return {
        "task_id": task.task_id,
        "task_type": task.task_type,
        "name": task.name,
        "status": task.status,
        "progress": live.get("progress", task.progress),
        "progress_message": live.get("message", ""),
        "params": task.params,
        "result": task.result,
        "error": task.error,
        "created_at": task.created_at.isoformat() if task.created_at else None,
        "started_at": task.started_at.isoformat() if task.started_at else None,
        "completed_at": task.completed_at.isoformat() if task.completed_at else None,
    }


@router.delete("/{task_id}", summary="Delete a completed/failed task")
def delete_task(
    task_id: str,
    user=Depends(require_auth),
    db: Session = Depends(get_db),
):
    from database import BackgroundTask
    task = db.query(BackgroundTask).filter(
        BackgroundTask.task_id == task_id,
        BackgroundTask.user_id == user.id,
    ).first()
    if not task:
        raise HTTPException(404, "Task not found")
    if task.status in ("queued", "running"):
        raise HTTPException(400, "Cannot delete a running task")
    db.delete(task)
    db.commit()
    return {"ok": True}
