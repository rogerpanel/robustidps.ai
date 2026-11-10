"""Start agent runs from BlueSec Runs ("Run agent"), through the runner service.

The runner (bluesec/runner, service bluesec-runner) executes the same
command-line agent as the SOCGraph experiments, in its own container. This
module forwards admin requests to it and, when a run has finished, imports its
trace folders into BlueSec Runs for the user who started it.

API keys pass through to the runner in the request body and are never stored
or logged here. The research results are produced with the command line; runs
started here are for testing and demonstration.
"""

import json
import os
import re
from pathlib import Path
from typing import Any, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy.orm import Session

from auth import User, require_role
from database import get_db

from .api import MAX_FOLDER_FILES, MAX_PAYLOAD_BYTES, _meta, _save, limiter
from .db_models import BlueSecRun
from .traces import TraceError, build_run

RUNNER_URL = os.getenv("BLUESEC_RUNNER_URL", "").rstrip("/")
RUNNER_TOKEN = os.getenv("BLUESEC_RUNNER_TOKEN", "")
WEB_RUNS_DIR = Path(os.getenv("BLUESEC_WEB_RUNS_DIR", "/app/bluesec_web_runs"))
RATE_START = os.getenv("BLUESEC_RATE_AGENT_RUN", "12/hour")
FOLDER_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,200}$")

router = APIRouter(prefix="/api/bluesec-runs/agent", tags=["BlueSec Runs"])

# Who started which runner job, so finished runs are saved for that user.
_owners: dict[str, int] = {}


class StartBody(BaseModel):
    pack: Literal["v1.1", "blind", "mimicry"] = "v1.1"
    suite: bool = False
    ablate: list[Literal["cache", "validation", "grounding", "budget", "method"]] = Field(
        default_factory=list, max_length=5)
    provider: Literal["anthropic", "openai"] = "anthropic"
    model: str = Field("", max_length=120)
    effort: Literal["low", "medium", "high", "xhigh", "max"] = "high"
    base_url: str = Field("", max_length=300)
    api_key: SecretStr = Field(..., min_length=1, max_length=500)
    label: str = Field("", max_length=120)
    concurrency: int = Field(4, ge=1, le=4)
    tasks: list[str] = Field(default_factory=list, max_length=21)


def _runner(method: str, path: str, body: dict[str, Any] | None = None) -> Any:
    """Call the runner; map its errors to HTTP errors for the browser."""
    if not RUNNER_URL:
        raise HTTPException(503, "The agent runner is not configured on this server.")
    headers = {"X-Runner-Token": RUNNER_TOKEN} if RUNNER_TOKEN else {}
    try:
        with httpx.Client(timeout=30) as client:
            r = client.request(method, f"{RUNNER_URL}{path}", json=body, headers=headers)
    except httpx.HTTPError:
        raise HTTPException(503, "The agent runner is not reachable.") from None
    if r.status_code >= 400:
        try:
            detail = r.json().get("detail")
        except ValueError:
            detail = None
        if isinstance(detail, list):   # pydantic validation errors
            detail = "; ".join(str(d.get("msg", d)) for d in detail)
        raise HTTPException(r.status_code if r.status_code < 500 else 502,
                            detail or f"runner error {r.status_code}")
    return r.json()


def _import_folders(db: Session, user: User, job: dict[str, Any]) -> list[dict[str, Any]]:
    """Save each trace folder of a finished job once; return what is saved.

    A folder in which no task completed (for example after an invalid API key)
    is reported with a reason instead of being saved."""
    root = (WEB_RUNS_DIR / "traces").resolve()
    saved = []
    for folder in job.get("folders") or []:
        if not FOLDER_NAME.match(folder):
            continue
        source = f"web:{folder}"
        existing = db.query(BlueSecRun).filter(BlueSecRun.user_id == user.id,
                                               BlueSecRun.source == source).first()
        if existing:
            saved.append({"folder": folder, "run_id": existing.id})
            continue
        path = (root / folder).resolve()
        if path.parent != root or not path.is_dir():
            continue
        documents = []
        for f in sorted(path.glob("*.json"))[:MAX_FOLDER_FILES]:
            if f.stat().st_size > MAX_PAYLOAD_BYTES:
                continue
            try:
                documents.append(json.loads(f.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
        try:
            built = build_run(documents)
        except TraceError:
            continue
        if not built["aggregates"].get("n_completed"):
            saved.append({"folder": folder, "run_id": None,
                          "skipped": "no task completed; see the errors above"})
            continue
        pack = (job.get("params") or {}).get("pack", "")
        notes = f"Started from the web on pack {pack}." if pack else "Started from the web."
        run = _save(db, user, built, name="", notes=notes, source=source, folder=folder)
        saved.append({"folder": folder, "run_id": run.id, "run": _meta(run)})
    return saved


@router.get("/status")
def status(_: User = Depends(require_role("admin"))) -> dict[str, Any]:
    try:
        health = _runner("GET", "/health")
    except HTTPException as exc:
        return {"available": False, "reason": exc.detail}
    return {"available": True, **health}


@router.post("/runs")
@limiter.limit(RATE_START)
def start(request: Request, body: StartBody,
          user: User = Depends(require_role("admin"))) -> dict[str, Any]:
    payload = body.model_dump()
    payload["api_key"] = body.api_key.get_secret_value()
    job = _runner("POST", "/runs", payload)
    _owners[job["id"]] = user.id
    return job


@router.get("/runs")
def list_runs(_: User = Depends(require_role("admin"))) -> dict[str, Any]:
    return _runner("GET", "/runs")


@router.get("/runs/{job_id}")
def get_run(job_id: str, user: User = Depends(require_role("admin")),
            db: Session = Depends(get_db)) -> dict[str, Any]:
    if not re.match(r"^[a-f0-9]{1,32}$", job_id):
        raise HTTPException(404, "unknown run")
    job = _runner("GET", f"/runs/{job_id}")
    job["saved"] = []
    if job.get("status") in ("done", "failed", "cancelled") and job.get("folders"):
        if _owners.get(job_id, user.id) == user.id:
            job["saved"] = _import_folders(db, user, job)
    return job


@router.post("/runs/{job_id}/cancel")
def cancel(job_id: str, _: User = Depends(require_role("admin"))) -> dict[str, Any]:
    if not re.match(r"^[a-f0-9]{1,32}$", job_id):
        raise HTTPException(404, "unknown run")
    return _runner("POST", f"/runs/{job_id}/cancel")
