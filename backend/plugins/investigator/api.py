"""HTTP surface for the SOC Investigator.

Runs execute in a background thread and are polled, because a full
investigation can outlast Cloudflare's 100-second proxy timeout. Run state
lives in this process; the backend runs a single uvicorn worker.
"""

import os
import threading
import uuid
from collections import OrderedDict

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from auth import require_auth, User
from config import ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY, DEEPSEEK_API_KEY

from .agent import DEFAULT_MODELS, RunConfig, investigate, new_trace
from .evidence import MissionEvidence
from .missions import load_missions
from .scorer import score

try:
    from main import limiter
except Exception:  # pragma: no cover — keeps the plugin importable in tests
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    limiter = Limiter(key_func=get_remote_address)

RATE_RUN = os.getenv("INVESTIGATOR_RATE_RUN", "10/minute")
MAX_KEPT_RUNS = 50
SERVER_KEYS = {"anthropic": ANTHROPIC_API_KEY, "openai": OPENAI_API_KEY,
               "google": GOOGLE_API_KEY, "deepseek": DEEPSEEK_API_KEY}

router = APIRouter(prefix="/api/investigator", tags=["SOC Investigator"])

_missions = load_missions()
_runs: "OrderedDict[str, dict]" = OrderedDict()
_lock = threading.Lock()


class RunRequest(BaseModel):
    mission_id: str
    provider: str = "anthropic"
    model: str | None = None
    effort: str = Field("high", pattern="^(low|medium|high|xhigh|max)$")
    max_tool_calls: int = Field(15, ge=1, le=60)
    api_key: str | None = Field(None, description="Optional; otherwise the server's key for the provider.")


@router.get("/missions")
def list_missions(_: User = Depends(require_auth)) -> dict:
    return {"missions": [m.public() for m in _missions.values()],
            "providers": {p: {"default_model": DEFAULT_MODELS[p], "server_key": bool(SERVER_KEYS[p])}
                          for p in DEFAULT_MODELS}}


def _execute(run_id: str, mission_id: str, cfg: RunConfig) -> None:
    mission = _missions[mission_id]
    trace = _runs[run_id]["trace"]
    investigate(mission.brief, MissionEvidence(mission), cfg, trace=trace)
    # Reveal the expected answer only once the run has finished.
    _runs[run_id]["score"] = score(trace, mission.answer, mission.optimal_tool_calls)
    _runs[run_id]["answer"] = mission.answer


@router.post("/runs")
@limiter.limit(RATE_RUN)
def start_run(request: Request, body: RunRequest, _: User = Depends(require_auth)) -> dict:
    if body.mission_id not in _missions:
        raise HTTPException(404, f"unknown mission {body.mission_id!r}")
    if body.provider not in DEFAULT_MODELS:
        raise HTTPException(400, f"provider must be one of {sorted(DEFAULT_MODELS)}")
    key = body.api_key or SERVER_KEYS[body.provider]
    if not key:
        raise HTTPException(400, f"no API key for {body.provider}: supply one or configure the server")
    cfg = RunConfig(provider=body.provider, model=body.model, effort=body.effort,
                    max_tool_calls=body.max_tool_calls, api_key=key)
    run_id = uuid.uuid4().hex[:12]
    with _lock:
        _runs[run_id] = {"trace": new_trace(cfg, body.mission_id), "score": None, "answer": None}
        while len(_runs) > MAX_KEPT_RUNS:
            _runs.popitem(last=False)
    threading.Thread(target=_execute, args=(run_id, body.mission_id, cfg), daemon=True).start()
    return {"run_id": run_id}


@router.get("/runs/{run_id}")
def get_run(run_id: str, _: User = Depends(require_auth)) -> dict:
    run = _runs.get(run_id)
    if run is None:
        raise HTTPException(404, "unknown or expired run")
    trace = dict(run["trace"])
    trace["steps"] = list(trace["steps"])  # snapshot; the worker may still be appending
    return {"run_id": run_id, "trace": trace, "score": run["score"], "answer": run["answer"]}
