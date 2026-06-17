"""FastAPI router for the UAV plugin.

Mount point: /api/uav/*. The router is imported by backend/main.py via
`from plugins.uav import router` so the kernel itself is untouched
(chapter 6 §6.7). All business logic lives in `services.py` so the
SOC Copilot tool dispatcher can reuse the same functions synchronously
without round-tripping through HTTP or the event loop.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from plugins.uav import services as _svc

router = APIRouter(prefix="/api/uav", tags=["UAV / Aerial Defense"])


# ── Schemas ──────────────────────────────────────────────────────────────

class AttackRequest(BaseModel):
    attack: Literal["fgsm", "pgd"] = Field("pgd")
    epsilon: float = Field(4 / 255, gt=0, le=0.5)
    pgd_steps: int = Field(20, ge=1, le=100)
    sample_index: int = Field(0, ge=0, lt=64)


class MissionPlanReviewRequest(BaseModel):
    plan_text: str = Field(..., min_length=1, max_length=20000)
    plan_format: Literal["plan", "json-ld", "owl"] = "plan"


# ── Endpoints ───────────────────────────────────────────────────────────

@router.get("/overview")
async def overview() -> dict:
    return _svc.overview_payload()


@router.get("/ew-bench/curves")
async def ew_curves() -> dict:
    return _svc.ew_curves_payload()


@router.get("/swarm/snapshot")
async def swarm_snapshot() -> dict:
    return _svc.swarm_snapshot_payload()


@router.get("/gnss/sky")
async def gnss_sky() -> dict:
    return _svc.gnss_payload()


@router.get("/certificates")
async def certificates() -> dict:
    return _svc.certificates_payload()


@router.post("/perception/attack")
async def perception_attack(req: AttackRequest) -> dict:
    return _svc.perception_attack_payload(req.attack, req.epsilon, req.pgd_steps, req.sample_index)


@router.post("/mission-plan/review")
async def mission_plan_review(req: MissionPlanReviewRequest) -> dict:
    return _svc.mission_plan_review_payload(req.plan_text, req.plan_format)


@router.get("/metrics")
async def metrics() -> dict:
    if not _svc.METRICS_PATH.exists():
        raise HTTPException(404, "Phase-A metrics not yet produced; run scripts/run_phase_a.sh")
    return json.loads(_svc.METRICS_PATH.read_text())


@router.get("/industry-comparison")
async def industry_comparison() -> dict:
    return _svc.industry_payload()


@router.get("/regulatory")
async def regulatory() -> dict:
    return {"entries": _svc.REGULATORY}
