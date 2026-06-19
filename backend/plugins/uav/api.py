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


# ── Phase B (chapter 6 §6.4 roadmap) ────────────────────────────────────

@router.get("/phase-b/status")
async def phase_b_status() -> dict:
    return _svc.phase_b_status_payload()


@router.post("/phase-b/automl/run")
async def phase_b_automl_run(model_kind: Literal["ct_tgnn", "mamba_shield"] = "ct_tgnn",
                             n_trials: int = 8) -> dict:
    """Trigger an Optuna search. WRITE — takes several minutes; in a
    real deployment this would queue to a background worker."""
    from plugins.uav.uav_defense.automl import run_search
    return run_search(model_kind=model_kind, n_trials=n_trials)


@router.post("/phase-b/onnx/export")
async def phase_b_onnx_export(model_kind: Literal["ct_tgnn", "mamba_shield"] = "ct_tgnn") -> dict:
    """Export the current checkpoint to ONNX and benchmark latency."""
    from plugins.uav.uav_defense.onnx_export import export
    checkpoint = f"weights/uav_{model_kind}.pt"
    output = f"weights/uav_{model_kind}.onnx"
    return export(model_kind=model_kind, checkpoint=checkpoint, output=output)


# ── Dataset manifest (drives the React Dataset Selector) ────────────────

@router.get("/datasets")
async def datasets_manifest() -> dict:
    from plugins.uav.datasets_manifest import manifest_payload
    return manifest_payload()


@router.get("/datasets/for-page/{page}")
async def datasets_for_page(page: str) -> dict:
    from pathlib import Path as _P
    from plugins.uav.datasets_manifest import list_for_page
    out = []
    for d in list_for_page(page):
        subset_exists = d.demo_subset_path is not None and _P(d.demo_subset_path).exists()
        out.append({
            "id": d.id, "name": d.name, "domain": d.domain,
            "size_full": d.size_full,
            "tier": "curated_50mb" if subset_exists else d.tier,
            "declared_tier": d.tier,
            "source_url": d.source_url, "citation": d.citation,
            "demo_subset_available": subset_exists,
        })
    return {"page": page, "datasets": out}


@router.get("/datasets/{dataset_id}/subset")
async def dataset_subset(dataset_id: str, limit: int = 50) -> dict:
    """Return the first N records of a curated 50 MB demo subset.
    Used by the operator pages when the panel switches datasets."""
    from plugins.uav.demo_subsets import get_subset
    data = get_subset(dataset_id)
    if data is None:
        return {"dataset_id": dataset_id, "status": "not_available",
                "hint": "Run scripts/bootstrap_demo_datasets.sh on the server first."}
    # Truncate large arrays so the UI doesn't choke on 50 MB
    if "annotations" in data and isinstance(data["annotations"], list):
        data["_total_records"] = len(data["annotations"])
        data["annotations"] = data["annotations"][:limit]
    if "samples" in data and isinstance(data["samples"], list):
        data["_total_records"] = len(data["samples"])
        data["samples"] = data["samples"][:limit]
    if "traces" in data and isinstance(data["traces"], list):
        data["_total_records"] = len(data["traces"])
        data["traces"] = data["traces"][:limit]
    if data.get("format") == "csv":
        lines = data.get("csv", "").splitlines()
        data["_total_records"] = max(0, len(lines) - 1)
        data["csv"] = "\n".join(lines[: limit + 1])
    return {"dataset_id": dataset_id, "status": "loaded",
            "preview_limit": limit, "data": data}


@router.get("/ew-bench/operating-point")
async def ew_bench_operating_point(js_db: float) -> dict:
    """Sample all four MCR curves at a specific J/S — drives the
    UAV Monitor's live J/S slider."""
    from plugins.uav.uav_defense.ew_bench import best_available_curves
    js_int = int(round(js_db))
    js_int = max(0, min(40, js_int))
    payload = best_available_curves()
    points = {}
    for curve in payload["curves"]:
        pt = next((p for p in curve["points"] if p["js_db"] == js_int), curve["points"][0])
        points[curve["config_key"]] = {
            "mcr": pt["mcr"],
            "ci_low": pt["ci_low"],
            "ci_high": pt["ci_high"],
            "above_do_326a": pt["mcr"] >= 0.90,
            "label": curve["label"],
            "color": curve["color"],
        }
    return {"js_db": js_int, "do_326a_threshold": 0.90, "points": points,
            "source": payload.get("source", "unknown")}


# ── Phase D — measured Mission-Completion-Rate via the simulator ────────

@router.post("/ew-bench/run")
async def ew_bench_run(quick: bool = False, n_reps: int = 200) -> dict:
    """Trigger a UAV-EW-Bench-2026 simulator run. WRITE — wall-clock
    is ~30 s for the default 200 reps × 3 missions × 3 receivers ×
    3 seeds. Set quick=true for a 10-s reduced grid."""
    from plugins.uav.uav_defense.ew_bench.simulator import (
        BenchConfig, run_bench,
    )
    if quick:
        cfg = BenchConfig(
            js_grid_db=list(range(0, 41, 2)),
            n_reps_per_point=50, seeds=(42,),
            missions=("delivery",),
            receivers=("ublox_f9p_sim",),
        )
    else:
        cfg = BenchConfig(n_reps_per_point=n_reps)
    return run_bench(cfg)


@router.get("/ew-bench/measured-status")
async def ew_bench_measured_status() -> dict:
    """Has a measured Phase-D run been produced yet?"""
    from plugins.uav.uav_defense.ew_bench import latest_measured
    measured = latest_measured()
    if measured is None:
        return {"status": "not_run",
                "hint": "POST /api/uav/ew-bench/run (quick=true for a 10-s smoke run)"}
    return {
        "status": "ready",
        "n_total_flights": measured["benchmark"]["n_total_flights"],
        "n_missions": measured["benchmark"]["n_missions"],
        "n_gnss_receivers": measured["benchmark"]["n_gnss_receivers"],
        "do_326a_crossings_db": {c["config_key"]: c["do_326a_crossing_db"]
                                  for c in measured["curves"]},
    }
