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

from fastapi import APIRouter, HTTPException, UploadFile, File, Body, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from plugins.uav import services as _svc

router = APIRouter(prefix="/api/uav", tags=["UAV / Aerial Defense"])


# ── Schemas ──────────────────────────────────────────────────────────────

class AttackRequest(BaseModel):
    attack: Literal[
        "fgsm", "pgd", "cw", "deepfool",
        "hop_skip_jump", "boundary",
        "gaussian", "feature_mask", "label_flip",
    ] = Field("pgd")
    epsilon: float = Field(4 / 255, gt=0, le=0.5)
    pgd_steps: int = Field(20, ge=1, le=100)
    sample_index: int = Field(0, ge=0, lt=64)
    cw_kappa: float = Field(5.0, ge=0, le=50)
    cw_c: float = Field(1.0, gt=0, le=1000)
    cw_steps: int = Field(100, ge=10, le=500)
    deepfool_max_iter: int = Field(50, ge=5, le=200)
    hsj_queries: int = Field(200, ge=50, le=2000)
    boundary_steps: int = Field(100, ge=10, le=500)
    gaussian_sigma: float = Field(0.05, gt=0, le=1.0)
    mask_fraction: float = Field(0.2, gt=0, lt=1.0)
    label_flip_fraction: float = Field(0.1, gt=0, le=1.0)


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
async def gnss_sky(
    seed: int | None = Query(None, ge=0, le=2**31 - 1,
                             description="Reproducible seed; None = time-bucketed"),
    receiver_model: Literal["gp_software", "ublox_f9p_sim", "novatel_oem7_sim"] = Query("gp_software"),
    jamming_db: float = Query(0.0, ge=0.0, le=40.0,
                              description="J/S ratio in dB at the antenna"),
    n_spoofed: int | None = Query(None, ge=0, le=8,
                                  description="How many satellites the jammer targets (None = default {G03,G05})"),
    spoof_threshold: float = Query(0.5, ge=0.0, le=1.0,
                                   description="M1 CT-TGNN spoof-confidence flagging threshold"),
) -> dict:
    return _svc.gnss_payload(
        seed=seed,
        receiver_model=receiver_model,
        jamming_db=jamming_db,
        n_spoofed=n_spoofed,
        spoof_threshold=spoof_threshold,
    )


@router.get("/certificates")
async def certificates() -> dict:
    return _svc.certificates_payload()


@router.post("/perception/attack")
async def perception_attack(req: AttackRequest) -> dict:
    return _svc.perception_attack_payload(
        attack=req.attack, epsilon=req.epsilon,
        pgd_steps=req.pgd_steps, sample_index=req.sample_index,
        cw_kappa=req.cw_kappa, cw_c=req.cw_c, cw_steps=req.cw_steps,
        deepfool_max_iter=req.deepfool_max_iter,
        hsj_queries=req.hsj_queries, boundary_steps=req.boundary_steps,
        gaussian_sigma=req.gaussian_sigma, mask_fraction=req.mask_fraction,
        label_flip_fraction=req.label_flip_fraction,
    )


@router.get("/perception/attack-catalog")
async def perception_attack_catalog() -> dict:
    from plugins.uav.uav_defense.attacks import ATTACK_CATALOG
    return {"attacks": ATTACK_CATALOG, "total": len(ATTACK_CATALOG)}


# ── Live multi-UAV fleet demo ───────────────────────────────────────────

class FleetStepRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)
    per_uav_attack: dict[str, str] = Field(default_factory=dict)
    js_db: float = Field(10.0, ge=0, le=40)
    dt_s: float = Field(1.0, gt=0, le=10)


class FleetResetRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)
    n_uavs: int = Field(3, ge=1, le=12)


@router.post("/fleet/step")
async def fleet_step(req: FleetStepRequest) -> dict:
    from plugins.uav.fleet_simulator import step_fleet
    return step_fleet(req.session_id, req.per_uav_attack, req.js_db, req.dt_s)


@router.post("/fleet/reset")
async def fleet_reset(req: FleetResetRequest) -> dict:
    from plugins.uav.fleet_simulator import reset_fleet
    fleet = reset_fleet(req.session_id, req.n_uavs)
    return {"session_id": req.session_id, "n_uavs": len(fleet),
            "uavs": [u.as_dict() for u in fleet]}


@router.get("/fleet/sample-pack")
async def fleet_sample_pack() -> JSONResponse:
    """Downloadable mixed-data UAV fleet sample (re-uploadable for the live demo)."""
    from plugins.uav.fleet_simulator import sample_pack
    payload = sample_pack()
    return JSONResponse(
        content=payload,
        headers={"Content-Disposition": "attachment; filename=robustidps-uav-fleet-sample.json"},
    )


@router.post("/fleet/upload")
async def fleet_upload(file: UploadFile = File(...)) -> dict:
    """Accept a user-uploaded fleet bundle. Returns a parse summary
    plus a session_id ready to drive the live demo."""
    from plugins.uav.fleet_simulator import validate_upload, _FLEET_STORE, UAVState
    raw = await file.read()
    result = validate_upload(raw)
    if not result["ok"]:
        raise HTTPException(400, result.get("error", "Invalid bundle"))
    import uuid
    session_id = f"upload-{uuid.uuid4().hex[:10]}"
    fleet = []
    for u in result["parsed"]["uavs"]:
        last = (u.get("telemetry") or [{}])[-1]
        pos = last.get("position_xyz") or [0.0, 0.0, 80.0]
        fleet.append(UAVState(
            uav_id=u["uav_id"],
            kind=u.get("kind", "delivery"),
            defense=u.get("defense", "framework"),
            battery_pct=float(last.get("battery_pct", 100.0)),
            link_quality_pct=float(last.get("link_quality_pct", 100.0)),
            position=tuple(pos),
        ))
    _FLEET_STORE[session_id] = fleet
    return {"session_id": session_id, **result["summary"],
            "uavs": [u.as_dict() for u in fleet]}


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
async def ew_bench_run(quick: bool = False, n_reps: int = 200,
                       use_real_trajectories: bool = False) -> dict:
    """Trigger a UAV-EW-Bench-2026 simulator run. WRITE — wall-clock
    is ~30 s for the default 200 reps × 3 missions × 3 receivers ×
    3 seeds. Set quick=true for a 10-s reduced grid.

    use_real_trajectories=true activates Phase E mode: the simulator
    runs against discovered real flight trajectories from
    FLIGHT_TRAJECTORIES_ROOT (PX4 SITL / EuRoC MAV / UZH-FPV), or
    synthetic-fallback trajectories when none are on disk.
    """
    from plugins.uav.uav_defense.ew_bench.simulator import (
        BenchConfig, run_bench, run_bench_with_real_trajectories,
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
    if use_real_trajectories:
        return run_bench_with_real_trajectories(cfg)
    return run_bench(cfg)


@router.get("/flight-trajectories")
async def flight_trajectories_manifest() -> dict:
    """List real flight trajectories discovered on disk + the synthetic
    fallback specs. Drives the React Trajectory Selector for Phase E
    bench runs."""
    from plugins.uav.uav_defense.datasets.flight_trajectories import manifest_payload
    return manifest_payload()


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
