"""
Experiment Tracking & Comparison — versioned experiment management.
===================================================================

Provides:
  - Create / list / get / delete experiments
  - Tag and name experiment runs
  - Side-by-side comparison of experiments
  - Reproducible experiment manifests (JSON export)

Each experiment captures the full context: task type, parameters,
model used, dataset, and results with extracted key metrics.
"""

import datetime
import json
import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, or_
from sqlalchemy.orm import Session

from auth import require_auth
from database import get_db

logger = logging.getLogger("robustidps.experiments")

router = APIRouter(prefix="/api/experiments", tags=["Experiments"])


# ── Pydantic schemas ─────────────────────────────────────────────────────

class ExperimentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str = ""
    tags: list[str] = []
    task_type: str = ""           # ablation | redteam | prediction | federated | xai | benchmark
    dataset_name: str = ""
    model_used: str = ""
    params: dict = {}
    results: dict = {}
    metrics: dict = {}            # key metrics for quick comparison


class ExperimentUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[list[str]] = None


# ── Helpers ──────────────────────────────────────────────────────────────

def _extract_comparison_metrics(results: dict) -> dict:
    """Extract common comparison metrics from various result types."""
    m = {}
    # Direct top-level metrics
    for key in ("accuracy", "f1", "precision", "recall", "auc_roc", "ece",
                "n_flows", "n_threats", "robustness_score"):
        if key in results:
            m[key] = results[key]

    # Nested in per_class_metrics — compute macro averages
    pcm = results.get("per_class_metrics", {})
    if pcm:
        f1s = [v.get("f1", 0) for v in pcm.values() if isinstance(v, dict)]
        if f1s:
            m["macro_f1"] = round(sum(f1s) / len(f1s), 4)

    # Ablation-specific
    if "branch_impact" in results:
        m["branch_impact"] = results["branch_impact"]

    # Red-team specific
    attacks = results.get("attacks", {})
    if attacks and isinstance(attacks, dict):
        accs = []
        for a in attacks.values():
            if isinstance(a, dict) and "accuracy_after" in a:
                accs.append(a["accuracy_after"])
        if accs:
            m["mean_adversarial_accuracy"] = round(sum(accs) / len(accs), 4)

    return m


def _experiment_to_dict(exp) -> dict:
    return {
        "experiment_id": exp.experiment_id,
        "name": exp.name,
        "description": exp.description,
        "tags": exp.tags or [],
        "task_type": exp.task_type,
        "dataset_name": exp.dataset_name,
        "model_used": exp.model_used,
        "params": exp.params or {},
        "results": exp.results or {},
        "metrics": exp.metrics or {},
        "created_at": exp.created_at.isoformat() if exp.created_at else None,
        "updated_at": exp.updated_at.isoformat() if exp.updated_at else None,
    }


# ── Endpoints ────────────────────────────────────────────────────────────

@router.post("", summary="Create a new experiment")
def create_experiment(
    body: ExperimentCreate,
    user=Depends(require_auth),
    db: Session = Depends(get_db),
):
    from database import Experiment
    experiment_id = uuid.uuid4().hex[:12]

    # Auto-extract metrics if not provided
    metrics = body.metrics or _extract_comparison_metrics(body.results)

    exp = Experiment(
        experiment_id=experiment_id,
        user_id=user.id,
        name=body.name,
        description=body.description,
        tags=body.tags,
        task_type=body.task_type,
        dataset_name=body.dataset_name,
        model_used=body.model_used,
        params=body.params,
        results=body.results,
        metrics=metrics,
    )
    db.add(exp)
    db.commit()
    db.refresh(exp)
    logger.info("Experiment %s created by user %d: %s", experiment_id, user.id, body.name)
    return _experiment_to_dict(exp)


@router.get("", summary="List experiments")
def list_experiments(
    task_type: Optional[str] = Query(None),
    tag: Optional[str] = Query(None, description="Filter by tag"),
    search: Optional[str] = Query(None, description="Search name/description"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user=Depends(require_auth),
    db: Session = Depends(get_db),
):
    from database import Experiment
    q = db.query(Experiment).filter(Experiment.user_id == user.id)

    if task_type:
        q = q.filter(Experiment.task_type == task_type)
    if search:
        pattern = f"%{search}%"
        q = q.filter(or_(
            Experiment.name.ilike(pattern),
            Experiment.description.ilike(pattern),
        ))

    total = q.count()
    experiments = q.order_by(desc(Experiment.created_at)).offset(offset).limit(limit).all()

    items = [_experiment_to_dict(e) for e in experiments]

    # If tag filter, apply in-memory (JSON array filtering varies by DB)
    if tag:
        items = [e for e in items if tag in (e.get("tags") or [])]
        total = len(items)

    return {"experiments": items, "total": total}


@router.get("/tags", summary="List all tags used across experiments")
def list_tags(
    user=Depends(require_auth),
    db: Session = Depends(get_db),
):
    from database import Experiment
    experiments = db.query(Experiment.tags).filter(
        Experiment.user_id == user.id
    ).all()
    all_tags = set()
    for (tags,) in experiments:
        if tags:
            all_tags.update(tags)
    return {"tags": sorted(all_tags)}


@router.get("/compare", summary="Compare 2-4 experiments side by side")
def compare_experiments(
    ids: str = Query(..., description="Comma-separated experiment IDs (2-4)"),
    user=Depends(require_auth),
    db: Session = Depends(get_db),
):
    from database import Experiment
    exp_ids = [i.strip() for i in ids.split(",") if i.strip()]
    if len(exp_ids) < 2 or len(exp_ids) > 4:
        raise HTTPException(400, "Provide 2-4 experiment IDs")

    experiments = db.query(Experiment).filter(
        Experiment.experiment_id.in_(exp_ids),
        Experiment.user_id == user.id,
    ).all()

    if len(experiments) != len(exp_ids):
        found = {e.experiment_id for e in experiments}
        missing = [i for i in exp_ids if i not in found]
        raise HTTPException(404, f"Experiments not found: {', '.join(missing)}")

    comparison = []
    all_metric_keys = set()
    for exp in experiments:
        m = exp.metrics or {}
        all_metric_keys.update(m.keys())
        comparison.append({
            "experiment_id": exp.experiment_id,
            "name": exp.name,
            "task_type": exp.task_type,
            "model_used": exp.model_used,
            "dataset_name": exp.dataset_name,
            "params": exp.params or {},
            "metrics": m,
            "created_at": exp.created_at.isoformat() if exp.created_at else None,
        })

    # Build comparison table: metric -> {exp_id: value}
    metric_table = {}
    for key in sorted(all_metric_keys):
        row = {}
        for exp_data in comparison:
            val = exp_data["metrics"].get(key)
            row[exp_data["experiment_id"]] = val
        metric_table[key] = row

    return {
        "experiments": comparison,
        "metric_table": metric_table,
        "metric_keys": sorted(all_metric_keys),
    }


@router.get("/{experiment_id}", summary="Get experiment details")
def get_experiment(
    experiment_id: str,
    user=Depends(require_auth),
    db: Session = Depends(get_db),
):
    from database import Experiment
    exp = db.query(Experiment).filter(
        Experiment.experiment_id == experiment_id,
        Experiment.user_id == user.id,
    ).first()
    if not exp:
        raise HTTPException(404, "Experiment not found")
    return _experiment_to_dict(exp)


@router.patch("/{experiment_id}", summary="Update experiment name/description/tags")
def update_experiment(
    experiment_id: str,
    body: ExperimentUpdate,
    user=Depends(require_auth),
    db: Session = Depends(get_db),
):
    from database import Experiment
    exp = db.query(Experiment).filter(
        Experiment.experiment_id == experiment_id,
        Experiment.user_id == user.id,
    ).first()
    if not exp:
        raise HTTPException(404, "Experiment not found")

    if body.name is not None:
        exp.name = body.name
    if body.description is not None:
        exp.description = body.description
    if body.tags is not None:
        exp.tags = body.tags
    exp.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(exp)
    return _experiment_to_dict(exp)


@router.delete("/{experiment_id}", summary="Delete an experiment")
def delete_experiment(
    experiment_id: str,
    user=Depends(require_auth),
    db: Session = Depends(get_db),
):
    from database import Experiment
    exp = db.query(Experiment).filter(
        Experiment.experiment_id == experiment_id,
        Experiment.user_id == user.id,
    ).first()
    if not exp:
        raise HTTPException(404, "Experiment not found")
    db.delete(exp)
    db.commit()
    return {"ok": True}


@router.get("/{experiment_id}/manifest", summary="Export reproducible experiment manifest")
def export_manifest(
    experiment_id: str,
    user=Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Export a JSON manifest that fully describes the experiment for reproducibility."""
    from database import Experiment
    exp = db.query(Experiment).filter(
        Experiment.experiment_id == experiment_id,
        Experiment.user_id == user.id,
    ).first()
    if not exp:
        raise HTTPException(404, "Experiment not found")

    manifest = {
        "schema_version": "1.0",
        "platform": "RobustIDPS.AI",
        "experiment_id": exp.experiment_id,
        "name": exp.name,
        "description": exp.description,
        "task_type": exp.task_type,
        "model": exp.model_used,
        "dataset": exp.dataset_name,
        "parameters": exp.params or {},
        "metrics_summary": exp.metrics or {},
        "tags": exp.tags or [],
        "created_at": exp.created_at.isoformat() if exp.created_at else None,
        "reproducibility_notes": (
            "Re-run this experiment by submitting the same parameters to the "
            f"/api/{exp.task_type}/run endpoint with the specified model and dataset."
        ),
    }

    from fastapi.responses import JSONResponse
    return JSONResponse(
        content=manifest,
        headers={
            "Content-Disposition": f'attachment; filename="experiment_{experiment_id}.json"',
        },
    )
