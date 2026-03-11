"""
Dataset Drift & Model Health Monitoring
=========================================

Provides:
  - Statistical drift detection (KS test, PSI, feature-level analysis)
  - Model performance degradation tracking
  - Drift severity scoring per feature
  - Auto-alert when drift exceeds thresholds
  - Reference distribution management (store baseline stats)
"""

import datetime
import logging
from typing import Optional

import numpy as np
import torch
from fastapi import APIRouter, Body, Depends, HTTPException, UploadFile, File, Form
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth import require_auth
from config import DEVICE
from database import get_db

logger = logging.getLogger("robustidps.drift")

router = APIRouter(prefix="/api/drift", tags=["Drift Detection"])


# ── Reference distribution store ────────────────────────────────────────

_reference: dict = {}  # {model_id: {means, stds, quantiles, n_samples, created_at}}


def _compute_stats(features: np.ndarray) -> dict:
    """Compute reference statistics from a feature matrix."""
    return {
        "means": features.mean(axis=0).tolist(),
        "stds": features.std(axis=0).tolist(),
        "mins": features.min(axis=0).tolist(),
        "maxs": features.max(axis=0).tolist(),
        "q25": np.percentile(features, 25, axis=0).tolist(),
        "q50": np.percentile(features, 50, axis=0).tolist(),
        "q75": np.percentile(features, 75, axis=0).tolist(),
        "n_samples": int(features.shape[0]),
        "n_features": int(features.shape[1]),
    }


# ── Statistical tests ───────────────────────────────────────────────────

def _ks_test(ref_values: np.ndarray, new_values: np.ndarray) -> tuple[float, float]:
    """
    Two-sample Kolmogorov-Smirnov test.
    Returns (statistic, p_value).
    """
    # Manual KS implementation (avoids scipy dependency)
    n1 = len(ref_values)
    n2 = len(new_values)
    if n1 == 0 or n2 == 0:
        return 0.0, 1.0

    all_values = np.concatenate([ref_values, new_values])
    all_values.sort()

    cdf1 = np.searchsorted(np.sort(ref_values), all_values, side="right") / n1
    cdf2 = np.searchsorted(np.sort(new_values), all_values, side="right") / n2

    d_stat = float(np.max(np.abs(cdf1 - cdf2)))

    # Approximate p-value using asymptotic formula
    en = np.sqrt(n1 * n2 / (n1 + n2))
    p_value = float(np.exp(-2.0 * (d_stat * en) ** 2))
    p_value = min(max(p_value, 0.0), 1.0)

    return d_stat, p_value


def _psi(ref_dist: np.ndarray, new_dist: np.ndarray, n_bins: int = 10) -> float:
    """
    Population Stability Index (PSI).
    PSI < 0.1 = no drift, 0.1-0.2 = moderate, > 0.2 = significant.
    """
    if len(ref_dist) == 0 or len(new_dist) == 0:
        return 0.0

    # Create bins from reference distribution
    breakpoints = np.percentile(ref_dist, np.linspace(0, 100, n_bins + 1))
    breakpoints = np.unique(breakpoints)
    if len(breakpoints) < 2:
        return 0.0

    ref_counts = np.histogram(ref_dist, bins=breakpoints)[0].astype(float)
    new_counts = np.histogram(new_dist, bins=breakpoints)[0].astype(float)

    # Avoid division by zero
    ref_pct = ref_counts / ref_counts.sum() + 1e-8
    new_pct = new_counts / new_counts.sum() + 1e-8

    psi = float(np.sum((new_pct - ref_pct) * np.log(new_pct / ref_pct)))
    return max(psi, 0.0)


def _mean_shift(ref_mean: float, ref_std: float, new_mean: float) -> float:
    """Compute standardized mean shift (z-score of shift)."""
    if ref_std < 1e-10:
        return 0.0
    return abs(new_mean - ref_mean) / ref_std


# ── Drift analysis ──────────────────────────────────────────────────────

def analyze_drift(
    ref_stats: dict,
    new_features: np.ndarray,
    feature_names: Optional[list[str]] = None,
) -> dict:
    """
    Compare new feature data against reference statistics.

    Returns per-feature drift scores plus aggregate metrics.
    """
    n_features = min(new_features.shape[1], len(ref_stats["means"]))
    new_stats = _compute_stats(new_features[:, :n_features])

    per_feature = []
    drift_scores = []

    for i in range(n_features):
        fname = feature_names[i] if feature_names and i < len(feature_names) else f"feature_{i}"
        ref_mean = ref_stats["means"][i]
        ref_std = ref_stats["stds"][i]
        new_mean = new_stats["means"][i]
        new_std = new_stats["stds"][i]

        # Mean shift (z-score)
        z_shift = _mean_shift(ref_mean, ref_std, new_mean)

        # Variance ratio
        var_ratio = (new_std / ref_std) if ref_std > 1e-10 else 1.0

        # Range drift
        ref_range = ref_stats["maxs"][i] - ref_stats["mins"][i]
        new_range = new_stats["maxs"][i] - new_stats["mins"][i]
        range_drift = abs(new_range - ref_range) / (ref_range + 1e-10)

        # Combined drift score (0-1 scale)
        drift_score = min(1.0, (
            0.4 * min(z_shift / 3.0, 1.0) +      # z > 3 = max contribution
            0.3 * min(abs(var_ratio - 1.0), 1.0) + # variance change
            0.3 * min(range_drift, 1.0)             # range change
        ))

        severity = "none"
        if drift_score > 0.5:
            severity = "critical"
        elif drift_score > 0.3:
            severity = "high"
        elif drift_score > 0.15:
            severity = "moderate"
        elif drift_score > 0.05:
            severity = "low"

        per_feature.append({
            "feature": fname,
            "index": i,
            "ref_mean": round(ref_mean, 6),
            "new_mean": round(new_mean, 6),
            "z_shift": round(z_shift, 4),
            "ref_std": round(ref_std, 6),
            "new_std": round(new_std, 6),
            "var_ratio": round(var_ratio, 4),
            "drift_score": round(drift_score, 4),
            "severity": severity,
        })
        drift_scores.append(drift_score)

    # Aggregate metrics
    drift_scores_arr = np.array(drift_scores)
    n_drifted = int(np.sum(drift_scores_arr > 0.15))
    n_critical = int(np.sum(drift_scores_arr > 0.5))
    aggregate_score = float(np.mean(drift_scores_arr))

    overall_severity = "none"
    if aggregate_score > 0.3 or n_critical > n_features * 0.1:
        overall_severity = "critical"
    elif aggregate_score > 0.2 or n_drifted > n_features * 0.3:
        overall_severity = "high"
    elif aggregate_score > 0.1 or n_drifted > n_features * 0.15:
        overall_severity = "moderate"
    elif n_drifted > 0:
        overall_severity = "low"

    # Top drifted features
    top_drifted = sorted(per_feature, key=lambda x: -x["drift_score"])[:10]

    return {
        "aggregate_drift_score": round(aggregate_score, 4),
        "overall_severity": overall_severity,
        "n_features_analyzed": n_features,
        "n_features_drifted": n_drifted,
        "n_features_critical": n_critical,
        "ref_samples": ref_stats["n_samples"],
        "new_samples": int(new_features.shape[0]),
        "top_drifted_features": top_drifted,
        "per_feature": per_feature,
        "recommendation": _recommendation(overall_severity),
        "analyzed_at": datetime.datetime.utcnow().isoformat(),
    }


def _recommendation(severity: str) -> str:
    recs = {
        "none": "No significant drift detected. Model performance should remain stable.",
        "low": "Minor feature distribution changes detected. Monitor over the next few prediction cycles.",
        "moderate": "Moderate drift detected in multiple features. Consider running a model evaluation on recent data.",
        "high": "Significant drift detected. Recommend running continual learning update or model re-evaluation.",
        "critical": "Critical drift detected across many features. Immediate model update or re-training recommended.",
    }
    return recs.get(severity, recs["none"])


# ── Endpoints ────────────────────────────────────────────────────────────

@router.post("/reference", summary="Set reference distribution from uploaded file")
def set_reference(
    file: UploadFile = File(...),
    model_id: str = Form("surrogate"),
    user=Depends(require_auth),
):
    """Upload a CSV file to establish the reference (training) distribution."""
    from features import load_and_extract
    import io

    content = file.file.read()
    try:
        features, metadata, labels, label_names = load_and_extract(
            io.BytesIO(content), file.filename or "reference.csv"
        )
    except Exception as e:
        raise HTTPException(400, f"Failed to extract features: {e}")

    features_np = features.numpy() if isinstance(features, torch.Tensor) else np.array(features)
    stats = _compute_stats(features_np)
    stats["model_id"] = model_id
    stats["created_at"] = datetime.datetime.utcnow().isoformat()
    stats["filename"] = file.filename

    _reference[model_id] = stats
    logger.info("Reference distribution set for model %s: %d samples, %d features",
                model_id, stats["n_samples"], stats["n_features"])

    return {
        "ok": True,
        "model_id": model_id,
        "n_samples": stats["n_samples"],
        "n_features": stats["n_features"],
    }


@router.post("/analyze", summary="Analyze drift between reference and new data")
def analyze(
    file: UploadFile = File(...),
    model_id: str = Form("surrogate"),
    user=Depends(require_auth),
):
    """Upload a new CSV file and compare its distribution to the reference."""
    if model_id not in _reference:
        raise HTTPException(400, f"No reference distribution set for model '{model_id}'. Upload a reference first via POST /api/drift/reference")

    from features import load_and_extract
    import io

    content = file.file.read()
    try:
        features, metadata, labels, label_names = load_and_extract(
            io.BytesIO(content), file.filename or "new_data.csv"
        )
    except Exception as e:
        raise HTTPException(400, f"Failed to extract features: {e}")

    features_np = features.numpy() if isinstance(features, torch.Tensor) else np.array(features)
    result = analyze_drift(_reference[model_id], features_np)
    result["model_id"] = model_id
    result["ref_filename"] = _reference[model_id].get("filename", "unknown")
    result["new_filename"] = file.filename

    # Forward critical drift to SIEM if connectors are configured
    if result["overall_severity"] in ("high", "critical"):
        try:
            from siem_connectors import emit_event
            emit_event({
                "threat_label": "MODEL_DRIFT",
                "severity": result["overall_severity"],
                "confidence": result["aggregate_drift_score"],
                "src_ip": "system",
                "dst_ip": "system",
                "model_used": model_id,
                "job_id": f"drift-{model_id}",
            })
        except ImportError:
            pass

    return result


@router.get("/reference", summary="Get current reference distribution metadata")
def get_reference(
    model_id: str = "surrogate",
    user=Depends(require_auth),
):
    if model_id not in _reference:
        return {"has_reference": False, "model_id": model_id}

    ref = _reference[model_id]
    return {
        "has_reference": True,
        "model_id": model_id,
        "n_samples": ref["n_samples"],
        "n_features": ref["n_features"],
        "created_at": ref.get("created_at"),
        "filename": ref.get("filename"),
    }


@router.get("/reference/stats", summary="Get reference distribution statistics")
def get_reference_stats(
    model_id: str = "surrogate",
    user=Depends(require_auth),
):
    if model_id not in _reference:
        raise HTTPException(404, f"No reference distribution for model '{model_id}'")

    ref = _reference[model_id]
    # Return summary (not full per-feature arrays for large responses)
    return {
        "model_id": model_id,
        "n_samples": ref["n_samples"],
        "n_features": ref["n_features"],
        "created_at": ref.get("created_at"),
        "feature_summary": [
            {
                "index": i,
                "mean": round(ref["means"][i], 6),
                "std": round(ref["stds"][i], 6),
                "min": round(ref["mins"][i], 6),
                "max": round(ref["maxs"][i], 6),
                "q50": round(ref["q50"][i], 6),
            }
            for i in range(min(ref["n_features"], 83))
        ],
    }


@router.delete("/reference", summary="Clear reference distribution")
def clear_reference(
    model_id: str = "surrogate",
    user=Depends(require_auth),
):
    _reference.pop(model_id, None)
    return {"ok": True}
