"""
Dataset management endpoints for PQC-IDS testing and model comparison.

Provides:
  GET    /api/datasets                  List available datasets
  GET    /api/datasets/{name}/info      Dataset metadata and PQ distribution
  POST   /api/datasets/upload           Upload a custom dataset
  DELETE /api/datasets/{name}           Remove an uploaded dataset
  POST   /api/datasets/{name}/predict   Run prediction on a stored dataset
  POST   /api/datasets/{name}/compare   Run all 7 branches + ablation comparison
"""

import os
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File
from slowapi import Limiter
from slowapi.util import get_remote_address

from auth import require_auth
from config import DATASETS_DIR, MAX_UPLOAD_SIZE_MB, DEVICE, MC_PASSES, MAX_ROWS
from features import extract_features
from uncertainty import predict_with_uncertainty
from models.surrogate import SurrogateIDS

router = APIRouter(prefix="/api/datasets", tags=["datasets"])
limiter = Limiter(key_func=get_remote_address)

DATASETS_DIR.mkdir(parents=True, exist_ok=True)

DATASET_EXTENSIONS = {".csv"}


def _resolve_path(name: str) -> Path:
    """Resolve a dataset name to its file path."""
    path = DATASETS_DIR / f"{name}.csv"
    if not path.exists():
        path = DATASETS_DIR / name
    if not path.exists() or not path.is_file():
        raise HTTPException(404, f"Dataset '{name}' not found")
    return path


def _dataset_meta(path: Path) -> dict:
    """Extract metadata from a dataset file without loading all data."""
    stat = path.stat()
    size_mb = stat.st_size / (1024 * 1024)

    try:
        df_head = pd.read_csv(path, nrows=5, low_memory=False)
        columns = list(df_head.columns)
        with open(path, "r") as f:
            n_rows = sum(1 for _ in f) - 1
    except Exception:
        columns = []
        n_rows = 0

    has_pq_meta = "pq_algorithm" in columns
    pq_distribution = {}
    label_distribution = {}

    if n_rows <= 200_000:
        try:
            cols_to_read = []
            if has_pq_meta:
                cols_to_read.append("pq_algorithm")
            if "label" in columns:
                cols_to_read.append("label")
            elif "Label" in columns:
                cols_to_read.append("Label")

            if cols_to_read:
                df_labels = pd.read_csv(path, usecols=cols_to_read, low_memory=False)
                if "pq_algorithm" in df_labels.columns:
                    pq_distribution = df_labels["pq_algorithm"].value_counts().to_dict()
                label_col = "label" if "label" in df_labels.columns else "Label" if "Label" in df_labels.columns else None
                if label_col:
                    label_distribution = df_labels[label_col].value_counts().to_dict()
        except Exception:
            pass

    return {
        "name": path.stem,
        "filename": path.name,
        "size_mb": round(size_mb, 2),
        "n_rows": n_rows,
        "n_columns": len(columns),
        "columns": columns,
        "has_pq_metadata": has_pq_meta,
        "pq_distribution": pq_distribution,
        "label_distribution": label_distribution,
    }


def _load_and_sample(path: Path, max_rows: int):
    """Load dataset, extract features, and optionally sample."""
    with open(path, "rb") as f:
        file_bytes = f.read()

    features, metadata, labels_encoded, label_names, fmt = extract_features(file_bytes, path.name)
    total_rows = len(features)
    sampled = False

    if total_rows > max_rows:
        idx = torch.randperm(total_rows)[:max_rows].sort().values
        features = features[idx]
        metadata = metadata.iloc[idx.numpy()].reset_index(drop=True)
        if labels_encoded is not None:
            labels_encoded = labels_encoded[idx]
        if label_names is not None:
            label_names = [label_names[i] for i in idx.tolist()]
        sampled = True

    return features, metadata, labels_encoded, label_names, fmt, total_rows, sampled


# ── Endpoints ─────────────────────────────────────────────────────────────


@router.get("")
async def list_datasets(user=Depends(require_auth)):
    """List all available datasets in the datasets directory."""
    datasets = []
    for f in sorted(DATASETS_DIR.iterdir()):
        if f.suffix.lower() == ".csv" and f.is_file():
            try:
                datasets.append(_dataset_meta(f))
            except Exception:
                datasets.append({"name": f.stem, "filename": f.name, "error": "Could not read metadata"})
    return {"datasets": datasets, "datasets_dir": str(DATASETS_DIR)}


@router.get("/{name}/info")
async def dataset_info(name: str, user=Depends(require_auth)):
    """Get detailed metadata for a specific dataset."""
    return _dataset_meta(_resolve_path(name))


@router.post("/upload")
@limiter.limit("5/minute")
async def upload_dataset(
    request: Request,
    file: UploadFile = File(...),
    user=Depends(require_auth),
):
    """Upload a custom dataset CSV to the datasets directory."""
    if not file.filename:
        raise HTTPException(400, "No filename provided")
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in DATASET_EXTENSIONS:
        raise HTTPException(400, f"Only CSV files are supported. Got: {ext}")

    data = await file.read()
    if len(data) > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(413, f"File too large. Maximum: {MAX_UPLOAD_SIZE_MB}MB")

    safe_name = "".join(c for c in file.filename if c.isalnum() or c in "._-").strip(".")
    if not safe_name:
        safe_name = "uploaded_dataset.csv"
    if not safe_name.endswith(".csv"):
        safe_name += ".csv"

    dest = DATASETS_DIR / safe_name
    with open(dest, "wb") as f:
        f.write(data)

    return {"message": f"Dataset uploaded as {safe_name}", "filename": safe_name, **_dataset_meta(dest)}


@router.delete("/{name}")
async def delete_dataset(name: str, user=Depends(require_auth)):
    """Delete a dataset from the datasets directory."""
    path = _resolve_path(name)
    path.unlink()
    return {"message": f"Dataset '{name}' deleted"}


@router.post("/{name}/predict")
@limiter.limit("5/minute")
async def predict_dataset(
    request: Request,
    name: str,
    mc_passes: int = 20,
    user=Depends(require_auth),
):
    """Run prediction on a stored dataset."""
    from models.model_registry import load_model as registry_load

    path = _resolve_path(name)
    features, metadata, labels_encoded, label_names, fmt, total_rows, sampled = _load_and_sample(path, MAX_ROWS)

    model = registry_load("surrogate", device=DEVICE)
    result = predict_with_uncertainty(
        model, features.to(DEVICE),
        labels=labels_encoded.to(DEVICE) if labels_encoded is not None else None,
        n_mc=mc_passes,
    )

    # result["predictions"] contains argmax class indices (1D tensor)
    preds = result["predictions"].cpu()
    pred_labels = [SurrogateIDS.CLASS_NAMES[p] for p in preds.tolist()]
    attack_dist = {}
    for lbl in pred_labels:
        attack_dist[lbl] = attack_dist.get(lbl, 0) + 1

    # Compute per-class metrics if labels available
    per_class = {}
    confusion = None
    if label_names:
        from sklearn.metrics import precision_recall_fscore_support, confusion_matrix as cm_fn
        all_labels = sorted(set(label_names) | set(pred_labels))
        p, r_val, f, _ = precision_recall_fscore_support(
            label_names, pred_labels, labels=all_labels, zero_division=0
        )
        for idx, lbl in enumerate(all_labels):
            per_class[lbl] = {
                "precision": round(float(p[idx]), 4),
                "recall": round(float(r_val[idx]), 4),
                "f1": round(float(f[idx]), 4),
            }
        confusion = cm_fn(label_names, pred_labels, labels=all_labels).tolist()

    accuracy = None
    if labels_encoded is not None:
        accuracy = round((preds == labels_encoded.cpu()).float().mean().item(), 4)

    return {
        "dataset": name,
        "format_detected": fmt,
        "total_rows": total_rows,
        "analysed_rows": len(features),
        "sampled": sampled,
        "mc_passes": mc_passes,
        "accuracy": accuracy,
        "n_threats": sum(1 for l in pred_labels if l != "Benign"),
        "n_benign": sum(1 for l in pred_labels if l == "Benign"),
        "attack_distribution": attack_dist,
        "ece": result.get("ece"),
        "per_class_metrics": per_class,
        "confusion_matrix": confusion,
    }


@router.post("/{name}/compare")
@limiter.limit("3/minute")
async def compare_branches(
    request: Request,
    name: str,
    mc_passes: int = 10,
    user=Depends(require_auth),
):
    """
    Run all 7 surrogate branches + ablation on a stored dataset.
    Returns per-branch accuracy drop and PQ-IDPS specific metrics.
    """
    from models.model_registry import load_model as registry_load

    path = _resolve_path(name)
    compare_max = min(MAX_ROWS, 5000)
    features, metadata, labels_encoded, label_names, fmt, total_rows, _ = _load_and_sample(path, compare_max)

    model = registry_load("surrogate", device=DEVICE)

    # Full ensemble prediction
    full_result = predict_with_uncertainty(
        model, features.to(DEVICE),
        labels=labels_encoded.to(DEVICE) if labels_encoded is not None else None,
        n_mc=mc_passes,
    )

    # predictions are already argmax indices (1D)
    full_preds = full_result["predictions"].cpu()
    full_accuracy = None
    if labels_encoded is not None:
        full_accuracy = round((full_preds == labels_encoded.cpu()).float().mean().item(), 4)

    # Per-branch ablation
    branch_results = {}
    for branch_idx in range(SurrogateIDS.N_BRANCHES):
        branch_name = SurrogateIDS.BRANCH_NAMES[branch_idx]
        ablated_result = predict_with_uncertainty(
            model, features.to(DEVICE),
            labels=labels_encoded.to(DEVICE) if labels_encoded is not None else None,
            n_mc=mc_passes,
            disabled_branches={branch_idx},
        )
        ablated_preds = ablated_result["predictions"].cpu()
        ablated_accuracy = None
        accuracy_drop = None
        if labels_encoded is not None:
            ablated_accuracy = round((ablated_preds == labels_encoded.cpu()).float().mean().item(), 4)
            accuracy_drop = round(full_accuracy - ablated_accuracy, 4) if full_accuracy is not None else None

        changed = int((full_preds != ablated_preds).sum().item())

        branch_results[branch_name] = {
            "branch_index": branch_idx,
            "accuracy_without": ablated_accuracy,
            "accuracy_drop": accuracy_drop,
            "predictions_changed": changed,
            "predictions_changed_pct": round(changed / len(features) * 100, 2),
        }

    # PQ-specific analysis
    pq_analysis = None
    if "pq_algorithm" in metadata.columns:
        pred_labels = [SurrogateIDS.CLASS_NAMES[p] for p in full_preds.tolist()]
        pq_algos = {"Kyber-768", "Kyber-512", "Kyber-1024"}

        pq_mask = metadata["pq_algorithm"].isin(pq_algos)
        classical_mask = metadata["pq_algorithm"] == "X25519-Classical"
        attack_mask = ~metadata["pq_algorithm"].isin(pq_algos | {"X25519-Classical", "N/A"})

        pq_total = int(pq_mask.sum())
        classical_total = int(classical_mask.sum())
        attack_total = int(attack_mask.sum())

        pq_benign = sum(1 for i in range(len(pred_labels)) if pq_mask.iloc[i] and pred_labels[i] == "Benign")
        cl_benign = sum(1 for i in range(len(pred_labels)) if classical_mask.iloc[i] and pred_labels[i] == "Benign")
        atk_detected = sum(1 for i in range(len(pred_labels)) if attack_mask.iloc[i] and pred_labels[i] != "Benign")

        pq_analysis = {
            "pq_traffic_recognition_rate": round(pq_benign / max(pq_total, 1), 4),
            "pq_traffic_total": pq_total,
            "classical_traffic_recognition_rate": round(cl_benign / max(classical_total, 1), 4),
            "classical_traffic_total": classical_total,
            "pq_attack_detection_rate": round(atk_detected / max(attack_total, 1), 4),
            "pq_attack_total": attack_total,
            "pq_idps_branch_impact": branch_results.get("PQ-IDPS (Post-quantum)", {}),
        }

    pred_labels_full = [SurrogateIDS.CLASS_NAMES[p] for p in full_preds.tolist()]
    return {
        "dataset": name,
        "format_detected": fmt,
        "total_rows": total_rows,
        "analysed_rows": len(features),
        "mc_passes": mc_passes,
        "full_ensemble": {
            "accuracy": full_accuracy,
            "ece": full_result.get("ece"),
            "n_threats": sum(1 for l in pred_labels_full if l != "Benign"),
            "n_benign": sum(1 for l in pred_labels_full if l == "Benign"),
        },
        "branch_ablation": branch_results,
        "pq_analysis": pq_analysis,
    }


@router.get("/{name}/download")
async def download_dataset(name: str, user=Depends(require_auth)):
    """Download a dataset file."""
    path = _resolve_path(name)
    from fastapi.responses import FileResponse
    return FileResponse(path, media_type="text/csv", filename=path.name)
