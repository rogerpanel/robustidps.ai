"""
RobustIDPS FastAPI backend
==========================

Endpoints:
  POST   /api/upload              Upload CSV, return job_id
  GET    /api/results/{job_id}    Get predictions for uploaded file
  POST   /api/predict             Upload + predict in one call
  POST   /api/predict_uncertain   Predict with MC Dropout uncertainty
  POST   /api/ablation            Run ablation study
  GET    /api/analytics           Pre-computed benchmark / research metrics
  GET    /api/export/{job_id}     Export results as CSV
  GET    /api/model_info          Model metadata and branch names
  GET    /api/health              Health check
  WS     /ws/stream               WebSocket: stream predictions row-by-row
"""

import asyncio
import json
import os
import uuid
from pathlib import Path

import io

import torch
import numpy as np
from fastapi import FastAPI, UploadFile, File, Form, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from models.surrogate import SurrogateIDS
from models.model_registry import list_models, load_model as registry_load, MODEL_INFO
from features import extract_features
from uncertainty import predict_with_uncertainty
from ablation import run_ablation
from benchmark import get_analytics_payload

WEIGHTS_DIR = Path(__file__).parent / "weights"
DEVICE = os.getenv("DEVICE", "cpu")
MC_PASSES = int(os.getenv("MC_PASSES", "20"))

app = FastAPI(title="RobustIDPS.ai", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------
model: SurrogateIDS | None = None
loaded_models: dict = {}  # cache: model_id -> nn.Module
active_model_id: str = "surrogate"
job_store: dict = {}


def load_model() -> SurrogateIDS:
    # Use low dropout for inference — model was trained with dropout=0.05.
    # MC Dropout passes will still enable dropout via model.train().
    m = SurrogateIDS(dropout=0.05)
    weight_path = WEIGHTS_DIR / "surrogate.pt"
    if weight_path.exists():
        state = torch.load(weight_path, map_location=DEVICE, weights_only=True)
        m.load_state_dict(state)
    m.to(DEVICE)
    m.eval()
    return m


def get_model(model_id: str | None = None):
    """Get a model by ID, using cache. Falls back to active model."""
    global active_model_id
    mid = model_id or active_model_id
    if mid == "surrogate":
        return model
    if mid not in loaded_models:
        try:
            loaded_models[mid] = registry_load(mid, device=DEVICE, dropout=0.05)
        except Exception:
            return model  # fallback to surrogate
    return loaded_models[mid]


@app.on_event("startup")
async def startup():
    global model
    model = load_model()
    loaded_models["surrogate"] = model


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_predictions(features, metadata, labels_encoded, label_names,
                       result_dict):
    preds = result_dict["predictions"].cpu()
    confidence = result_dict["confidence"].cpu()
    epistemic = result_dict["epistemic"].cpu()
    aleatoric = result_dict["aleatoric"].cpu()

    rows = []
    for i in range(len(preds)):
        cls_idx = preds[i].item()
        label_pred = SurrogateIDS.CLASS_NAMES[cls_idx] if cls_idx < len(SurrogateIDS.CLASS_NAMES) else f"class_{cls_idx}"
        true_label = label_names[i] if label_names else None

        rows.append({
            "flow_id": i,
            "src_ip": str(metadata["src_ip"].iloc[i]) if "src_ip" in metadata.columns else "",
            "dst_ip": str(metadata["dst_ip"].iloc[i]) if "dst_ip" in metadata.columns else "",
            "label_predicted": label_pred,
            "label_true": true_label,
            "confidence": round(float(confidence[i]), 4),
            "severity": SurrogateIDS.severity_for(label_pred),
            "epistemic_uncertainty": round(float(epistemic[i]), 4),
            "aleatoric_uncertainty": round(float(aleatoric[i]), 4),
            "total_uncertainty": round(float(epistemic[i] + aleatoric[i]), 4),
        })

    # Aggregate
    n_threats = sum(1 for r in rows if r["severity"] != "benign")
    n_benign = len(rows) - n_threats

    attack_dist: dict = {}
    for r in rows:
        attack_dist[r["label_predicted"]] = attack_dist.get(r["label_predicted"], 0) + 1

    # Per-class metrics (if ground truth present)
    per_class = {}
    confusion = None
    if label_names:
        from sklearn.metrics import precision_recall_fscore_support, confusion_matrix
        pred_labels = [r["label_predicted"] for r in rows]
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
        confusion = confusion_matrix(label_names, pred_labels, labels=all_labels).tolist()

    return {
        "n_flows": len(rows),
        "n_threats": n_threats,
        "n_benign": n_benign,
        "ece": round(result_dict["ece"], 4),
        "predictions": rows,
        "attack_distribution": attack_dist,
        "confusion_matrix": confusion,
        "per_class_metrics": per_class,
        "class_labels": SurrogateIDS.CLASS_NAMES,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    return {"status": "ok", "model_loaded": model is not None}


@app.get("/api/models")
async def get_available_models():
    """List all available models with metadata."""
    return {
        "models": list_models(),
        "active_model": active_model_id,
    }


@app.post("/api/models/{model_id}/activate")
async def activate_model(model_id: str):
    """Switch the active model."""
    global active_model_id
    if model_id not in MODEL_INFO:
        return JSONResponse(
            {"error": f"Unknown model: {model_id}"},
            status_code=400,
        )
    active_model_id = model_id
    _ = get_model(model_id)  # pre-load
    return {"active_model": active_model_id}


@app.get("/api/model_info")
async def model_info():
    return {
        "model": "SurrogateIDS",
        "active_model": active_model_id,
        "n_features": SurrogateIDS.N_FEATURES,
        "n_classes": SurrogateIDS.N_CLASSES,
        "n_branches": SurrogateIDS.N_BRANCHES,
        "branch_names": SurrogateIDS.BRANCH_NAMES,
        "class_names": SurrogateIDS.CLASS_NAMES,
    }


@app.post("/api/upload")
async def upload(file: UploadFile = File(...)):
    job_id = str(uuid.uuid4())[:8]
    data = await file.read()
    features, metadata, labels_encoded, label_names, fmt = extract_features(data, file.filename or "upload.csv")
    job_store[job_id] = {
        "features": features,
        "metadata": metadata,
        "labels_encoded": labels_encoded,
        "label_names": label_names,
    }
    return {"job_id": job_id, "n_flows": len(features)}


@app.get("/api/results/{job_id}")
async def get_results(job_id: str):
    if job_id not in job_store:
        return JSONResponse({"error": "job not found"}, status_code=404)
    job = job_store[job_id]
    result = predict_with_uncertainty(
        model, job["features"].to(DEVICE),
        labels=job["labels_encoded"].to(DEVICE) if job["labels_encoded"] is not None else None,
        n_mc=MC_PASSES,
    )
    payload = _build_predictions(
        job["features"], job["metadata"],
        job["labels_encoded"], job["label_names"], result,
    )
    payload["job_id"] = job_id
    return payload


@app.post("/api/predict")
async def predict(file: UploadFile = File(...)):
    data = await file.read()
    features, metadata, labels_encoded, label_names, fmt = extract_features(data, file.filename or "upload.csv")
    result = predict_with_uncertainty(
        model, features.to(DEVICE),
        labels=labels_encoded.to(DEVICE) if labels_encoded is not None else None,
        n_mc=MC_PASSES,
    )
    payload = _build_predictions(features, metadata, labels_encoded, label_names, result)
    payload["job_id"] = str(uuid.uuid4())[:8]
    return payload


MAX_ROWS = 10_000  # Cap rows to keep MC Dropout feasible on CPU


@app.post("/api/predict_uncertain")
async def predict_uncertain(
    file: UploadFile = File(...),
    mc_passes: int = Form(default=20),
    model_name: str = Form(default=""),
):
    data = await file.read()
    features, metadata, labels_encoded, label_names, fmt = extract_features(data, file.filename or "upload.csv")

    total_rows = len(features)
    sampled = False
    if total_rows > MAX_ROWS:
        # Random sample to keep inference fast
        idx = torch.randperm(total_rows)[:MAX_ROWS].sort().values
        features = features[idx]
        metadata = metadata.iloc[idx.numpy()].reset_index(drop=True)
        if labels_encoded is not None:
            labels_encoded = labels_encoded[idx]
        if label_names is not None:
            label_names = [label_names[i] for i in idx.tolist()]
        sampled = True

    selected = get_model(model_name if model_name else None)
    result = predict_with_uncertainty(
        selected, features.to(DEVICE),
        labels=labels_encoded.to(DEVICE) if labels_encoded is not None else None,
        n_mc=mc_passes,
    )
    payload = _build_predictions(features, metadata, labels_encoded, label_names, result)
    payload["job_id"] = str(uuid.uuid4())[:8]
    payload["model_used"] = model_name if model_name else active_model_id
    fmt_labels = {
        "ciciot2023": "CIC-IoT-2023",
        "cicids2018": "CSE-CIC-IDS2018",
        "unsw": "UNSW-NB15",
        "generic": "Generic CSV",
    }
    payload["dataset_info"] = {
        "total_rows": total_rows,
        "analysed_rows": len(features),
        "sampled": sampled,
        "format": fmt_labels.get(fmt, fmt),
        "columns": list(metadata.columns),
    }
    return payload


@app.post("/api/ablation")
async def ablation_endpoint(
    file: UploadFile = File(...),
    disabled_branches: str = Form(default="[]"),
    model_name: str = Form(default=""),
):
    data = await file.read()
    features, metadata, labels_encoded, label_names, fmt = extract_features(data, file.filename or "upload.csv")

    disabled = set(json.loads(disabled_branches))
    selected = get_model(model_name if model_name else None)

    # Full ablation study (only supported for surrogate)
    if hasattr(selected, 'N_BRANCHES') and selected.N_BRANCHES == 7:
        ablation_result = run_ablation(
            selected, features.to(DEVICE),
            labels=labels_encoded.to(DEVICE) if labels_encoded is not None else None,
        )
        single = ablation_result["single"]
        pairwise = ablation_result["pairwise"]
        incremental = ablation_result["incremental"]
    else:
        # Non-surrogate model — run single full-model prediction
        with torch.no_grad():
            selected.eval()
            preds = selected(features.to(DEVICE)).argmax(-1)
            if labels_encoded is not None:
                acc = (preds == labels_encoded.to(DEVICE)).float().mean().item()
            else:
                acc = 1.0
            single = {
                "Full System": {
                    "accuracy": acc, "precision": 0.0, "recall": 0.0,
                    "f1": 0.0, "accuracy_drop": 0.0, "disabled": [],
                },
            }
        pairwise = {}
        incremental = []

    # Also run with custom disabled set (only for surrogate)
    if disabled and hasattr(selected, 'N_BRANCHES'):
        with torch.no_grad():
            selected.eval()
            custom_preds = selected(features.to(DEVICE), disabled_branches=disabled).argmax(-1)
            full_preds = selected(features.to(DEVICE)).argmax(-1)
            if labels_encoded is not None:
                custom_acc = (custom_preds == labels_encoded.to(DEVICE)).float().mean().item()
                full_acc = (full_preds == labels_encoded.to(DEVICE)).float().mean().item()
            else:
                custom_acc = (custom_preds == full_preds).float().mean().item()
                full_acc = 1.0
            single["Custom"] = {
                "accuracy": custom_acc, "precision": 0.0, "recall": 0.0,
                "f1": 0.0, "accuracy_drop": full_acc - custom_acc,
                "disabled": list(disabled),
            }

    # Serialise (remove tensors)
    clean = {}
    for k, v in single.items():
        clean[k] = {
            "accuracy": round(v["accuracy"], 4),
            "precision": round(v.get("precision", 0.0), 4),
            "recall": round(v.get("recall", 0.0), 4),
            "f1": round(v.get("f1", 0.0), 4),
            "accuracy_drop": round(v.get("accuracy_drop", 0.0), 4),
            "disabled": v["disabled"],
        }

    return {
        "ablation": clean,
        "pairwise": pairwise,
        "incremental": incremental,
        "branch_names": SurrogateIDS.BRANCH_NAMES,
        "model_used": model_name if model_name else active_model_id,
    }


@app.get("/api/analytics")
async def analytics():
    """Return pre-computed benchmark data for the Analytics page."""
    return get_analytics_payload()


@app.get("/api/export/{job_id}")
async def export_results(job_id: str):
    """Export prediction results as downloadable CSV."""
    if job_id not in job_store:
        return JSONResponse({"error": "job not found"}, status_code=404)
    job = job_store[job_id]

    # Re-run lightweight prediction (no MC) for export
    selected = get_model()
    selected.eval()
    with torch.no_grad():
        logits = selected(job["features"].to(DEVICE))
        probs = torch.softmax(logits, dim=-1)
        preds = probs.argmax(-1).cpu()
        confs = probs.max(-1).values.cpu()

    import csv
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "flow_id", "src_ip", "dst_ip", "label_predicted", "label_true",
        "confidence", "severity", "action",
    ])
    from benchmark import ACTION_MAP
    metadata = job["metadata"]
    label_names = job["label_names"]
    for i in range(len(preds)):
        cls_idx = preds[i].item()
        label = SurrogateIDS.CLASS_NAMES[cls_idx] if cls_idx < len(SurrogateIDS.CLASS_NAMES) else f"class_{cls_idx}"
        sev = SurrogateIDS.severity_for(label)
        writer.writerow([
            i,
            str(metadata["src_ip"].iloc[i]) if "src_ip" in metadata.columns else "",
            str(metadata["dst_ip"].iloc[i]) if "dst_ip" in metadata.columns else "",
            label,
            label_names[i] if label_names else "",
            round(float(confs[i]), 4),
            sev,
            ACTION_MAP.get(sev, {}).get("action", "MONITOR"),
        ])

    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=robustidps_results_{job_id}.csv"},
    )


@app.websocket("/ws/stream")
async def stream(ws: WebSocket):
    await ws.accept()
    try:
        # Wait for file data (client sends JSON with base64 or job_id)
        init = await ws.receive_text()
        msg = json.loads(init)
        job_id = msg.get("job_id")
        rate = float(msg.get("rate", 100))  # flows/sec

        if job_id not in job_store:
            await ws.send_json({"error": "job not found"})
            await ws.close()
            return

        job = job_store[job_id]
        features = job["features"].to(DEVICE)
        metadata = job["metadata"]
        label_names = job["label_names"]

        model.eval()
        delay = 1.0 / rate if rate > 0 else 0.01

        with torch.no_grad():
            for i in range(len(features)):
                row_feat = features[i : i + 1]
                logits = model(row_feat)
                probs = torch.softmax(logits, dim=-1)
                cls_idx = probs.argmax(-1).item()
                conf = probs.max(-1).values.item()
                label_pred = SurrogateIDS.CLASS_NAMES[cls_idx] if cls_idx < len(SurrogateIDS.CLASS_NAMES) else f"class_{cls_idx}"
                true_label = label_names[i] if label_names else None

                await ws.send_json({
                    "flow_id": i,
                    "src_ip": str(metadata["src_ip"].iloc[i]) if "src_ip" in metadata.columns else "",
                    "dst_ip": str(metadata["dst_ip"].iloc[i]) if "dst_ip" in metadata.columns else "",
                    "label_predicted": label_pred,
                    "label_true": true_label,
                    "confidence": round(conf, 4),
                    "severity": SurrogateIDS.severity_for(label_pred),
                })
                await asyncio.sleep(delay)

        await ws.send_json({"done": True})
    except WebSocketDisconnect:
        pass
