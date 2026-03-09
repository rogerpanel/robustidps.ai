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
  GET    /metrics                 Prometheus metrics
  POST   /api/auth/register       Register new account
  POST   /api/auth/login          Login, returns JWT
  GET    /api/auth/me             Current user info
  GET    /api/audit/logs          Audit trail (admin)
  POST   /api/firewall/generate   Generate firewall rules
  POST   /api/models/benchmark    Quick benchmark across enabled models
  POST   /api/redteam/run         Adversarial Red Team Arena
  GET    /api/redteam/attacks     List available attacks
  POST   /api/xai/run             Explainability Studio
  POST   /api/federated/run       Federated Learning Simulator
  GET    /api/pq/algorithms       PQ Cryptography algorithm catalogue
  POST   /api/pq/benchmark        PQ algorithm benchmark
  GET    /api/pq/risk-assessment  Quantum risk assessment
  POST   /api/pq/simulate-handshake  PQ key exchange simulation
  GET    /api/pq/comparison-matrix   PQ algorithm comparison
  POST   /api/pq/migration-assessment  PQ migration readiness
  GET    /api/zerotrust/trust-score     Zero-Trust score
  GET    /api/zerotrust/policies        Governance policies
  GET    /api/zerotrust/compliance      Compliance dashboard
  GET    /api/zerotrust/model-provenance  Model integrity
  GET    /api/zerotrust/access-analytics  Access analytics (admin)
  GET    /api/zerotrust/verification-status  Continuous verification
  GET    /api/threat-response/playbooks     Response playbooks
  POST   /api/threat-response/simulate      Simulate threat response
  GET    /api/threat-response/incidents      Incident timeline
  GET    /api/threat-response/integrations   Security integrations
  GET    /api/threat-response/response-metrics  Response metrics
  GET    /api/datasets                          List available datasets
  GET    /api/datasets/{name}/info              Dataset metadata
  POST   /api/datasets/upload                   Upload custom dataset
  DELETE /api/datasets/{name}                   Remove dataset
  POST   /api/datasets/{name}/predict           Predict on stored dataset
  POST   /api/datasets/{name}/compare           Branch ablation comparison
"""

import asyncio
import io
import json
import logging
import os
import uuid
from pathlib import Path

import torch
import torch.nn as nn
import numpy as np
from fastapi import (
    FastAPI, UploadFile, File, Form, WebSocket, WebSocketDisconnect,
    Depends, HTTPException, Request,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from config import (
    CORS_ORIGINS, DEVICE, MC_PASSES, MAX_ROWS,
    RATE_LIMIT_DEFAULT, RATE_LIMIT_HEAVY, MAX_UPLOAD_SIZE_MB,
    ALLOWED_EXTENSIONS,
)
from models.surrogate import SurrogateIDS
from models.model_registry import list_models, load_model as registry_load, MODEL_INFO
from features import extract_features
from uncertainty import predict_with_uncertainty
from ablation import run_ablation
from benchmark import get_analytics_payload
from database import init_db, get_db, SessionLocal, Job, AuditLog
from auth import (
    router as auth_router, get_current_user, require_auth, require_role,
    ensure_default_admin,
)
from audit import AuditMiddleware, log_audit
from firewall import router as firewall_router
from copilot import router as copilot_router
from continual import ContinualLearningEngine
from redteam import run_arena, ATTACKS as REDTEAM_ATTACKS
from explainability import run_explainability
from federated import simulate_federated
from pq_crypto import router as pq_router
from zerotrust import router as zerotrust_router
from threat_response import router as threat_response_router
from supply_chain import router as supply_chain_router
from datasets import router as datasets_router

# ── Logging ───────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("robustidps")

# ── Rate Limiter ──────────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)

# ── Application ───────────────────────────────────────────────────────────

WEIGHTS_DIR = Path(__file__).parent / "weights"

app = FastAPI(
    title="RobustIDPS.ai",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS (hardened) ───────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# ── Request ID Middleware (security tracing) ────────────────────────────

from starlette.middleware.base import BaseHTTPMiddleware

class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach a unique request ID to every response for audit tracing."""
    async def dispatch(self, request, call_next):
        request_id = request.headers.get("X-Request-ID", uuid.uuid4().hex[:16])
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

app.add_middleware(RequestIdMiddleware)

# ── Audit Middleware ──────────────────────────────────────────────────────

app.add_middleware(AuditMiddleware)

# ── Prometheus Metrics ────────────────────────────────────────────────────

try:
    from prometheus_fastapi_instrumentator import Instrumentator
    Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        excluded_handlers=["/metrics", "/api/health"],
    ).instrument(app).expose(app, endpoint="/metrics")
    logger.info("Prometheus metrics enabled at /metrics")
except ImportError:
    logger.warning("prometheus-fastapi-instrumentator not installed — metrics disabled")

# ── Include routers ───────────────────────────────────────────────────────

app.include_router(auth_router)
app.include_router(firewall_router)
app.include_router(copilot_router)
app.include_router(pq_router)
app.include_router(zerotrust_router)
app.include_router(threat_response_router)
app.include_router(supply_chain_router)
app.include_router(datasets_router)

# ── Model loading ─────────────────────────────────────────────────────────

model: SurrogateIDS | None = None
loaded_models: dict = {}
active_model_id: str = "surrogate"
enabled_models: set = {"surrogate"}  # models available for selection in Upload
custom_models: dict = {}  # user-uploaded models: {model_id: {"path": ..., "user_id": ..., "name": ...}}
job_store: dict = {}
cl_engine: ContinualLearningEngine | None = None  # continual learning engine

CUSTOM_MODELS_DIR = Path(__file__).parent / "custom_models"
CUSTOM_MODELS_DIR.mkdir(exist_ok=True)
CHECKPOINTS_DIR = Path(__file__).parent / "checkpoints"
CHECKPOINTS_DIR.mkdir(exist_ok=True)


def _load_model() -> SurrogateIDS:
    m = SurrogateIDS(dropout=0.05)
    weight_path = WEIGHTS_DIR / "surrogate.pt"
    if weight_path.exists():
        state = torch.load(weight_path, map_location=DEVICE, weights_only=True)
        m.load_state_dict(state)
    m.to(DEVICE)
    m.eval()
    return m


def get_model(model_id: str | None = None):
    global active_model_id
    mid = model_id or active_model_id
    if mid == "surrogate":
        return model
    if mid not in loaded_models:
        try:
            # Check custom models first
            if mid in custom_models:
                path = Path(custom_models[mid]["path"])
                state_dict = torch.load(path, map_location=DEVICE, weights_only=True)
                custom_model = _build_custom_model(state_dict)
                custom_model.load_state_dict(state_dict)
                custom_model.to(DEVICE)
                custom_model.eval()
                loaded_models[mid] = custom_model
            else:
                loaded_models[mid] = registry_load(mid, device=DEVICE, dropout=0.05)
        except Exception:
            return model
    return loaded_models[mid]


# ── Startup ───────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    global model
    # Initialise database
    try:
        init_db()
        db = SessionLocal()
        try:
            ensure_default_admin(db)
        finally:
            db.close()
        logger.info("Database initialised")
    except Exception:
        logger.exception("Database initialisation failed — continuing without DB")

    # Load model
    model = _load_model()
    loaded_models["surrogate"] = model
    logger.info("Model loaded: SurrogateIDS (%d classes, %d branches)",
                SurrogateIDS.N_CLASSES, SurrogateIDS.N_BRANCHES)

    # Initialise continual learning engine
    global cl_engine
    cl_engine = ContinualLearningEngine(
        model, device=DEVICE, checkpoint_dir=CHECKPOINTS_DIR, max_replay=5000,
    )
    if cl_engine.load_checkpoint():
        logger.info("Continual learning state restored (version %d)", cl_engine.state.version)
    else:
        logger.info("Continual learning engine initialised (no prior checkpoint)")


# ── Input validation ─────────────────────────────────────────────────────

def _validate_upload(file: UploadFile) -> None:
    """Validate uploaded file: extension and size."""
    filename = (file.filename or "").lower()
    ext = Path(filename).suffix
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed: {', '.join(ALLOWED_EXTENSIONS)}",
        )
    # Check content-length header if available
    if file.size and file.size > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum: {MAX_UPLOAD_SIZE_MB}MB",
        )


# ── Helpers ───────────────────────────────────────────────────────────────

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

    n_threats = sum(1 for r in rows if r["severity"] != "benign")
    n_benign = len(rows) - n_threats

    attack_dist: dict = {}
    for r in rows:
        attack_dist[r["label_predicted"]] = attack_dist.get(r["label_predicted"], 0) + 1

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


# ── Public endpoints ──────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "model_loaded": model is not None}


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


@app.get("/api/models")
async def get_available_models():
    models = list_models()
    # Add enabled status to each model
    for m in models:
        m["enabled"] = m["id"] in enabled_models
    # Append custom models
    for cid, cinfo in custom_models.items():
        models.append({
            "id": cid,
            "name": cinfo["name"],
            "description": f"Custom model uploaded by user",
            "paper": "User-uploaded model",
            "has_ablation": False,
            "category": "custom",
            "weights_available": True,
            "enabled": cid in enabled_models,
            "custom": True,
            "uploaded_by": cinfo.get("user_email", ""),
        })
    return {"models": models, "active_model": active_model_id, "enabled_models": list(enabled_models)}


@app.get("/api/analytics")
async def analytics():
    return get_analytics_payload()


# ── Authenticated endpoints ───────────────────────────────────────────────

@app.post("/api/models/{model_id}/activate")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def activate_model(
    request: Request,
    model_id: str,
    user=Depends(require_auth),
):
    global active_model_id
    if model_id not in MODEL_INFO and model_id not in custom_models:
        return JSONResponse({"error": f"Unknown model: {model_id}"}, status_code=400)
    active_model_id = model_id
    _ = get_model(model_id)
    logger.info("Model switched to %s by %s", model_id, user.email)
    return {"active_model": active_model_id, "enabled_models": list(enabled_models)}


@app.post("/api/models/{model_id}/enable")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def enable_model(
    request: Request,
    model_id: str,
    user=Depends(require_auth),
):
    """Enable a model so it appears in the Upload & Analyse model selector."""
    if model_id not in MODEL_INFO and model_id not in custom_models:
        return JSONResponse({"error": f"Unknown model: {model_id}"}, status_code=400)
    enabled_models.add(model_id)
    # Pre-load the model
    _ = get_model(model_id)
    logger.info("Model %s enabled by %s", model_id, user.email)
    return {"enabled_models": list(enabled_models)}


@app.post("/api/models/{model_id}/disable")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def disable_model(
    request: Request,
    model_id: str,
    user=Depends(require_auth),
):
    """Disable a model from the Upload & Analyse model selector."""
    global active_model_id
    if model_id == "surrogate":
        return JSONResponse({"error": "Cannot disable the default surrogate model"}, status_code=400)
    enabled_models.discard(model_id)
    # If the disabled model was the active default, reset to surrogate
    if active_model_id == model_id:
        active_model_id = "surrogate"
    logger.info("Model %s disabled by %s", model_id, user.email)
    return {"enabled_models": list(enabled_models)}


@app.post("/api/upload")
@limiter.limit(RATE_LIMIT_HEAVY)
async def upload(
    request: Request,
    file: UploadFile = File(...),
    user=Depends(require_auth),
    db=Depends(get_db),
):
    _validate_upload(file)
    data = await file.read()
    if len(data) > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File too large. Maximum: {MAX_UPLOAD_SIZE_MB}MB")

    features, metadata, labels_encoded, label_names, fmt = extract_features(data, file.filename or "upload.csv")
    job_id = str(uuid.uuid4())[:8]
    job_store[job_id] = {
        "features": features,
        "metadata": metadata,
        "labels_encoded": labels_encoded,
        "label_names": label_names,
    }

    # Persist job metadata to DB
    db_job = Job(
        id=job_id,
        user_id=user.id,
        filename=file.filename,
        format_detected=fmt,
        n_flows=len(features),
        model_used=active_model_id,
    )
    db.add(db_job)
    db.commit()

    return {"job_id": job_id, "n_flows": len(features)}


@app.get("/api/results/{job_id}")
@limiter.limit(RATE_LIMIT_HEAVY)
async def get_results(
    request: Request,
    job_id: str,
    user=Depends(require_auth),
):
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
@limiter.limit(RATE_LIMIT_HEAVY)
async def predict(
    request: Request,
    file: UploadFile = File(...),
    user=Depends(require_auth),
):
    _validate_upload(file)
    data = await file.read()
    if len(data) > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File too large. Maximum: {MAX_UPLOAD_SIZE_MB}MB")

    features, metadata, labels_encoded, label_names, fmt = extract_features(data, file.filename or "upload.csv")
    result = predict_with_uncertainty(
        model, features.to(DEVICE),
        labels=labels_encoded.to(DEVICE) if labels_encoded is not None else None,
        n_mc=MC_PASSES,
    )
    payload = _build_predictions(features, metadata, labels_encoded, label_names, result)
    payload["job_id"] = str(uuid.uuid4())[:8]
    return payload


@app.post("/api/predict_uncertain")
@limiter.limit(RATE_LIMIT_HEAVY)
async def predict_uncertain(
    request: Request,
    file: UploadFile = File(...),
    mc_passes: int = Form(default=20),
    model_name: str = Form(default=""),
    user=Depends(get_current_user),
    db=Depends(get_db),
):
    _validate_upload(file)
    data = await file.read()
    if len(data) > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File too large. Maximum: {MAX_UPLOAD_SIZE_MB}MB")

    features, metadata, labels_encoded, label_names, fmt = extract_features(data, file.filename or "upload.csv")

    total_rows = len(features)
    sampled = False
    if total_rows > MAX_ROWS:
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
    job_id = str(uuid.uuid4())[:8]
    payload["job_id"] = job_id
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

    # Store for streaming / export / firewall generation
    job_store[job_id] = {
        "features": features,
        "metadata": metadata,
        "labels_encoded": labels_encoded,
        "label_names": label_names,
        "_model_ref": selected,
    }

    # Persist job to DB
    db_job = Job(
        id=job_id,
        user_id=user.id if user else None,
        filename=file.filename,
        format_detected=fmt,
        n_flows=total_rows,
        n_threats=payload["n_threats"],
        model_used=payload["model_used"],
    )
    db.add(db_job)
    db.commit()

    return payload


@app.post("/api/ablation")
@limiter.limit(RATE_LIMIT_HEAVY)
async def ablation_endpoint(
    request: Request,
    file: UploadFile = File(...),
    disabled_branches: str = Form(default="[]"),
    model_name: str = Form(default=""),
    user=Depends(require_auth),
):
    _validate_upload(file)
    data = await file.read()
    features, metadata, labels_encoded, label_names, fmt = extract_features(data, file.filename or "upload.csv")

    disabled = set(json.loads(disabled_branches))
    selected = get_model(model_name if model_name else None)

    if hasattr(selected, 'N_BRANCHES') and selected.N_BRANCHES == 7:
        ablation_result = run_ablation(
            selected, features.to(DEVICE),
            labels=labels_encoded.to(DEVICE) if labels_encoded is not None else None,
        )
        single = ablation_result["single"]
        pairwise = ablation_result["pairwise"]
        incremental = ablation_result["incremental"]
    else:
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


@app.post("/api/models/benchmark")
@limiter.limit(RATE_LIMIT_HEAVY)
async def benchmark_models(
    request: Request,
    user=Depends(require_auth),
):
    """
    Run a quick benchmark across all enabled models using synthetic test data.
    No dataset upload needed — generates random feature vectors and measures
    inference speed and prediction distribution for each model.
    """
    import time as _time

    n_samples = 200
    test_features = torch.randn(n_samples, SurrogateIDS.N_FEATURES).to(DEVICE)

    results = []
    for mid in sorted(enabled_models):
        try:
            m = get_model(mid)
            m.eval()
            # Warm-up run
            with torch.no_grad():
                _ = m(test_features[:1])

            # Timed inference
            start = _time.perf_counter()
            with torch.no_grad():
                logits = m(test_features)
            elapsed = _time.perf_counter() - start

            probs = torch.softmax(logits, dim=-1)
            preds = probs.argmax(-1).cpu()
            confidence = probs.max(-1).values.cpu()

            # Class distribution
            class_counts: dict = {}
            for idx in preds.tolist():
                label = SurrogateIDS.CLASS_NAMES[idx] if idx < len(SurrogateIDS.CLASS_NAMES) else f"class_{idx}"
                class_counts[label] = class_counts.get(label, 0) + 1

            # Top 5 predictions
            top5 = sorted(class_counts.items(), key=lambda x: -x[1])[:5]

            # Threat rate (non-Benign)
            benign_count = class_counts.get("Benign", 0)
            threat_rate = round(1.0 - benign_count / max(n_samples, 1), 4)

            info = MODEL_INFO.get(mid, {})
            results.append({
                "model_id": mid,
                "model_name": info.get("name", mid),
                "category": info.get("category", "custom"),
                "inference_ms": round(elapsed * 1000, 1),
                "throughput": round(n_samples / max(elapsed, 0.001)),
                "mean_confidence": round(confidence.mean().item(), 4),
                "std_confidence": round(confidence.std().item(), 4),
                "threat_rate": threat_rate,
                "n_classes_predicted": len(class_counts),
                "top_predictions": [{"label": l, "count": c} for l, c in top5],
                "class_distribution": class_counts,
            })
        except Exception as e:
            logger.warning("Benchmark failed for %s: %s", mid, e)
            info = MODEL_INFO.get(mid, {})
            results.append({
                "model_id": mid,
                "model_name": info.get("name", mid),
                "category": info.get("category", "custom"),
                "error": str(e),
            })

    return {
        "n_samples": n_samples,
        "device": str(DEVICE),
        "results": results,
        "active_model": active_model_id,
    }


@app.delete("/api/jobs/{job_id}")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def delete_job(
    request: Request,
    job_id: str,
    user=Depends(require_auth),
    db=Depends(get_db),
):
    """Delete a job: removes from memory, DB (cascades firewall rules), and frees resources."""
    # Remove from in-memory store
    job_store.pop(job_id, None)

    # Remove from DB (firewall rules cascade via relationship)
    from database import FirewallRule
    db_job = db.get(Job, job_id)
    if not db_job:
        return JSONResponse({"error": "Job not found"}, status_code=404)

    # Only allow owner or admin to delete
    if db_job.user_id and db_job.user_id != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorised to delete this job")

    # Delete related firewall rules first
    db.query(FirewallRule).filter(FirewallRule.job_id == job_id).delete()
    db.delete(db_job)
    db.commit()

    logger.info("Job %s deleted by %s", job_id, user.email)
    return {"deleted": job_id}


# ── Custom Model Upload ──────────────────────────────────────────────────

@app.post("/api/models/custom/upload")
@limiter.limit(RATE_LIMIT_HEAVY)
async def upload_custom_model(
    request: Request,
    file: UploadFile = File(...),
    model_name: str = Form(default=""),
    user=Depends(require_auth),
):
    """Upload a custom PyTorch model (.pt/.pth) for testing.
    Model must accept [batch, 83] input and output [batch, 34] logits.
    """
    filename = (file.filename or "").lower()
    if not filename.endswith((".pt", ".pth")):
        raise HTTPException(status_code=400, detail="Only .pt or .pth PyTorch model files are accepted")

    data = await file.read()
    if len(data) > 200 * 1024 * 1024:  # 200MB limit
        raise HTTPException(status_code=413, detail="Model file too large. Maximum: 200MB")

    # Save to temp file first for validation
    model_id = f"custom_{str(uuid.uuid4())[:8]}"
    save_path = CUSTOM_MODELS_DIR / f"{model_id}.pt"
    save_path.write_bytes(data)

    # Validate: try loading and running a forward pass
    try:
        state_dict = torch.load(save_path, map_location="cpu", weights_only=True)

        # Try to infer architecture from state dict
        custom_model = _build_custom_model(state_dict)
        custom_model.load_state_dict(state_dict)
        custom_model.eval()

        # Test forward pass with dummy input
        with torch.no_grad():
            test_input = torch.randn(2, SurrogateIDS.N_FEATURES)
            output = custom_model(test_input)
            if output.shape[-1] != SurrogateIDS.N_CLASSES:
                raise ValueError(
                    f"Model output has {output.shape[-1]} classes, expected {SurrogateIDS.N_CLASSES}"
                )

        custom_model.to(DEVICE)
        loaded_models[model_id] = custom_model
        enabled_models.add(model_id)

    except Exception as e:
        save_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=400,
            detail=f"Invalid model: {str(e)}. Model must be a PyTorch state_dict with input_dim=83, output_dim=34.",
        )

    name = model_name or file.filename or model_id
    custom_models[model_id] = {
        "name": name,
        "path": str(save_path),
        "user_id": user.id,
        "user_email": user.email,
        "filename": file.filename,
    }

    logger.info("Custom model '%s' uploaded by %s as %s", name, user.email, model_id)
    return {
        "model_id": model_id,
        "name": name,
        "message": f"Model '{name}' uploaded and validated successfully. Available in Upload & Analyse.",
    }


@app.delete("/api/models/custom/{model_id}")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def delete_custom_model(
    request: Request,
    model_id: str,
    user=Depends(require_auth),
):
    """Delete a custom uploaded model and free resources."""
    if model_id not in custom_models:
        return JSONResponse({"error": "Custom model not found"}, status_code=404)

    info = custom_models[model_id]
    # Only owner or admin can delete
    if info["user_id"] != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorised to delete this model")

    # Clean up
    global active_model_id
    loaded_models.pop(model_id, None)
    enabled_models.discard(model_id)
    if active_model_id == model_id:
        active_model_id = "surrogate"

    # Delete file
    path = Path(info["path"])
    path.unlink(missing_ok=True)

    del custom_models[model_id]
    logger.info("Custom model %s deleted by %s", model_id, user.email)
    return {"deleted": model_id}


def _build_custom_model(state_dict: dict) -> nn.Module:
    """Infer a simple sequential model architecture from a state dict."""
    # Analyse the state dict to reconstruct layers
    layers = []
    layer_keys = sorted(state_dict.keys())

    # Group by layer index
    weight_shapes = {}
    for key in layer_keys:
        parts = key.split(".")
        # Handle both "0.weight", "layers.0.weight", etc.
        for i, p in enumerate(parts):
            if p == "weight" and i > 0:
                layer_name = ".".join(parts[:i])
                weight_shapes[layer_name] = ("weight", state_dict[key].shape)
            elif p == "bias" and i > 0:
                layer_name = ".".join(parts[:i])
                if layer_name not in weight_shapes:
                    weight_shapes[layer_name] = ("bias", state_dict[key].shape)

    # Build sequential model from detected linear layers
    layer_list = []
    for key in sorted(weight_shapes.keys()):
        kind, shape = weight_shapes[key]
        if kind == "weight" and len(shape) == 2:
            out_dim, in_dim = shape
            layer_list.append(nn.Linear(in_dim, out_dim))
            # Add ReLU between hidden layers (not after last)
            layer_list.append(nn.ReLU())

    # Remove last ReLU (output layer shouldn't have activation)
    if layer_list and isinstance(layer_list[-1], nn.ReLU):
        layer_list.pop()

    if not layer_list:
        raise ValueError("Could not reconstruct model architecture from state dict")

    model = nn.Sequential(*layer_list)

    # Remap state dict keys to sequential indices
    new_state = {}
    linear_idx = 0
    seq_idx = 0
    for layer in model:
        if isinstance(layer, nn.Linear):
            # Find original keys for this linear layer
            orig_keys = [k for k in layer_keys if "weight" in k or "bias" in k]
            weight_key = None
            bias_key = None
            for k in layer_keys:
                if k.endswith(".weight") and state_dict[k].shape == layer.weight.shape:
                    if k not in [v for v in new_state.values()]:
                        weight_key = k
                        break
            for k in layer_keys:
                if k.endswith(".bias") and state_dict[k].shape == layer.bias.shape:
                    if k not in [v for v in new_state.values()]:
                        bias_key = k
                        break
            if weight_key:
                new_state[f"{seq_idx}.weight"] = state_dict[weight_key]
                layer_keys.remove(weight_key)
            if bias_key:
                new_state[f"{seq_idx}.bias"] = state_dict[bias_key]
                layer_keys.remove(bias_key)
            linear_idx += 1
        seq_idx += 1

    # If remapping worked, update the state dict
    if new_state:
        state_dict.clear()
        state_dict.update(new_state)

    return model


@app.get("/api/export/{job_id}")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def export_results(
    request: Request,
    job_id: str,
    user=Depends(require_auth),
):
    if job_id not in job_store:
        return JSONResponse({"error": "job not found"}, status_code=404)
    job = job_store[job_id]

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


# ── Audit log endpoint (admin) ────────────────────────────────────────────

@app.get("/api/audit/logs")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_audit_logs(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    admin=Depends(require_role("admin")),
    db=Depends(get_db),
):
    """Retrieve audit logs (admin only)."""
    from sqlalchemy import select, func
    total = db.execute(select(func.count(AuditLog.id))).scalar()
    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .offset(offset)
        .limit(min(limit, 500))
        .all()
    )
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "logs": [
            {
                "id": l.id,
                "user_id": l.user_id,
                "action": l.action,
                "resource": l.resource,
                "details": l.details,
                "ip_address": l.ip_address,
                "timestamp": l.timestamp.isoformat() if l.timestamp else None,
            }
            for l in logs
        ],
    }


# ── Continual Learning ────────────────────────────────────────────────────

@app.get("/api/continual/status")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def continual_status(request: Request, user=Depends(require_auth)):
    """Return the current continual learning engine status."""
    if cl_engine is None:
        return JSONResponse({"error": "Continual learning engine not initialised"}, status_code=503)
    return cl_engine.get_status()


@app.post("/api/continual/update")
@limiter.limit(RATE_LIMIT_HEAVY)
async def continual_update(
    request: Request,
    file: UploadFile = File(...),
    epochs: int = Form(default=5),
    lr: float = Form(default=1e-4),
    ewc_lambda: float = Form(default=5000.0),
    user=Depends(require_auth),
):
    """Incrementally update the model on new traffic data using EWC."""
    if cl_engine is None:
        return JSONResponse({"error": "Continual learning engine not initialised"}, status_code=503)

    _validate_upload(file)
    data = await file.read()
    if len(data) > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File too large. Maximum: {MAX_UPLOAD_SIZE_MB}MB")

    features, metadata, labels_encoded, label_names, fmt = extract_features(data, file.filename or "update.csv")

    if labels_encoded is None:
        raise HTTPException(
            status_code=400,
            detail="Labelled data required for continual learning. Upload a dataset with ground-truth labels.",
        )

    # Cap dataset for training
    if len(features) > MAX_ROWS:
        idx = torch.randperm(len(features))[:MAX_ROWS].sort().values
        features = features[idx]
        labels_encoded = labels_encoded[idx]

    record = cl_engine.update(
        features, labels_encoded,
        epochs=epochs, lr=lr, ewc_lambda=ewc_lambda,
        dataset_format=fmt,
    )

    logger.info("Continual update by %s: %s (acc %.4f → %.4f)",
                user.email, record.update_id, record.acc_before, record.acc_after)

    return {
        "update_id": record.update_id,
        "version": cl_engine.state.version,
        "acc_before": record.acc_before,
        "acc_after": record.acc_after,
        "loss_before": record.loss_before,
        "loss_after": record.loss_after,
        "n_samples": record.n_samples,
        "epochs": record.epochs,
        "ewc_lambda": record.ewc_lambda,
        "replay_size": record.replay_size,
        "message": f"Model updated to version {cl_engine.state.version}. Accuracy: {record.acc_before:.2%} → {record.acc_after:.2%}",
    }


@app.post("/api/continual/drift")
@limiter.limit(RATE_LIMIT_HEAVY)
async def continual_drift(
    request: Request,
    file: UploadFile = File(...),
    user=Depends(require_auth),
):
    """Measure distribution drift on new data without updating the model."""
    if cl_engine is None:
        return JSONResponse({"error": "Continual learning engine not initialised"}, status_code=503)

    _validate_upload(file)
    data = await file.read()
    features, metadata, labels_encoded, label_names, fmt = extract_features(data, file.filename or "drift.csv")

    if labels_encoded is None:
        raise HTTPException(status_code=400, detail="Labelled data required for drift measurement.")

    if len(features) > MAX_ROWS:
        idx = torch.randperm(len(features))[:MAX_ROWS].sort().values
        features = features[idx]
        labels_encoded = labels_encoded[idx]

    result = cl_engine.measure_drift(features, labels_encoded)
    result["dataset_format"] = fmt
    return result


@app.post("/api/continual/rollback")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def continual_rollback(request: Request, user=Depends(require_auth)):
    """Rollback the model to the state before the last update."""
    if cl_engine is None:
        return JSONResponse({"error": "Continual learning engine not initialised"}, status_code=503)

    success = cl_engine.rollback()
    if not success:
        return JSONResponse({"error": "No previous state available to rollback to"}, status_code=400)

    logger.info("Continual rollback by %s → version %d", user.email, cl_engine.state.version)
    return {
        "version": cl_engine.state.version,
        "message": f"Model rolled back to version {cl_engine.state.version}",
    }


# ── Sample Data ──────────────────────────────────────────────────────────

@app.get("/api/sample-data")
async def get_sample_data(dataset: str = "ciciot"):
    """Serve built-in sample CSV for demo operations.
    dataset: 'ciciot' (default) or 'pqc' for PQC test dataset.
    """
    if dataset == "pqc":
        filename = "pqc_test_dataset.csv"
    else:
        filename = "ciciot_sample.csv"

    sample_path = Path(__file__).parent / "sample_data" / filename
    if not sample_path.exists():
        sample_path = Path(__file__).parent.parent / "sample_data" / filename
    if not sample_path.exists():
        raise HTTPException(404, f"Sample data file '{filename}' not found")
    return FileResponse(
        sample_path,
        media_type="text/csv",
        filename=filename,
    )


def _find_sample_dir() -> Path:
    """Locate sample_data directory (works both locally and in Docker)."""
    # Docker volume mount: /app/sample_data
    d = Path(__file__).parent / "sample_data"
    if d.is_dir():
        return d
    # Local dev: ../sample_data relative to backend/
    d = Path(__file__).parent.parent / "sample_data"
    if d.is_dir():
        return d
    return d  # fallback


_adversarial_pcap_path: Path | None = None


def _ensure_adversarial_pcap() -> Path:
    """Return path to adversarial benchmark PCAP, generating it if needed."""
    global _adversarial_pcap_path
    if _adversarial_pcap_path and _adversarial_pcap_path.exists():
        return _adversarial_pcap_path

    sample_dir = _find_sample_dir()
    out = sample_dir / "adversarial_benchmark.pcap"
    if not out.exists():
        import sys as _sys
        gen_dir = str(sample_dir)
        if gen_dir not in _sys.path:
            _sys.path.insert(0, gen_dir)
        from generate_adversarial_pcap import generate_pcap
        generate_pcap(str(out), 500)

    _adversarial_pcap_path = out
    return out


@app.get("/api/sample-data/adversarial-benchmark.pcap")
async def download_adversarial_benchmark():
    """Download pre-generated adversarial benchmark PCAP (~10 MB).
    Contains all 34 attack classes, PQ-TLS handshakes, adversarial ML flows,
    and banking/government attack scenarios.
    """
    loop = asyncio.get_event_loop()
    pcap_path = await loop.run_in_executor(None, _ensure_adversarial_pcap)
    return FileResponse(
        pcap_path,
        media_type="application/vnd.tcpdump.pcap",
        filename="adversarial_benchmark.pcap",
    )


# ── Adversarial Red Team Arena ─────────────────────────────────────────────

@app.get("/api/redteam/attacks")
async def redteam_attacks():
    """List available adversarial attacks."""
    return {
        "attacks": [
            {"id": k, "label": v["label"], "needs_grad": v["needs_grad"]}
            for k, v in REDTEAM_ATTACKS.items()
        ],
    }


# In-memory store for long-running background jobs (avoids Cloudflare 524 timeout)
_bg_jobs: dict = {}


@app.post("/api/redteam/run")
@limiter.limit(RATE_LIMIT_HEAVY)
async def redteam_run(
    request: Request,
    file: UploadFile = File(...),
    attacks: str = Form(default="[]"),
    epsilon: float = Form(default=0.1),
    n_samples: int = Form(default=500),
    model_name: str = Form(default=""),
    user=Depends(require_auth),
):
    """Start red-team arena as background job. Poll /api/job/status/{job_id}."""
    _validate_upload(file)
    data = await file.read()
    if len(data) > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File too large. Maximum: {MAX_UPLOAD_SIZE_MB}MB")

    filename = file.filename or "redteam.csv"
    selected = get_model(model_name if model_name else None)
    attack_list = json.loads(attacks) if attacks and attacks != "[]" else None
    job_id = str(uuid.uuid4())[:8]
    _bg_jobs[job_id] = {"status": "running", "result": None, "error": None}

    async def _run():
        try:
            features, metadata, labels_encoded, label_names, fmt = await asyncio.to_thread(
                extract_features, data, filename
            )
            result = await asyncio.to_thread(
                run_arena, selected, features,
                labels_encoded, attack_list, epsilon, min(n_samples, MAX_ROWS),
            )
            result["model_used"] = model_name if model_name else active_model_id
            result["dataset_format"] = fmt
            _bg_jobs[job_id] = {"status": "done", "result": result, "error": None}
            logger.info("Red team arena by %s: %d attacks, eps=%.3f (job %s)",
                        user.email, len(result["attacks"]), epsilon, job_id)
        except Exception as exc:
            logger.exception("Redteam job %s failed", job_id)
            _bg_jobs[job_id] = {"status": "error", "result": None, "error": str(exc)}

    asyncio.create_task(_run())
    return {"job_id": job_id, "status": "running"}


# ── Explainability Studio ─────────────────────────────────────────────────

@app.post("/api/xai/run")
@limiter.limit(RATE_LIMIT_HEAVY)
async def xai_run(
    request: Request,
    file: UploadFile = File(...),
    method: str = Form(default="all"),
    n_samples: int = Form(default=200),
    model_name: str = Form(default=""),
    user=Depends(require_auth),
):
    """Start XAI analysis as background job. Poll /api/job/status/{job_id}."""
    _validate_upload(file)
    data = await file.read()
    if len(data) > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File too large. Maximum: {MAX_UPLOAD_SIZE_MB}MB")

    filename = file.filename or "xai.csv"
    selected = get_model(model_name if model_name else None)
    job_id = str(uuid.uuid4())[:8]
    _bg_jobs[job_id] = {"status": "running", "result": None, "error": None}

    async def _run():
        try:
            features, metadata, labels_encoded, label_names, fmt = await asyncio.to_thread(
                extract_features, data, filename
            )
            result = await asyncio.to_thread(
                run_explainability, selected, features,
                labels_encoded, min(n_samples, MAX_ROWS), method,
            )
            result["model_used"] = model_name if model_name else active_model_id
            result["dataset_format"] = fmt
            _bg_jobs[job_id] = {"status": "done", "result": result, "error": None}
            logger.info("XAI analysis by %s: method=%s, %d samples (job %s)",
                        user.email, method, result["n_samples"], job_id)
        except Exception as exc:
            logger.exception("XAI job %s failed", job_id)
            _bg_jobs[job_id] = {"status": "error", "result": None, "error": str(exc)}

    asyncio.create_task(_run())
    return {"job_id": job_id, "status": "running"}


# ── Federated Learning Simulator ──────────────────────────────────────────


@app.post("/api/federated/run")
@limiter.limit(RATE_LIMIT_HEAVY)
async def federated_run(
    request: Request,
    file: UploadFile = File(...),
    n_nodes: int = Form(default=4),
    rounds: int = Form(default=5),
    local_epochs: int = Form(default=3),
    lr: float = Form(default=0.0001),
    strategy: str = Form(default="fedavg"),
    dp_enabled: bool = Form(default=False),
    dp_sigma: float = Form(default=0.01),
    iid: bool = Form(default=True),
    model_name: str = Form(default=""),
    user=Depends(require_auth),
):
    """Start federated learning simulation as a background job.

    Returns a job_id immediately. Poll /api/federated/status/{job_id}
    until status == 'done' to get results (avoids Cloudflare 524 timeout).
    """
    _validate_upload(file)
    data = await file.read()
    if len(data) > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File too large. Maximum: {MAX_UPLOAD_SIZE_MB}MB")

    filename = file.filename or "federated.csv"
    selected = get_model(model_name if model_name else None)
    job_id = str(uuid.uuid4())[:8]
    _bg_jobs[job_id] = {"status": "running", "result": None, "error": None}

    async def _run():
        try:
            features, metadata, labels_encoded, label_names, fmt = await asyncio.to_thread(
                extract_features, data, filename
            )
            result = await asyncio.to_thread(
                simulate_federated,
                selected, features,
                labels=labels_encoded,
                n_nodes=min(n_nodes, 6),
                rounds=min(rounds, 20),
                local_epochs=min(local_epochs, 10),
                lr=lr,
                strategy=strategy,
                dp_enabled=dp_enabled,
                dp_sigma=dp_sigma,
                iid=iid,
            )
            result["model_used"] = model_name if model_name else active_model_id
            result["dataset_format"] = fmt
            _bg_jobs[job_id] = {"status": "done", "result": result, "error": None}
            logger.info("Federated sim by %s: %d nodes, %d rounds, strategy=%s (job %s)",
                        user.email, n_nodes, rounds, strategy, job_id)
        except Exception as exc:
            logger.exception("Federated sim job %s failed", job_id)
            _bg_jobs[job_id] = {"status": "error", "result": None, "error": str(exc)}

    asyncio.create_task(_run())
    return {"job_id": job_id, "status": "running"}


# ── Unified background job status endpoint ────────────────────────────────

@app.get("/api/job/status/{job_id}")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def bg_job_status(
    request: Request,
    job_id: str,
    user=Depends(require_auth),
):
    """Poll background job status (used by redteam, xai, federated)."""
    job = _bg_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job["status"] == "done":
        result = job["result"]
        del _bg_jobs[job_id]
        return {"status": "done", "result": result}
    if job["status"] == "error":
        error = job["error"]
        del _bg_jobs[job_id]
        raise HTTPException(status_code=500, detail=error)
    return {"status": "running"}


# Keep old endpoint for backwards compatibility
@app.get("/api/federated/status/{job_id}")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def federated_status(request: Request, job_id: str, user=Depends(require_auth)):
    return await bg_job_status(request, job_id, user)


# ── WebSocket ─────────────────────────────────────────────────────────────

@app.websocket("/ws/stream")
async def stream(ws: WebSocket):
    await ws.accept()
    try:
        init = await ws.receive_text()
        msg = json.loads(init)
        job_id = msg.get("job_id")
        rate = float(msg.get("rate", 100))
        stream_model_name = msg.get("model_name", "")

        if job_id not in job_store:
            await ws.send_json({"error": "job not found"})
            await ws.close()
            return

        job = job_store[job_id]
        features = job["features"].to(DEVICE)
        metadata = job["metadata"]
        label_names = job["label_names"]

        # Use specified model or fall back to active model
        stream_model = get_model(stream_model_name if stream_model_name else None)
        stream_model.eval()
        delay = 1.0 / rate if rate > 0 else 0.01

        with torch.no_grad():
            for i in range(len(features)):
                row_feat = features[i : i + 1]
                logits = stream_model(row_feat)
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



# ── Live Network Capture ──────────────────────────────────────────────────

@app.websocket("/ws/live_capture")
async def live_capture(ws: WebSocket):
    """
    Continuous live network capture mode.
    Client sends: { "interface": "eth0", "interval": 30, "model_name": "" }
    Server captures on the interface for interval seconds via NFStream,
    classifies each flow, sends results, then repeats until disconnect.
    """
    await ws.accept()
    try:
        init = await ws.receive_text()
        msg = json.loads(init)
        iface = msg.get("interface", "eth0")
        interval = min(max(int(msg.get("interval", 30)), 5), 300)
        model_name = msg.get("model_name", "")

        active_model = model
        if model_name:
            try:
                active_model = registry_load(model_name, DEVICE)
            except Exception:
                active_model = model

        active_model.eval()
        cycle = 0

        await ws.send_json({
            "status": "started",
            "interface": iface,
            "interval": interval,
            "message": f"Capturing on {iface} every {interval}s",
        })

        while True:
            cycle += 1
            await ws.send_json({
                "status": "capturing",
                "cycle": cycle,
                "message": f"Cycle {cycle}: capturing {interval}s on {iface}...",
            })

            try:
                import time as _time
                from nfstream import NFStreamer
                streamer = NFStreamer(
                    source=iface,
                    statistical_analysis=True,
                    active_timeout=interval,
                    idle_timeout=interval,
                )
                flows = []
                start_t = _time.time()
                for flow in streamer:
                    flows.append(flow)
                    if _time.time() - start_t >= interval:
                        break
                del streamer

                if not flows:
                    await ws.send_json({
                        "status": "cycle_done", "cycle": cycle,
                        "flows_captured": 0,
                        "message": f"Cycle {cycle}: no flows captured",
                    })
                    await asyncio.sleep(2)
                    continue

                import pandas as pd
                records = []
                for f in flows:
                    records.append({
                        "src_ip": f.src_ip, "dst_ip": f.dst_ip,
                        "src_port": f.src_port, "dst_port": f.dst_port,
                        "protocol": f.protocol,
                        "bidirectional_packets": f.bidirectional_packets,
                        "bidirectional_bytes": f.bidirectional_bytes,
                        "bidirectional_duration_ms": f.bidirectional_duration_ms,
                        "src2dst_packets": f.src2dst_packets,
                        "src2dst_bytes": f.src2dst_bytes,
                        "dst2src_packets": f.dst2src_packets,
                        "dst2src_bytes": f.dst2src_bytes,
                    })
                df = pd.DataFrame(records)
                metadata = df[["src_ip", "dst_ip"]].copy()

                from features import build_feature_tensor
                features_t = build_feature_tensor(df).to(DEVICE)

                await ws.send_json({
                    "status": "analysing", "cycle": cycle,
                    "flows_captured": len(features_t),
                    "message": f"Cycle {cycle}: analysing {len(features_t)} flows...",
                })

                threats_in_cycle = 0
                with torch.no_grad():
                    for i in range(len(features_t)):
                        row = features_t[i:i+1]
                        logits = active_model(row)
                        probs = torch.softmax(logits, dim=-1)
                        cls_idx = probs.argmax(-1).item()
                        conf = probs.max(-1).values.item()
                        label = SurrogateIDS.CLASS_NAMES[cls_idx] if cls_idx < len(SurrogateIDS.CLASS_NAMES) else f"class_{cls_idx}"
                        sev = SurrogateIDS.severity_for(label)
                        if sev != "benign":
                            threats_in_cycle += 1

                        await ws.send_json({
                            "type": "flow", "cycle": cycle, "flow_id": i,
                            "src_ip": str(metadata.iloc[i]["src_ip"]),
                            "dst_ip": str(metadata.iloc[i]["dst_ip"]),
                            "label_predicted": label,
                            "confidence": round(conf, 4),
                            "severity": sev,
                        })

                await ws.send_json({
                    "status": "cycle_done", "cycle": cycle,
                    "flows_captured": len(features_t),
                    "threats_found": threats_in_cycle,
                    "message": f"Cycle {cycle} done: {len(features_t)} flows, {threats_in_cycle} threats",
                })

            except ImportError:
                await ws.send_json({
                    "status": "error",
                    "message": "NFStream not available. Live capture requires nfstream and libpcap.",
                })
                break
            except PermissionError:
                await ws.send_json({
                    "status": "error",
                    "message": f"Permission denied on {iface}. Container needs NET_ADMIN + NET_RAW capabilities.",
                })
                break
            except Exception as e:
                await ws.send_json({
                    "status": "error", "cycle": cycle,
                    "message": f"Capture error: {str(e)}",
                })
                await asyncio.sleep(5)

    except WebSocketDisconnect:
        pass
