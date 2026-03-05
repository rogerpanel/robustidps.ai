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
"""

import asyncio
import io
import json
import logging
import os
import uuid
from pathlib import Path

import torch
import numpy as np
from fastapi import (
    FastAPI, UploadFile, File, Form, WebSocket, WebSocketDisconnect,
    Depends, HTTPException, Request,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

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

# ── Model loading ─────────────────────────────────────────────────────────

model: SurrogateIDS | None = None
loaded_models: dict = {}
active_model_id: str = "surrogate"
job_store: dict = {}


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
    return {"models": list_models(), "active_model": active_model_id}


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
    if model_id not in MODEL_INFO:
        return JSONResponse({"error": f"Unknown model: {model_id}"}, status_code=400)
    active_model_id = model_id
    _ = get_model(model_id)
    logger.info("Model switched to %s by %s", model_id, user.email)
    return {"active_model": active_model_id}


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


# ── WebSocket ─────────────────────────────────────────────────────────────

@app.websocket("/ws/stream")
async def stream(ws: WebSocket):
    await ws.accept()
    try:
        init = await ws.receive_text()
        msg = json.loads(init)
        job_id = msg.get("job_id")
        rate = float(msg.get("rate", 100))

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
