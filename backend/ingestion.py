"""
Live PCAP / NetFlow / Zeek Ingestion Pipeline
===============================================

Provides:
  - POST /api/ingest/netflow  — Receive NetFlow v5/v9/IPFIX JSON records
  - POST /api/ingest/zeek     — Receive Zeek conn.log JSON records
  - POST /api/ingest/syslog   — Receive syslog/CEF events for classification
  - GET  /api/ingest/status   — Ingestion pipeline stats
  - WS   /ws/ingest           — WebSocket for streaming ingestion + real-time classification

Each record is converted to the 83-feature CIC-IoT format,
classified by the active model, and optionally forwarded to SIEM connectors.
"""

import datetime
import logging
import time
import uuid
from collections import deque
from typing import Optional

import numpy as np
import torch
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth import require_auth
from config import DEVICE
from database import get_db

logger = logging.getLogger("robustidps.ingestion")

router = APIRouter(prefix="/api/ingest", tags=["Ingestion"])


# ── Stats tracking ──────────────────────────────────────────────────────

class IngestionStats:
    def __init__(self):
        self.total_records = 0
        self.total_threats = 0
        self.records_per_source: dict[str, int] = {}
        self.threat_distribution: dict[str, int] = {}
        self.last_event_at: Optional[str] = None
        self.started_at = datetime.datetime.utcnow().isoformat()
        self._recent: deque = deque(maxlen=100)  # last 100 classified events

    def record(self, source: str, label: str, confidence: float, event: dict):
        self.total_records += 1
        self.records_per_source[source] = self.records_per_source.get(source, 0) + 1
        if label != "Benign":
            self.total_threats += 1
            self.threat_distribution[label] = self.threat_distribution.get(label, 0) + 1
        self.last_event_at = datetime.datetime.utcnow().isoformat()
        self._recent.append({
            "label": label,
            "confidence": round(confidence, 4),
            "source": source,
            "src_ip": event.get("src_ip"),
            "dst_ip": event.get("dst_ip"),
            "timestamp": self.last_event_at,
        })

    def to_dict(self) -> dict:
        return {
            "total_records": self.total_records,
            "total_threats": self.total_threats,
            "records_per_source": self.records_per_source,
            "threat_distribution": self.threat_distribution,
            "last_event_at": self.last_event_at,
            "started_at": self.started_at,
            "recent_events": list(self._recent)[-20:],
        }


_stats = IngestionStats()


# ── Feature conversion helpers ──────────────────────────────────────────

# Canonical 83-feature order (CIC-IoT-2023 compatible)
N_FEATURES = 83

def _netflow_to_features(record: dict) -> tuple[np.ndarray, dict]:
    """
    Convert a NetFlow/IPFIX JSON record to an 83-element feature vector.
    Maps common NetFlow fields to CIC-IoT feature positions.
    """
    features = np.zeros(N_FEATURES, dtype=np.float32)

    # Map NetFlow fields to feature positions (CIC-IoT-2023 ordering)
    features[0] = record.get("flow_duration", record.get("duration", 0))
    features[1] = record.get("fwd_pkts_tot", record.get("in_pkts", 0))
    features[2] = record.get("bwd_pkts_tot", record.get("out_pkts", 0))
    features[3] = record.get("fwd_data_pkts_tot", 0)
    features[4] = record.get("bwd_data_pkts_tot", 0)
    features[5] = record.get("fwd_pkts_per_sec", 0)
    features[6] = record.get("bwd_pkts_per_sec", 0)
    features[7] = record.get("flow_pkts_per_sec", 0)
    features[8] = record.get("down_up_ratio", 0)
    features[9] = record.get("fwd_header_size_tot", 0)
    features[10] = record.get("fwd_header_size_min", 0)
    features[11] = record.get("bwd_header_size_tot", 0)
    features[12] = record.get("bwd_header_size_min", 0)
    features[13] = record.get("flow_FIN_flag_count", record.get("tcp_flags_fin", 0))
    features[14] = record.get("flow_SYN_flag_count", record.get("tcp_flags_syn", 0))
    features[15] = record.get("flow_RST_flag_count", record.get("tcp_flags_rst", 0))
    features[16] = record.get("fwd_PSH_flag_count", record.get("tcp_flags_psh", 0))
    features[17] = record.get("fwd_URG_flag_count", record.get("tcp_flags_urg", 0))
    features[18] = record.get("fwd_pkts_payload.min", record.get("fwd_payload_min", 0))
    features[19] = record.get("fwd_pkts_payload.max", record.get("fwd_payload_max", 0))
    features[20] = record.get("fwd_pkts_payload.tot", record.get("in_bytes", 0))
    features[21] = record.get("fwd_pkts_payload.avg", record.get("fwd_payload_avg", 0))
    features[22] = record.get("fwd_pkts_payload.std", 0)
    features[23] = record.get("bwd_pkts_payload.min", record.get("bwd_payload_min", 0))
    features[24] = record.get("bwd_pkts_payload.max", record.get("bwd_payload_max", 0))
    features[25] = record.get("bwd_pkts_payload.tot", record.get("out_bytes", 0))
    features[26] = record.get("bwd_pkts_payload.avg", record.get("bwd_payload_avg", 0))
    features[27] = record.get("bwd_pkts_payload.std", 0)
    features[28] = record.get("flow_pkts_payload.min", 0)
    features[29] = record.get("flow_pkts_payload.max", 0)
    features[30] = record.get("flow_pkts_payload.tot", 0)
    features[31] = record.get("flow_pkts_payload.avg", 0)
    features[32] = record.get("flow_pkts_payload.std", 0)
    # Protocol encoding
    proto = record.get("protocol", record.get("proto", 6))
    features[40] = float(proto)

    # Metadata for response
    meta = {
        "src_ip": record.get("src_ip", record.get("src_addr", "")),
        "dst_ip": record.get("dst_ip", record.get("dst_addr", "")),
        "src_port": record.get("src_port", 0),
        "dst_port": record.get("dst_port", 0),
        "protocol": proto,
    }

    # Replace NaN/Inf
    features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)
    return features, meta


def _zeek_to_features(record: dict) -> tuple[np.ndarray, dict]:
    """Convert a Zeek conn.log JSON record to feature vector."""
    features = np.zeros(N_FEATURES, dtype=np.float32)

    duration = record.get("duration", 0) or 0
    features[0] = float(duration) * 1e6  # seconds to microseconds

    orig_pkts = record.get("orig_pkts", 0) or 0
    resp_pkts = record.get("resp_pkts", 0) or 0
    orig_bytes = record.get("orig_ip_bytes", record.get("orig_bytes", 0)) or 0
    resp_bytes = record.get("resp_ip_bytes", record.get("resp_bytes", 0)) or 0

    features[1] = orig_pkts
    features[2] = resp_pkts
    features[20] = orig_bytes
    features[25] = resp_bytes

    if duration > 0:
        features[5] = orig_pkts / duration
        features[6] = resp_pkts / duration
        features[7] = (orig_pkts + resp_pkts) / duration

    if orig_pkts > 0:
        features[21] = orig_bytes / orig_pkts
    if resp_pkts > 0:
        features[26] = resp_bytes / resp_pkts
    if resp_pkts > 0 and orig_pkts > 0:
        features[8] = resp_pkts / orig_pkts

    proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
    features[40] = proto_map.get(record.get("proto", "tcp"), 6)

    meta = {
        "src_ip": record.get("id.orig_h", record.get("orig_h", "")),
        "dst_ip": record.get("id.resp_h", record.get("resp_h", "")),
        "src_port": record.get("id.orig_p", record.get("orig_p", 0)),
        "dst_port": record.get("id.resp_p", record.get("resp_p", 0)),
        "protocol": record.get("proto", "tcp"),
        "zeek_uid": record.get("uid", ""),
    }

    features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)
    return features, meta


# ── Classification helper ───────────────────────────────────────────────

def _classify(features: np.ndarray, model) -> tuple[str, float, str]:
    """Classify a single feature vector. Returns (label, confidence, severity)."""
    tensor = torch.tensor(features, dtype=torch.float32).unsqueeze(0).to(DEVICE)
    with torch.no_grad():
        logits = model(tensor)
    probs = torch.softmax(logits, dim=1)
    conf, pred_idx = probs.max(dim=1)
    label = model.CLASSES[pred_idx.item()] if hasattr(model, "CLASSES") else f"class_{pred_idx.item()}"
    severity = "info"
    if hasattr(model, "SEVERITY_MAP"):
        severity = model.SEVERITY_MAP.get(label, "medium")
    return label, conf.item(), severity


# ── Schemas ──────────────────────────────────────────────────────────────

class NetFlowBatch(BaseModel):
    records: list[dict] = Field(..., min_length=1, max_length=1000)
    source: str = "netflow"


class ZeekBatch(BaseModel):
    records: list[dict] = Field(..., min_length=1, max_length=1000)
    source: str = "zeek"


class SyslogBatch(BaseModel):
    messages: list[str] = Field(..., min_length=1, max_length=500)
    source: str = "syslog"


# ── Endpoints ────────────────────────────────────────────────────────────

def _get_active_model():
    """Import model lazily from main to avoid circular imports."""
    from main import get_model
    return get_model()


@router.post("/netflow", summary="Ingest NetFlow/IPFIX records for real-time classification")
def ingest_netflow(batch: NetFlowBatch, user=Depends(require_auth)):
    model = _get_active_model()
    if model is None:
        raise HTTPException(503, "No model loaded")

    results = []
    events_for_siem = []
    for record in batch.records:
        features, meta = _netflow_to_features(record)
        label, conf, severity = _classify(features, model)
        result = {
            "src_ip": meta["src_ip"],
            "dst_ip": meta["dst_ip"],
            "label": label,
            "confidence": round(conf, 4),
            "severity": severity,
        }
        results.append(result)
        _stats.record("netflow", label, conf, meta)

        if label != "Benign":
            events_for_siem.append({
                "threat_label": label, "severity": severity, "confidence": conf,
                "src_ip": meta["src_ip"], "dst_ip": meta["dst_ip"],
                "model_used": "active",
            })

    # Forward threats to SIEM connectors
    if events_for_siem:
        try:
            from siem_connectors import emit_batch
            emit_batch(events_for_siem)
        except ImportError:
            pass

    n_threats = sum(1 for r in results if r["label"] != "Benign")
    return {
        "processed": len(results),
        "threats": n_threats,
        "results": results,
    }


@router.post("/zeek", summary="Ingest Zeek conn.log records for classification")
def ingest_zeek(batch: ZeekBatch, user=Depends(require_auth)):
    model = _get_active_model()
    if model is None:
        raise HTTPException(503, "No model loaded")

    results = []
    events_for_siem = []
    for record in batch.records:
        features, meta = _zeek_to_features(record)
        label, conf, severity = _classify(features, model)
        result = {
            "src_ip": meta["src_ip"],
            "dst_ip": meta["dst_ip"],
            "zeek_uid": meta.get("zeek_uid", ""),
            "label": label,
            "confidence": round(conf, 4),
            "severity": severity,
        }
        results.append(result)
        _stats.record("zeek", label, conf, meta)

        if label != "Benign":
            events_for_siem.append({
                "threat_label": label, "severity": severity, "confidence": conf,
                "src_ip": meta["src_ip"], "dst_ip": meta["dst_ip"],
                "model_used": "active",
            })

    if events_for_siem:
        try:
            from siem_connectors import emit_batch
            emit_batch(events_for_siem)
        except ImportError:
            pass

    n_threats = sum(1 for r in results if r["label"] != "Benign")
    return {
        "processed": len(results),
        "threats": n_threats,
        "results": results,
    }


@router.post("/syslog", summary="Ingest raw syslog messages for classification")
def ingest_syslog(batch: SyslogBatch, user=Depends(require_auth)):
    """
    Accept raw syslog messages. This is a lightweight passthrough that
    logs the messages and returns an acknowledgement. Full syslog-to-feature
    parsing requires format-specific extractors.
    """
    _stats.records_per_source["syslog"] = _stats.records_per_source.get("syslog", 0) + len(batch.messages)
    _stats.total_records += len(batch.messages)
    _stats.last_event_at = datetime.datetime.utcnow().isoformat()

    return {
        "processed": len(batch.messages),
        "note": "Syslog messages logged. Feature extraction requires format-specific parsing.",
    }


@router.get("/status", summary="Get ingestion pipeline statistics")
def ingestion_status(user=Depends(require_auth)):
    return _stats.to_dict()


@router.post("/status/reset", summary="Reset ingestion counters")
def reset_stats(user=Depends(require_auth)):
    global _stats
    _stats = IngestionStats()
    return {"ok": True}
