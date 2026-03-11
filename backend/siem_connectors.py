"""
SIEM/SOAR Live Connectors — real-time event forwarding.
========================================================

Provides configurable connectors for:
  - Syslog (CEF/LEEF format) — Splunk, QRadar, ArcSight
  - Webhook (JSON) — SOAR platforms, Slack, Teams, PagerDuty
  - Elasticsearch direct indexing
  - Generic HTTP POST

Events are forwarded asynchronously via a background sender thread
so detection latency is not affected.
"""

import datetime
import json
import logging
import os
import queue
import socket
import ssl
import threading
from typing import Optional

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth import require_auth, require_role
from database import get_db

logger = logging.getLogger("robustidps.siem")

router = APIRouter(prefix="/api/siem", tags=["SIEM Connectors"])


# ── CEF/LEEF Formatters ─────────────────────────────────────────────────

def _format_cef(event: dict) -> str:
    """Format event as CEF (Common Event Format) for Splunk/ArcSight."""
    severity_map = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}
    sev = severity_map.get(event.get("severity", "medium"), 5)

    header = (
        f"CEF:0|RobustIDPS|IDS|1.0|{event.get('threat_label', 'Unknown')}|"
        f"{event.get('threat_label', 'Unknown')}|{sev}|"
    )

    extensions = []
    if event.get("src_ip"):
        extensions.append(f"src={event['src_ip']}")
    if event.get("dst_ip"):
        extensions.append(f"dst={event['dst_ip']}")
    if event.get("confidence"):
        extensions.append(f"cfp1={event['confidence']:.4f}")
        extensions.append("cfp1Label=ML Confidence")
    if event.get("model_used"):
        extensions.append(f"cs1={event['model_used']}")
        extensions.append("cs1Label=Model")
    if event.get("job_id"):
        extensions.append(f"externalId={event['job_id']}")
    extensions.append(f"rt={datetime.datetime.utcnow().strftime('%b %d %Y %H:%M:%S')}")
    extensions.append("cat=Intrusion Detection")

    return header + " ".join(extensions)


def _format_leef(event: dict) -> str:
    """Format event as LEEF (Log Event Extended Format) for QRadar."""
    fields = {
        "src": event.get("src_ip", ""),
        "dst": event.get("dst_ip", ""),
        "cat": event.get("threat_label", "Unknown"),
        "sev": event.get("severity", "medium"),
        "confidence": str(event.get("confidence", 0)),
        "model": event.get("model_used", "surrogate"),
        "jobId": event.get("job_id", ""),
    }
    field_str = "\t".join(f"{k}={v}" for k, v in fields.items() if v)
    return f"LEEF:2.0|RobustIDPS|IDS|1.0|ThreatDetected|{field_str}"


def _format_json(event: dict) -> str:
    """Format event as structured JSON for webhooks and Elasticsearch."""
    payload = {
        "@timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "event.kind": "alert",
        "event.category": "intrusion_detection",
        "event.module": "robustidps",
        "source.ip": event.get("src_ip"),
        "destination.ip": event.get("dst_ip"),
        "threat.indicator.type": event.get("threat_label"),
        "threat.indicator.confidence": event.get("confidence"),
        "threat.indicator.severity": event.get("severity"),
        "robustidps.model": event.get("model_used"),
        "robustidps.job_id": event.get("job_id"),
        "robustidps.flow_id": event.get("flow_id"),
    }
    # Strip None values
    payload = {k: v for k, v in payload.items() if v is not None}
    return json.dumps(payload)


FORMATTERS = {
    "cef": _format_cef,
    "leef": _format_leef,
    "json": _format_json,
}


# ── Connector Registry ──────────────────────────────────────────────────

_connectors: dict[str, dict] = {}
_event_queue: queue.Queue = queue.Queue(maxsize=10000)
_sender_thread: Optional[threading.Thread] = None
_sender_running = False


class ConnectorConfig(BaseModel):
    connector_id: str = Field(..., min_length=1, max_length=50)
    connector_type: str = Field(..., description="syslog | webhook | elasticsearch | slack | teams")
    name: str = Field(..., min_length=1, max_length=255)
    enabled: bool = True

    # Syslog settings
    syslog_host: str = ""
    syslog_port: int = 514
    syslog_protocol: str = "udp"  # udp | tcp | tcp+tls
    syslog_format: str = "cef"     # cef | leef | json

    # Webhook settings
    webhook_url: str = ""
    webhook_headers: dict = {}

    # Elasticsearch settings
    elastic_url: str = ""
    elastic_index: str = "robustidps-alerts"
    elastic_api_key: str = ""

    # Slack/Teams
    slack_webhook_url: str = ""
    teams_webhook_url: str = ""

    # Filtering
    min_severity: str = "low"  # low | medium | high | critical
    threat_labels: list[str] = []  # empty = all


def _severity_rank(sev: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev, 0)


# ── Event Sender (background thread) ────────────────────────────────────

def _send_syslog(connector: dict, message: str):
    """Send a syslog message via UDP, TCP, or TCP+TLS."""
    host = connector["syslog_host"]
    port = connector["syslog_port"]
    proto = connector.get("syslog_protocol", "udp")

    msg_bytes = message.encode("utf-8")
    facility = 4  # auth
    severity_val = 6  # informational
    pri = facility * 8 + severity_val
    syslog_msg = f"<{pri}>{message}".encode("utf-8")

    try:
        if proto == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(syslog_msg, (host, port))
            sock.close()
        elif proto in ("tcp", "tcp+tls"):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            if proto == "tcp+tls":
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.connect((host, port))
            sock.sendall(syslog_msg + b"\n")
            sock.close()
    except Exception as e:
        logger.warning("Syslog send to %s:%d failed: %s", host, port, e)


def _send_webhook(connector: dict, payload: str):
    """Send event via HTTP POST webhook."""
    url = connector.get("webhook_url", "")
    if not url:
        return
    headers = {"Content-Type": "application/json"}
    headers.update(connector.get("webhook_headers", {}))
    try:
        with httpx.Client(timeout=10) as client:
            client.post(url, content=payload, headers=headers)
    except Exception as e:
        logger.warning("Webhook to %s failed: %s", url, e)


def _send_elasticsearch(connector: dict, payload: str):
    """Index event directly into Elasticsearch/OpenSearch."""
    url = connector.get("elastic_url", "").rstrip("/")
    index = connector.get("elastic_index", "robustidps-alerts")
    api_key = connector.get("elastic_api_key", "")
    if not url:
        return

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"

    try:
        with httpx.Client(timeout=10) as client:
            client.post(f"{url}/{index}/_doc", content=payload, headers=headers)
    except Exception as e:
        logger.warning("Elasticsearch index to %s failed: %s", url, e)


def _send_slack(connector: dict, event: dict):
    """Send alert to Slack via incoming webhook."""
    url = connector.get("slack_webhook_url", "")
    if not url:
        return
    sev = event.get("severity", "medium")
    emoji = {"critical": ":rotating_light:", "high": ":warning:", "medium": ":large_orange_diamond:", "low": ":information_source:"}.get(sev, ":shield:")

    blocks = {
        "text": f"{emoji} RobustIDPS Alert: {event.get('threat_label', 'Unknown')}",
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": f"{emoji} Threat Detected: {event.get('threat_label', 'Unknown')}"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Severity:* {sev}"},
                {"type": "mrkdwn", "text": f"*Confidence:* {event.get('confidence', 0):.2%}"},
                {"type": "mrkdwn", "text": f"*Source:* `{event.get('src_ip', 'N/A')}`"},
                {"type": "mrkdwn", "text": f"*Destination:* `{event.get('dst_ip', 'N/A')}`"},
                {"type": "mrkdwn", "text": f"*Model:* {event.get('model_used', 'surrogate')}"},
                {"type": "mrkdwn", "text": f"*Job:* {event.get('job_id', 'N/A')}"},
            ]},
        ],
    }
    try:
        with httpx.Client(timeout=10) as client:
            client.post(url, json=blocks)
    except Exception as e:
        logger.warning("Slack webhook failed: %s", e)


def _send_teams(connector: dict, event: dict):
    """Send alert to Microsoft Teams via incoming webhook."""
    url = connector.get("teams_webhook_url", "")
    if not url:
        return
    sev = event.get("severity", "medium")
    color = {"critical": "FF0000", "high": "FF6600", "medium": "FFaa00", "low": "00AA00"}.get(sev, "0078D4")

    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary": f"RobustIDPS: {event.get('threat_label', 'Unknown')}",
        "sections": [{
            "activityTitle": f"Threat Detected: {event.get('threat_label', 'Unknown')}",
            "facts": [
                {"name": "Severity", "value": sev},
                {"name": "Confidence", "value": f"{event.get('confidence', 0):.2%}"},
                {"name": "Source IP", "value": event.get("src_ip", "N/A")},
                {"name": "Destination IP", "value": event.get("dst_ip", "N/A")},
                {"name": "Model", "value": event.get("model_used", "surrogate")},
            ],
        }],
    }
    try:
        with httpx.Client(timeout=10) as client:
            client.post(url, json=card)
    except Exception as e:
        logger.warning("Teams webhook failed: %s", e)


def _sender_loop():
    """Background thread: dequeue events and send to all matching connectors."""
    global _sender_running
    while _sender_running:
        try:
            event = _event_queue.get(timeout=1)
        except queue.Empty:
            continue

        event_sev_rank = _severity_rank(event.get("severity", "medium"))

        for cid, cfg in list(_connectors.items()):
            if not cfg.get("enabled", True):
                continue
            # Severity filter
            if event_sev_rank < _severity_rank(cfg.get("min_severity", "low")):
                continue
            # Label filter
            labels = cfg.get("threat_labels", [])
            if labels and event.get("threat_label") not in labels:
                continue

            ctype = cfg.get("connector_type", "")
            try:
                if ctype == "syslog":
                    fmt = cfg.get("syslog_format", "cef")
                    formatter = FORMATTERS.get(fmt, _format_cef)
                    _send_syslog(cfg, formatter(event))
                elif ctype == "webhook":
                    _send_webhook(cfg, _format_json(event))
                elif ctype == "elasticsearch":
                    _send_elasticsearch(cfg, _format_json(event))
                elif ctype == "slack":
                    _send_slack(cfg, event)
                elif ctype == "teams":
                    _send_teams(cfg, event)
            except Exception as e:
                logger.error("Connector %s error: %s", cid, e)


def _ensure_sender():
    """Start the sender thread if not already running."""
    global _sender_thread, _sender_running
    if _sender_thread and _sender_thread.is_alive():
        return
    _sender_running = True
    _sender_thread = threading.Thread(target=_sender_loop, daemon=True, name="siem-sender")
    _sender_thread.start()


# ── Public API: emit events from detection pipeline ─────────────────────

def emit_event(event: dict):
    """
    Called by the detection pipeline to forward events to all configured connectors.

    Args:
        event: dict with keys like threat_label, severity, confidence,
               src_ip, dst_ip, model_used, job_id, flow_id.
    """
    if not _connectors:
        return
    _ensure_sender()
    try:
        _event_queue.put_nowait(event)
    except queue.Full:
        logger.warning("SIEM event queue full — dropping event")


def emit_batch(events: list[dict]):
    """Emit multiple events at once."""
    for e in events:
        emit_event(e)


# ── REST Endpoints ───────────────────────────────────────────────────────

@router.get("/connectors", summary="List configured SIEM/SOAR connectors")
def list_connectors(user=Depends(require_auth)):
    # Redact sensitive fields
    result = []
    for cid, cfg in _connectors.items():
        safe = {k: v for k, v in cfg.items() if k not in ("elastic_api_key", "webhook_headers")}
        safe["connector_id"] = cid
        safe["has_api_key"] = bool(cfg.get("elastic_api_key"))
        result.append(safe)
    return {"connectors": result, "total": len(result)}


@router.post("/connectors", summary="Add or update a SIEM/SOAR connector")
def upsert_connector(
    config: ConnectorConfig,
    user=Depends(require_role("admin")),
):
    _connectors[config.connector_id] = config.dict()
    _ensure_sender()
    logger.info("Connector %s (%s) configured by admin", config.connector_id, config.connector_type)
    return {"ok": True, "connector_id": config.connector_id}


@router.delete("/connectors/{connector_id}", summary="Remove a connector")
def delete_connector(
    connector_id: str,
    user=Depends(require_role("admin")),
):
    if connector_id not in _connectors:
        raise HTTPException(404, "Connector not found")
    del _connectors[connector_id]
    return {"ok": True}


@router.post("/connectors/{connector_id}/test", summary="Send a test event to a connector")
def test_connector(
    connector_id: str,
    user=Depends(require_role("admin")),
):
    if connector_id not in _connectors:
        raise HTTPException(404, "Connector not found")

    test_event = {
        "threat_label": "TEST-RobustIDPS",
        "severity": "low",
        "confidence": 0.99,
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "model_used": "surrogate",
        "job_id": "test-0000",
        "flow_id": 0,
    }
    emit_event(test_event)
    return {"ok": True, "message": "Test event queued for delivery"}


@router.get("/stats", summary="Get event forwarding statistics")
def connector_stats(user=Depends(require_auth)):
    return {
        "queue_size": _event_queue.qsize(),
        "queue_max": _event_queue.maxsize,
        "connectors_active": sum(1 for c in _connectors.values() if c.get("enabled")),
        "connectors_total": len(_connectors),
        "sender_alive": _sender_thread.is_alive() if _sender_thread else False,
    }


@router.get("/formats", summary="List supported output formats")
def list_formats(user=Depends(require_auth)):
    return {
        "formats": [
            {"id": "cef", "name": "CEF (Common Event Format)", "targets": ["Splunk", "ArcSight", "QRadar"]},
            {"id": "leef", "name": "LEEF (Log Event Extended Format)", "targets": ["QRadar"]},
            {"id": "json", "name": "ECS-compatible JSON", "targets": ["Elasticsearch", "OpenSearch", "Webhooks"]},
        ],
        "connector_types": [
            {"id": "syslog", "name": "Syslog (UDP/TCP/TLS)", "protocols": ["udp", "tcp", "tcp+tls"]},
            {"id": "webhook", "name": "Generic HTTP Webhook"},
            {"id": "elasticsearch", "name": "Elasticsearch / OpenSearch"},
            {"id": "slack", "name": "Slack Incoming Webhook"},
            {"id": "teams", "name": "Microsoft Teams Webhook"},
        ],
    }
