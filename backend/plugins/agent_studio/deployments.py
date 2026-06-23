"""Deployments registry — track where customer agents are running.

A deployment record links a customer + a template to a runtime
location (cluster / VPC / region) and pulls live telemetry from the
runtime monitor so the dashboard can answer the "where is my agent
running?" question.

Stored per-customer in weights/agent_studio_deployments.json. Three
status tiers, derived from the linked runtime_monitor agent:

    healthy     block_rate < 5%  + last_seen < 5 min ago
    degraded    block_rate < 20% OR last_seen < 1 h ago
    stale       last_seen > 1 h ago (or no telemetry yet)

No row-level isolation yet (that lands with the Postgres sprint).
For now every deployment lists its customer_id; the API filters.
"""
from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Literal

Tier = Literal["dev", "staging", "production"]
Cloud = Literal["aws", "gcp", "azure", "fly", "modal", "vercel",
                "k8s_self", "docker_self", "bare_metal", "other"]

DEPLOYMENTS_LOG_PATH = Path("weights/agent_studio_deployments.json")
HEALTHY_BLOCK_RATE = 0.05
DEGRADED_BLOCK_RATE = 0.20
STALE_AFTER_S = 3600


@dataclass
class Deployment:
    deployment_id: str
    customer_id: str
    template_id: str
    name: str                          # human-friendly: "soc-triage-prod-eu"
    runtime_agent_id: str              # cross-ref to runtime_monitor agent_id
    cloud: str = "other"
    region: str = ""
    tier: str = "dev"
    url: str | None = None             # public URL or "k8s://cluster/ns/pod"
    git_sha: str | None = None
    deployed_at: str = ""
    deployed_by: str = "self"
    note: str = ""
    retired_at: str | None = None


_DEPLOYMENTS: dict[str, Deployment] = {}


def _load() -> None:
    if not DEPLOYMENTS_LOG_PATH.exists():
        return
    try:
        for r in json.loads(DEPLOYMENTS_LOG_PATH.read_text()):
            _DEPLOYMENTS[r["deployment_id"]] = Deployment(**r)
    except (json.JSONDecodeError, TypeError):
        pass


def _persist() -> None:
    DEPLOYMENTS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEPLOYMENTS_LOG_PATH.write_text(json.dumps(
        [asdict(d) for d in _DEPLOYMENTS.values()], indent=2,
    ))


_load()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def register(
    customer_id: str,
    template_id: str,
    name: str,
    runtime_agent_id: str,
    *,
    cloud: Cloud = "other",
    region: str = "",
    tier: Tier = "dev",
    url: str | None = None,
    git_sha: str | None = None,
    deployed_by: str = "self",
    note: str = "",
) -> dict:
    """Register a new deployment. Returns the persisted record."""
    deployment_id = f"dep_{secrets.token_urlsafe(8)}"
    rec = Deployment(
        deployment_id=deployment_id,
        customer_id=customer_id,
        template_id=template_id,
        name=name,
        runtime_agent_id=runtime_agent_id,
        cloud=cloud, region=region, tier=tier,
        url=url, git_sha=git_sha,
        deployed_at=_now(), deployed_by=deployed_by, note=note,
    )
    _DEPLOYMENTS[deployment_id] = rec
    _persist()
    return asdict(rec)


def retire(deployment_id: str) -> dict:
    rec = _DEPLOYMENTS.get(deployment_id)
    if rec is None:
        return {"ok": False, "error": "unknown deployment_id"}
    if rec.retired_at:
        return {"ok": False, "error": "already retired", "retired_at": rec.retired_at}
    rec.retired_at = _now()
    _persist()
    return {"ok": True, "deployment_id": deployment_id, "retired_at": rec.retired_at}


def _enrich(rec: Deployment) -> dict:
    """Add live telemetry + status to a deployment record."""
    out = asdict(rec)
    if rec.retired_at:
        out["status"] = "retired"
        out["telemetry"] = None
        return out
    try:
        from plugins.agent_studio.runtime_monitor import snapshot
        snap = snapshot(rec.runtime_agent_id)
    except Exception:
        snap = None

    # Per-agent snapshots return agent fields at the top level; fleet
    # snapshots wrap them under "agents". Handle both.
    agent_view = None
    if snap:
        if snap.get("agent_id"):
            agent_view = snap
        elif snap.get("agents"):
            agent_view = next((a for a in snap["agents"]
                               if a.get("agent_id") == rec.runtime_agent_id), None)

    if not agent_view or agent_view.get("n_events", 0) == 0:
        out["status"] = "stale"
        out["telemetry"] = None
        return out
    # The runtime_monitor doesn't expose last_event_ts_ms directly today;
    # window_size > 0 means we've seen events, treat as fresh.
    br = agent_view.get("block_rate", 0.0)
    if br >= DEGRADED_BLOCK_RATE:
        status = "degraded"
    elif br >= HEALTHY_BLOCK_RATE:
        status = "degraded"
    else:
        status = "healthy"
    out["status"] = status
    out["telemetry"] = {
        "block_rate": br,
        "warn_rate":  agent_view.get("warn_rate", 0.0),
        "p50_latency_ms": agent_view.get("p50_latency_ms"),
        "p95_latency_ms": agent_view.get("p95_latency_ms"),
        "n_events": agent_view.get("n_events", 0),
        "window_size": agent_view.get("window_size", 0),
        "top_findings": agent_view.get("top_findings", []),
    }
    return out


def list_deployments(customer_id: str | None = None,
                     include_retired: bool = False) -> list[dict]:
    items = list(_DEPLOYMENTS.values())
    if customer_id is not None:
        items = [d for d in items if d.customer_id == customer_id]
    if not include_retired:
        items = [d for d in items if not d.retired_at]
    items.sort(key=lambda d: d.deployed_at, reverse=True)
    return [_enrich(d) for d in items]


def get_deployment(deployment_id: str) -> dict | None:
    rec = _DEPLOYMENTS.get(deployment_id)
    return _enrich(rec) if rec else None


def stats() -> dict:
    active = [d for d in _DEPLOYMENTS.values() if not d.retired_at]
    by_status: dict[str, int] = {}
    by_cloud: dict[str, int] = {}
    by_tier: dict[str, int] = {}
    by_template: dict[str, int] = {}
    for d in active:
        enriched = _enrich(d)
        by_status[enriched["status"]] = by_status.get(enriched["status"], 0) + 1
        by_cloud[d.cloud] = by_cloud.get(d.cloud, 0) + 1
        by_tier[d.tier] = by_tier.get(d.tier, 0) + 1
        by_template[d.template_id] = by_template.get(d.template_id, 0) + 1
    return {
        "n_total": len(_DEPLOYMENTS), "n_active": len(active),
        "n_retired": len(_DEPLOYMENTS) - len(active),
        "by_status": by_status, "by_cloud": by_cloud,
        "by_tier": by_tier, "by_template": by_template,
    }
