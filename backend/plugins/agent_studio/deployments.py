"""Deployments registry — DB-backed (Sprint 4 migration).

Tracks where customer agents are running, enriches with live runtime
telemetry from the runtime monitor. Tenant-scoped via the `scoped()`
helper in db_models.
"""
from __future__ import annotations

import datetime
import secrets
import time
from typing import Literal

from sqlalchemy.orm import Session

from plugins.agent_studio.db_models import (
    AgentStudioDeployment, scoped,
)

Tier = Literal["dev", "staging", "production"]
Cloud = Literal["aws", "gcp", "azure", "fly", "modal", "vercel",
                "k8s_self", "docker_self", "bare_metal", "other"]

HEALTHY_BLOCK_RATE = 0.05
DEGRADED_BLOCK_RATE = 0.20
STALE_AFTER_S = 3600


def register(
    db: Session,
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
    rec = AgentStudioDeployment(
        deployment_id=f"dep_{secrets.token_urlsafe(8)}",
        customer_id=customer_id, template_id=template_id, name=name,
        runtime_agent_id=runtime_agent_id,
        cloud=cloud, region=region, tier=tier,
        url=url, git_sha=git_sha,
        deployed_at=datetime.datetime.utcnow(),
        deployed_by=deployed_by, note=note,
    )
    db.add(rec)
    db.commit()
    return _enrich(rec)


def retire(db: Session, deployment_id: str) -> dict:
    rec = db.get(AgentStudioDeployment, deployment_id)
    if rec is None:
        return {"ok": False, "error": "unknown deployment_id"}
    if rec.retired_at:
        return {"ok": False, "error": "already retired",
                "retired_at": _iso(rec.retired_at)}
    rec.retired_at = datetime.datetime.utcnow()
    db.commit()
    return {"ok": True, "deployment_id": deployment_id,
            "retired_at": _iso(rec.retired_at)}


def list_deployments(db: Session, customer: dict | None,
                     include_retired: bool = False) -> list[dict]:
    q = db.query(AgentStudioDeployment)
    q = scoped(q, AgentStudioDeployment, customer)
    if not include_retired:
        q = q.filter(AgentStudioDeployment.retired_at.is_(None))
    q = q.order_by(AgentStudioDeployment.deployed_at.desc())
    return [_enrich(d) for d in q.all()]


def get_deployment(db: Session, deployment_id: str) -> dict | None:
    rec = db.get(AgentStudioDeployment, deployment_id)
    return _enrich(rec) if rec else None


def stats(db: Session) -> dict:
    active = db.query(AgentStudioDeployment).filter(
        AgentStudioDeployment.retired_at.is_(None)).all()
    retired = db.query(AgentStudioDeployment).filter(
        AgentStudioDeployment.retired_at.isnot(None)).count()
    by_status: dict[str, int] = {}
    by_cloud: dict[str, int] = {}
    by_tier: dict[str, int] = {}
    by_template: dict[str, int] = {}
    for d in active:
        e = _enrich(d)
        by_status[e["status"]] = by_status.get(e["status"], 0) + 1
        by_cloud[d.cloud] = by_cloud.get(d.cloud, 0) + 1
        by_tier[d.tier] = by_tier.get(d.tier, 0) + 1
        by_template[d.template_id] = by_template.get(d.template_id, 0) + 1
    return {
        "n_total": len(active) + retired, "n_active": len(active),
        "n_retired": retired,
        "by_status": by_status, "by_cloud": by_cloud,
        "by_tier": by_tier, "by_template": by_template,
    }


def _enrich(rec: AgentStudioDeployment) -> dict:
    out = {
        "deployment_id": rec.deployment_id,
        "customer_id": rec.customer_id,
        "template_id": rec.template_id,
        "name": rec.name,
        "runtime_agent_id": rec.runtime_agent_id,
        "cloud": rec.cloud, "region": rec.region, "tier": rec.tier,
        "url": rec.url, "git_sha": rec.git_sha,
        "deployed_at": _iso(rec.deployed_at),
        "deployed_by": rec.deployed_by,
        "note": rec.note or "",
        "retired_at": _iso(rec.retired_at),
    }
    if rec.retired_at:
        out["status"] = "retired"
        out["telemetry"] = None
        return out

    try:
        from plugins.agent_studio.runtime_monitor import snapshot
        snap = snapshot(rec.runtime_agent_id)
    except Exception:
        snap = None

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


def _iso(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)
