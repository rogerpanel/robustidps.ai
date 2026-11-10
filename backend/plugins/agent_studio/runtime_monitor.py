"""Runtime monitor — live agent-traffic telemetry ingestion + per-agent
dashboards + alert routing.

The AegisAgents Kit SDK ships verdict envelopes from customer agents
to this service. The service maintains a rolling per-agent window
(last 100 events), surfaces aggregate signals (verdict mix, severity
distribution, latency p50/p95), and fires alerts when thresholds
are crossed.

In-memory store; production swap-in is per-tenant ClickHouse or
Postgres. The Live Fleet Demo pattern is the precedent — same
session-scoped store + 1 Hz polling.
"""
from __future__ import annotations

import json
import time
import uuid
from collections import deque
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Literal

EventKind = Literal["verdict", "tool_call", "llm_call", "error"]
Severity = Literal["info", "warn", "alert"]

RUNTIME_LOG_PATH = Path("weights/agent_runtime_alerts.json")
WINDOW_SIZE = 100      # rolling window of events per agent
ALERT_THRESHOLD = 0.20  # 20% blocked verdicts in window -> alert


@dataclass
class Event:
    t_ms: int
    kind: EventKind
    decision: str           # allow / warn / block — for verdict events
    finding_codes: list[str]
    latency_ms: float
    severity: Severity


@dataclass
class AgentSeries:
    agent_id: str
    framework: str          # langgraph / crewai / mcp / a2a / anp / autogen / pydantic_ai / openai_agents
    events: deque[Event] = field(default_factory=lambda: deque(maxlen=WINDOW_SIZE))
    last_alert_ts_ms: int = 0


_AGENTS: dict[str, AgentSeries] = {}
_ALERTS: deque[dict] = deque(maxlen=500)


def ingest(agent_id: str, framework: str, decision: str,
           finding_codes: list[str], latency_ms: float,
           kind: EventKind = "verdict") -> dict:
    """Push one verdict / tool-call / llm-call event into the rolling
    window. Returns a snapshot + any newly-fired alert."""
    if agent_id not in _AGENTS:
        _AGENTS[agent_id] = AgentSeries(agent_id=agent_id, framework=framework)
    series = _AGENTS[agent_id]
    severity: Severity = (
        "alert" if decision == "block"
        else "warn" if decision == "warn"
        else "info"
    )
    event = Event(
        t_ms=int(time.time() * 1000),
        kind=kind, decision=decision,
        finding_codes=finding_codes[:10],
        latency_ms=round(latency_ms, 2),
        severity=severity,
    )
    series.events.append(event)

    alert = _maybe_alert(series, event)
    return {
        "ingested": True, "agent_id": agent_id,
        "window_size": len(series.events),
        "alert_fired": alert is not None, "alert": alert,
    }


def _maybe_alert(series: AgentSeries, event: Event) -> dict | None:
    """Fire an alert if the rolling block-rate exceeds the threshold."""
    if len(series.events) < 20:
        return None
    blocked = sum(1 for e in series.events if e.decision == "block")
    block_rate = blocked / len(series.events)
    if block_rate < ALERT_THRESHOLD:
        return None
    # Throttle: at most one alert per agent per 60 s
    if event.t_ms - series.last_alert_ts_ms < 60_000:
        return None
    series.last_alert_ts_ms = event.t_ms
    alert = {
        "alert_id": f"alert-{uuid.uuid4().hex[:10]}",
        "ts_ms": event.t_ms,
        "agent_id": series.agent_id,
        "framework": series.framework,
        "block_rate": round(block_rate, 3),
        "window_size": len(series.events),
        "trigger": event.finding_codes,
        "severity": "alert",
        "message": f"Block rate {block_rate * 100:.1f}% exceeds {ALERT_THRESHOLD * 100:.0f}% threshold",
    }
    _ALERTS.append(alert)
    _persist_alert(alert)
    return alert


def _persist_alert(alert: dict) -> None:
    RUNTIME_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    history: list[dict] = []
    if RUNTIME_LOG_PATH.exists():
        try:
            history = json.loads(RUNTIME_LOG_PATH.read_text())
        except json.JSONDecodeError:
            history = []
    history.append(alert)
    history = history[-500:]
    RUNTIME_LOG_PATH.write_text(json.dumps(history, indent=2))


def snapshot(agent_id: str | None = None) -> dict:
    """Return current fleet state. If agent_id is given, return that
    agent's detail; otherwise the aggregate fleet summary."""
    if agent_id and agent_id in _AGENTS:
        s = _AGENTS[agent_id]
        return {
            "agent_id": s.agent_id, "framework": s.framework,
            "window_size": len(s.events),
            "events": [asdict(e) for e in list(s.events)[-50:]],
            **_aggregate(s),
        }
    # fleet aggregate
    agents = []
    for s in _AGENTS.values():
        agents.append({
            "agent_id": s.agent_id, "framework": s.framework,
            "window_size": len(s.events),
            **_aggregate(s),
        })
    return {
        "n_agents": len(_AGENTS),
        "agents": agents,
        "recent_alerts": list(_ALERTS)[-20:],
    }


def _aggregate(series: AgentSeries) -> dict:
    events = list(series.events)
    n = len(events)
    if n == 0:
        return {"n_events": 0, "block_rate": 0.0, "warn_rate": 0.0,
                "p50_latency_ms": 0.0, "p95_latency_ms": 0.0,
                "top_findings": []}
    blocked = sum(1 for e in events if e.decision == "block")
    warned = sum(1 for e in events if e.decision == "warn")
    latencies = sorted(e.latency_ms for e in events)
    finding_counts: dict[str, int] = {}
    for e in events:
        for code in e.finding_codes:
            finding_counts[code] = finding_counts.get(code, 0) + 1
    top = sorted(finding_counts.items(), key=lambda x: -x[1])[:5]
    return {
        "n_events": n,
        "block_rate": round(blocked / n, 3),
        "warn_rate": round(warned / n, 3),
        "p50_latency_ms": round(latencies[n // 2], 2),
        "p95_latency_ms": round(latencies[min(n - 1, int(n * 0.95))], 2),
        "top_findings": [{"code": c, "count": ct} for c, ct in top],
    }


def reset() -> dict:
    """Clear all agents and alerts — for demo reset."""
    global _AGENTS, _ALERTS
    _AGENTS = {}
    _ALERTS = deque(maxlen=500)
    return {"reset": True}


# ── Demo seed: synthesise a plausible fleet so the page renders ─────

def seed_demo_fleet() -> dict:
    """Inject 3 demo agents with realistic event streams so the
    dashboard shows live data on first visit."""
    reset()
    import random
    rng = random.Random(42)
    agents = [
        ("billing-rag", "langgraph"),
        ("ops-copilot", "openai_agents"),
        ("hr-assistant", "crewai"),
    ]
    finding_pool = ["MCP-S05", "MCP-S08", "LLM-04", "LLM-06", "LLM-08",
                    "ASI01.A", "ASI03.A", "ASI06.A"]
    for agent_id, framework in agents:
        block_p = rng.uniform(0.05, 0.30)
        warn_p = rng.uniform(0.05, 0.20)
        for _ in range(60):
            roll = rng.random()
            if roll < block_p:
                dec, codes = "block", rng.sample(finding_pool, 2)
            elif roll < block_p + warn_p:
                dec, codes = "warn", rng.sample(finding_pool, 1)
            else:
                dec, codes = "allow", []
            ingest(agent_id, framework, dec, codes,
                   latency_ms=rng.uniform(80, 420))
    return snapshot()
