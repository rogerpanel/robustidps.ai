"""Test sessions — the 'Start session' stage of the Quickstart wizard.

A session is a sandboxed conversation tied to one template + one customer.
Sending a message:

1. Aegis-checks the input against the scanner (`input_kind=system_prompt`).
2. If allowed, builds a synthetic response by running the input through a
   template-aware response simulator. This is NOT a live LLM call — it's a
   deterministic test-run so the wizard works without burning OpenAI tokens.
3. Aegis-checks the output before returning.

Why deterministic + synthetic? Two reasons:
- The wizard's job is to surface verdict envelopes, not to be a creative
  agent. The real LLM lives downstream in the customer's app.
- It keeps test runs free, fast, and reproducible for support / replay.

Real-LLM sessions can swap in by replacing `_simulate_response()` with a
provider call; the verdict checks stay identical.
"""
from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from plugins.agent_studio.scanner import run_scan
from plugins.agent_studio.templates import get_template


SESSION_LOG_PATH = Path("weights/agent_studio_sessions.json")
MAX_HISTORY = 30          # cap per-session
MAX_SESSIONS = 200        # cap globally


@dataclass
class SessionMessage:
    role: str              # "user" | "agent" | "system"
    text: str
    ts: str
    decision: str = "allow"   # aegis verdict on the text
    n_findings: int = 0
    findings: list[dict] = field(default_factory=list)


@dataclass
class Session:
    session_id: str
    template_id: str
    customer_id: str
    created_at: str
    history: list[SessionMessage] = field(default_factory=list)
    aborted: bool = False


_SESSIONS: dict[str, Session] = {}


def _load() -> None:
    if not SESSION_LOG_PATH.exists():
        return
    try:
        for r in json.loads(SESSION_LOG_PATH.read_text()):
            s = Session(
                session_id=r["session_id"],
                template_id=r["template_id"],
                customer_id=r["customer_id"],
                created_at=r["created_at"],
                aborted=r.get("aborted", False),
            )
            s.history = [SessionMessage(**m) for m in r.get("history", [])]
            _SESSIONS[s.session_id] = s
    except (json.JSONDecodeError, KeyError):
        pass


def _persist() -> None:
    SESSION_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    items = []
    for s in list(_SESSIONS.values())[-MAX_SESSIONS:]:
        items.append({
            "session_id": s.session_id, "template_id": s.template_id,
            "customer_id": s.customer_id, "created_at": s.created_at,
            "aborted": s.aborted,
            "history": [asdict(m) for m in s.history[-MAX_HISTORY:]],
        })
    SESSION_LOG_PATH.write_text(json.dumps(items, indent=2))


_load()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _aegis_scan(text: str, input_kind: str = "system_prompt") -> tuple[str, int, list[dict]]:
    """Return (decision, n_findings, findings) for a piece of text."""
    if not text.strip():
        return ("allow", 0, [])
    report = run_scan(text[:50_000], input_kind=input_kind)
    sev = report.severity_breakdown or {}
    if sev.get("critical", 0) or sev.get("high", 0):
        decision = "block"
    elif sev.get("medium", 0):
        decision = "warn"
    else:
        decision = "allow"
    findings = [
        {"code": r.code, "severity": r.severity, "title": r.title}
        for r in report.results if r.triggered
    ]
    return (decision, len(findings), findings)


def _simulate_response(template: dict, user_input: str, history: list[SessionMessage]) -> str:
    """Template-aware synthetic response.

    Pattern: each archetype gets a short, structurally-correct reply that
    matches what the real agent would produce. The point of the wizard is
    to surface verdict envelopes, not to be creative.
    """
    name = template.get("spec", {}).get("name", template["id"])
    tools = [t["name"] for t in template.get("spec", {}).get("tools", [])]
    tools_str = ", ".join(tools[:4]) or "(none)"
    n = len(history) + 1

    arche = template["category"]

    if arche == "soc":
        return (f"[{name} · turn {n}] Parsed alert. severity=medium, "
                f"attack_pattern=T1059, recommended_action='isolate the host + "
                f"open ticket via open_ticket'. Evidence sourced via {tools_str}.")
    if arche == "ir":
        return (f"[{name} · turn {n}] Opened war-room #incident-{int(time.time()) % 10000}, "
                f"paged on-call rotation, attached runbook. Status posted via {tools_str}.")
    if arche == "compliance":
        return (f"[{name} · turn {n}] Per ISO 42001 §6.2 — controls present. "
                f"Cite: policy_corpus#iso-42001-6.2 (retrieved via {tools_str}).")
    if arche == "vuln":
        return (f"[{name} · turn {n}] CVE matched against SBOM via {tools_str}. "
                f"EPSS=0.18, affected services=2, owner=team-payments. Triage=tier-1.")
    if arche == "mcp":
        return (f"[{name} · turn {n}] Scanner verdict=FAIL: 1 critical (MCP-CR-shell), "
                f"3 high. Recommended remediation: scope shell tool to allowlist.")
    if arche == "hunt":
        return (f"[{name} · turn {n}] Hypothesis tested over loglake via {tools_str}. "
                f"3 candidate hosts; base-rate × severity ranks top: HOST-042.")
    if arche == "redteam":
        return (f"[{name} · turn {n}] Garak suite executed; 4 findings (2 high, 2 medium). "
                f"ATLAS chain: AML.T0051 → AML.T0048. Report rendered via {tools_str}.")
    if arche == "pentest":
        return (f"[{name} · turn {n}] Recon within authorized scope. 12 hosts up, "
                f"34 services exposed, 0 exploits attempted (read-only).")
    if arche == "awareness":
        return (f"[{name} · turn {n}] Campaign drafted, recipients validated against "
                f"address_book.engineering. Send queued for review (rate-limited).")
    if arche == "support":
        return (f"[{name} · turn {n}] Per docs[user-guide#api-key-rotation]: "
                f"open /agent-studio/account → Issue key → revoke the old one.")
    if arche == "billing":
        return (f"[{name} · turn {n}] Invoice INV-1042 status: settled 2026-06-01 "
                f"(no double-charge). If you see a duplicate, open a refund ticket.")
    if arche == "rag":
        return (f"[{name} · turn {n}] Per kb[payments/on-call#rota]: rotation Mon/Wed/Fri "
                f"= Mei, Bashir, Anya. Source verified via {tools_str}.")
    return f"[{name} · turn {n}] Acknowledged input ({len(user_input)} chars)."


# ── Public API ─────────────────────────────────────────────────────────

def create_session(template_id: str, customer_id: str) -> dict:
    template = get_template(template_id)
    if template is None:
        raise KeyError(f"Unknown template: {template_id}")
    session_id = f"sess_{secrets.token_urlsafe(10)}"
    s = Session(
        session_id=session_id,
        template_id=template_id,
        customer_id=customer_id,
        created_at=_now(),
    )
    sp = template.get("spec", {}).get("system_prompt", "")
    if sp:
        sp_decision, sp_n, sp_findings = _aegis_scan(sp, input_kind="system_prompt")
        s.history.append(SessionMessage(
            role="system", text=sp, ts=_now(),
            decision=sp_decision, n_findings=sp_n, findings=sp_findings,
        ))
        if sp_decision == "block":
            s.aborted = True
    _SESSIONS[session_id] = s
    _persist()
    return asdict(s)


def get_session(session_id: str) -> dict | None:
    s = _SESSIONS.get(session_id)
    return asdict(s) if s else None


def list_sessions(customer_id: str | None = None, limit: int = 50) -> list[dict]:
    items = list(_SESSIONS.values())
    if customer_id:
        items = [s for s in items if s.customer_id == customer_id]
    items = sorted(items, key=lambda s: s.created_at, reverse=True)[:limit]
    return [
        {"session_id": s.session_id, "template_id": s.template_id,
         "customer_id": s.customer_id, "created_at": s.created_at,
         "n_messages": len(s.history), "aborted": s.aborted}
        for s in items
    ]


def post_message(session_id: str, user_input: str) -> dict:
    s = _SESSIONS.get(session_id)
    if s is None:
        raise KeyError(f"Unknown session: {session_id}")
    if s.aborted:
        return {"ok": False, "error": "Session aborted by aegis verdict on system prompt."}

    in_decision, in_n, in_findings = _aegis_scan(user_input, input_kind="system_prompt")
    s.history.append(SessionMessage(
        role="user", text=user_input, ts=_now(),
        decision=in_decision, n_findings=in_n, findings=in_findings,
    ))
    if in_decision == "block":
        _persist()
        return {
            "blocked_on": "input", "decision": "block",
            "n_findings": in_n, "findings": in_findings,
            "agent_reply": None,
        }

    template = get_template(s.template_id) or {"category": "blank", "id": s.template_id}
    reply = _simulate_response(template, user_input, s.history[:-1])

    out_decision, out_n, out_findings = _aegis_scan(reply, input_kind="agent_card")
    s.history.append(SessionMessage(
        role="agent", text=reply, ts=_now(),
        decision=out_decision, n_findings=out_n, findings=out_findings,
    ))
    if len(s.history) > MAX_HISTORY:
        s.history = s.history[-MAX_HISTORY:]
    _persist()
    return {
        "decision": out_decision,
        "n_findings": out_n,
        "findings": out_findings,
        "agent_reply": reply,
        "input_decision": in_decision,
        "input_n_findings": in_n,
    }


def stats() -> dict:
    items = list(_SESSIONS.values())
    by_template: dict[str, int] = {}
    for s in items:
        by_template[s.template_id] = by_template.get(s.template_id, 0) + 1
    return {
        "n_sessions": len(items),
        "n_aborted": sum(1 for s in items if s.aborted),
        "by_template": by_template,
    }
