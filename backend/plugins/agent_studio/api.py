"""FastAPI router for Agent Studio + Agent Security plugin.

Mount point: /api/agent-studio/*. The free scanner endpoint is public
(no auth) by design — it's the venture plan's top-of-funnel wedge.
Production note: rate-limit at the platform edge before exposing
publicly (slowapi limiter already mounted in main.py).
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Literal

from fastapi import APIRouter, Header, Request
from pydantic import BaseModel, Field

from plugins.agent_studio.billing import handle_event as _billing_handle, parse_event as _billing_parse
from plugins.agent_studio.entitlement import public_catalog as _tier_catalog
from plugins.agent_studio.scanner import run_scan, SCANNER_CHECKS

router = APIRouter(prefix="/api/agent-studio", tags=["Agent Studio + Security"])


class ScannerInput(BaseModel):
    text: str = Field(..., min_length=1, max_length=50_000)
    input_kind: Literal["mcp_manifest", "tool_list", "system_prompt", "agent_card"] = "mcp_manifest"


SKU_CATALOG = [
    {"id": "agent_lab", "name": "Agent Lab", "price_usd": "20-45k", "duration": "4-6 wk",
     "summary": "PoC: one RAG/copilot agent, one data source, self-hostable open weights."},
    {"id": "agent_factory", "name": "Agent Factory", "price_usd": "90-280k", "duration": "12-20 wk",
     "summary": "Production multi-agent system, MCP integrations, evals, observability."},
    {"id": "agent_red_team", "name": "Agent Red Team", "price_usd": "35-90k", "duration": "2-4 wk",
     "summary": "OWASP Agentic Top 10 + MITRE ATLAS + MambaGuard adversarial testing."},
    {"id": "continuous_defense", "name": "Continuous Defense", "price_usd": "5-15k/mo", "duration": "rolling",
     "summary": "Quarterly re-test, runtime MambaGuard detection, threat-intel, IR SLA."},
    {"id": "secure_by_design", "name": "Secure-by-Design Build", "price_usd": "180-450k", "duration": "16-26 wk",
     "summary": "FLYWHEEL SKU: Factory + Red Team + 6 mo Defense + full assurance dossier."},
]


@router.post("/scanner/run")
async def scanner_run(payload: ScannerInput) -> dict:
    report = run_scan(payload.text, input_kind=payload.input_kind)
    return {
        "input_kind": report.input_kind,
        "input_size_chars": report.input_size_chars,
        "n_checks_run": report.n_checks_run,
        "n_findings": report.n_findings,
        "severity_breakdown": report.severity_breakdown,
        "results": [asdict(r) for r in report.results],
    }


@router.get("/scanner/checks")
async def scanner_checks() -> dict:
    return {
        "checks": [
            {"code": c.code, "title": c.title, "severity": c.severity,
             "owasp_agentic": c.owasp_agentic, "remediation": c.remediation}
            for c in SCANNER_CHECKS
        ],
        "owasp_agentic_top_10_url": "https://genai.owasp.org/llm-top-10-for-llm-applications/",
        "mitre_atlas_url": "https://atlas.mitre.org/",
    }


@router.get("/sku-catalog")
async def sku_catalog() -> dict:
    return {"skus": SKU_CATALOG}


# ── Entitlement ──────────────────────────────────────────────────────────

@router.get("/entitlement/tiers")
async def entitlement_tiers() -> dict:
    """Public tier catalog — drives the portal's pricing table."""
    return _tier_catalog()


# ── Billing (Stripe webhook) ─────────────────────────────────────────────

@router.post("/billing/webhook")
async def billing_webhook(request: Request,
                          stripe_signature: str | None = Header(default=None, alias="Stripe-Signature")) -> dict:
    """Stripe → tier-change intent. Safe to deploy before Stripe is
    funded — runs in staging mode (no signature requirement) until
    STRIPE_WEBHOOK_SECRET is set in the env."""
    body = await request.body()
    try:
        event = _billing_parse(body, stripe_signature)
    except ValueError as e:
        return {"received": False, "error": str(e)}
    return {"received": True, **_billing_handle(event)}


# ── Eval Harness ───────────────────────────────────────────────────────

class EvalRunRequest(BaseModel):
    agent_spec: dict = Field(..., description="System prompt + tools + name")


@router.post("/eval/run")
async def eval_run(req: EvalRunRequest) -> dict:
    from dataclasses import asdict as _asdict
    from plugins.agent_studio.eval_harness import run_eval
    run = run_eval(req.agent_spec)
    return {
        "run_id": run.run_id, "agent_name": run.agent_name,
        "timestamp": run.timestamp,
        "overall_score": run.overall_score,
        "overall_verdict": run.overall_verdict,
        "results": [_asdict(r) for r in run.results],
    }


@router.get("/eval/history")
async def eval_history(limit: int = 20) -> dict:
    from plugins.agent_studio.eval_harness import history
    return {"runs": history(limit)}


# ── Red Team Automation ───────────────────────────────────────────────

class RedTeamRunRequest(BaseModel):
    target_spec: dict = Field(..., description="Agent spec to probe")


@router.post("/red-team/run")
async def red_team_run(req: RedTeamRunRequest) -> dict:
    from dataclasses import asdict as _asdict
    from plugins.agent_studio.red_team import run_red_team
    run = run_red_team(req.target_spec)
    return {
        "run_id": run.run_id, "target_name": run.target_name,
        "timestamp": run.timestamp,
        "n_probes": run.n_probes, "n_findings": run.n_findings,
        "severity_breakdown": run.severity_breakdown,
        "atlas_chain": run.atlas_chain,
        "results": [_asdict(r) for r in run.results],
    }


@router.get("/red-team/catalog")
async def red_team_catalog() -> dict:
    from plugins.agent_studio.red_team import catalog
    return catalog()


@router.get("/red-team/history")
async def red_team_history(limit: int = 20) -> dict:
    from plugins.agent_studio.red_team import history
    return {"runs": history(limit)}


# ── Runtime Monitor ───────────────────────────────────────────────────

class RuntimeIngestRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=128)
    framework: str = Field("langgraph")
    decision: Literal["allow", "warn", "block"] = "allow"
    finding_codes: list[str] = Field(default_factory=list)
    latency_ms: float = 100.0


@router.post("/runtime/ingest")
async def runtime_ingest(req: RuntimeIngestRequest) -> dict:
    from plugins.agent_studio.runtime_monitor import ingest
    return ingest(req.agent_id, req.framework, req.decision,
                  req.finding_codes, req.latency_ms)


@router.get("/runtime/snapshot")
async def runtime_snapshot(agent_id: str | None = None) -> dict:
    from plugins.agent_studio.runtime_monitor import snapshot
    return snapshot(agent_id)


@router.post("/runtime/seed-demo")
async def runtime_seed_demo() -> dict:
    """Inject 3 synthetic agents with realistic event streams so the
    dashboard shows live data on first visit."""
    from plugins.agent_studio.runtime_monitor import seed_demo_fleet
    return seed_demo_fleet()


@router.post("/runtime/reset")
async def runtime_reset() -> dict:
    from plugins.agent_studio.runtime_monitor import reset
    return reset()


# ── Model Supply Chain ────────────────────────────────────────────────

class SupplyChainScanRequest(BaseModel):
    model_id: str = Field(..., min_length=1, max_length=256)
    spec: dict = Field(default_factory=dict,
                       description="Optional: licence, files[], dependencies[], framework, etc.")


@router.post("/supply-chain/scan")
async def supply_chain_scan(req: SupplyChainScanRequest) -> dict:
    from dataclasses import asdict as _asdict
    from plugins.agent_studio.supply_chain import scan_model
    return _asdict(scan_model(req.model_id, req.spec))


@router.get("/supply-chain/history")
async def supply_chain_history(limit: int = 20) -> dict:
    from plugins.agent_studio.supply_chain import history
    return {"scans": history(limit)}
