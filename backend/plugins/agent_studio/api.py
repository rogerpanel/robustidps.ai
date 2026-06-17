"""FastAPI router for Agent Studio + Agent Security plugin.

Mount point: /api/agent-studio/*. The free scanner endpoint is public
(no auth) by design — it's the venture plan's top-of-funnel wedge.
Production note: rate-limit at the platform edge before exposing
publicly (slowapi limiter already mounted in main.py).
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

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
