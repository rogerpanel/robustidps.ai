"""FastAPI router for Agent Studio + Agent Security plugin.

Mount point: /api/agent-studio/*. The free scanner endpoint is public
(no auth) by design — it's the venture plan's top-of-funnel wedge.
Production note: rate-limit at the platform edge before exposing
publicly (slowapi limiter already mounted in main.py).
"""
from __future__ import annotations

import os
from dataclasses import asdict
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from plugins.agent_studio.auth import require_api_key, require_admin
from plugins.agent_studio.billing import handle_event as _billing_handle, parse_event as _billing_parse
from plugins.agent_studio.entitlement import public_catalog as _tier_catalog
from plugins.agent_studio.scanner import run_scan, SCANNER_CHECKS

# Reuse the platform's slowapi limiter so all 429s look the same to clients.
try:
    from main import limiter
except Exception:    # pragma: no cover — keeps the plugin importable in tests
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    limiter = Limiter(key_func=get_remote_address)


# Pull per-endpoint quotas from env so ops can dial them at runtime.
RATE_SCAN     = os.getenv("AGENT_STUDIO_RATE_SCAN",     "60/minute")
RATE_EVAL     = os.getenv("AGENT_STUDIO_RATE_EVAL",     "20/minute")
RATE_REDTEAM  = os.getenv("AGENT_STUDIO_RATE_REDTEAM",  "10/minute")
RATE_INGEST   = os.getenv("AGENT_STUDIO_RATE_INGEST",   "300/minute")
RATE_SESSION  = os.getenv("AGENT_STUDIO_RATE_SESSION",  "30/minute")
RATE_BILLING  = os.getenv("AGENT_STUDIO_RATE_BILLING",  "30/minute")
RATE_ADMIN    = os.getenv("AGENT_STUDIO_RATE_ADMIN",    "60/minute")

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
@limiter.limit(RATE_SCAN)
async def scanner_run(request: Request, payload: ScannerInput) -> dict:
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


@router.get("/access-info")
async def access_info_route() -> dict:
    """Public probe — surfaces which identity modes the server accepts
    so the UI can render 'Demo mode' / 'Sign in for full access' banners
    on every Agent Studio page."""
    from plugins.agent_studio.auth import access_info
    return access_info()


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
@limiter.limit(RATE_EVAL)
async def eval_run(request: Request, req: EvalRunRequest,
                   customer: dict = Depends(require_api_key)) -> dict:
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
@limiter.limit(RATE_REDTEAM)
async def red_team_run(request: Request, req: RedTeamRunRequest,
                       customer: dict = Depends(require_api_key)) -> dict:
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
@limiter.limit(RATE_INGEST)
async def runtime_ingest(request: Request, req: RuntimeIngestRequest,
                         customer: dict = Depends(require_api_key)) -> dict:
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
@limiter.limit(RATE_EVAL)
async def supply_chain_scan(request: Request, req: SupplyChainScanRequest,
                            customer: dict = Depends(require_api_key)) -> dict:
    from dataclasses import asdict as _asdict
    from plugins.agent_studio.supply_chain import scan_model
    return _asdict(scan_model(req.model_id, req.spec))


@router.get("/supply-chain/history")
async def supply_chain_history(limit: int = 20) -> dict:
    from plugins.agent_studio.supply_chain import history
    return {"scans": history(limit)}


# ── Proposal 1 — pluggable deep backends ──────────────────────────────

@router.post("/red-team/garak")
@limiter.limit(RATE_REDTEAM)
async def red_team_garak_run(request: Request, req: RedTeamRunRequest,
                             customer: dict = Depends(require_api_key)) -> dict:
    from dataclasses import asdict as _asdict
    from plugins.agent_studio.red_team_garak import run_garak
    run = run_garak(req.target_spec)
    return {
        "run_id": run.run_id, "target_name": run.target_name,
        "timestamp": run.timestamp,
        "n_probes": run.n_probes, "n_findings": run.n_findings,
        "severity_breakdown": run.severity_breakdown,
        "atlas_chain": run.atlas_chain,
        "results": [_asdict(r) for r in run.results],
    }


@router.get("/red-team/garak/info")
async def red_team_garak_info() -> dict:
    from plugins.agent_studio.red_team_garak import runner_info
    return runner_info()


class OTelSpanRequest(BaseModel):
    trace_id: str = ""
    span_id: str = ""
    name: str = "agent.run"
    start_time_unix_nano: int = 0
    end_time_unix_nano: int = 0
    attributes: dict = Field(default_factory=dict)


@router.post("/runtime/otel/spans")
@limiter.limit(RATE_INGEST)
async def runtime_otel_span(request: Request, req: OTelSpanRequest,
                            customer: dict = Depends(require_api_key)) -> dict:
    """Ingest a single trimmed GenAI span."""
    from plugins.agent_studio.runtime_otel import receive_span
    return receive_span(req.dict())


@router.post("/runtime/otel/traces")
@limiter.limit(RATE_INGEST)
async def runtime_otel_traces(request: Request,
                              customer: dict = Depends(require_api_key)) -> dict:
    """Ingest a full OTLP/JSON traces envelope."""
    from plugins.agent_studio.runtime_otel import receive_otlp_json
    body = await request.json()
    return receive_otlp_json(body)


@router.get("/runtime/otel/info")
async def runtime_otel_info() -> dict:
    from plugins.agent_studio.runtime_otel import receiver_info
    return receiver_info()


@router.post("/supply-chain/scan-live")
@limiter.limit(RATE_EVAL)
async def supply_chain_scan_live(request: Request, req: SupplyChainScanRequest,
                                 customer: dict = Depends(require_api_key)) -> dict:
    """Like /supply-chain/scan but enriches the spec with live
    HuggingFace Hub metadata first (when reachable)."""
    from dataclasses import asdict as _asdict
    from plugins.agent_studio.supply_chain import scan_model
    from plugins.agent_studio.supply_chain_hf import fetch_hf_metadata
    enriched = dict(req.spec)
    hf = fetch_hf_metadata(req.model_id)
    if hf is not None:
        # User-supplied spec wins on any key collision
        for k, v in hf.items():
            enriched.setdefault(k, v)
    result = scan_model(req.model_id, enriched)
    return {**_asdict(result), "hf_enrichment_used": hf is not None}


@router.get("/supply-chain/hf-info")
async def supply_chain_hf_info() -> dict:
    from plugins.agent_studio.supply_chain_hf import runner_info
    return runner_info()


# ── Proposal 2 — commerce ─────────────────────────────────────────────

class CheckoutRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=256)
    tier: Literal["pro", "enterprise"] = "pro"
    trial_days: int = Field(14, ge=0, le=30)


class CheckoutCompleteRequest(BaseModel):
    session_id: str
    email: str
    tier: Literal["pro", "enterprise"]


@router.post("/billing/checkout")
@limiter.limit(RATE_BILLING)
async def billing_checkout(request: Request, req: CheckoutRequest) -> dict:
    """Create a Stripe Checkout session. Returns a redirect URL."""
    from plugins.agent_studio.billing import create_checkout_session
    return create_checkout_session(req.email, req.tier, req.trial_days)


@router.post("/billing/checkout/complete")
async def billing_checkout_complete(req: CheckoutCompleteRequest,
                                    db: Session = Depends(get_db)) -> dict:
    """Post-checkout fulfilment: creates the customer record + issues
    the initial API key. Called by the success-URL handler."""
    from plugins.agent_studio.billing import complete_checkout
    return complete_checkout(db, req.session_id, req.email, req.tier)


@router.get("/customers/{customer_id}")
async def customer_detail(customer_id: str, request: Request,
                          db: Session = Depends(get_db)) -> dict:
    from plugins.agent_studio.auth import require_self_or_admin
    require_self_or_admin(customer_id, request, db)
    from plugins.agent_studio.billing import get_customer
    data = get_customer(db, customer_id)
    if data is None:
        raise HTTPException(404, "Customer not found")
    return data


class ApiKeyRequest(BaseModel):
    customer_id: str
    label: str = Field("default", max_length=64)


@router.post("/api-keys/issue")
async def api_key_issue(req: ApiKeyRequest, request: Request,
                        db: Session = Depends(get_db)) -> dict:
    from plugins.agent_studio.auth import require_self_or_admin
    require_self_or_admin(req.customer_id, request, db)
    from plugins.agent_studio.billing import issue_api_key, get_customer
    try:
        key = issue_api_key(db, req.customer_id, req.label)
    except KeyError as e:
        raise HTTPException(404, str(e))
    customer = get_customer(db, req.customer_id)
    return {"api_key": key, "key_id": customer["api_keys"][-1]["id"],
            "label": req.label, "customer_id": req.customer_id}


class ApiKeyRevokeRequest(BaseModel):
    customer_id: str
    key_id: str


@router.post("/api-keys/revoke")
async def api_key_revoke(req: ApiKeyRevokeRequest, request: Request,
                         db: Session = Depends(get_db)) -> dict:
    from plugins.agent_studio.auth import require_self_or_admin
    require_self_or_admin(req.customer_id, request, db)
    from plugins.agent_studio.billing import revoke_api_key
    return revoke_api_key(db, req.customer_id, req.key_id)


@router.get("/customers")
async def customers_list(admin: dict = Depends(require_admin),
                         db: Session = Depends(get_db)) -> dict:
    """Admin-only — surface every customer for audit / support."""
    from plugins.agent_studio.billing import list_customers
    return {"customers": list_customers(db)}


# ── Admin grants — side-channel access (Russia / Crimea / wire / crypto) ──

class AdminGrantRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=256)
    tier: Literal["pro", "enterprise"] = "pro"
    months: int = Field(12, ge=0, le=120)
    payment_rail: Literal[
        "wire", "crypto", "yoomoney", "qiwi", "sbp",
        "bank_card_offshore", "comp", "sponsorship", "other",
    ] = "comp"
    note: str = Field("", max_length=512)
    granted_by: str = Field("admin", max_length=64)


@router.post("/admin/grants")
@limiter.limit(RATE_ADMIN)
async def admin_grant_create(request: Request, req: AdminGrantRequest,
                             admin: dict = Depends(require_admin),
                             db: Session = Depends(get_db)) -> dict:
    """Issue a licence without touching Stripe. Plaintext API key returned ONCE."""
    from plugins.agent_studio.billing import grant_license
    return grant_license(
        db, email=req.email, tier=req.tier, months=req.months,
        payment_rail=req.payment_rail, note=req.note,
        granted_by=req.granted_by,
    )


@router.get("/admin/grants")
async def admin_grant_list(include_revoked: bool = True,
                           admin: dict = Depends(require_admin),
                           db: Session = Depends(get_db)) -> dict:
    from plugins.agent_studio.billing import list_grants, grant_stats
    return {"grants": list_grants(db, include_revoked), "stats": grant_stats(db)}


@router.post("/admin/grants/{grant_id}/revoke")
async def admin_grant_revoke(grant_id: str,
                             admin: dict = Depends(require_admin),
                             db: Session = Depends(get_db)) -> dict:
    from plugins.agent_studio.billing import revoke_grant
    return revoke_grant(db, grant_id, revoked_by=admin.get("role", "admin"))


@router.get("/admin/whoami")
async def admin_whoami(admin: dict = Depends(require_admin)) -> dict:
    """Cheap probe so the Admin Console can verify the token without
    committing to a destructive operation."""
    return {"role": admin["role"], "ok": True}


# ── Quickstart templates — agent archetypes a user can fork ───────────

@router.get("/templates")
async def templates_list(tier: str | None = None) -> dict:
    """List Quickstart agent templates. Filter by tier=A|B|C|blank."""
    from plugins.agent_studio.templates import list_templates, template_stats
    return {"templates": list_templates(tier), "stats": template_stats()}


@router.get("/templates/{template_id}")
async def template_detail(template_id: str) -> dict:
    from plugins.agent_studio.templates import get_template
    data = get_template(template_id)
    if data is None:
        raise HTTPException(404, f"Unknown template: {template_id}")
    return data


# ── Sessions — Step 3 of the Quickstart wizard ────────────────────────

class SessionCreateRequest(BaseModel):
    template_id: str
    customer_id: str | None = None


@router.post("/sessions")
@limiter.limit(RATE_SESSION)
async def session_create(request: Request, req: SessionCreateRequest,
                         customer: dict = Depends(require_api_key)) -> dict:
    """Spin up a sandboxed test session against a template."""
    from plugins.agent_studio.sessions import create_session
    try:
        return create_session(req.template_id,
                              req.customer_id or customer.get("customer_id", "anon"))
    except KeyError as e:
        raise HTTPException(404, str(e))


@router.get("/sessions/{session_id}")
async def session_detail(session_id: str,
                         customer: dict = Depends(require_api_key)) -> dict:
    from plugins.agent_studio.sessions import get_session
    data = get_session(session_id)
    if data is None:
        raise HTTPException(404, "Session not found")
    return data


@router.get("/sessions")
async def sessions_list(limit: int = 50,
                        customer: dict = Depends(require_api_key)) -> dict:
    from plugins.agent_studio.sessions import list_sessions, stats
    return {
        "sessions": list_sessions(customer.get("customer_id"), limit),
        "stats": stats(),
    }


class SessionMessageRequest(BaseModel):
    input: str = Field(..., min_length=1, max_length=20_000)


@router.post("/sessions/{session_id}/messages")
@limiter.limit(RATE_SESSION)
async def session_post_message(session_id: str, request: Request,
                               req: SessionMessageRequest,
                               customer: dict = Depends(require_api_key)) -> dict:
    from plugins.agent_studio.sessions import post_message
    try:
        return post_message(session_id, req.input)
    except KeyError as e:
        raise HTTPException(404, str(e))


@router.get("/sessions/llm-info")
async def session_llm_info() -> dict:
    """Surface which provider sessions will use (synthetic_fallback when
    no provider is keyed). Public so the wizard can label the chat panel."""
    from plugins.agent_studio.llm_dispatch import info
    return info()


# ── Deployments registry — where customer agents are running ─────────

class DeploymentRegisterRequest(BaseModel):
    template_id: str
    name: str = Field(..., min_length=1, max_length=128)
    runtime_agent_id: str = Field(..., min_length=1, max_length=128)
    cloud: Literal["aws", "gcp", "azure", "fly", "modal", "vercel",
                   "k8s_self", "docker_self", "bare_metal", "other"] = "other"
    region: str = Field("", max_length=64)
    tier: Literal["dev", "staging", "production"] = "dev"
    url: str | None = Field(None, max_length=512)
    git_sha: str | None = Field(None, max_length=64)
    deployed_by: str = Field("self", max_length=64)
    note: str = Field("", max_length=512)


@router.post("/deployments")
@limiter.limit(RATE_BILLING)
async def deployments_register(request: Request, req: DeploymentRegisterRequest,
                               customer: dict = Depends(require_api_key),
                               db: Session = Depends(get_db)) -> dict:
    """Register a new deployment for the calling customer. The
    runtime_agent_id should match the agent_id used by the deployed
    instance's MambaGuardClient — that's the cross-ref the dashboard
    uses to pull live telemetry."""
    from plugins.agent_studio.deployments import register
    return register(
        db, customer_id=customer.get("customer_id", "anon"),
        template_id=req.template_id, name=req.name,
        runtime_agent_id=req.runtime_agent_id,
        cloud=req.cloud, region=req.region, tier=req.tier,
        url=req.url, git_sha=req.git_sha,
        deployed_by=req.deployed_by, note=req.note,
    )


@router.get("/deployments")
async def deployments_list(include_retired: bool = False,
                           customer: dict = Depends(require_api_key),
                           db: Session = Depends(get_db)) -> dict:
    """List the calling customer's deployments enriched with live
    runtime telemetry + status (healthy / degraded / stale / retired).
    Tenant-scoped via the `scoped()` helper in db_models."""
    from plugins.agent_studio.deployments import list_deployments, stats
    return {
        "deployments": list_deployments(db, customer, include_retired),
        "stats": stats(db),
    }


@router.get("/deployments/{deployment_id}")
async def deployments_detail(deployment_id: str,
                             customer: dict = Depends(require_api_key),
                             db: Session = Depends(get_db)) -> dict:
    from plugins.agent_studio.deployments import get_deployment
    data = get_deployment(db, deployment_id)
    if data is None:
        raise HTTPException(404, "Deployment not found")
    if data["customer_id"] != customer.get("customer_id") and \
       customer.get("role") != "admin":
        raise HTTPException(403, "Deployment belongs to a different customer")
    return data


@router.post("/deployments/{deployment_id}/retire")
@limiter.limit(RATE_BILLING)
async def deployments_retire(deployment_id: str, request: Request,
                             customer: dict = Depends(require_api_key),
                             db: Session = Depends(get_db)) -> dict:
    from plugins.agent_studio.deployments import retire, get_deployment
    data = get_deployment(db, deployment_id)
    if data is None:
        raise HTTPException(404, "Deployment not found")
    if data["customer_id"] != customer.get("customer_id") and \
       customer.get("role") != "admin":
        raise HTTPException(403, "Deployment belongs to a different customer")
    return retire(db, deployment_id)


# ── Activity rollup — one-shot pull for the SOC Copilot / dossier ─────

@router.get("/activity")
async def activity_rollup(limit: int = 10,
                          customer: dict = Depends(require_api_key),
                          db: Session = Depends(get_db)) -> dict:
    """Recent artefacts across every Agent Studio surface, gated to the
    calling customer. Drives the Copilot's 'follow-up-on-last-activity'
    prompt and the dossier's evidence pack."""
    from plugins.agent_studio.eval_harness import history as _eval_hist
    from plugins.agent_studio.red_team import history as _rt_hist
    from plugins.agent_studio.supply_chain import history as _sc_hist
    from plugins.agent_studio.sessions import list_sessions, stats as _sess_stats
    from plugins.agent_studio.runtime_monitor import snapshot as _rt_snap
    from plugins.agent_studio.billing import grant_stats
    from plugins.agent_studio.deployments import list_deployments, stats as _dep_stats

    cid = customer.get("customer_id")
    return {
        "customer_id": cid,
        "eval_runs":          _eval_hist(limit),
        "red_team_runs":      _rt_hist(limit),
        "supply_chain_scans": _sc_hist(limit),
        "sessions":           list_sessions(cid, limit),
        "session_stats":      _sess_stats(),
        "runtime_snapshot":   _rt_snap(),
        "billing_admin_stats": grant_stats(db),
        "deployments":        list_deployments(db, customer)[:limit],
        "deployment_stats":   _dep_stats(db),
    }
