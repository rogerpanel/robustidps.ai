"""One-shot 'build → secure → ship' orchestrator.

Chains everything a customer would otherwise do by hand:
  1. Load template spec
  2. Run eval harness (5 canonical pre-flight evals)
  3. Run Garak red-team (12 curated Garak-shaped probes)
  4. Run model supply-chain scan (default: cybersec_llm)
  5. Save a workspace (persisted per-user)
  6. Register a deployment (with a suggested runtime_agent_id)
  7. Return run_ids + workspace_id + deployment_id + dossier URL

Exposed via POST /api/agent-studio/orchestrate and the SOC Copilot tool
`orchestrate_build_and_ship_agent`. Idempotent: if a workspace with the
same (owner, template, name) exists it upserts; deployments are always
fresh (registrations are cheap and users can retire dupes).
"""
from __future__ import annotations

import datetime
import logging
import time
from dataclasses import asdict as _asdict
from typing import Any

from sqlalchemy.orm import Session

logger = logging.getLogger("agent_studio.orchestrator")


def orchestrate_build_and_ship(
    db: Session,
    customer: dict,
    template_id: str,
    name: str | None = None,
    *,
    cloud: str = "docker_self",
    region: str = "",
    tier: str = "dev",
    supply_model_id: str | None = None,
    register_deployment: bool = True,
) -> dict:
    """One-turn end-to-end pipeline. Every stage is captured; failures
    in a single stage don't halt the pipeline — they surface in the
    stages[] list with `ok: false` + the error, so partial completion
    is honest."""
    from plugins.agent_studio.templates import get_template
    from plugins.agent_studio.eval_harness import run_eval
    from plugins.agent_studio.red_team_garak import run_garak
    from plugins.agent_studio.supply_chain import scan_model
    from plugins.agent_studio.workspaces import save_workspace
    from plugins.agent_studio.deployments import register as register_dep

    started = time.time()
    tpl = get_template(template_id)
    if tpl is None:
        return {"ok": False, "error": f"Unknown template: {template_id}",
                "stages": []}

    spec = tpl["spec"]
    workspace_name = name or f"{template_id}-orchestrated-{datetime.datetime.utcnow().strftime('%Y%m%d')}"
    supply_target = supply_model_id or "cybersec_llm"
    runtime_agent_id = workspace_name
    stages: list[dict] = []

    # ── 1. Eval harness ────────────────────────────────────────────
    eval_out: dict = {}
    try:
        run = run_eval(spec)
        eval_out = {
            "run_id": run.run_id, "overall_score": run.overall_score,
            "overall_verdict": run.overall_verdict,
        }
        stages.append({"stage": "eval", "ok": True, "result": eval_out})
    except Exception as e:
        logger.exception("orchestrator: eval stage failed")
        stages.append({"stage": "eval", "ok": False, "error": str(e)})

    # ── 2. Garak red-team ─────────────────────────────────────────
    red_out: dict = {}
    try:
        rt = run_garak(spec)
        red_out = {
            "run_id": rt.run_id, "n_probes": rt.n_probes,
            "n_findings": rt.n_findings,
            "severity_breakdown": rt.severity_breakdown,
            "atlas_chain": rt.atlas_chain,
        }
        stages.append({"stage": "red_team", "ok": True, "result": red_out})
    except Exception as e:
        logger.exception("orchestrator: red-team stage failed")
        stages.append({"stage": "red_team", "ok": False, "error": str(e)})

    # ── 3. Supply-chain scan ──────────────────────────────────────
    sc_out: dict = {}
    try:
        sc = scan_model(supply_target, {})
        sc_dict = _asdict(sc)
        sc_out = {"scan_id": sc_dict.get("scan_id"),
                   "model_id": sc_dict.get("model_id"),
                   "risk_level": sc_dict.get("risk_level"),
                   "risk_score": sc_dict.get("risk_score"),
                   "n_cve": len(sc_dict.get("cve_matches") or [])}
        stages.append({"stage": "supply_chain", "ok": True, "result": sc_out})
    except Exception as e:
        logger.exception("orchestrator: supply-chain stage failed")
        stages.append({"stage": "supply_chain", "ok": False, "error": str(e)})

    # ── 4. Save workspace ─────────────────────────────────────────
    ws_out: dict = {}
    ws_state = {
        "step": 4,                    # user lands on the "Integrate" step
        "specJson": _pretty(spec),
        "envJson": _pretty(tpl.get("environment") or {}),
        "sessionId": None,
        "chatInput": (tpl.get("test_inputs") or ["ping"])[0],
        "snippetIdx": 0,
        "orchestrator": {
            "eval": eval_out, "red_team": red_out, "supply_chain": sc_out,
        },
    }
    if customer.get("source") == "demo_mode":
        stages.append({"stage": "workspace", "ok": False,
                        "error": "demo mode cannot persist"})
    else:
        try:
            ws = save_workspace(db, customer, template_id, workspace_name,
                                 ws_state,
                                 note=f"Orchestrator run ({datetime.datetime.utcnow().isoformat(timespec='seconds')}Z)")
            ws_out = {"workspace_id": ws["workspace_id"], "name": ws["name"]}
            stages.append({"stage": "workspace", "ok": True, "result": ws_out})
        except Exception as e:
            logger.exception("orchestrator: workspace stage failed")
            stages.append({"stage": "workspace", "ok": False, "error": str(e)})

    # ── 5. Register deployment (optional) ─────────────────────────
    dep_out: dict = {}
    if register_deployment and customer.get("source") != "demo_mode":
        try:
            dep = register_dep(
                db, customer_id=customer.get("customer_id", "anon"),
                template_id=template_id, name=workspace_name,
                runtime_agent_id=runtime_agent_id,
                cloud=cloud, region=region, tier=tier,
                deployed_by=customer.get("email", "orchestrator"),
                note="Registered by build_and_ship orchestrator",
            )
            dep_out = {"deployment_id": dep["deployment_id"],
                        "name": dep["name"],
                        "runtime_agent_id": dep["runtime_agent_id"],
                        "status": dep.get("status", "stale")}
            stages.append({"stage": "deployment", "ok": True, "result": dep_out})
        except Exception as e:
            logger.exception("orchestrator: deployment stage failed")
            stages.append({"stage": "deployment", "ok": False, "error": str(e)})
    else:
        stages.append({"stage": "deployment", "ok": False,
                        "error": "skipped (register_deployment=False or demo mode)"})

    return {
        "ok": all(s["ok"] for s in stages if s["stage"] != "deployment"),
        "template_id": template_id,
        "workspace_name": workspace_name,
        "runtime_agent_id": runtime_agent_id,
        "elapsed_s": round(time.time() - started, 3),
        "stages": stages,
        "eval": eval_out, "red_team": red_out,
        "supply_chain": sc_out, "workspace": ws_out, "deployment": dep_out,
        "next_steps": {
            "resume_wizard": f"/agent-studio/build/{template_id}",
            "dossier":       "/dossier?vertical=agent_studio",
            "runtime":       "/agent-studio/runtime",
            "workspaces":    "/agent-studio/workspaces",
            "deployments":   "/agent-studio/deployments",
        },
    }


def _pretty(obj: Any) -> str:
    import json
    try:
        return json.dumps(obj, indent=2)
    except (TypeError, ValueError):
        return str(obj)
