"""
SOC Copilot — Agentic AI assistant for security analysts.

Hybrid approach:
  - Claude API (Anthropic): Full reasoning with tool-use
  - OpenAI (GPT-4o, etc.): Function calling with tool-use
  - Google Gemini: Tool-use with function calling
  - DeepSeek: Chat completion
  - Local fallback: Structured responses from scan data without external API
"""

import json
import logging
from typing import Optional, AsyncIterator

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, func, desc
from sqlalchemy.orm import Session

from config import ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY, DEEPSEEK_API_KEY
from database import get_db, Job, FirewallRule, AuditLog
from auth import require_auth, User

logger = logging.getLogger("robustidps.copilot")

router = APIRouter(prefix="/api/copilot", tags=["SOC Copilot"])


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    api_key: str = ""
    provider: str = "auto"          # auto | anthropic | openai | google | deepseek
    model: str = ""                 # optional model override e.g. "gpt-4o", "gemini-2.0-flash"
    active_ids_models: list[str] = []  # IDS models to include in context

class ChatResponse(BaseModel):
    content: str
    provider: str


# ---------------------------------------------------------------------------
# Provider configuration
# ---------------------------------------------------------------------------

PROVIDER_DEFAULTS = {
    "anthropic": "claude-sonnet-4-20250514",
    "openai": "gpt-4o",
    "google": "gemini-2.0-flash",
    "deepseek": "deepseek-chat",
}

PROVIDER_KEY_PREFIXES = {
    "sk-ant-": "anthropic",
    "sk-": "openai",       # OpenAI keys start with sk- (but not sk-ant-)
    "AIza": "google",
    "dsk-": "deepseek",    # DeepSeek keys
}


def detect_provider(api_key: str) -> str:
    """Detect the LLM provider from the API key prefix."""
    if not api_key:
        return "local"
    # Check specific prefixes (order matters: sk-ant- before sk-)
    for prefix, provider in PROVIDER_KEY_PREFIXES.items():
        if api_key.startswith(prefix):
            return provider
    return "openai"  # default fallback for unrecognised keys


# ---------------------------------------------------------------------------
# Tools (shared across providers)
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "get_recent_jobs",
        "description": "Get recent analysis jobs with their results (threats found, model used, etc.)",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Number of recent jobs to return", "default": 10},
            },
            "required": [],
        },
    },
    {
        "name": "get_job_details",
        "description": "Get detailed results for a specific analysis job by job_id",
        "input_schema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "The 8-character job ID"},
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "get_firewall_rules",
        "description": "Get firewall rules generated for a specific job",
        "input_schema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "The job ID to get firewall rules for"},
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "get_threat_summary",
        "description": "Get an aggregate summary of all threats detected across all jobs",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "get_audit_logs",
        "description": "Get recent audit log entries (login, upload, predict actions)",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Number of entries", "default": 20},
            },
            "required": [],
        },
    },
    {
        "name": "get_system_status",
        "description": "Get current system status: model loaded, device (CPU/GPU), user count, job count",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "get_active_operations",
        "description": "Get all currently retained operation results across pages (live monitor, red team, XAI, federated, upload, ablation). Shows what analyses are active in the platform right now.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "get_page_result",
        "description": "Get detailed results from a specific active page operation. Use after get_active_operations to drill into results.",
        "input_schema": {
            "type": "object",
            "properties": {
                "page": {"type": "string", "description": "Page: upload, redteam, xai, federated, live_monitor, ablation, continual, pq_crypto, zero_trust, supply_chain, threat_response, rl_response, adversarial, prompt_injection, jailbreak_taxonomy, rag_poisoning, multi_agent"},
                "job_id": {"type": "string", "description": "Optional specific job_id"},
            },
            "required": ["page"],
        },
    },
    {
        "name": "get_model_performance",
        "description": "Get performance metrics and ablation analysis for all IDS models.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "get_pq_crypto_status",
        "description": "Get post-quantum cryptography risk assessment and algorithm benchmarks.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "get_zero_trust_status",
        "description": "Get Zero-Trust AI Governance status: trust scores, compliance, policy state.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "get_supply_chain_status",
        "description": "Get model supply chain security: vulnerabilities, scan results, risk matrix.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "get_threat_response_status",
        "description": "Get autonomous threat response: active playbooks, incidents, response metrics.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "get_llm_attack_results",
        "description": "Get LLM Attack Surface testing results: prompt injection evaluations, jailbreak taxonomy findings, RAG poisoning simulations, and multi-agent chain attack results. These are client-side simulation results stored when users interact with the LLM Attack Surfaces pages.",
        "input_schema": {
            "type": "object",
            "properties": {
                "page": {
                    "type": "string",
                    "description": "Specific LLM attack page: prompt_injection, jailbreak_taxonomy, rag_poisoning, multi_agent, or 'all' for combined summary",
                    "enum": ["prompt_injection", "jailbreak_taxonomy", "rag_poisoning", "multi_agent", "all"],
                },
            },
            "required": [],
        },
    },
]


def _summarise_page_result(page: str, result: dict) -> dict:
    """Extract a concise summary from a page result dict."""
    summary = {}
    if page == "redteam" and "attacks" in result:
        attacks = result["attacks"]
        summary["n_attacks"] = len(attacks)
        summary["model_used"] = result.get("model_used", "")
        summary["epsilon"] = result.get("epsilon")
        summary["n_samples"] = result.get("n_samples", 0)
        summary["clean_accuracy"] = result.get("clean_accuracy")
        summary["clean_confidence"] = result.get("clean_confidence")
        summary["robustness_score"] = result.get("robustness_score")
        summary["dataset_format"] = result.get("dataset_format", "")
        # Per-attack detailed metrics (attacks is a list of dicts)
        attack_details = []
        if isinstance(attacks, list):
            for atk in attacks:
                if isinstance(atk, dict):
                    detail = {
                        "attack": atk.get("attack"),
                        "label": atk.get("label"),
                    }
                    if "error" in atk:
                        detail["error"] = atk["error"]
                    else:
                        detail["accuracy_adversarial"] = atk.get("accuracy_adversarial")
                        detail["confidence_adversarial"] = atk.get("confidence_adversarial")
                        detail["confidence_drop"] = atk.get("confidence_drop")
                        detail["flip_rate"] = atk.get("flip_rate")
                        detail["perturbation_l2"] = atk.get("perturbation_l2")
                        detail["time_ms"] = atk.get("time_ms")
                    attack_details.append(detail)
            summary["attack_types"] = [a.get("attack") or a.get("label", "") for a in attacks if isinstance(a, dict)]
        elif isinstance(attacks, dict):
            for atk_name, atk_data in attacks.items():
                if isinstance(atk_data, dict):
                    attack_details.append({"attack": atk_name, **{k: atk_data.get(k) for k in
                        ("accuracy_adversarial", "confidence_adversarial", "flip_rate", "perturbation_l2")}})
            summary["attack_types"] = list(attacks.keys())
        summary["attack_details"] = attack_details
        # Clean per-class breakdown
        clean_per_class = result.get("clean_per_class", {})
        if clean_per_class:
            summary["clean_per_class"] = clean_per_class
    elif page == "xai":
        summary["n_samples"] = result.get("n_samples", 0)
        summary["method"] = result.get("method", "all")
        summary["model_used"] = result.get("model_used", "")
        summary["dataset_format"] = result.get("dataset_format", "")
        summary["time_ms"] = result.get("time_ms")
        # Prediction summary
        pred_summary = result.get("prediction_summary", {})
        if pred_summary:
            summary["accuracy"] = pred_summary.get("accuracy")
            summary["mean_confidence"] = pred_summary.get("mean_confidence")
        # Gradient saliency — top features
        saliency = result.get("saliency", {})
        if saliency:
            summary["saliency_top_features"] = saliency.get("global_importance", [])[:15]
            # Per-class top features (just top 3 per class, limit to 10 classes)
            per_class = saliency.get("per_class_importance", {})
            if per_class:
                summary["saliency_per_class"] = {
                    cls: feats[:5] for cls, feats in list(per_class.items())[:10]
                }
        # Integrated gradients — top attributions
        ig = result.get("integrated_gradients", {})
        if ig:
            summary["ig_top_attributions"] = ig.get("global_attribution", [])[:15]
        # Sensitivity — most sensitive features
        sens = result.get("sensitivity", {})
        if sens:
            summary["sensitivity_top_features"] = sens.get("top_sensitive_features", [])[:15]
        # Feature names for reference
        feature_names = result.get("feature_names", [])
        if feature_names:
            summary["n_features"] = len(feature_names)
    elif page == "federated":
        rounds = result.get("rounds", [])
        summary["n_rounds"] = len(rounds)
        summary["n_nodes"] = result.get("n_nodes", 0)
        summary["strategy"] = result.get("strategy", "")
        summary["model_used"] = result.get("model_used", "")
        summary["dp_enabled"] = result.get("dp_enabled", False)
        summary["dp_sigma"] = result.get("dp_sigma")
        summary["iid"] = result.get("iid")
        summary["n_samples_total"] = result.get("n_samples_total", 0)
        summary["baseline_accuracy"] = result.get("baseline_accuracy")
        summary["final_accuracy"] = result.get("final_accuracy")
        summary["accuracy_gain"] = result.get("accuracy_gain")
        summary["time_ms"] = result.get("time_ms")
        summary["dataset_format"] = result.get("dataset_format", "")
        # Node distribution
        node_dist = result.get("node_distribution", [])
        if node_dist:
            summary["node_distribution"] = node_dist
        # Round-by-round convergence (include all rounds for charting)
        if rounds:
            summary["round_history"] = [
                {"round": r.get("round"), "global_accuracy": r.get("global_accuracy"),
                 "avg_node_accuracy": r.get("avg_node_accuracy")}
                for r in rounds
            ]
        # Per-class final metrics
        per_class = result.get("per_class", {})
        if per_class:
            summary["per_class"] = per_class
    elif page == "ablation" and "ablation" in result:
        ablation = result["ablation"]
        branch_names = result.get("branch_names", [])
        summary["model_used"] = result.get("model_used", "")
        summary["n_branches"] = len(branch_names)
        summary["branch_names"] = branch_names
        # Per-branch accuracy and drop
        branch_results = []
        for name, metrics in ablation.items():
            if isinstance(metrics, dict):
                branch_results.append({
                    "name": name,
                    "accuracy": metrics.get("accuracy"),
                    "accuracy_drop": metrics.get("accuracy_drop"),
                    "precision": metrics.get("precision"),
                    "recall": metrics.get("recall"),
                    "f1": metrics.get("f1"),
                    "disabled": metrics.get("disabled", []),
                })
        summary["branch_results"] = branch_results
        # Find most/least important branches
        drops = [(b["name"], b["accuracy_drop"]) for b in branch_results if b["accuracy_drop"] is not None and b["name"] != "Full System" and b["name"] != "Custom"]
        if drops:
            drops.sort(key=lambda x: x[1], reverse=True)
            summary["most_important_branch"] = drops[0][0]
            summary["most_important_drop"] = drops[0][1]
            summary["least_important_branch"] = drops[-1][0]
            summary["least_important_drop"] = drops[-1][1]
        # Full system baseline
        if "Full System" in ablation:
            summary["full_system_accuracy"] = ablation["Full System"].get("accuracy")
        # Pairwise interactions
        pairwise = result.get("pairwise", {})
        if pairwise:
            summary["n_pairwise"] = len(pairwise)
            pw_details = []
            for pw_name, pw_data in pairwise.items():
                if isinstance(pw_data, dict):
                    pw_details.append({
                        "pair": pw_name,
                        "pair_accuracy": pw_data.get("pair_accuracy"),
                        "pair_drop": pw_data.get("pair_drop"),
                        "interaction": pw_data.get("interaction"),
                    })
            summary["pairwise_details"] = pw_details
        # Incremental gains
        incremental = result.get("incremental", [])
        if incremental:
            summary["n_incremental_steps"] = len(incremental)
            summary["incremental_steps"] = [
                {"step": s.get("step"), "label": s.get("label"), "added": s.get("added"),
                 "accuracy": s.get("accuracy"), "gain": s.get("gain")}
                for s in incremental
            ]
    elif page == "rl_response":
        summary["num_episodes"] = result.get("num_episodes", 0)
        summary["total_steps"] = result.get("total_steps", 0)
        summary["threat_mitigation_rate"] = result.get("threat_mitigation_rate")
        summary["fp_blocking_rate"] = result.get("fp_blocking_rate")
        summary["mean_episode_reward"] = result.get("mean_episode_reward")
        summary["constraint_violations"] = result.get("constraint_violations", 0)
        summary["total_attacks"] = result.get("total_attacks", 0)
        summary["total_threats_mitigated"] = result.get("total_threats_mitigated", 0)
        summary["total_benign_blocked"] = result.get("total_benign_blocked", 0)
        summary["action_distribution"] = result.get("action_distribution", {})
        summary["dataset_format"] = result.get("dataset_format", "")
        summary["n_samples"] = result.get("n_samples", 0)
    elif page == "adversarial":
        summary["model_id"] = result.get("model_id", "")
        summary["model_name"] = result.get("model_name", "")
        summary["clean_accuracy"] = result.get("clean_accuracy")
        summary["n_samples"] = result.get("n_samples", 0)
        summary["dataset_format"] = result.get("dataset_format", "")
        attacks = result.get("attacks", {})
        if isinstance(attacks, dict):
            attack_details = []
            for atk_name, atk_data in attacks.items():
                if isinstance(atk_data, dict):
                    attack_details.append({
                        "attack": atk_name,
                        "label": atk_data.get("label", atk_name),
                        "accuracy": atk_data.get("accuracy"),
                        "accuracy_drop": atk_data.get("accuracy_drop"),
                        "robustness_ratio": atk_data.get("robustness_ratio"),
                    })
            summary["attack_details"] = attack_details
            summary["attack_types"] = list(attacks.keys())
            ratios = [a.get("robustness_ratio", 0) for a in attacks.values() if isinstance(a, dict) and "robustness_ratio" in a]
            if ratios:
                summary["avg_robustness"] = round(sum(ratios) / len(ratios) * 100, 2)
                summary["min_robustness"] = round(min(ratios) * 100, 2)
    return summary


def _exec_tool(name: str, args: dict, db: Session, user: Optional["User"] = None) -> str:
    try:
        if name == "get_recent_jobs":
            limit = args.get("limit", 10)
            q = select(Job).order_by(desc(Job.created_at)).limit(limit)
            # Non-admin users only see their own jobs
            if user and user.role != "admin":
                q = select(Job).where(Job.user_id == user.id).order_by(desc(Job.created_at)).limit(limit)
            jobs = db.execute(q).scalars().all()
            return json.dumps([{"job_id": j.id, "filename": j.filename, "format": j.format_detected, "n_flows": j.n_flows, "n_threats": j.n_threats, "model_used": j.model_used, "created_at": j.created_at.isoformat() if j.created_at else None} for j in jobs])

        elif name == "get_job_details":
            job = db.get(Job, args["job_id"])
            if not job:
                return json.dumps({"error": f"Job {args['job_id']} not found"})
            rules = db.execute(select(FirewallRule).where(FirewallRule.job_id == args["job_id"])).scalars().all()
            return json.dumps({"job_id": job.id, "filename": job.filename, "format": job.format_detected, "n_flows": job.n_flows, "n_threats": job.n_threats, "model_used": job.model_used, "created_at": job.created_at.isoformat() if job.created_at else None, "firewall_rules_count": len(rules), "top_threats": [{"source_ip": r.source_ip, "threat": r.threat_label, "severity": r.severity, "confidence": r.confidence} for r in rules[:10]]})

        elif name == "get_firewall_rules":
            rules = db.execute(select(FirewallRule).where(FirewallRule.job_id == args["job_id"])).scalars().all()
            return json.dumps([{"rule_type": r.rule_type, "source_ip": r.source_ip, "action": r.action, "threat_label": r.threat_label, "severity": r.severity, "confidence": r.confidence, "rule_text": r.rule_text} for r in rules])

        elif name == "get_threat_summary":
            total_jobs = db.execute(select(func.count(Job.id))).scalar() or 0
            total_flows = db.execute(select(func.sum(Job.n_flows))).scalar() or 0
            total_threats = db.execute(select(func.sum(Job.n_threats))).scalar() or 0
            return json.dumps({"total_jobs": total_jobs, "total_flows_analysed": total_flows, "total_threats_detected": total_threats, "threat_rate": round(total_threats / max(total_flows, 1) * 100, 2)})

        elif name == "get_audit_logs":
            limit = args.get("limit", 20)
            logs = db.execute(select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit)).scalars().all()
            return json.dumps([{"action": l.action, "resource": l.resource, "details": l.details, "ip_address": l.ip_address, "timestamp": l.timestamp.isoformat() if l.timestamp else None} for l in logs])

        elif name == "get_system_status":
            total_users = db.execute(select(func.count(User.id))).scalar() or 0
            total_jobs = db.execute(select(func.count(Job.id))).scalar() or 0
            from config import DEVICE
            from models.model_registry import MODEL_INFO
            return json.dumps({"device": DEVICE, "total_users": total_users, "total_jobs": total_jobs, "models_available": len(MODEL_INFO), "platform": "RobustIDPS.ai"})

        elif name == "get_active_operations":
            # Access in-memory job stores from main module
            import main as _main
            is_admin = user and user.role == "admin"
            uid = user.id if user else None
            ops = []
            # Background jobs (redteam, xai, federated) — filtered by user
            for jid, job in list(_main._bg_jobs.items()):
                if not is_admin and uid and job.get("user_id") and job["user_id"] != uid:
                    continue
                ops.append({"job_id": jid, "status": job["status"], "type": "background_job",
                            "has_result": job["result"] is not None})
            # Upload/stream job store — filtered by user
            for jid, job in list(_main.job_store.items()):
                if not is_admin and uid and job.get("user_id") and job["user_id"] != uid:
                    continue
                n_flows = len(job["features"]) if "features" in job else 0
                ops.append({"job_id": jid, "type": "upload_analysis", "n_flows": n_flows,
                            "has_labels": job.get("labels_encoded") is not None})
            # Cached completed page results (redteam, xai, federated, ablation) — survive polling
            for (cache_uid, page_type), cached in list(_main._completed_results.items()):
                if not is_admin and uid and cache_uid != uid:
                    continue
                result = cached.get("result", {})
                summary = {"job_id": cached["job_id"], "type": f"{page_type}_completed",
                           "status": "done", "timestamp": cached.get("timestamp")}
                summary.update(_summarise_page_result(page_type, result))
                ops.append(summary)
            # Recent DB jobs — filtered by user
            q = select(Job).order_by(desc(Job.created_at)).limit(5)
            if not is_admin and uid:
                q = select(Job).where(Job.user_id == uid).order_by(desc(Job.created_at)).limit(5)
            recent = db.execute(q).scalars().all()
            for j in recent:
                ops.append({"job_id": j.id, "type": "completed_analysis", "filename": j.filename,
                            "format": j.format_detected, "n_flows": j.n_flows, "n_threats": j.n_threats,
                            "model_used": j.model_used, "created_at": j.created_at.isoformat() if j.created_at else None})
            return json.dumps({"active_operations": ops, "total": len(ops)})

        elif name == "get_page_result":
            page = args.get("page", "")
            job_id = args.get("job_id")
            import main as _main
            is_admin = user and user.role == "admin"
            uid = user.id if user else None

            if page == "upload":
                if job_id and job_id in _main.job_store:
                    job = _main.job_store[job_id]
                    if not is_admin and uid and job.get("user_id") and job["user_id"] != uid:
                        return json.dumps({"page": page, "status": "no_active_result"})
                    return json.dumps({"page": page, "job_id": job_id, "n_flows": len(job["features"]),
                                       "has_labels": job.get("labels_encoded") is not None,
                                       "n_label_classes": len(set(job["label_names"])) if job.get("label_names") else 0})
                q = select(Job).order_by(desc(Job.created_at)).limit(1)
                if not is_admin and uid:
                    q = select(Job).where(Job.user_id == uid).order_by(desc(Job.created_at)).limit(1)
                recent = db.execute(q).scalars().first()
                if recent:
                    return json.dumps({"page": page, "job_id": recent.id, "filename": recent.filename,
                                       "n_flows": recent.n_flows, "n_threats": recent.n_threats, "model": recent.model_used})
                return json.dumps({"page": page, "status": "no_active_result"})

            if page == "live_monitor":
                # Check in-memory live capture results first
                live_data = _main._live_capture_results.get("latest")
                if live_data:
                    result = {
                        "page": "live_monitor",
                        "status": live_data.get("status", "unknown"),
                        "interface": live_data.get("interface"),
                        "cycle": live_data.get("cycle", 0),
                        "interval": live_data.get("interval"),
                        "flows_captured": live_data.get("flows_captured", 0),
                        "threats_found": live_data.get("threats_found", 0),
                        "models_used": live_data.get("models_used", []),
                        "timestamp": live_data.get("timestamp"),
                        "capture_id": live_data.get("capture_id"),
                        "source": live_data.get("source", "interface"),
                    }
                    # Include attack distribution and severity breakdown if available
                    if live_data.get("attack_distribution"):
                        result["attack_distribution"] = live_data["attack_distribution"]
                    if live_data.get("severity_counts"):
                        result["severity_counts"] = live_data["severity_counts"]
                    if live_data.get("top_threat_sources"):
                        result["top_threat_sources"] = live_data["top_threat_sources"]
                    # Include job_id for file replay sessions
                    if live_data.get("job_id"):
                        result["job_id"] = live_data["job_id"]
                        # Enrich with filename from DB Job record
                        db_job = db.execute(select(Job).where(Job.id == live_data["job_id"])).scalars().first()
                        if db_job and db_job.filename:
                            result["capture_file"] = db_job.filename
                            result["data_format"] = db_job.format_detected
                    return json.dumps(result)
                # Fall back to job_store (file replay mode)
                if job_id and job_id in _main.job_store:
                    job = _main.job_store[job_id]
                    if not is_admin and uid and job.get("user_id") and job["user_id"] != uid:
                        return json.dumps({"page": page, "status": "no_active_result"})
                    return json.dumps({"page": page, "job_id": job_id, "n_flows": len(job["features"]),
                                       "has_labels": job.get("labels_encoded") is not None})
                # Fall back to most recent DB job
                q = select(Job).order_by(desc(Job.created_at)).limit(1)
                if not is_admin and uid:
                    q = select(Job).where(Job.user_id == uid).order_by(desc(Job.created_at)).limit(1)
                recent = db.execute(q).scalars().first()
                if recent:
                    return json.dumps({"page": page, "job_id": recent.id, "filename": recent.filename,
                                       "n_flows": recent.n_flows, "n_threats": recent.n_threats, "model": recent.model_used})
                return json.dumps({"page": "live_monitor", "status": "no_active_result"})

            if page in ("redteam", "xai", "federated", "ablation", "rl_response", "adversarial"):
                # Check running/pending background jobs first (user-scoped)
                for jid, job in list(_main._bg_jobs.items()):
                    if not is_admin and uid and job.get("user_id") and job["user_id"] != uid:
                        continue
                    if job["status"] == "done" and job["result"]:
                        result = job["result"]
                        summary = {"page": page, "job_id": jid, "status": "done"}
                        summary.update(_summarise_page_result(page, result))
                        return json.dumps(summary)

                # Fall back to persistent completed results cache
                lookup_uid = uid
                if is_admin:
                    # Admin: check all users, prefer most recent
                    for (cache_uid, cache_page), cached in _main._completed_results.items():
                        if cache_page == page:
                            result = cached["result"]
                            summary = {"page": page, "job_id": cached["job_id"], "status": "done",
                                       "timestamp": cached.get("timestamp"), "source": "cached"}
                            summary.update(_summarise_page_result(page, result))
                            return json.dumps(summary)
                else:
                    cached = _main._completed_results.get((uid, page))
                    if cached:
                        result = cached["result"]
                        summary = {"page": page, "job_id": cached["job_id"], "status": "done",
                                   "timestamp": cached.get("timestamp"), "source": "cached"}
                        summary.update(_summarise_page_result(page, result))
                        return json.dumps(summary)

                return json.dumps({"page": page, "status": "no_active_result"})

            if page in ("prompt_injection", "jailbreak_taxonomy", "rag_poisoning", "multi_agent"):
                # LLM attack surface results are stored client-side and synced to _completed_results
                cache_key = (uid, f"llm_{page}")
                cached = _main._completed_results.get(cache_key)
                if cached:
                    result = cached.get("result", {})
                    return json.dumps({"page": page, "status": "done", "timestamp": cached.get("timestamp"), **result})
                # Admin fallback
                if is_admin:
                    for (cache_uid, cache_page), c in _main._completed_results.items():
                        if cache_page == f"llm_{page}":
                            return json.dumps({"page": page, "status": "done", "timestamp": c.get("timestamp"), **c.get("result", {})})
                return json.dumps({"page": page, "status": "no_active_result",
                                   "hint": "User should run simulations on the LLM Attack Surfaces pages first."})

            return json.dumps({"page": page, "status": "no_data_available"})

        elif name == "get_model_performance":
            from models.model_registry import MODEL_INFO
            models = []
            for key, info in MODEL_INFO.items():
                models.append({"id": key, "name": info["name"], "category": info["category"],
                               "description": info["description"]})
            return json.dumps({"models": models, "total": len(models)})

        elif name == "get_pq_crypto_status":
            try:
                from pq_crypto import PQ_ALGORITHMS
                algos = [{"name": a["name"], "type": a["type"], "nist_level": a["nist_level"],
                          "key_size": a.get("key_size", "N/A")} for a in PQ_ALGORITHMS.values()]
                return json.dumps({"algorithms": algos, "total": len(algos)})
            except Exception:
                return json.dumps({"status": "pq_module_not_available"})

        elif name == "get_zero_trust_status":
            try:
                from zero_trust import compute_trust_score, get_policies
                score = compute_trust_score()
                policies = get_policies()
                return json.dumps({"trust_score": score, "n_policies": len(policies)})
            except Exception:
                return json.dumps({"status": "zero_trust_module_not_available"})

        elif name == "get_supply_chain_status":
            try:
                from supply_chain import get_overview
                overview = get_overview()
                return json.dumps(overview)
            except Exception:
                return json.dumps({"status": "supply_chain_module_not_available"})

        elif name == "get_threat_response_status":
            try:
                from threat_response import get_playbooks, get_incidents, get_response_metrics
                playbooks = get_playbooks()
                incidents = get_incidents(limit=5)
                metrics = get_response_metrics()
                return json.dumps({"n_playbooks": len(playbooks), "recent_incidents": len(incidents),
                                   "metrics": metrics})
            except Exception:
                return json.dumps({"status": "threat_response_module_not_available"})

        elif name == "get_llm_attack_results":
            # LLM attack results are stored client-side in localStorage.
            # The frontend sends them via the chat message context.
            # Return a helpful description so the LLM can guide the user.
            page_filter = args.get("page", "all")
            import main as _main
            uid = user.id if user else None

            # Check for client-submitted LLM attack results in _completed_results cache
            llm_pages = ["prompt_injection", "jailbreak_taxonomy", "rag_poisoning", "multi_agent"]
            results = {}
            for lp in llm_pages:
                if page_filter not in ("all", lp):
                    continue
                cache_key = (uid, f"llm_{lp}")
                cached = _main._completed_results.get(cache_key)
                if cached:
                    results[lp] = cached.get("result", {})

            if results:
                return json.dumps({"llm_attack_results": results, "pages_with_data": list(results.keys())})

            return json.dumps({
                "status": "no_llm_attack_results",
                "message": "No LLM attack surface results found. The user needs to run simulations on the Prompt Injection, Jailbreak Taxonomy, RAG Poisoning, or Multi-Agent Chain pages first. Results are automatically saved when users interact with these pages.",
                "available_pages": llm_pages if page_filter == "all" else [page_filter],
            })

        return json.dumps({"error": f"Unknown tool: {name}"})
    except Exception as e:
        logger.exception("Tool %s failed", name)
        return json.dumps({"error": "Tool execution failed. Please try again."})


# ---------------------------------------------------------------------------
# System prompt (shared)
# ---------------------------------------------------------------------------

def _build_system_prompt(active_ids_models: list[str] = None) -> str:
    base = """You are the RobustIDPS.ai SOC Copilot — an AI security analyst assistant embedded in an adversarially-robust intrusion detection and prevention system.

You help security analysts by:
1. Analysing scan results and explaining detected threats in plain language
2. Providing remediation recommendations for detected attacks
3. Generating incident reports from job data
4. Explaining the AI/ML models' decisions and confidence scores
5. Answering questions about network security, attack types, and defence strategies
6. Helping configure and tune the IDPS (firewall rules, thresholds, model selection)

The platform has the following IDS/ML models available:

**Surrogate Ensemble (7-branch MLP):**
- Branch 0: CT-TGNN (Neural ODE) — Temporal Adaptive Neural ODE with point processes
- Branch 1: TripleE-TGNN — Multi-scale temporal graph neural network
- Branch 2: FedLLM-API — Zero-shot federated LLM intrusion detection
- Branch 3: PQ-IDPS — Post-quantum cryptography-enhanced IDS
- Branch 4: MambaShield — Selective state-space model for streaming inference
- Branch 5: Stochastic Transformer — PAC-Bayesian with MC-Dropout uncertainty
- Branch 6: Game-Theoretic Defence — Nash equilibrium robustness certificate

**Independent Research Models:**
- Neural ODE (TA-BN-ODE + Point Process) — Continuous-time temporal detection
- Optimal Transport (PPFOT-IDS) — Multi-cloud federated domain adaptation
- FedGTD — Federated graph temporal dynamics with Byzantine robustness
- SDE-TGNN — Stochastic differential equation temporal graph network
- CyberSecLLM (Mamba–CrossAttn–MoE) — Cybersecurity foundation model"""

    if active_ids_models:
        base += f"\n\n**Currently active models for analysis:** {', '.join(active_ids_models)}"

    base += """

Attack types detected (34 classes): DDoS (TCP/UDP/ICMP/HTTP/SYN flood, SlowLoris, RST-FIN, PSH-ACK, fragmentation), Recon (port scan, OS scan, host discovery, ping sweep), BruteForce (SSH, FTP, HTTP, dictionary), Spoofing (ARP, DNS, IP), WebAttack (SQLi, XSS, command injection, browser hijacking), Malware (backdoor, ransomware), Mirai variants, and DNS spoofing.

**Platform Pages & Operations You Can Access:**
- **Upload & Analyse**: Upload prediction results, dataset info, threat tables, uncertainty charts
- **Live Monitor**: Real-time streaming classification results, threat counts
- **Red Team Arena**: Adversarial attack results (FGSM, PGD, DeepFool, C&W, Gaussian, Masking)
- **Explainability Studio**: XAI analysis (gradient saliency, integrated gradients, sensitivity)
- **Federated Learning**: Simulation results (rounds, accuracy, strategies, differential privacy)
- **Ablation Studio**: Branch importance analysis, component removal impact
- **PQ Cryptography**: Post-quantum algorithm benchmarks, risk assessment
- **Zero-Trust Governance**: Trust scores, compliance policies, model provenance
- **Supply Chain Security**: Model vulnerability scans, SBOM, risk matrix
- **Threat Response**: Automated playbooks, incident management, response metrics
- **RL Response Agent**: CPO-based autonomous threat response simulation, action distribution, mitigation rates (page="rl_response")
- **Adversarial Robustness**: 6-attack robustness evaluation (FGSM, PGD, C&W, DeepFool, Gaussian, Label masking), multi-dataset comparison (page="adversarial")
- **Continual Learning**: Model drift detection, incremental updates
- **Prompt Injection Playground**: Test LLM resilience against 8 injection attack types with 6 defence strategies — block rates, confidence, defence effectiveness matrix (page="prompt_injection")
- **Jailbreak Taxonomy**: Comprehensive catalogue of 8 jailbreak techniques across 6 categories — effectiveness vs detection difficulty, mitigations, vulnerable models (page="jailbreak_taxonomy")
- **RAG Poisoning Simulator**: Knowledge base poisoning attacks on RAG pipelines — 6 poison types, 6 defence mechanisms, risk assessment (page="rag_poisoning")
- **Multi-Agent Chain Simulation**: Attack propagation through 5-agent LLM systems — 5 chain attack scenarios, agent compromise tracking, defence evaluation (page="multi_agent")

IMPORTANT: Always use the available tools to look up actual data before answering. NEVER give generic descriptions of what a page "can do" — instead, call `get_active_operations` first to see the user's completed operations, then `get_page_result` with the specific page name (e.g. page="redteam", page="federated") to get the actual results. Completed results are cached and available even after the user has navigated away from the page. Be specific and data-driven — report actual numbers, attack success rates, accuracy scores, and model names from the results. When explaining threats, include the attack type, severity, affected IPs, and recommended actions."""

    return base


# ---------------------------------------------------------------------------
# Provider: Anthropic Claude
# ---------------------------------------------------------------------------

async def _claude_stream(messages: list[ChatMessage], api_key: str, model: str, db: Session, active_ids_models: list[str] = None, user: Optional["User"] = None) -> AsyncIterator[str]:
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    api_messages = [{"role": m.role, "content": m.content} for m in messages]
    system_prompt = _build_system_prompt(active_ids_models)

    response = client.messages.create(
        model=model or PROVIDER_DEFAULTS["anthropic"],
        max_tokens=4096,
        system=system_prompt,
        tools=TOOLS,
        messages=api_messages,
    )

    for _ in range(5):
        if response.stop_reason != "tool_use":
            break

        tool_results = []
        assistant_content = response.content
        for block in response.content:
            if block.type == "tool_use":
                result = _exec_tool(block.name, block.input, db, user=user)
                tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": result})

        api_messages.append({"role": "assistant", "content": assistant_content})
        api_messages.append({"role": "user", "content": tool_results})

        response = client.messages.create(
            model=model or PROVIDER_DEFAULTS["anthropic"],
            max_tokens=4096,
            system=system_prompt,
            tools=TOOLS,
            messages=api_messages,
        )

    for block in response.content:
        if hasattr(block, "text"):
            yield block.text


# ---------------------------------------------------------------------------
# Provider: OpenAI
# ---------------------------------------------------------------------------

def _tools_to_openai_functions() -> list:
    """Convert our tool definitions to OpenAI function-calling format."""
    funcs = []
    for tool in TOOLS:
        funcs.append({
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["input_schema"],
            },
        })
    return funcs


async def _openai_stream(messages: list[ChatMessage], api_key: str, model: str, db: Session, active_ids_models: list[str] = None, user: Optional["User"] = None) -> AsyncIterator[str]:
    import openai

    client = openai.OpenAI(api_key=api_key)
    system_prompt = _build_system_prompt(active_ids_models)
    api_messages = [{"role": "system", "content": system_prompt}]
    api_messages += [{"role": m.role, "content": m.content} for m in messages]
    tools = _tools_to_openai_functions()

    response = client.chat.completions.create(
        model=model or PROVIDER_DEFAULTS["openai"],
        messages=api_messages,
        tools=tools,
        max_tokens=4096,
    )

    for _ in range(5):
        choice = response.choices[0]
        if choice.finish_reason != "tool_calls" or not choice.message.tool_calls:
            break

        api_messages.append(choice.message)
        for tc in choice.message.tool_calls:
            args = json.loads(tc.function.arguments) if tc.function.arguments else {}
            result = _exec_tool(tc.function.name, args, db, user=user)
            api_messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result,
            })

        response = client.chat.completions.create(
            model=model or PROVIDER_DEFAULTS["openai"],
            messages=api_messages,
            tools=tools,
            max_tokens=4096,
        )

    content = response.choices[0].message.content or ""
    yield content


# ---------------------------------------------------------------------------
# Provider: Google Gemini
# ---------------------------------------------------------------------------

async def _google_stream(messages: list[ChatMessage], api_key: str, model: str, db: Session, active_ids_models: list[str] = None, user: Optional["User"] = None) -> AsyncIterator[str]:
    import openai  # Google Gemini supports OpenAI-compatible API

    client = openai.OpenAI(
        api_key=api_key,
        base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
    )
    system_prompt = _build_system_prompt(active_ids_models)
    api_messages = [{"role": "system", "content": system_prompt}]
    api_messages += [{"role": m.role, "content": m.content} for m in messages]

    response = client.chat.completions.create(
        model=model or PROVIDER_DEFAULTS["google"],
        messages=api_messages,
        max_tokens=4096,
    )

    content = response.choices[0].message.content or ""
    yield content


# ---------------------------------------------------------------------------
# Provider: DeepSeek
# ---------------------------------------------------------------------------

async def _deepseek_stream(messages: list[ChatMessage], api_key: str, model: str, db: Session, active_ids_models: list[str] = None, user: Optional["User"] = None) -> AsyncIterator[str]:
    import openai

    client = openai.OpenAI(
        api_key=api_key,
        base_url="https://api.deepseek.com",
    )
    system_prompt = _build_system_prompt(active_ids_models)
    api_messages = [{"role": "system", "content": system_prompt}]
    api_messages += [{"role": m.role, "content": m.content} for m in messages]

    response = client.chat.completions.create(
        model=model or PROVIDER_DEFAULTS["deepseek"],
        messages=api_messages,
        max_tokens=4096,
    )

    content = response.choices[0].message.content or ""
    yield content


# ---------------------------------------------------------------------------
# Local fallback
# ---------------------------------------------------------------------------

def _local_response(messages: list[ChatMessage], db: Session, user: Optional["User"] = None) -> str:
    last_msg = messages[-1].content.lower() if messages else ""

    if any(w in last_msg for w in ["threat", "summary", "overview", "status"]):
        data = json.loads(_exec_tool("get_threat_summary", {}, db, user=user))
        status = json.loads(_exec_tool("get_system_status", {}, db, user=user))
        return (
            f"**System Status**\n"
            f"- Device: {status['device'].upper()}\n"
            f"- Users: {status['total_users']}\n"
            f"- Models available: {status['models_available']}\n\n"
            f"**Threat Summary**\n"
            f"- Total jobs analysed: {data['total_jobs']}\n"
            f"- Total flows processed: {data['total_flows_analysed']:,}\n"
            f"- Threats detected: {data['total_threats_detected']:,}\n"
            f"- Threat rate: {data['threat_rate']}%\n\n"
            f"*For deeper investigation and AI-powered analysis, add your API key in Settings.*"
        )

    if any(w in last_msg for w in ["job", "recent", "scan", "analyse"]):
        data = json.loads(_exec_tool("get_recent_jobs", {"limit": 5}, db, user=user))
        if not data:
            return "No analysis jobs found yet. Upload a dataset to get started."
        lines = ["**Recent Analysis Jobs**\n"]
        for j in data:
            lines.append(f"- **{j['job_id']}**: {j['filename']} — {j['n_flows']} flows, {j['n_threats']} threats ({j['model_used']})")
        lines.append("\n*For detailed threat investigation, provide your API key in Settings.*")
        return "\n".join(lines)

    if any(w in last_msg for w in ["audit", "log", "activity"]):
        data = json.loads(_exec_tool("get_audit_logs", {"limit": 10}, db, user=user))
        if not data:
            return "No audit log entries found."
        lines = ["**Recent Activity**\n"]
        for l in data:
            lines.append(f"- [{l['action']}] {l['resource']} from {l['ip_address']} — {l['details']}")
        return "\n".join(lines)

    if any(w in last_msg for w in ["active", "operation", "running", "current", "page"]):
        data = json.loads(_exec_tool("get_active_operations", {}, db, user=user))
        ops = data.get("active_operations", [])
        if not ops:
            return "No active operations running across any pages. Upload a dataset or run an analysis to get started."
        lines = ["**Active Operations Across Pages**\n"]
        for op in ops:
            if op["type"] == "background_job":
                lines.append(f"- **Background Job** `{op['job_id']}`: {op['status']}")
            elif op["type"] == "upload_analysis":
                lines.append(f"- **Upload** `{op['job_id']}`: {op['n_flows']} flows loaded")
            elif op["type"] == "completed_analysis":
                lines.append(f"- **{op.get('filename', 'Analysis')}** `{op['job_id']}`: {op['n_flows']} flows, {op['n_threats']} threats ({op['model_used']})")
        lines.append("\n*For deeper investigation, provide your API key in Settings.*")
        return "\n".join(lines)

    if any(w in last_msg for w in ["help", "what can", "how to", "capabilities"]):
        return (
            "**SOC Copilot Capabilities**\n\n"
            "I can help you with:\n"
            "- **Threat analysis**: Ask about detected threats, attack types, and severity\n"
            "- **Job investigation**: Get details on any analysis job by ID\n"
            "- **Active operations**: Query live results from any page (Red Team, XAI, Federated, etc.)\n"
            "- **Incident reports**: Generate reports from scan results\n"
            "- **System status**: Check model status, user activity, threat overview\n"
            "- **Model performance**: Compare IDS models and ablation impact\n"
            "- **PQ Crypto**: Post-quantum algorithm status and risk assessment\n"
            "- **Zero-Trust**: Governance scores and policy compliance\n"
            "- **Supply Chain**: Model security scans and vulnerabilities\n"
            "- **Threat Response**: Playbook status and incident metrics\n"
            "- **LLM Attack Surfaces**: Prompt injection test results, jailbreak taxonomy, RAG poisoning, multi-agent chain attacks\n"
            "- **Remediation**: Get recommended actions for detected attacks\n"
            "- **Firewall rules**: Review auto-generated rules for any job\n"
            "- **Audit logs**: View recent system activity\n\n"
            "**Local mode** (current): I provide structured data lookups.\n"
            "**AI mode**: Add your API key (Anthropic, OpenAI, Google, or DeepSeek) in Settings "
            "for full AI-powered investigation, natural language analysis, and report generation."
        )

    return (
        "I'm the RobustIDPS.ai SOC Copilot. I can help you investigate threats, "
        "review scan results, generate reports, and explain detections.\n\n"
        "Try asking:\n"
        "- \"Show me the threat summary\"\n"
        "- \"What are the recent scan jobs?\"\n"
        "- \"Show audit logs\"\n"
        "- \"What can you do?\"\n\n"
        "*Currently running in local mode. Add an API key in Settings for full AI-powered analysis.*"
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

PROVIDER_STREAMS = {
    "anthropic": _claude_stream,
    "openai": _openai_stream,
    "google": _google_stream,
    "deepseek": _deepseek_stream,
}


@router.post("/chat")
async def chat(req: ChatRequest, user: User = Depends(require_auth), db: Session = Depends(get_db)):
    # Determine which API key and provider to use
    api_key = req.api_key
    provider = req.provider

    # If no client key, try server-side keys (only for authenticated users)
    if not api_key:
        if user is None:
            raise HTTPException(status_code=401, detail="API key required")
        server_keys = {
            "anthropic": ANTHROPIC_API_KEY,
            "openai": OPENAI_API_KEY,
            "google": GOOGLE_API_KEY,
            "deepseek": DEEPSEEK_API_KEY,
        }
        if provider != "auto" and server_keys.get(provider):
            # User selected a specific provider — use the matching server key
            api_key = server_keys[provider]
        else:
            # Auto mode — pick first available key, detect provider from prefix
            for env_key, prov_name in [
                (ANTHROPIC_API_KEY, "anthropic"),
                (OPENAI_API_KEY, "openai"),
                (GOOGLE_API_KEY, "google"),
                (DEEPSEEK_API_KEY, "deepseek"),
            ]:
                if env_key:
                    api_key = env_key
                    detected = detect_provider(env_key)
                    provider = detected if detected != "local" else prov_name
                    break

    # Auto-detect provider from key prefix if still "auto"
    if provider == "auto":
        provider = detect_provider(api_key)

    # Safety: verify the key actually matches the chosen provider
    if api_key and provider not in ("auto", "local"):
        actual = detect_provider(api_key)
        if actual != "local" and actual != provider:
            # Key doesn't match provider — use the correct provider for this key
            logger.warning("API key prefix (%s) doesn't match selected provider (%s), switching to %s",
                           api_key[:8], provider, actual)
            provider = actual

    if not api_key or provider == "local":
        content = _local_response(req.messages, db, user=user)
        return ChatResponse(content=content, provider="local")

    stream_fn = PROVIDER_STREAMS.get(provider)
    if not stream_fn:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")

    model = req.model or ""

    async def generate():
        try:
            async for chunk in stream_fn(req.messages, api_key, model, db, req.active_ids_models, user=user):
                yield f"data: {json.dumps({'content': chunk, 'provider': provider})}\n\n"
            yield f"data: {json.dumps({'done': True, 'provider': provider})}\n\n"
        except Exception as e:
            logger.exception("Chat error for provider %s", provider)
            yield f"data: {json.dumps({'error': 'LLM provider request failed. Check your API key or try a different provider.', 'provider': provider})}\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")


@router.get("/status")
def copilot_status(user: User = Depends(require_auth)):
    configured = {}
    if ANTHROPIC_API_KEY:
        configured["anthropic"] = True
    if OPENAI_API_KEY:
        configured["openai"] = True
    if GOOGLE_API_KEY:
        configured["google"] = True
    if DEEPSEEK_API_KEY:
        configured["deepseek"] = True
    return {
        "providers_available": any(configured.values()) if configured else False,
        "local_available": True,
    }


@router.get("/models")
def copilot_models(user: User = Depends(require_auth)):
    """Return list of IDS models available for the copilot context."""
    from models.model_registry import MODEL_INFO, WEIGHTS_DIR
    from models.surrogate import SurrogateIDS

    models = []

    # Surrogate branches
    for i, name in enumerate(SurrogateIDS.BRANCH_NAMES):
        models.append({
            "id": f"surrogate_branch_{i}",
            "name": name,
            "category": "surrogate",
            "branch_index": i,
            "description": f"Branch {i} of the 7-branch SurrogateIDS ensemble",
        })

    # Independent models
    for key, info in MODEL_INFO.items():
        if key == "surrogate":
            continue
        weight_path = WEIGHTS_DIR / info["weight_file"]
        models.append({
            "id": key,
            "name": info["name"],
            "category": info["category"],
            "description": info["description"],
            "weights_available": weight_path.exists(),
        })

    return {"models": models}


@router.post("/llm-attack-results")
async def store_llm_attack_results(req: dict, user: User = Depends(require_auth)):
    """Store condensed LLM attack surface results from the frontend for copilot access."""
    import main as _main
    from datetime import datetime

    uid = user.id if user else None
    summary = req.get("summary", {})

    # Store each page's results in the shared _completed_results cache
    page_map = {
        "prompt_injection": summary.get("prompt_injection"),
        "jailbreak_taxonomy": summary.get("jailbreak_taxonomy"),
        "rag_poisoning": summary.get("rag_poisoning"),
        "multi_agent": summary.get("multi_agent"),
    }

    stored = []
    for page_key, page_data in page_map.items():
        if page_data is not None:
            cache_key = (uid, f"llm_{page_key}")
            _main._completed_results[cache_key] = {
                "job_id": f"llm_{page_key}_{uid or 'anon'}",
                "result": page_data,
                "timestamp": datetime.utcnow().isoformat(),
            }
            stored.append(page_key)

    return {"status": "ok", "stored_pages": stored}
