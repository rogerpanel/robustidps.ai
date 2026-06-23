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
                "page": {"type": "string", "description": "Page: upload, redteam, xai, federated, live_monitor, ablation, continual_learning, pq_crypto, zero_trust, supply_chain, threat_response, rl_response, adversarial, prompt_injection, jailbreak_taxonomy, rag_poisoning, multi_agent, mitre_attack, mitre_atlas, mcp_security, investigation_chain, bas, mambaguard, sode_guard, ssl_graph_anomaly_full, alert_triage, attack_chain, data_poisoning, autoencoder, causality_graph, pq_traffic_lab, auto_investigation, threat_hunt, incident_reports, threat_intel, rule_generator, cve_mapper, executive_dashboard, device_discovery, network_map, domain_transfer, uav_monitor, uav_perception, uav_gnss, uav_certification, uav_swarm, uav_mission_plan"},
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
    # ── UAV / Aerial Defense plugin (chapter 6) ─────────────────────────
    {
        "name": "get_uav_overview",
        "description": "Get the UAV / Aerial Defense Monitor overview: three-tier (edge/droneport/cloud) method assignment, edge profile (Jetson Orin Nano latency/RAM/CPU), UAV-EW-Bench-2026 metadata, all four MCR-vs-J/S configurations with DO-326A 0.90-floor crossings, and the latest Phase-A metrics.json if produced. Use this first whenever the user asks about UAV / drone / aerial defense state.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_uav_ew_bench_curves",
        "description": "Get the UAV-EW-Bench-2026 Mission-Completion-Rate vs Jamming-to-Signal Ratio curves for all four configurations (No-Def PX4 baseline, CAF-CNN+PX4, Seq2Seq Transformer+PX4, M1+M4+M6+M7 framework). Returns per-J/S-dB points with mean MCR + 95% Wilson CI plus the DO-326A floor crossing. The framework's gain over baselines (in dB) is the chapter 6 headline operational result.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_uav_certificates",
        "description": "Get live UAV robustness certificates recomputed on the current synthetic batch: Lipschitz L_g (Theorem 6.1), Gronwall radius (T, epsilon_out), Cohen randomized-smoothing l_2 radius (sigma, alpha, n_samples), PAC-Bayes bound, (epsilon, delta)-DP budget, and the operational interpretation (J/S dB floor and MCR floor under DO-326A).",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_uav_gnss_status",
        "description": "Get the current GNSS Spoof Monitor reading: 8-satellite sky plot (azimuth, elevation, C/N0, spoof confidence per SV), how many SVs are currently flagged as spoofed, cross-droneport fleet disagreement score, autopilot mode (nominal vs GNSS-degraded), and the M6 UC-HGP fallback navigation source if engaged.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_uav_industry_comparison",
        "description": "Get the chapter 6 Table 6.x industry comparison across seven criteria (Lipschitz cert, RS l_2 cert, Byzantine-resilient federated aggregation, differential privacy, LLM mission-plan audit, PQC C2 readiness, Stackelberg vs EW) against Anduril Lattice, Shield AI Hivemind, Skydio Autonomy, PX4 Auterion Enterprise.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_uav_regulatory_evidence",
        "description": "Get the UAV regulatory evidence pack: Russian instruments (RF Government Decree №1701, GOST R 59276-2020, GOST R 56122-2014) and international instruments (NIST AI RMF 1.0, EU AI Act Art. 15, DO-326A/ED-202A) with the specific framework method that satisfies each requirement and the evidence type produced. Use when the user asks about UAV compliance, certification, or regulatory mapping.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "uav_run_perception_attack",
        "description": "Actively run a white-box adversarial attack (FGSM or PGD) against the UAV M1 CT-TGNN model on a sample from the synthetic CAF batch. Returns clean prediction, adversarial prediction, whether the model was fooled, l_2 and l_inf distortion. WRITE ACTION — only call when the user explicitly asks you to run / probe / test an attack.",
        "input_schema": {
            "type": "object",
            "properties": {
                "attack": {"type": "string", "enum": ["fgsm", "pgd"], "description": "Attack family"},
                "epsilon": {"type": "number", "description": "Perturbation budget (typical: 0.0157 = 4/255)", "default": 0.0157},
                "pgd_steps": {"type": "integer", "description": "PGD iterations (ignored for FGSM)", "default": 20, "minimum": 1, "maximum": 100},
                "sample_index": {"type": "integer", "description": "Sample index 0-63", "default": 0, "minimum": 0, "maximum": 63},
            },
            "required": ["attack"],
        },
    },
    {
        "name": "uav_review_mission_plan",
        "description": "Run the CyberSecLLM mission-plan audit (chapter 6 §6.5 cloud-tier surface) on a .plan / JSON-LD / OWL document. Returns approve/block verdict and per-finding severity flags (missing geofence, missing RTL fallback, undeclared altitude band, missing RF Decree №1701 acknowledgment). WRITE ACTION — call when the user wants you to audit a UAV mission document.",
        "input_schema": {
            "type": "object",
            "properties": {
                "plan_text": {"type": "string", "description": "The mission plan document body"},
                "plan_format": {"type": "string", "enum": ["plan", "json-ld", "owl"], "default": "plan"},
            },
            "required": ["plan_text"],
        },
    },
    # ── Agent Studio + Security plugin (venture plan, free wedge) ───────
    {
        "name": "agent_scanner_run",
        "description": "Run the free MCP / agent scanner over a pasted MCP server manifest, tool-list JSON, agent system prompt, or agent card. Twelve checks across OWASP Agentic Top 10 (ASI01-ASI10) plus MCP-specific framing risks (credential leakage, unauthenticated resources, hidden side-effects, prompt-injection echo, rogue-agent identity assertion). Returns per-check severity and remediation. Use whenever the user pastes an MCP manifest, an agent.json, a system prompt, or asks to security-audit an agent definition.",
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "The pasted MCP manifest, tool list, system prompt, or agent card"},
                "input_kind": {"type": "string", "enum": ["mcp_manifest", "tool_list", "system_prompt", "agent_card"], "default": "mcp_manifest"},
            },
            "required": ["text"],
        },
    },
    {
        "name": "agent_studio_sku_catalog",
        "description": "Get the Agent Studio + Agent Security five-SKU catalog: Agent Lab, Agent Factory, Agent Red Team, Continuous Defense, and the flywheel Secure-by-Design Build SKU. Use when the user asks about Agent Studio pricing, deliverables, durations, or the flywheel.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    # ── Assurance dossier (shared by both verticals) ────────────────────
    {
        "name": "assemble_dossier",
        "description": "Assemble a canonical assurance dossier for either vertical (UAV or Agent Studio). The dossier bundles certificates, attack coverage, industry position, regulatory mapping (EU AI Act Art. 15, NIST AI RMF, DO-326A, ISO 42001, OWASP Agentic Top 10), and reproducibility. Use whenever the user asks for a dossier, assurance pack, audit pack, evidence pack, certification report, or wants something paper-ready for a regulator/auditor/investor. Tell the user they can navigate to /dossier?vertical=<v> in the UI and Cmd-P for a printed PDF.",
        "input_schema": {
            "type": "object",
            "properties": {
                "vertical": {"type": "string", "enum": ["uav", "agent_studio"]},
                "audience": {"type": "string", "enum": ["operator", "auditor", "investor"], "default": "auditor"},
            },
            "required": ["vertical"],
        },
    },
    # ── UAV Phase B (chapter 6 §6.4 roadmap) ────────────────────────────
    {
        "name": "get_uav_phase_b_status",
        "description": "Get the UAV Phase B status: AutoML (Optuna) best-trial summaries per model, ONNX export latency benchmark vs the 5 ms airframe-edge target, and progressive-distillation framework readiness (the chapter-6 fix for the CW κ=5 robust-accuracy gap). Use when the user asks about Phase B, AutoML, ONNX, edge latency, or what's next after Phase A.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_uav_swarm_snapshot",
        "description": "Get the three-time-slice UAV swarm graph 𝒢ₜ — node identities (UAVs, droneports, intruders), edge identities (trusted radio, jammed, hostile), and the time-slice labels (clean / jamming / intruder). Use when the user asks about the swarm graph, FANET topology, or how M1 CT-TGNN sees the airspace.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_uav_datasets",
        "description": "Get the full chapter-6 dataset manifest — all 17 datasets with their tier (curated_50mb / on_demand / reference_only), citation, full size, and source URL. Use when the user asks 'did you test on X dataset?' or for any data-provenance question. Returns the full manifest plus a tier-key explaining what each tier means.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "query_uav_ew_bench_at",
        "description": "Sample all four UAV-EW-Bench-2026 configurations at a specific Jamming-to-Signal Ratio (J/S in dB, 0-40). Returns per-config MCR + 95% CI + pass/fail against the DO-326A 0.90 floor. Use when the user asks what happens at a particular J/S level, or for comparative numbers at the typical-EW J/S=20 dB operating point.",
        "input_schema": {
            "type": "object",
            "properties": {
                "js_db": {"type": "integer", "minimum": 0, "maximum": 40, "default": 20,
                          "description": "Jamming-to-Signal Ratio in dB"},
            },
            "required": ["js_db"],
        },
    },
    {
        "name": "get_agent_studio_tiers",
        "description": "Get the Agent Studio three-tier catalog (Community / Pro / Enterprise) with per-tier features, price, and seats. Use when the user asks about Agent Studio pricing tiers, SaaS plans, or which features are gated by which tier.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_uav_ew_bench_source",
        "description": "Check whether the UAV-EW-Bench-2026 MCR-vs-J/S curves currently served are Phase A (chapter-anchored linear interpolation of the chapter 6 Fig. 6.x published 9-point anchors), Phase D (measured via the physics-informed simulator with synthetic trajectories), or Phase E (measured against real flight trajectories from PX4 SITL / EuRoC MAV / UZH-FPV / Blackbird). Returns DO-326A crossings per configuration when measured.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_uav_flight_trajectories",
        "description": "Get the manifest of real flight trajectories available for Phase E EW-Bench runs. Lists discovered PX4 SITL / EuRoC MAV / UZH-FPV / Blackbird flights on disk + the synthetic-fallback mission profiles. Use when the user asks about real flight data, what trajectories the bench runs against, or how to wire in actual recorded flights.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_uav_attack_catalog",
        "description": "Get the full UAV Perception Tester attack catalog — 9 attacks across white-box / black-box / baseline / training-time categories: FGSM, PGD, C&W, DeepFool, HopSkipJump, BoundaryAttack, Gaussian noise, FeatureMask, label-flip. Use when the user asks what attacks the UAV plugin supports.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "step_uav_fleet",
        "description": "Step a live multi-UAV fleet by 1 second. Per-UAV attack injection + ambient J/S setting. Returns each UAV's mission progress, battery, link, GNSS spoof confidence, autopilot mode plus an aggregate fleet MCR. Use when the user wants to drive the Live Fleet Demo or simulate a multi-UAV scenario from the copilot.",
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "default": "copilot-session"},
                "per_uav_attack": {"type": "object", "description": "Map of uav_id → attack kind (none, fgsm, pgd, cw, deepfool, gaussian, spoof_gnss, jam_link, label_flip)"},
                "js_db": {"type": "number", "minimum": 0, "maximum": 40, "default": 10},
                "dt_s": {"type": "number", "minimum": 0.1, "maximum": 10, "default": 1.0},
            },
            "required": [],
        },
    },
    # ── Agent Studio: eval harness + red team + runtime + supply chain ──
    {
        "name": "run_agent_eval",
        "description": "Run the Agent Studio eval harness against an agent specification. Returns five eval scores: goal-hijack resistance, tool-use precision, hallucination resistance, goal-following / scope adherence, cost / latency discipline. Each score 0-1 with pass/warn/fail verdict. Use when the user asks to evaluate an agent's pre-flight safety.",
        "input_schema": {
            "type": "object",
            "properties": {
                "agent_spec": {"type": "object", "description": "Agent spec with system_prompt, tools[], name fields"},
            },
            "required": ["agent_spec"],
        },
    },
    {
        "name": "run_agent_red_team",
        "description": "Run the Agent Studio red-team automation harness (18 probes covering OWASP Agentic Top 10 ASI01-ASI10 + supply-chain + privacy + IR hygiene). Returns triggered findings with severity, MITRE ATLAS tactic mapping, and remediation copy. Use when the user wants to red-team an agent's defenses.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target_spec": {"type": "object", "description": "Agent spec to probe"},
            },
            "required": ["target_spec"],
        },
    },
    {
        "name": "get_agent_runtime_snapshot",
        "description": "Get the current Agent Studio runtime monitor snapshot — aggregate per-agent block rate, warn rate, p50/p95 latency, top finding codes, plus recent alerts. Optionally filter to one agent_id. Use when the user asks what's happening on the agent runtime dashboard right now.",
        "input_schema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string", "description": "Optional: filter to one agent"},
            },
            "required": [],
        },
    },
    {
        "name": "scan_agent_model_supply_chain",
        "description": "Run the Agent Studio model supply-chain scanner on a HuggingFace model ID or local model path. Returns a CycloneDX-AI SBOM fragment, licence + format risk assessment, CVE matches against the known transformers/huggingface_hub/llama.cpp corpus, and an aggregate 0-1 risk score with risk level (safe/low/medium/high/critical). Use when the user asks to assess a model's supply-chain risk.",
        "input_schema": {
            "type": "object",
            "properties": {
                "model_id": {"type": "string", "description": "HF model ID (e.g. meta-llama/Llama-3.1-8B) or path"},
                "spec": {"type": "object", "description": "Optional: licence, files[], dependencies[], framework"},
            },
            "required": ["model_id"],
        },
    },
    {
        "name": "get_agent_red_team_catalog",
        "description": "Get the catalog of 18 red-team probes the Agent Studio harness ships, organised by OWASP Agentic Top 10 category. Use when the user asks what attacks the red-team SKU automatically covers.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "run_agent_red_team_garak",
        "description": "Run the Garak-integrated red-team probe runner against an agent spec. Returns Garak-shaped findings (garak.dan, garak.continuation, garak.promptinject, etc.) with severity, OWASP Agentic / MITRE ATLAS labels, and remediation. When Garak is installed in the backend image the runner uses live Garak probes; otherwise a deterministic 12-probe fallback. Use this when the user wants deep LLM-jailbreak coverage beyond the 18 baseline probes.",
        "input_schema": {
            "type": "object",
            "properties": {"target_spec": {"type": "object"}},
            "required": ["target_spec"],
        },
    },
    {
        "name": "scan_agent_supply_chain_live",
        "description": "Run the supply-chain scanner with live HuggingFace Hub metadata enrichment. Fetches downloads / likes / licence / file list / framework hints from huggingface.co/api/models/{id}, merges into the spec, then runs the standard risk scorer. Falls back to the user-supplied spec when the HF API is unreachable. Use when the user asks to scan a real HF model and wants live metadata.",
        "input_schema": {
            "type": "object",
            "properties": {
                "model_id": {"type": "string"},
                "spec": {"type": "object"},
            },
            "required": ["model_id"],
        },
    },
    {
        "name": "create_agent_studio_checkout",
        "description": "Create a Stripe Checkout session for an Agent Studio Pro or Enterprise subscription. Returns a redirect URL the user opens to complete payment. Safe to call before Stripe is funded — returns a staging-mode session that still issues an API key.",
        "input_schema": {
            "type": "object",
            "properties": {
                "email": {"type": "string"},
                "tier": {"type": "string", "enum": ["pro", "enterprise"], "default": "pro"},
                "trial_days": {"type": "integer", "default": 14, "minimum": 0, "maximum": 30},
            },
            "required": ["email"],
        },
    },
    {
        "name": "get_agent_studio_customer",
        "description": "Look up an Agent Studio customer record by customer_id. Returns email, tier, trial end date, and the list of issued API keys (prefix + label + revocation state; never the plaintext).",
        "input_schema": {
            "type": "object",
            "properties": {"customer_id": {"type": "string"}},
            "required": ["customer_id"],
        },
    },
    {
        "name": "list_agent_studio_templates",
        "description": "List the Quickstart agent templates (13 archetypes: 6 defenders / 3 attackers / 3 productivity / 1 blank). Optionally filter by tier (A, B, C, blank).",
        "input_schema": {
            "type": "object",
            "properties": {
                "tier": {"type": "string", "enum": ["A", "B", "C", "blank"]},
            },
            "required": [],
        },
    },
    {
        "name": "get_agent_studio_template",
        "description": "Fetch a single agent template by id (e.g. 'soc_triage', 'red_team_operator', 'billing_copilot'). Returns the full agent spec a developer can fork.",
        "input_schema": {
            "type": "object",
            "properties": {"template_id": {"type": "string"}},
            "required": ["template_id"],
        },
    },
    {
        "name": "get_agent_studio_admin_stats",
        "description": "Read-only stats on admin-issued licences: total / active / revoked grants, breakdown by payment_rail (wire/crypto/yoomoney/qiwi/sbp/comp/...) and tier. Doesn't expose customer details — use list_customers (admin-gated) for that.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_agent_studio_session",
        "description": "Fetch a single Agent Studio test session by session_id (template_id, history with per-message Aegis decisions, aborted flag).",
        "input_schema": {
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
            "required": ["session_id"],
        },
    },
    {
        "name": "get_agent_studio_session_stats",
        "description": "Aggregate stats on Agent Studio test sessions: total, aborted, breakdown by template_id. Useful for surfacing which templates customers gravitate toward.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_agent_studio_eval_history",
        "description": "Read recent Eval Harness runs (most recent first). Each entry has run_id, agent_name, overall_score, overall_verdict (pass/warn/fail), and per-eval results. Use this to follow up on 'what did my last eval find?' without re-running.",
        "input_schema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "default": 10}},
            "required": [],
        },
    },
    {
        "name": "get_agent_studio_red_team_history",
        "description": "Read recent Red-Team runs (deterministic + Garak adapter). Each entry has run_id, target_name, severity_breakdown, atlas_chain, n_findings. Use to triage what's already been probed before re-running.",
        "input_schema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "default": 10}},
            "required": [],
        },
    },
    {
        "name": "get_agent_studio_supply_chain_history",
        "description": "Read recent Model Supply-Chain scans. Each entry has scan_id, model_id, risk_level, risk_score, CVE matches, and CycloneDX-AI SBOM fragment. Use to follow up on 'what risk did we score Llama-3.1?' without re-fetching.",
        "input_schema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "default": 10}},
            "required": [],
        },
    },
    {
        "name": "list_agent_studio_sessions",
        "description": "List recent test sessions across templates. Each entry has session_id, template_id, n_messages, aborted flag. Pair with get_agent_studio_session(session_id) for the full transcript + per-message Aegis verdicts.",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 50},
                "customer_id": {"type": "string", "description": "Optional filter."},
            },
            "required": [],
        },
    },
    {
        "name": "get_agent_studio_activity",
        "description": "ONE-SHOT activity rollup across every Agent Studio surface: recent eval runs, red-team runs, supply-chain scans, sessions, runtime snapshot, billing/admin stats, deployments. Use this when the user asks 'what's my latest activity?' or 'follow up on what we did last' — saves N separate tool calls.",
        "input_schema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "default": 5}},
            "required": [],
        },
    },
    {
        "name": "list_agent_studio_deployments",
        "description": "List the customer's registered Agent Studio deployments with live runtime telemetry (status: healthy / degraded / stale / retired, block_rate, p50/p95 latency, top finding codes). Use this when the user asks 'where is my agent running?' or 'is my prod agent healthy?'",
        "input_schema": {
            "type": "object",
            "properties": {
                "customer_id": {"type": "string"},
                "include_retired": {"type": "boolean", "default": False},
            },
            "required": [],
        },
    },
    {
        "name": "get_agent_studio_deployment",
        "description": "Fetch a single deployment by deployment_id (full registration info + live telemetry). Use to drill into a specific 'degraded' or 'stale' deployment surfaced by list_agent_studio_deployments.",
        "input_schema": {
            "type": "object",
            "properties": {"deployment_id": {"type": "string"}},
            "required": ["deployment_id"],
        },
    },
    {
        "name": "get_agent_studio_llm_info",
        "description": "Surface which LLM provider Agent Studio test sessions will use (synthetic_fallback when no provider key is configured). Use when the user asks 'are sessions hitting a real model?'",
        "input_schema": {"type": "object", "properties": {}, "required": []},
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
    elif page == "mitre_atlas":
        summary["n_flows"] = result.get("n_flows", 0)
        summary["n_threats"] = result.get("n_threats", 0)
        summary["model_used"] = result.get("model_used", "")
    elif page == "mcp_security":
        summary["total_tests"] = result.get("total_tests", 0)
        summary["blocked"] = result.get("blocked", 0)
        summary["partial"] = result.get("partial", 0)
        summary["bypassed"] = result.get("bypassed", 0)
        summary["block_rate"] = result.get("block_rate", 0)
        summary["defenses_enabled"] = result.get("defenses_enabled", [])
        summary["critical_bypasses"] = result.get("critical_bypasses", [])
    elif page == "investigation_chain":
        summary["n_flows"] = result.get("n_flows", 0)
        summary["n_threats"] = result.get("n_threats", 0)
        summary["n_incidents"] = result.get("n_incidents", 0)
        summary["n_hunt_findings"] = result.get("n_hunt_findings", 0)
        summary["n_recommendations"] = result.get("n_recommendations", 0)
        summary["critical_incidents"] = result.get("critical_incidents", 0)
        summary["attack_types"] = result.get("attack_types", [])
        summary["model_used"] = result.get("model_used", "")
    elif page == "bas":
        summary["scenarios_run"] = result.get("scenarios_run", 0)
        summary["total_steps"] = result.get("total_steps", 0)
        summary["total_detected"] = result.get("total_detected", 0)
        summary["overall_detection_rate"] = result.get("overall_detection_rate", 0)
        summary["detectors_enabled"] = result.get("detectors_enabled", [])
        summary["critical_missed"] = result.get("critical_missed", 0)
    elif page == "mambaguard":
        summary["n_flows"] = result.get("n_flows", 0)
        summary["n_threats"] = result.get("n_threats", 0)
        summary["macro_f1"] = result.get("macro_f1")
        summary["latency_ms"] = result.get("latency_ms")
        summary["model_used"] = result.get("model_used", "")
        summary["smoothing_radius"] = result.get("smoothing_radius")
        summary["stackelberg_value"] = result.get("stackelberg_value")
        summary["hedge_regret_bound"] = result.get("hedge_regret_bound")
        summary["protocols_covered"] = result.get("protocols_covered", [])
    elif page == "sode_guard":
        summary["n_flows"] = result.get("n_flows", 0)
        summary["n_threats"] = result.get("n_threats", 0)
        summary["chaos_degree"] = result.get("chaos_degree")
        summary["mean_anti_concentration"] = result.get("mean_anti_concentration")
        summary["tightest_cert"] = result.get("tightest_cert")
        summary["loosest_cert"] = result.get("loosest_cert")
        summary["model_used"] = result.get("model_used", "")
    elif page == "ssl_graph_anomaly_full" or page == "ssl_graph_anomaly":
        summary["n_flows"] = result.get("n_flows", 0)
        summary["n_threats"] = result.get("n_threats", 0)
        summary["alpha_target"] = result.get("alpha_target")
        summary["calibration_n"] = result.get("calibration_n", 0)
        summary["threshold"] = result.get("threshold")
        summary["empirical_coverage_bound"] = result.get("empirical_coverage_bound")
        summary["model_used"] = result.get("model_used", "")
    elif page.endswith("_multi"):
        # Multi-dataset/multi-model runs from the MultiRunPanel on the three
        # new model pages (mambaguard_multi, sode_guard_multi,
        # ssl_graph_anomaly_multi). Same shape on every page so a single
        # handler covers them all.
        summary["base_page"] = page.removesuffix("_multi")
        summary["n_runs"] = result.get("n_runs", 0)
        summary["models"] = result.get("models", [])
        summary["n_datasets"] = result.get("n_datasets", 0)
        summary["per_run_summary"] = result.get("per_run_summary", [])
    elif page == "upload":
        summary["file_name"] = result.get("file_name", "")
        summary["n_flows"] = result.get("n_flows", 0)
        summary["n_threats"] = result.get("n_threats", 0)
        summary["model_used"] = result.get("model_used", "")
        summary["dataset_format"] = result.get("dataset_format", "")
        summary["accuracy"] = result.get("accuracy")
        summary["job_id"] = result.get("job_id")
    elif page == "live_monitor":
        summary["source"] = result.get("source", "")
        summary["total_flows"] = result.get("total_flows", 0)
        summary["threat_count"] = result.get("threat_count", 0)
        summary["benign_count"] = result.get("benign_count", 0)
        summary["capture_timestamp"] = result.get("capture_timestamp")
        summary["source_file"] = result.get("source_file", "")
        summary["n_flows"] = result.get("n_flows", 0)
        summary["n_threats"] = result.get("n_threats", 0)
        summary["model_used"] = result.get("model_used", "")
    elif page == "pq_crypto":
        summary["algorithms_evaluated"] = result.get("algorithms_evaluated", [])
        summary["recommended"] = result.get("recommended")
        summary["risk_assessment"] = result.get("risk_assessment")
        summary["benchmark"] = result.get("benchmark")
    elif page == "zero_trust":
        summary["trust_score"] = result.get("trust_score")
        summary["policies_active"] = result.get("policies_active", 0)
        summary["compliance"] = result.get("compliance", {})
        summary["violations"] = result.get("violations", 0)
    elif page == "supply_chain":
        summary["models_scanned"] = result.get("models_scanned", 0)
        summary["vulnerabilities"] = result.get("vulnerabilities", 0)
        summary["risk_matrix"] = result.get("risk_matrix")
        summary["high_risk"] = result.get("high_risk", 0)
    elif page == "threat_response":
        summary["active_playbooks"] = result.get("active_playbooks", 0)
        summary["incidents_handled"] = result.get("incidents_handled", 0)
        summary["response_time_avg_ms"] = result.get("response_time_avg_ms")
        summary["auto_executed"] = result.get("auto_executed", 0)
    elif page == "continual_learning":
        summary["tasks_seen"] = result.get("tasks_seen", 0)
        summary["fim_norm"] = result.get("fim_norm")
        summary["last_update"] = result.get("last_update")
        summary["accuracy_per_task"] = result.get("accuracy_per_task", [])
        summary["forgetting"] = result.get("forgetting")
    elif page == "alert_triage":
        summary["alerts_total"] = result.get("alerts_total", 0)
        summary["true_positives"] = result.get("true_positives", 0)
        summary["false_positives"] = result.get("false_positives", 0)
        summary["needs_review"] = result.get("needs_review", 0)
        summary["model_used"] = result.get("model_used", "")
    elif page == "attack_chain":
        summary["n_chains_predicted"] = result.get("n_chains_predicted", 0)
        summary["top_chain"] = result.get("top_chain")
        summary["risk_score"] = result.get("risk_score")
        summary["attack_types"] = result.get("attack_types", [])
    elif page == "data_poisoning":
        summary["scenarios_tested"] = result.get("scenarios_tested", 0)
        summary["mitigation_rate"] = result.get("mitigation_rate")
        summary["critical_findings"] = result.get("critical_findings", 0)
        summary["defenses_active"] = result.get("defenses_active", [])
    elif page == "autoencoder":
        summary["model_used"] = result.get("model_used", "")
        summary["n_flows"] = result.get("n_flows", 0)
        summary["n_anomalies"] = result.get("n_anomalies", 0)
        summary["anomaly_rate"] = result.get("anomaly_rate")
        summary["threshold"] = result.get("threshold")
        summary["reconstruction_error_mean"] = result.get("reconstruction_error_mean")
    elif page == "causality_graph":
        summary["n_alerts"] = result.get("n_alerts", 0)
        summary["n_edges"] = result.get("n_edges", 0)
        summary["root_causes"] = result.get("root_causes", [])
        summary["isolated_clusters"] = result.get("isolated_clusters", 0)
    elif page == "pq_traffic_lab":
        summary["pqc_flows"] = result.get("pqc_flows", 0)
        summary["algorithms_detected"] = result.get("algorithms_detected", [])
        summary["handshake_count"] = result.get("handshake_count", 0)
        summary["risk_assessment"] = result.get("risk_assessment")
    elif page == "threat_intel":
        summary["iocs_loaded"] = result.get("iocs_loaded", 0)
        summary["iocs_matched"] = result.get("iocs_matched", 0)
        summary["feeds_active"] = result.get("feeds_active", [])
        summary["top_threats"] = result.get("top_threats", [])
    elif page == "cve_mapper":
        summary["cves_mapped"] = result.get("cves_mapped", 0)
        summary["critical_cves"] = result.get("critical_cves", 0)
        summary["affected_classes"] = result.get("affected_classes", [])
        summary["highest_cvss"] = result.get("highest_cvss")
    elif page == "executive_dashboard":
        summary["network_health_score"] = result.get("network_health_score")
        summary["threat_count"] = result.get("threat_count", 0)
        summary["severity_distribution"] = result.get("severity_distribution", {})
        summary["top_attacking_ips"] = result.get("top_attacking_ips", [])
        summary["model_used"] = result.get("model_used", "")
    elif page == "domain_transfer":
        summary["selected_tab"] = result.get("selected_tab", "")
        summary["domains_evaluated"] = result.get("domains_evaluated", [])
        summary["accuracy_drop"] = result.get("accuracy_drop")
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
            # Enforce per-job authorization
            if user and user.role != "admin" and job.user_id != user.id:
                return json.dumps({"error": "Access denied — you can only view your own jobs"})
            rules = db.execute(select(FirewallRule).where(FirewallRule.job_id == args["job_id"])).scalars().all()
            return json.dumps({"job_id": job.id, "filename": job.filename, "format": job.format_detected, "n_flows": job.n_flows, "n_threats": job.n_threats, "model_used": job.model_used, "created_at": job.created_at.isoformat() if job.created_at else None, "firewall_rules_count": len(rules), "top_threats": [{"source_ip": r.source_ip, "threat": r.threat_label, "severity": r.severity, "confidence": r.confidence} for r in rules[:10]]})

        elif name == "get_firewall_rules":
            # Enforce per-job authorization
            job = db.get(Job, args["job_id"])
            if not job:
                return json.dumps({"error": "Job not found"})
            if user and user.role != "admin" and job.user_id != user.id:
                return json.dumps({"error": "Access denied — you can only view your own jobs"})
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

            if page in ("mitre_attack", "alert_triage", "attack_chain", "data_poisoning", "autoencoder", "causality_graph", "pq_traffic_lab", "auto_investigation", "threat_hunt", "incident_reports", "threat_intel", "rule_generator", "cve_mapper", "continual_learning", "executive_dashboard", "device_discovery", "network_map", "domain_transfer"):
                cache_key = (uid, page)
                cached = _main._completed_results.get(cache_key)
                if cached:
                    result = cached.get("result", {})
                    return json.dumps({"page": page, "status": "done", "timestamp": cached.get("timestamp"), **result})
                # Admin fallback
                if is_admin:
                    for (cache_uid, cache_page), c in _main._completed_results.items():
                        if cache_page == page:
                            return json.dumps({"page": page, "status": "done", "timestamp": c.get("timestamp"), **c.get("result", {})})
                return json.dumps({"page": page, "status": "no_active_result",
                                   "hint": f"Run an analysis on the {page.replace('_', ' ').title()} page first."})

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

            if page in ("uav_monitor", "uav_perception", "uav_gnss", "uav_certification",
                        "uav_swarm", "uav_mission_plan"):
                # UAV plugin pages are stateless aggregations — point the LLM at the
                # dedicated UAV tools that actually carry data.
                page_to_tool = {
                    "uav_monitor":       "get_uav_overview",
                    "uav_perception":    "uav_run_perception_attack (write) or get_uav_overview",
                    "uav_gnss":          "get_uav_gnss_status",
                    "uav_certification": "get_uav_certificates / get_uav_industry_comparison / get_uav_regulatory_evidence",
                    "uav_swarm":         "get_uav_overview (swarm snapshot is part of the overview payload)",
                    "uav_mission_plan":  "uav_review_mission_plan (write action — needs plan_text)",
                }
                return json.dumps({
                    "page": page, "status": "use_dedicated_tool",
                    "tool": page_to_tool[page],
                    "hint": "The UAV plugin (chapter 6) exposes typed tools for each operator surface; call the named tool above instead of get_page_result.",
                })

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

        # ── UAV / Aerial Defense plugin (chapter 6) ─────────────────────
        # All UAV business logic lives in plugins.uav.services and is called
        # synchronously here so the dispatcher works inside the FastAPI event
        # loop without coroutine juggling.
        elif name == "get_uav_overview":
            from plugins.uav import services as _uav_svc
            payload = _uav_svc.overview_payload()
            payload["do_326a_crossings_db"] = {
                c["config_key"]: c["do_326a_crossing_db"] for c in payload["ew_curves"]
            }
            payload["plugin_path"] = "robustidps_web_app/plugins/uav/"
            return json.dumps(payload)

        elif name == "get_uav_ew_bench_curves":
            from plugins.uav import services as _uav_svc
            return json.dumps(_uav_svc.ew_curves_payload())

        elif name == "get_uav_certificates":
            try:
                from plugins.uav import services as _uav_svc
                return json.dumps(_uav_svc.certificates_payload())
            except Exception as e:
                return json.dumps({"status": "model_not_available", "error": str(e),
                                   "hint": "Run scripts/run_phase_a.sh; certificates need torch + CT-TGNN."})

        elif name == "get_uav_gnss_status":
            from plugins.uav import services as _uav_svc
            return json.dumps(_uav_svc.gnss_payload())

        elif name == "get_uav_industry_comparison":
            from plugins.uav import services as _uav_svc
            return json.dumps(_uav_svc.industry_payload())

        elif name == "get_uav_regulatory_evidence":
            from plugins.uav import services as _uav_svc
            return json.dumps({"entries": _uav_svc.REGULATORY})

        elif name == "uav_run_perception_attack":
            try:
                from plugins.uav import services as _uav_svc
                return json.dumps(_uav_svc.perception_attack_payload(
                    attack=args.get("attack", "pgd"),
                    epsilon=float(args.get("epsilon", 4 / 255)),
                    pgd_steps=int(args.get("pgd_steps", 20)),
                    sample_index=int(args.get("sample_index", 0)),
                ))
            except Exception as e:
                return json.dumps({"status": "attack_run_failed", "error": str(e),
                                   "hint": "Verify torch is installed and the synthetic dataset loads."})

        elif name == "uav_review_mission_plan":
            from plugins.uav import services as _uav_svc
            return json.dumps(_uav_svc.mission_plan_review_payload(
                plan_text=args["plan_text"],
                plan_format=args.get("plan_format", "plan"),
            ))

        # ── Agent Studio + Security plugin ──────────────────────────────
        elif name == "agent_scanner_run":
            from dataclasses import asdict as _asdict
            from plugins.agent_studio.scanner import run_scan as _scan
            report = _scan(args["text"], input_kind=args.get("input_kind", "mcp_manifest"))
            return json.dumps({
                "input_kind": report.input_kind,
                "input_size_chars": report.input_size_chars,
                "n_checks_run": report.n_checks_run,
                "n_findings": report.n_findings,
                "severity_breakdown": report.severity_breakdown,
                "results": [_asdict(r) for r in report.results],
            })

        elif name == "agent_studio_sku_catalog":
            from plugins.agent_studio.api import SKU_CATALOG as _skus
            return json.dumps({"skus": _skus})

        elif name == "assemble_dossier":
            from plugins.dossier import assemble_dossier as _assemble
            return json.dumps(_assemble(
                vertical=args["vertical"],
                audience=args.get("audience", "auditor"),
            ))

        elif name == "get_uav_phase_b_status":
            from plugins.uav import services as _uav_svc
            return json.dumps(_uav_svc.phase_b_status_payload())

        elif name == "get_uav_swarm_snapshot":
            from plugins.uav import services as _uav_svc
            return json.dumps(_uav_svc.swarm_snapshot_payload())

        elif name == "get_uav_datasets":
            from plugins.uav.datasets_manifest import manifest_payload
            return json.dumps(manifest_payload())

        elif name == "query_uav_ew_bench_at":
            from plugins.uav.uav_defense.ew_bench import (
                UAV_EW_BENCH_2026, mission_completion_curve,
            )
            js = max(0, min(40, int(args.get("js_db", 20))))
            points = {}
            for key in UAV_EW_BENCH_2026["configurations"]:
                curve = mission_completion_curve(key)
                pt = next((p for p in curve["points"] if p["js_db"] == js),
                          curve["points"][0])
                points[key] = {
                    "label": curve["label"], "mcr": pt["mcr"],
                    "ci_low": pt["ci_low"], "ci_high": pt["ci_high"],
                    "above_do_326a": pt["mcr"] >= 0.90,
                }
            return json.dumps({
                "js_db": js, "do_326a_threshold": 0.90,
                "points": points,
                "operational_target_js_db": 20,
            })

        elif name == "get_agent_studio_tiers":
            from plugins.agent_studio.entitlement import public_catalog
            return json.dumps(public_catalog())

        elif name == "get_uav_ew_bench_source":
            from plugins.uav.uav_defense.ew_bench import latest_measured
            measured = latest_measured()
            if measured is None:
                return json.dumps({
                    "source": "phase_a_chapter_anchored",
                    "description": "Linear interpolation of chapter 6 Fig. 6.x 9-point anchors per configuration",
                    "hint": "POST /api/uav/ew-bench/run to produce a measured Phase D curve via the physics-informed simulator (30 s on CPU)",
                })
            source = measured.get("source", "phase_d_simulator")
            payload = {
                "source": source,
                "phase": measured["benchmark"].get("phase", "D"),
                "n_total_flights": measured["benchmark"].get("n_total_flights", 0),
                "do_326a_crossings_db": {c["config_key"]: c["do_326a_crossing_db"]
                                          for c in measured["curves"]},
            }
            if "trajectory_sources" in measured["benchmark"]:
                payload["trajectory_sources"] = measured["benchmark"]["trajectory_sources"]
                payload["n_real_trajectories"] = measured["benchmark"].get("n_real_trajectories", 0)
            return json.dumps(payload)

        elif name == "get_uav_flight_trajectories":
            from plugins.uav.uav_defense.datasets.flight_trajectories import manifest_payload
            return json.dumps(manifest_payload())

        elif name == "get_uav_attack_catalog":
            from plugins.uav.uav_defense.attacks import ATTACK_CATALOG
            return json.dumps({"attacks": ATTACK_CATALOG, "total": len(ATTACK_CATALOG)})

        elif name == "step_uav_fleet":
            from plugins.uav.fleet_simulator import step_fleet
            return json.dumps(step_fleet(
                session_id=args.get("session_id", "copilot-session"),
                per_uav_attack=args.get("per_uav_attack") or {},
                js_db=float(args.get("js_db", 10)),
                dt_s=float(args.get("dt_s", 1.0)),
            ))

        elif name == "run_agent_eval":
            from dataclasses import asdict as _asdict
            from plugins.agent_studio.eval_harness import run_eval
            run = run_eval(args["agent_spec"])
            return json.dumps({
                "run_id": run.run_id, "agent_name": run.agent_name,
                "overall_score": run.overall_score,
                "overall_verdict": run.overall_verdict,
                "results": [_asdict(r) for r in run.results],
            })

        elif name == "run_agent_red_team":
            from dataclasses import asdict as _asdict
            from plugins.agent_studio.red_team import run_red_team
            run = run_red_team(args["target_spec"])
            return json.dumps({
                "run_id": run.run_id, "target_name": run.target_name,
                "n_probes": run.n_probes, "n_findings": run.n_findings,
                "severity_breakdown": run.severity_breakdown,
                "atlas_chain": run.atlas_chain,
                "results": [_asdict(r) for r in run.results if r.triggered][:20],
            })

        elif name == "get_agent_runtime_snapshot":
            from plugins.agent_studio.runtime_monitor import snapshot
            return json.dumps(snapshot(args.get("agent_id")))

        elif name == "scan_agent_model_supply_chain":
            from dataclasses import asdict as _asdict
            from plugins.agent_studio.supply_chain import scan_model
            return json.dumps(_asdict(scan_model(args["model_id"], args.get("spec", {}))))

        elif name == "get_agent_red_team_catalog":
            from plugins.agent_studio.red_team import catalog
            return json.dumps(catalog())

        elif name == "run_agent_red_team_garak":
            from dataclasses import asdict as _asdict
            from plugins.agent_studio.red_team_garak import run_garak
            run = run_garak(args["target_spec"])
            return json.dumps({
                "run_id": run.run_id, "target_name": run.target_name,
                "n_probes": run.n_probes, "n_findings": run.n_findings,
                "severity_breakdown": run.severity_breakdown,
                "atlas_chain": run.atlas_chain,
                "results": [_asdict(r) for r in run.results if r.triggered][:20],
            })

        elif name == "scan_agent_supply_chain_live":
            from dataclasses import asdict as _asdict
            from plugins.agent_studio.supply_chain import scan_model
            from plugins.agent_studio.supply_chain_hf import fetch_hf_metadata
            spec = dict(args.get("spec") or {})
            hf = fetch_hf_metadata(args["model_id"])
            if hf is not None:
                for k, v in hf.items():
                    spec.setdefault(k, v)
            return json.dumps({**_asdict(scan_model(args["model_id"], spec)),
                               "hf_enrichment_used": hf is not None})

        elif name == "create_agent_studio_checkout":
            from plugins.agent_studio.billing import create_checkout_session
            return json.dumps(create_checkout_session(
                args["email"],
                args.get("tier", "pro"),
                int(args.get("trial_days", 14)),
            ))

        elif name == "get_agent_studio_customer":
            from plugins.agent_studio.billing import get_customer
            data = get_customer(args["customer_id"])
            if data is None:
                return json.dumps({"error": "Customer not found", "customer_id": args["customer_id"]})
            return json.dumps(data)

        elif name == "list_agent_studio_templates":
            from plugins.agent_studio.templates import list_templates, template_stats
            tier = args.get("tier")
            return json.dumps({
                "templates": list_templates(tier),
                "stats": template_stats(),
            })

        elif name == "get_agent_studio_template":
            from plugins.agent_studio.templates import get_template
            data = get_template(args["template_id"])
            if data is None:
                return json.dumps({"error": "Unknown template", "template_id": args["template_id"]})
            return json.dumps(data)

        elif name == "get_agent_studio_admin_stats":
            from plugins.agent_studio.billing import grant_stats
            return json.dumps(grant_stats())

        elif name == "get_agent_studio_session":
            from plugins.agent_studio.sessions import get_session
            data = get_session(args["session_id"])
            if data is None:
                return json.dumps({"error": "Session not found", "session_id": args["session_id"]})
            return json.dumps(data)

        elif name == "get_agent_studio_session_stats":
            from plugins.agent_studio.sessions import stats as _session_stats
            return json.dumps(_session_stats())

        elif name == "get_agent_studio_eval_history":
            from plugins.agent_studio.eval_harness import history as _eval_hist
            return json.dumps({"runs": _eval_hist(int(args.get("limit", 10)))})

        elif name == "get_agent_studio_red_team_history":
            from plugins.agent_studio.red_team import history as _rt_hist
            return json.dumps({"runs": _rt_hist(int(args.get("limit", 10)))})

        elif name == "get_agent_studio_supply_chain_history":
            from plugins.agent_studio.supply_chain import history as _sc_hist
            return json.dumps({"scans": _sc_hist(int(args.get("limit", 10)))})

        elif name == "list_agent_studio_sessions":
            from plugins.agent_studio.sessions import list_sessions
            return json.dumps({
                "sessions": list_sessions(args.get("customer_id"),
                                          int(args.get("limit", 50))),
            })

        elif name == "get_agent_studio_activity":
            from plugins.agent_studio.eval_harness import history as _eh
            from plugins.agent_studio.red_team import history as _rth
            from plugins.agent_studio.supply_chain import history as _sch
            from plugins.agent_studio.sessions import list_sessions, stats as _sst
            from plugins.agent_studio.runtime_monitor import snapshot as _rts
            from plugins.agent_studio.billing import grant_stats
            from plugins.agent_studio.deployments import list_deployments, stats as _dst
            lim = int(args.get("limit", 5))
            return json.dumps({
                "eval_runs":           _eh(lim),
                "red_team_runs":       _rth(lim),
                "supply_chain_scans":  _sch(lim),
                "sessions":            list_sessions(None, lim),
                "session_stats":       _sst(),
                "runtime_snapshot":    _rts(),
                "billing_admin_stats": grant_stats(),
                "deployments":         list_deployments(None)[:lim],
                "deployment_stats":    _dst(),
            })

        elif name == "list_agent_studio_deployments":
            from plugins.agent_studio.deployments import list_deployments, stats
            return json.dumps({
                "deployments": list_deployments(args.get("customer_id"),
                                                bool(args.get("include_retired", False))),
                "stats": stats(),
            })

        elif name == "get_agent_studio_deployment":
            from plugins.agent_studio.deployments import get_deployment
            data = get_deployment(args["deployment_id"])
            if data is None:
                return json.dumps({"error": "Deployment not found",
                                   "deployment_id": args["deployment_id"]})
            return json.dumps(data)

        elif name == "get_agent_studio_llm_info":
            from plugins.agent_studio.llm_dispatch import info
            return json.dumps(info())

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
- **Auto-Investigation**: One-click agentic investigation — autonomous triage, incident chaining, and report generation (page="auto_investigation")
- **Threat Hunt**: Natural language threat hunting — type queries like "show all SSH brute force with confidence above 90%" (page="threat_hunt")
- **Incident Reports**: Auto-generated incident reports with executive summary, threat landscape, timeline, recommendations (page="incident_reports")
- **Threat Intel**: IP reputation scoring, geo-location, threat scores for detected attackers (page="threat_intel")
- **Rule Generator**: Auto-generate Suricata/Snort IDS rules from detected attacks (page="rule_generator")
- **CVE Mapper**: Map detected web attacks to relevant CVE IDs with CVSS scores and remediation (page="cve_mapper")

**UAV / Aerial Defense plugin (chapter 6 of the parent dissertation)** — the platform also hosts a six-page UAV/drone defense surface mounted at `robustidps_web_app/plugins/uav/`. The kernel is unchanged; the UAV vertical is reached through dedicated tools rather than `get_page_result`:
- `get_uav_overview` — three-tier method assignment, edge profile, UAV-EW-Bench-2026 metadata, Phase-A metrics.json
- `get_uav_ew_bench_curves` — Mission-Completion-Rate vs Jamming-to-Signal Ratio (J/S, dB) for four configs: No-Def PX4, CAF-CNN+PX4, Seq2Seq Tr.+PX4, and the M1+M4+M6+M7 framework. Headline number: at J/S=20 dB the framework holds MCR=0.94 vs 0.27 for the unprotected baseline.
- `get_uav_certificates` — Lipschitz–Grönwall radius, Cohen randomized-smoothing radius, PAC-Bayes bound, (ε,δ)-DP budget — live-recomputed.
- `get_uav_gnss_status` — 8-satellite sky plot, spoof-flagged SVs, fleet disagreement, autopilot mode (nominal / GNSS-degraded).
- `get_uav_industry_comparison` — chapter 6 Table 6.x vs Anduril Lattice / Shield AI Hivemind / Skydio Autonomy / PX4 Auterion Enterprise across 7 criteria.
- `get_uav_regulatory_evidence` — RU instruments (RF Decree №1701, GOST R 59276-2020 / 56122-2014, GOST R 34.10-2012) and INT instruments (NIST AI RMF, EU AI Act Art. 15, DO-326A/ED-202A) mapped to satisfying framework methods.
- WRITE ACTIONS — call only when the user explicitly asks: `uav_run_perception_attack` (FGSM/PGD on a sample), `uav_review_mission_plan` (CyberSecLLM audit of a .plan / JSON-LD / OWL document).
When the user asks about UAVs, drones, aerial defense, GNSS spoofing, MCR, J/S, EW-Bench, DO-326A airworthiness, RF Decree 1701, or chapter 6, prefer these tools over `get_page_result`.

**Agent Studio + Agent Security plugin (venture-plan commercial vertical)** — the platform hosts an Agent Studio surface mounted at `plugins/agent_studio/`. It exposes a free MCP / agent scanner (the top-of-funnel wedge) and a five-SKU catalog (Agent Lab, Agent Factory, Agent Red Team, Continuous Defense, Secure-by-Design Build). Dedicated tools:
- `agent_scanner_run` — pass a pasted MCP manifest / tool-list JSON / agent system prompt / agent card; returns 12 checks across OWASP Agentic Top 10 (ASI01–ASI10) with severity and remediation. Call whenever the user pastes anything resembling an MCP server definition, tool list, system prompt, or agent.json.
- `agent_studio_sku_catalog` — pricing, duration, and summary for the five SKUs. Call when the user asks about Agent Studio pricing, the flywheel, or what RobustIDPS sells commercially in the agentic space.

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


async def _openai_compatible_call(
    messages: list[ChatMessage],
    api_key: str,
    model: str,
    db: Session,
    base_url: str | None,
    default_model: str,
    active_ids_models: list[str] = None,
    user: Optional["User"] = None,
    supports_tools: bool = True,
) -> str:
    """Shared OpenAI-compatible chat completion + tool-loop.

    Used by OpenAI, Google Gemini (via the OpenAI-compatible Gemini endpoint),
    and DeepSeek. Falls back to a tool-less single round if `supports_tools`
    is False or if the provider returns an error on the `tools` field.
    """
    import openai

    client = openai.OpenAI(api_key=api_key, base_url=base_url) if base_url \
             else openai.OpenAI(api_key=api_key)
    system_prompt = _build_system_prompt(active_ids_models)
    api_messages = [{"role": "system", "content": system_prompt}]
    api_messages += [{"role": m.role, "content": m.content} for m in messages]
    tools = _tools_to_openai_functions() if supports_tools else None

    def _call(msgs):
        kwargs = {"model": model or default_model, "messages": msgs, "max_tokens": 4096}
        if tools is not None:
            kwargs["tools"] = tools
        return client.chat.completions.create(**kwargs)

    try:
        response = _call(api_messages)
    except Exception:
        if tools is None:
            raise
        # Provider rejected tools — retry once without
        kwargs = {"model": model or default_model, "messages": api_messages, "max_tokens": 4096}
        response = client.chat.completions.create(**kwargs)
        return response.choices[0].message.content or ""

    for _ in range(5):
        choice = response.choices[0]
        tool_calls = getattr(choice.message, "tool_calls", None)
        if choice.finish_reason != "tool_calls" or not tool_calls:
            break
        api_messages.append(choice.message)
        for tc in tool_calls:
            args = json.loads(tc.function.arguments) if tc.function.arguments else {}
            result = _exec_tool(tc.function.name, args, db, user=user)
            api_messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result,
            })
        response = _call(api_messages)

    return response.choices[0].message.content or ""


async def _openai_stream(messages: list[ChatMessage], api_key: str, model: str, db: Session, active_ids_models: list[str] = None, user: Optional["User"] = None) -> AsyncIterator[str]:
    content = await _openai_compatible_call(
        messages, api_key, model, db,
        base_url=None,
        default_model=PROVIDER_DEFAULTS["openai"],
        active_ids_models=active_ids_models, user=user, supports_tools=True,
    )
    yield content


# ---------------------------------------------------------------------------
# Provider: Google Gemini (OpenAI-compatible endpoint, supports tools)
# ---------------------------------------------------------------------------

async def _google_stream(messages: list[ChatMessage], api_key: str, model: str, db: Session, active_ids_models: list[str] = None, user: Optional["User"] = None) -> AsyncIterator[str]:
    content = await _openai_compatible_call(
        messages, api_key, model, db,
        base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        default_model=PROVIDER_DEFAULTS["google"],
        active_ids_models=active_ids_models, user=user, supports_tools=True,
    )
    yield content


# ---------------------------------------------------------------------------
# Provider: DeepSeek (OpenAI-compatible, supports tools)
# ---------------------------------------------------------------------------

async def _deepseek_stream(messages: list[ChatMessage], api_key: str, model: str, db: Session, active_ids_models: list[str] = None, user: Optional["User"] = None) -> AsyncIterator[str]:
    content = await _openai_compatible_call(
        messages, api_key, model, db,
        base_url="https://api.deepseek.com",
        default_model=PROVIDER_DEFAULTS["deepseek"],
        active_ids_models=active_ids_models, user=user, supports_tools=True,
    )
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
