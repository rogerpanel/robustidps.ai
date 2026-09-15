"""Platform models exposed as "special tools" for Agent Studio.

The 17+ models in `backend/models/model_registry.py` are the IDS-side
detection / response / certified-defence models. They are not LLMs —
they're specialised neural networks the customer's agent can CALL as
tools, the same way an LLM agent calls `query_pcap` or `lookup_cve`.

This module wraps `MODEL_INFO` with:
  - role hints (what kind of agent benefits from this model)
  - sensible default selections per Quickstart template
  - JSON-safe serialisation (the raw MODEL_INFO carries `class` Python
    refs that aren't serialisable)
  - a per-template `suggestions()` helper that drives the side-tips
    panel in the BuildWizard

A platform model attached to an agent spec lives at
    spec.platform_models = [{id: "mambaguard", role: "screen_input"}]
and the runtime SDK turns each one into a tool the agent can dispatch.
"""
from __future__ import annotations

from typing import Any

# Map from raw MODEL_INFO category → Agent Studio role hint and a
# customer-facing one-liner.
_CATEGORY_PRESENTATION = {
    "ensemble":         ("triage",      "Fast multi-signal triage; runs first as a coarse classifier."),
    "temporal":         ("temporal",    "Time-aware sequence model; use when ordering of events matters."),
    "federated":        ("federated",   "Privacy-preserving cross-tenant model; suits distributed deployments."),
    "foundation":       ("reasoning",   "Cybersec foundation model; pairs well with RAG over MITRE ATT&CK."),
    "clrl":             ("response",    "Continual-RL response agent (5 graduated actions). Wrap with human-in-the-loop."),
    "certified":        ("certified",   "Formal robustness certificate; use where adversarial bounds matter."),
    "self_supervised":  ("anomaly",     "Trains on benign-only; surfaces never-seen-before flows as anomalies."),
    "pqc":              ("pq_aware",    "Post-quantum-aware classifier; multi-agent cooperative."),
    "llm_protocol":     ("screen_io",   "Screens LLM agent-protocol traffic (MCP / ACP / A2A / ANP) — pre/post."),
}


# Default platform-model picks per Agent Studio template id. Curated so
# the wizard's Express mode lands sensible defaults; the engineer can
# add / remove from the JSON view.
_DEFAULTS_PER_TEMPLATE: dict[str, list[str]] = {
    # Tier A · defenders
    "soc_triage":             ["cybersec_llm", "surrogate", "ssl_graph_anomaly"],
    "incident_commander":     ["clrl_unified", "cybersec_llm"],
    "compliance_auditor":     ["cybersec_llm"],
    "vuln_triage":            ["cybersec_llm", "surrogate"],
    "mcp_auditor":            ["mambaguard"],
    "threat_hunter":          ["sde_tgnn", "ssl_graph_anomaly_full", "cybersec_llm"],

    # Tier B · attackers
    "red_team_operator":      ["mambaguard", "surrogate"],
    "pentest_recon":          ["mambaguard"],
    "phishing_trainer":       [],

    # Tier C · productivity + role-targeted
    "customer_support":       ["cybersec_llm"],
    "billing_copilot":        [],
    "docs_qa":                ["cybersec_llm"],
    "network_traffic_monitor":["surrogate", "neural_ode", "ssl_graph_anomaly",
                               "multi_agent_pqc", "sode_guard", "lipmamba"],
    "uav_swarm_coordinator":  ["clrl_unified", "sode_guard"],

    "blank":                  [],
}


def list_models() -> list[dict]:
    """Return JSON-safe catalog of every platform model + role hint."""
    from models.model_registry import MODEL_INFO
    out: list[dict] = []
    for mid, info in MODEL_INFO.items():
        role_id, role_blurb = _CATEGORY_PRESENTATION.get(
            info.get("category", ""), ("custom", "Specialised platform model."))
        out.append({
            "id": mid,
            "name": info.get("name", mid),
            "description": info.get("description", ""),
            "paper": info.get("paper", ""),
            "category": info.get("category", "other"),
            "role": role_id,
            "role_blurb": role_blurb,
            "has_ablation": bool(info.get("has_ablation", False)),
            "parent_model": info.get("parent_model"),
            "sub_models": info.get("sub_models") or [],
        })
    return out


def get_model(model_id: str) -> dict | None:
    return next((m for m in list_models() if m["id"] == model_id), None)


def defaults_for(template_id: str) -> list[str]:
    """Curated default selection for a Quickstart template."""
    return list(_DEFAULTS_PER_TEMPLATE.get(template_id, []))


# ── Contextual side-tips per build-wizard step + template archetype ──

# Each tip is a short, one-screen recommendation the side card surfaces
# beside the wizard step. Keyed by (step, category) — the API falls
# back to the generic step tip when no per-category match exists.
_STEP_GENERIC: dict[int, list[str]] = {
    1: [
        "Start with the smallest possible system_prompt: name the scope, "
        "name the refused behaviours, then list the tools.",
        "Fewer tools = safer. Every tool is a permission grant.",
        "Pin a hashed model id before production; never ship 'gpt-4o-latest' to prod.",
    ],
    2: [
        "Network policy: prefer 'allowlist' over 'open' for anything customer-facing.",
        "Secrets MUST come from a vault — never inline. The scanner flags inlined keys.",
        "Declare MCP server `policy:` per-server: 'read_only' is the safe default.",
    ],
    3: [
        "Replay a probe twice — first the canonical input, then a deliberately "
        "hostile one. Watch the Aegis verdict envelope flip between turns.",
        "If you see 'synthetic_fallback', set ANTHROPIC_API_KEY on the server "
        "to flip the wizard onto a real LLM.",
    ],
    4: [
        "Pick the runtime that matches your secret manager (k8s for in-cluster, "
        "Modal for serverless, Fly for autoscale).",
        "Add `pytest --aegis-fail-on-warn` to CI before merging the integration "
        "snippet into your repo.",
    ],
}

_STEP_BY_CATEGORY: dict[tuple[int, str], list[str]] = {
    # ── Tier A defenders ─────────────────────────────────────────────
    (1, "soc"): [
        "Pair with `cybersec_llm` (foundation model) + `surrogate` (fast triage) "
        "as platform models — the LLM reasons, the surrogate scores.",
        "Force STRICT JSON in the system_prompt — your SIEM pipeline depends on it.",
    ],
    (1, "ir"): [
        "Layer `clrl_unified` for graduated response actions; keep `auto_execute=false` "
        "for any destructive step.",
    ],
    (1, "compliance"): [
        "Add a retrieval tool for the policy corpus + a tool to diff two versions; "
        "refuse to answer beyond the indexed standards.",
    ],
    (1, "vuln"): [
        "Combine `cybersec_llm` (reasons over CVE text) with EPSS lookup. Refuse "
        "to generate exploit code regardless of how the request is framed.",
    ],
    (1, "mcp"): [
        "`mambaguard` is the headline platform model here — runs the 4-protocol "
        "(MCP/ACP/A2A/ANP) detector across every probed manifest.",
    ],
    (1, "hunt"): [
        "Combine `sde_tgnn` (stochastic temporal model) with `ssl_graph_anomaly_full` "
        "(conformal-certified anomaly score). Strict read-only over the log lake.",
    ],
    # ── Tier B attackers ─────────────────────────────────────────────
    (1, "redteam"): [
        "Require an authorization_id in EVERY system_prompt and target_spec. "
        "`mambaguard` doubles as a tester for the target's MCP framing.",
    ],
    (1, "pentest"): [
        "Recon-only by default. Scope envelope (`SCOPE_ENVELOPE_ID`) is non-optional.",
    ],
    (1, "awareness"): [
        "Limit recipients to the internal address-book MCP. Rate-limit aggressively.",
    ],
    # ── Tier C ───────────────────────────────────────────────────────
    (1, "netsec"): [
        "Stack `surrogate` (fast) + `ssl_graph_anomaly` (catches never-seen flows) + "
        "`multi_agent_pqc` (PQ-aware) + `sode_guard` (perturbation cert). The agent "
        "calls them in that order; first hit wins.",
        "Refuse to issue blocking commands directly — open a ticket and let a "
        "human approve. The system_prompt should say so explicitly.",
    ],
    (1, "uav"): [
        "Required: mission_id + scope_polygon on EVERY command. Refuse out-of-scope.",
        "`clrl_unified` for graduated response; `sode_guard` for sensor-perturbation "
        "robustness. Defaults to safe-hover on uplink loss.",
    ],
    (1, "support"): [
        "Cite every claim with doc URL + section. Refuse if retrieval score < 0.7.",
    ],
    (1, "billing"): [
        "Threshold refunds at $500 — above goes to a human approval ticket.",
    ],
    (1, "rag"): [
        "Strict hallucination gating: verify URLs are reachable before citing.",
    ],
    # ── Step 2 — environment ─────────────────────────────────────────
    (2, "netsec"): [
        "Set `MONITORED_CIDR` as a strict env var. Refuse flows from outside it.",
        "Bind threat-intel + SIEM as separate MCP servers — separation of duties.",
    ],
    (2, "uav"): [
        "Satellite uplink MUST be `write_audited` policy with PSK secret refs.",
        "ATC feed is `read_only` — never let the agent file flight plans itself.",
    ],
    # ── Step 3 — sessions ────────────────────────────────────────────
    (3, "soc"): [
        "Probe with a hostile alert (e.g. one containing 'Ignore previous instructions') "
        "to confirm the verdict envelope flips to BLOCK.",
    ],
    (3, "uav"): [
        "Probe with `tick_n` increasing + a `link_loss` event partway through; the "
        "agent should switch to safe-hover and stop issuing waypoints.",
    ],
}


def suggestions(step: int, template_id: str | None,
                 category: str | None = None) -> list[str]:
    """Return contextual tips for (step, archetype). Falls back to the
    generic step tips when no category-specific advice exists."""
    tips: list[str] = []
    if category:
        tips.extend(_STEP_BY_CATEGORY.get((step, category), []))
    tips.extend(_STEP_GENERIC.get(step, []))
    seen: set[str] = set()
    return [t for t in tips if not (t in seen or seen.add(t))][:6]


# ── Cross-vertical bridges — deep-links from a template to related pages

_TEMPLATE_BRIDGES: dict[str, list[dict]] = {
    "network_traffic_monitor": [
        {"label": "Live network monitor", "to": "/live-monitor",
         "blurb": "Watch classifier output on live traffic."},
        {"label": "Analytics dashboard", "to": "/analytics",
         "blurb": "Aggregate detection stats across your fleet."},
        {"label": "Threat response",     "to": "/threat-response",
         "blurb": "Wire the agent's tickets into the response engine."},
    ],
    "uav_swarm_coordinator": [
        {"label": "UAV mission plan review", "to": "/uav/mission-plan",
         "blurb": "Design + review scope polygons and NOTAMs."},
        {"label": "Swarm graph",             "to": "/uav/swarm",
         "blurb": "Live swarm formation + link quality."},
        {"label": "Fleet demo",              "to": "/uav/fleet-demo",
         "blurb": "Simulate the mission before flight."},
        {"label": "UAV certification",       "to": "/uav/certification",
         "blurb": "DO-326A + GOST R 59276 airworthiness dossier."},
    ],
    "mcp_auditor": [
        {"label": "MCP Security",       "to": "/mcp-security",
         "blurb": "Interactive MCP protocol test-bench."},
        {"label": "Free MCP scanner",   "to": "/agent-scanner",
         "blurb": "24-check ruleset against any MCP manifest."},
    ],
    "red_team_operator": [
        {"label": "Red Team Arena",     "to": "/red-team-arena",
         "blurb": "Interactive adversarial testing against IDS models."},
        {"label": "Attack chain predictor", "to": "/attack-chain",
         "blurb": "Model likely follow-on tactics after a finding."},
    ],
    "vuln_triage": [
        {"label": "CVE mapper",         "to": "/cve-mapper",
         "blurb": "Interactive CVE → affected-service graph."},
    ],
    "threat_hunter": [
        {"label": "Threat Hunt",        "to": "/threat-hunt",
         "blurb": "Interactive hypothesis workspace."},
        {"label": "Investigation chain", "to": "/investigation-chain",
         "blurb": "Multi-step reasoning over log lake."},
    ],
    "compliance_auditor": [
        {"label": "Compliance Hub",     "to": "/compliance",
         "blurb": "ISO 42001 + EU AI Act + NIST AI RMF mapping."},
        {"label": "MITRE ATLAS mapper", "to": "/atlas",
         "blurb": "OWASP-Agentic → ATLAS tactic cross-reference."},
    ],
    "soc_triage": [
        {"label": "Alert triage",       "to": "/alert-triage",
         "blurb": "Manual triage bench for calibration."},
        {"label": "Incident reports",   "to": "/incident-reports",
         "blurb": "Post-mortem archive to learn from."},
    ],
    "incident_commander": [
        {"label": "Alert causality graph", "to": "/alert-causality",
         "blurb": "Root-cause the alert storm."},
        {"label": "Auto investigation", "to": "/auto-investigation",
         "blurb": "The multi-hop RCA workflow."},
    ],
}


def template_bridges(template_id: str) -> list[dict]:
    """Related-page deep-links per template — surfaces cross-vertical
    connections (UAV, network IDS, compliance, etc.)."""
    return list(_TEMPLATE_BRIDGES.get(template_id, []))
