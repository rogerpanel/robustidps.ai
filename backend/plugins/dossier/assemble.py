"""Vertical-agnostic dossier assembler.

Both the UAV vertical and the Agent Studio vertical (and any future
vertical mounted as a plugin) feed evidence through the same canonical
shape so the React `/dossier` route can render them with one component.
"""
from __future__ import annotations

import json
import subprocess
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

DossierVertical = Literal["uav", "agent_studio"]


@dataclass
class DossierSection:
    title: str
    body: dict


def _git_commit_short() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short=12", "HEAD"], stderr=subprocess.DEVNULL,
        )
        return out.decode().strip()
    except Exception:
        return "unknown"


def list_verticals() -> list[dict]:
    return [
        {"id": "uav", "label": "UAV / Aerial Defense", "chapter": "6"},
        {"id": "agent_studio", "label": "Agent Studio + Agent Security", "chapter": "venture plan"},
    ]


def _uav_dossier(dossier_id: str, audience: str) -> dict:
    from plugins.uav import services as _uav

    overview = _uav.overview_payload()
    certs = _uav.certificates_payload()
    industry = _uav.industry_payload()
    framework = next(c for c in overview["ew_curves"] if c["config_key"] == "framework")
    no_def = next(c for c in overview["ew_curves"] if c["config_key"] == "no_def")

    return {
        "dossier_id": dossier_id,
        "vertical": "uav",
        "vertical_label": "UAV / Aerial Defense",
        "audience": audience,
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "commit": _git_commit_short(),
        "subject": {
            "platform": "RobustIDPS.ai — UAV / Aerial Defense plugin (chapter 6)",
            "plugin_path": "robustidps_web_app/plugins/uav/",
            "kernel_modified": False,
            "tiers": overview["tiers"],
            "edge_profile": overview["edge_profile"],
        },
        "operational_headline": {
            "metric": "Mission-Completion-Rate vs Jamming-to-Signal Ratio",
            "benchmark": overview["benchmark"]["name"],
            "regulatory_threshold": overview["benchmark"]["regulatory_threshold"],
            "operational_target": overview["benchmark"]["operational_target"],
            "framework_do_326a_crossing_db": framework["do_326a_crossing_db"],
            "unprotected_do_326a_crossing_db": no_def["do_326a_crossing_db"],
            "advantage_db": (
                (framework["do_326a_crossing_db"] or 0) - (no_def["do_326a_crossing_db"] or 0)
                if framework["do_326a_crossing_db"] and no_def["do_326a_crossing_db"]
                else None
            ),
        },
        "certificates": certs,
        "attack_coverage": {
            "white_box": ["FGSM", "PGD", "Carlini-Wagner"],
            "black_box": ["HopSkipJump", "BoundaryAttack"],
            "training_stage": ["Clean-label feature-collision poisoning"],
            "physical": ["Adversarial patches (deferred to Phase B)",
                         "GNSS spoofing (TEXBAT scenarios 1, 3, 8)"],
        },
        "industry_position": industry,
        "regulatory_mapping": _uav.REGULATORY,
        "reproducibility": {
            "phase_a_runner": "bash backend/plugins/uav/uav_defense/scripts/run_phase_a.sh",
            "wall_clock_cpu_minutes": 5,
            "wall_clock_gpu_minutes": 1,
            "seeds": [42, 7, 13],
            "synthetic_corpus": "TEXBAT-like CAF generator (chapter §6.7)",
            "real_corpus": "TEXBAT (UT-RNL registration) + AU-AIR (open)",
            "phase_b_pending": [
                "Replace synthetic CAF with real TEXBAT IQ",
                "Wire AirSim / PX4 SITL into UAV-EW-Bench-2026 harness",
                "Progressive adversarial distillation lifts CW κ=5 robust acc from 0.00",
            ],
        },
    }


def _agent_studio_dossier(dossier_id: str, audience: str,
                          scan_report: dict | None = None) -> dict:
    from plugins.agent_studio.api import SKU_CATALOG
    from plugins.agent_studio.scanner import SCANNER_CHECKS

    return {
        "dossier_id": dossier_id,
        "vertical": "agent_studio",
        "vertical_label": "Agent Studio + Agent Security",
        "audience": audience,
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "commit": _git_commit_short(),
        "subject": {
            "platform": "RobustIDPS.ai — Agent Studio plugin (venture plan)",
            "plugin_path": "plugins/agent_studio/",
            "skus_offered": SKU_CATALOG,
        },
        "scan_report": scan_report,
        "attack_coverage": {
            "owasp_agentic_top_10": [
                "ASI01 Goal Hijack", "ASI02 Unauthenticated Resource",
                "ASI03 Resource Exhaustion", "ASI04 Credential Leakage",
                "ASI05 Hidden Side-Effects", "ASI06 Excessive Privilege",
                "ASI07 Unguarded LLM Routing", "ASI08 Memory Without TTL",
                "ASI09 Weak Trust Boundary", "ASI10 Rogue Agent Identity",
            ],
            "mcp_framing": [c.code for c in SCANNER_CHECKS if c.code.startswith("MCP-")],
        },
        "industry_position": {
            "vendors": ["Lakera Guard", "Noma", "Mindgard", "Adversa", "Pillar",
                        "RobustIDPS Agent Studio"],
            "differentiators": [
                "Integrated build + security flywheel (no incumbent ships both)",
                "Open-core platform with binding assurance dossier",
                "MambaGuard runtime monitoring on MCP / ACP / A2A / ANP",
                "First scanner that auto-emits ISO 42001 SoA evidence",
            ],
        },
        "regulatory_mapping": [
            {"jurisdiction": "INT", "instrument": "NIST AI RMF 1.0",
             "requirement": "Govern / Map / Measure / Manage",
             "satisfied_by": ["Scanner Measure outputs", "Dossier Govern artifact"],
             "evidence": "12-check report + remediation matrix"},
            {"jurisdiction": "INT", "instrument": "EU AI Act Art. 15",
             "requirement": "Accuracy / robustness / cybersecurity for high-risk AI",
             "satisfied_by": ["Agent Red Team SKU", "Continuous Defense SKU"],
             "evidence": "Per-engagement adversarial-robustness report"},
            {"jurisdiction": "INT", "instrument": "ISO/IEC 42001:2023",
             "requirement": "38-control AI management system",
             "satisfied_by": ["Statement of Applicability auto-generated by dossier"],
             "evidence": "Tier-3 Pro / Enterprise SaaS export"},
            {"jurisdiction": "INT", "instrument": "OWASP Agentic Top 10 (Dec 2025)",
             "requirement": "ASI01–ASI10 attestation",
             "satisfied_by": ["Free MCP / Agent Scanner"],
             "evidence": "Per-check pass/fail with severity"},
        ],
        "reproducibility": {
            "scanner_runner": "POST /api/agent-studio/scanner/run",
            "wall_clock_ms": 500,
            "checks_version": "v0.1.0",
        },
    }


def assemble_dossier(
    vertical: DossierVertical,
    audience: Literal["operator", "auditor", "investor"] = "auditor",
    scan_report: dict | None = None,
    dossier_id: str | None = None,
) -> dict:
    dossier_id = dossier_id or f"DOS-{uuid.uuid4().hex[:10]}"
    if vertical == "uav":
        return _uav_dossier(dossier_id, audience)
    if vertical == "agent_studio":
        return _agent_studio_dossier(dossier_id, audience, scan_report)
    raise ValueError(f"Unknown dossier vertical: {vertical}")
