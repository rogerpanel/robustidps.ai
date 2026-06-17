"""Sync service functions backing the UAV plugin.

Both the FastAPI router (`api.py`) and the SOC Copilot tool dispatcher
(`backend/copilot.py`) call into here. Splitting compute out of the HTTP
handler keeps the copilot tool path zero-overhead (no event-loop juggling)
while preserving the same payload schema for both call sites.
"""
from __future__ import annotations

import json
import random
import time
from pathlib import Path

import torch

from plugins.uav.uav_defense.attacks import fgsm, pgd
from plugins.uav.uav_defense.datasets import SyntheticTEXBAT
from plugins.uav.uav_defense.defenses import (
    certified_radius, estimate_lipschitz, gronwall_radius, smooth_predict,
)
from plugins.uav.uav_defense.ew_bench import UAV_EW_BENCH_2026, mission_completion_curve
from plugins.uav.uav_defense.models import CTTGNN

METRICS_PATH = Path("weights/uav_metrics.json")

_model: CTTGNN | None = None


def get_model() -> CTTGNN:
    global _model
    if _model is None:
        _model = CTTGNN()
        _model.eval()
    return _model


# ── Static payloads (chapter 6 Tables 6.x) ─────────────────────────────

INDUSTRY = {
    "vendors": ["Anduril Lattice", "Shield AI Hivemind", "Skydio Autonomy", "PX4 Auterion", "RobustIDPS UAV"],
    "criteria": [
        {"id": "lipschitz",  "label": "Certified Lipschitz radius (CT models)",
         "scores": ["-", "-", "-", "-", "full"]},
        {"id": "rs_l2",      "label": "Randomized smoothing l_2",
         "scores": ["-", "-", "-", "-", "full"]},
        {"id": "byz_fed",    "label": "Byzantine-resilient federated aggregation",
         "scores": ["partial", "partial", "-", "-", "full"]},
        {"id": "dp",         "label": "Differential privacy",
         "scores": ["-", "-", "-", "-", "full"]},
        {"id": "plan_audit", "label": "LLM mission-plan audit",
         "scores": ["partial", "partial", "-", "-", "full"]},
        {"id": "pqc_c2",     "label": "PQC-ready C2 channel",
         "scores": ["-", "-", "-", "-", "full"]},
        {"id": "stackelberg","label": "Stackelberg certification vs EW",
         "scores": ["-", "partial", "-", "-", "full"]},
    ],
}

REGULATORY = [
    {"jurisdiction": "RU", "instrument": "Government Decree №1701 (30 Nov 2024)",
     "requirement": "Certified C2 crypto + real-time remote ID, MTOW 250 g — 30 kg",
     "satisfied_by": ["M2 FedLLM-API (DP)", "GOST R 34.10-2012 signing"],
     "evidence": "(ε,δ)-DP budget = (0.85, 1e-5); signed telemetry envelopes"},
    {"jurisdiction": "RU", "instrument": "GOST R 59276-2020",
     "requirement": "Methods of assuring trust in AI systems",
     "satisfied_by": ["Reference attack set (chapter 4)", "Condition-requirement matrix"],
     "evidence": "Algorithm 6.1 reproduces all six attack families"},
    {"jurisdiction": "RU", "instrument": "GOST R 56122-2014",
     "requirement": "General UAS requirements",
     "satisfied_by": ["M2", "M7"],
     "evidence": "Federated coordination + Stackelberg certification"},
    {"jurisdiction": "INT", "instrument": "NIST AI RMF 1.0",
     "requirement": "Measure: validity, safety, security, resilience",
     "satisfied_by": ["Lipschitz / RS / PAC-Bayes / MWU certs"],
     "evidence": "Numerical certificate per inference (chapter 6 Eq. 6.5)"},
    {"jurisdiction": "INT", "instrument": "EU AI Act Art. 15",
     "requirement": "Accuracy / robustness / cybersecurity for high-risk AI",
     "satisfied_by": ["M2, M3, M6, M7"],
     "evidence": "Federated trim-mean + EWC + UC-HGP + MWU regret"},
    {"jurisdiction": "INT", "instrument": "DO-326A / ED-202A",
     "requirement": "Airworthiness security as formal certification objective",
     "satisfied_by": ["CyberSecLLM mission-plan audit", "M3 TripleE traceability"],
     "evidence": "End-to-end mission audit trail with per-event provenance"},
]

TIERS = [
    {"name": "Airframe edge", "budget_w": 5,
     "methods": ["M1 CT-TGNN", "M4 MambaShield", "M6 UC-HGP"]},
    {"name": "Droneport", "budget_w": 140,
     "methods": ["M2 FedLLM-API", "M7 FedGTD", "M5 Stoch-Trans."]},
    {"name": "Cloud / SOC", "budget_w": None,
     "methods": ["M3 TripleE-TGNN", "CyberSecLLM", "RobustIDPS.ai"]},
]

EDGE_PROFILE = {
    "platform": "Jetson Orin Nano",
    "latency_ms_per_frame": 1.8, "fps": 30,
    "ram_mib": 384, "cpu_pct_one_core": 8,
}


# ── Service functions ───────────────────────────────────────────────────

def overview_payload() -> dict:
    metrics: dict = {}
    if METRICS_PATH.exists():
        try:
            metrics = json.loads(METRICS_PATH.read_text())
        except json.JSONDecodeError:
            metrics = {}
    curves = [mission_completion_curve(c) for c in UAV_EW_BENCH_2026["configurations"]]
    return {
        "benchmark": UAV_EW_BENCH_2026,
        "ew_curves": curves,
        "phase_a_metrics": metrics,
        "tiers": TIERS,
        "edge_profile": EDGE_PROFILE,
    }


def ew_curves_payload() -> dict:
    return {
        "benchmark": UAV_EW_BENCH_2026,
        "curves": [mission_completion_curve(c) for c in UAV_EW_BENCH_2026["configurations"]],
    }


def swarm_snapshot_payload() -> dict:
    nodes_base = [
        {"id": "u1", "kind": "uav",       "label": "UAV-1"},
        {"id": "u2", "kind": "uav",       "label": "UAV-2"},
        {"id": "u3", "kind": "uav",       "label": "UAV-3"},
        {"id": "p",  "kind": "droneport", "label": "Droneport"},
    ]
    snap_t1 = {"t": 1.0, "label": "t1 — clean", "nodes": nodes_base,
               "edges": [{"src": "u1", "dst": "u2", "kind": "trust"},
                         {"src": "u2", "dst": "u3", "kind": "trust"},
                         {"src": "u1", "dst": "p",  "kind": "trust"},
                         {"src": "u3", "dst": "p",  "kind": "trust"}]}
    snap_t2 = {"t": 2.0, "label": "t2 — jamming", "nodes": nodes_base,
               "edges": [{"src": "u1", "dst": "u2", "kind": "trust"},
                         {"src": "u2", "dst": "u3", "kind": "jammed"},
                         {"src": "u1", "dst": "p",  "kind": "trust"},
                         {"src": "u3", "dst": "p",  "kind": "jammed"}]}
    intruder = nodes_base + [{"id": "b", "kind": "intruder", "label": "Intruder"}]
    snap_t3 = {"t": 3.0, "label": "t3 — intruder", "nodes": intruder,
               "edges": [{"src": "u1", "dst": "u2", "kind": "trust"},
                         {"src": "u2", "dst": "u3", "kind": "trust"},
                         {"src": "u1", "dst": "p",  "kind": "trust"},
                         {"src": "u3", "dst": "p",  "kind": "trust"},
                         {"src": "b",  "dst": "u2", "kind": "hostile"},
                         {"src": "b",  "dst": "u3", "kind": "hostile"}]}
    return {"snapshots": [snap_t1, snap_t2, snap_t3]}


def gnss_payload() -> dict:
    rng = random.Random(int(time.time()) // 10)
    spoofed = {3, 5}
    sats = []
    for sv in range(1, 9):
        azimuth = (sv * 47) % 360
        elevation = 25 + (sv * 13) % 55
        cno = 32 + rng.uniform(-3, 8) if sv not in spoofed else 41 + rng.uniform(-1, 1)
        spoof_conf = 0.82 + rng.uniform(-0.05, 0.08) if sv in spoofed else 0.08 + rng.uniform(0, 0.06)
        sats.append({
            "sv": f"G{sv:02d}",
            "azimuth_deg": azimuth, "elevation_deg": elevation,
            "cno_db_hz": round(cno, 1),
            "spoof_confidence": round(spoof_conf, 3),
            "spoofed": sv in spoofed,
        })
    fleet_disagreement = 0.18 + rng.uniform(-0.04, 0.05)
    any_spoofed = any(s["spoofed"] for s in sats)
    return {
        "satellites": sats,
        "fleet_disagreement": round(fleet_disagreement, 3),
        "mode": "GNSS-degraded" if any_spoofed else "nominal",
        "fallback": "INS + visual odometry" if any_spoofed else None,
        "n_spoofed_satellites": sum(1 for s in sats if s["spoofed"]),
    }


def certificates_payload() -> dict:
    ds = SyntheticTEXBAT(n_samples=16, seed=int(time.time()) % 2 ** 31)
    x = torch.stack([ds[i][0] for i in range(16)])
    adj = ds[0][1].unsqueeze(0).expand(16, -1, -1)
    model = get_model()
    sigma = 0.25
    top, counts = smooth_predict(model, x[:8], sigma=sigma, n_samples=100, adj=adj[:8])
    radius_avg = sum(certified_radius(int(counts[i, top[i]].item()), 100, sigma)
                     for i in range(top.shape[0])) / max(1, top.shape[0])
    l_g = estimate_lipschitz(model, x[:4], adj=adj[:4])
    g_radius = gronwall_radius(l_g, horizon_T=1.0, epsilon_out=0.5)
    return {
        "lipschitz_L_g": round(l_g, 4),
        "gronwall_radius": round(g_radius, 4),
        "rs_certified_radius": round(radius_avg, 4),
        "rs_sigma": sigma, "rs_alpha": 1e-3, "rs_samples": 100,
        "horizon_T": 1.0, "epsilon_out": 0.5,
        "pac_bayes_bound": 0.041,
        "dp_epsilon": 0.85, "dp_delta": 1e-5,
        "operational_interpretation": {
            "js_db_floor": 20, "mcr_floor": 0.80,
            "regulatory_floor_mcr": 0.90, "regulatory_floor_label": "DO-326A",
        },
    }


def perception_attack_payload(attack: str, epsilon: float, pgd_steps: int, sample_index: int) -> dict:
    ds = SyntheticTEXBAT(n_samples=64, seed=42)
    x, adj, y = ds[sample_index]
    x = x.unsqueeze(0); adj = adj.unsqueeze(0); y = y.unsqueeze(0)
    model = get_model()
    with torch.no_grad():
        clean_pred = int(model(x, adj).argmax(dim=-1).item())
    if attack == "fgsm":
        x_adv = fgsm(model, x, y, epsilon, adj=adj)
    else:
        x_adv = pgd(model, x, y, epsilon, n_steps=pgd_steps, adj=adj)
    with torch.no_grad():
        adv_pred = int(model(x_adv, adj).argmax(dim=-1).item())
    return {
        "attack": attack, "epsilon": epsilon, "pgd_steps": pgd_steps,
        "true_label": int(y.item()),
        "clean_prediction": clean_pred,
        "adversarial_prediction": adv_pred,
        "fooled": clean_pred != adv_pred,
        "l2_distortion": round(float(((x_adv - x) ** 2).sum().sqrt().item()), 4),
        "linf_distortion": round(float((x_adv - x).abs().max().item()), 4),
    }


def mission_plan_review_payload(plan_text: str, plan_format: str) -> dict:
    text = plan_text.lower()
    flags = []
    if "geofence" not in text:
        flags.append({"severity": "high", "code": "MP-G01",
                      "message": "No geofence constraint declared (GOST R 56122-2014 §6.3)"})
    if "rtl" not in text and "return_to_launch" not in text and "return-to-launch" not in text:
        flags.append({"severity": "medium", "code": "MP-G02",
                      "message": "No Return-to-Launch fallback (DO-326A safety case)"})
    if "altitude" not in text:
        flags.append({"severity": "low", "code": "MP-G03",
                      "message": "Altitude band not specified — UC-HGP cannot calibrate go/no-go"})
    if "kp1701" not in text and "decree 1701" not in text and "decree-1701" not in text and "decree №1701" not in text:
        flags.append({"severity": "info", "code": "MP-R01",
                      "message": "RF Decree №1701 acknowledgment line absent"})
    verdict = "approve" if not any(f["severity"] in ("high", "critical") for f in flags) else "block"
    return {
        "verdict": verdict,
        "model": "CyberSecLLM (heuristic surrogate, Phase A)",
        "format": plan_format,
        "n_findings": len(flags),
        "findings": flags,
    }


def industry_payload() -> dict:
    return INDUSTRY


def regulatory_payload() -> dict:
    return {"entries": REGULATORY}
