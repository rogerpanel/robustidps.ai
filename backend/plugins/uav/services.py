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
from plugins.uav.uav_defense.ew_bench import (
    UAV_EW_BENCH_2026, mission_completion_curve, best_available_curves, latest_measured,
)
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
    best = best_available_curves()
    return {
        "benchmark": best["benchmark"],
        "ew_curves": best["curves"],
        "ew_source": best.get("source", "unknown"),
        "phase_a_metrics": metrics,
        "tiers": TIERS,
        "edge_profile": EDGE_PROFILE,
    }


def ew_curves_payload() -> dict:
    best = best_available_curves()
    return {
        "benchmark": best["benchmark"],
        "curves": best["curves"],
        "source": best.get("source", "unknown"),
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
    snap_t4 = {"t": 4.0, "label": "t4 — combined view",
               "description": "Superimposed t1+t2+t3: trusted topology, jammed links (orange), hostile edges (red), intruder node.",
               "nodes": intruder,
               "edges": [{"src": "u1", "dst": "u2", "kind": "trust"},
                         {"src": "u2", "dst": "u3", "kind": "jammed"},
                         {"src": "u1", "dst": "p",  "kind": "trust"},
                         {"src": "u3", "dst": "p",  "kind": "jammed"},
                         {"src": "b",  "dst": "u2", "kind": "hostile"},
                         {"src": "b",  "dst": "u3", "kind": "hostile"}]}
    return {"snapshots": [snap_t1, snap_t2, snap_t3, snap_t4]}


RECEIVER_MODELS: dict[str, dict] = {
    "gp_software":      {"label": "GP-software",       "nominal_cno": 45.0, "jam_rejection_db":  0.0, "pvt_collapse_js_db": 22.0},
    "ublox_f9p_sim":    {"label": "u-blox F9P (sim)",  "nominal_cno": 47.0, "jam_rejection_db":  8.0, "pvt_collapse_js_db": 28.0},
    "novatel_oem7_sim": {"label": "NovAtel OEM7 (sim)","nominal_cno": 49.0, "jam_rejection_db": 12.0, "pvt_collapse_js_db": 32.0},
}


def gnss_payload(
    seed: int | None = None,
    receiver_model: str = "gp_software",
    jamming_db: float = 0.0,
    n_spoofed: int | None = None,
    spoof_threshold: float = 0.5,
) -> dict:
    """Interactive GNSS snapshot.

    Parameters let the UI drive the physics: pick the receiver front-end
    (each has its own jamming-rejection budget), dial the jammer level in
    dB, choose how many satellites are targeted, and set the M1 spoof-
    confidence flag threshold. Seed=None picks a time-bucketed seed
    (original behaviour); providing a seed makes results reproducible.
    """
    if seed is None:
        seed = int(time.time()) // 10
    rng = random.Random(int(seed))

    rx = RECEIVER_MODELS.get(receiver_model, RECEIVER_MODELS["gp_software"])
    nominal_cno = rx["nominal_cno"]
    jam_rejection = rx["jam_rejection_db"]
    pvt_collapse = rx["pvt_collapse_js_db"]

    # How many satellites the jammer targets. Default behaviour = {3,5}
    # to match the pre-existing snapshot; the UI can override.
    if n_spoofed is None:
        spoofed_ids = {3, 5}
    else:
        n_spoofed = max(0, min(8, int(n_spoofed)))
        spoofed_ids = set(rng.sample(range(1, 9), n_spoofed)) if n_spoofed else set()

    # Effective jamming above the receiver's front-end rejection budget.
    effective_js = max(0.0, float(jamming_db) - jam_rejection)
    # Signal degradation curve: linear drop, ceiling at pvt_collapse_js_db.
    signal_penalty_db = min(nominal_cno - 20.0, effective_js * 0.6)

    sats = []
    for sv in range(1, 9):
        azimuth = (sv * 47) % 360
        elevation = 25 + (sv * 13) % 55
        is_spoofed = sv in spoofed_ids
        if is_spoofed:
            # Spoofed sats read anomalously hot regardless of receiver
            cno_base = nominal_cno - 4.0 + rng.uniform(-1, 1)
        else:
            cno_base = nominal_cno - 13.0 + rng.uniform(-3, 8)
        cno = max(0.0, cno_base - signal_penalty_db)
        base_conf = 0.82 + rng.uniform(-0.05, 0.08) if is_spoofed else 0.08 + rng.uniform(0, 0.06)
        # Higher jamming raises the false-positive floor slightly.
        spoof_conf = min(0.99, base_conf + effective_js * 0.004)
        sats.append({
            "sv": f"G{sv:02d}",
            "azimuth_deg": azimuth, "elevation_deg": elevation,
            "cno_db_hz": round(cno, 1),
            "spoof_confidence": round(spoof_conf, 3),
            "spoofed": is_spoofed,
            "flagged": spoof_conf >= spoof_threshold,
        })
    fleet_disagreement = 0.18 + rng.uniform(-0.04, 0.05) + (0.02 * len(spoofed_ids))
    any_flagged = any(s["flagged"] for s in sats)
    pvt_collapsed = jamming_db >= pvt_collapse
    return {
        "satellites": sats,
        "fleet_disagreement": round(min(1.0, fleet_disagreement), 3),
        "mode": "GNSS-degraded" if (any_flagged or pvt_collapsed) else "nominal",
        "fallback": "INS + visual odometry" if (any_flagged or pvt_collapsed) else None,
        "n_spoofed_satellites": len(spoofed_ids),
        "n_flagged_satellites": sum(1 for s in sats if s["flagged"]),
        "controls": {
            "seed": int(seed),
            "receiver_model": receiver_model,
            "receiver_label": rx["label"],
            "jamming_db": float(jamming_db),
            "effective_js_db": round(effective_js, 2),
            "pvt_collapse_js_db": pvt_collapse,
            "pvt_collapsed": pvt_collapsed,
            "spoof_threshold": float(spoof_threshold),
            "n_spoofed_requested": len(spoofed_ids),
        },
        "receiver_catalog": [
            {"id": k, **v} for k, v in RECEIVER_MODELS.items()
        ],
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


def perception_attack_payload(
    attack: str, epsilon: float, pgd_steps: int, sample_index: int,
    cw_kappa: float = 5.0, cw_c: float = 1.0, cw_steps: int = 100,
    deepfool_max_iter: int = 50,
    hsj_queries: int = 200, boundary_steps: int = 100,
    gaussian_sigma: float = 0.05, mask_fraction: float = 0.2,
    label_flip_fraction: float = 0.1,
) -> dict:
    """Dispatch all 9 attacks the Perception Tester exposes."""
    from plugins.uav.uav_defense.attacks import (
        cw, deepfool, gaussian_noise, feature_mask,
        hop_skip_jump, boundary_attack, random_label_flip,
    )

    ds = SyntheticTEXBAT(n_samples=64, seed=42)
    x, adj, y = ds[sample_index]
    x = x.unsqueeze(0); adj = adj.unsqueeze(0); y = y.unsqueeze(0)
    model = get_model()
    with torch.no_grad():
        clean_logits = model(x, adj)
        clean_pred = int(clean_logits.argmax(dim=-1).item())
        clean_conf = round(float(torch.softmax(clean_logits, dim=-1).max().item()), 4)

    if attack == "fgsm":
        x_adv = fgsm(model, x, y, epsilon, adj=adj)
    elif attack == "pgd":
        x_adv = pgd(model, x, y, epsilon, n_steps=pgd_steps, adj=adj)
    elif attack == "cw":
        x_adv = cw(model, x, y, kappa=cw_kappa, c=cw_c, n_steps=cw_steps, adj=adj)
    elif attack == "deepfool":
        x_adv = deepfool(model, x, y, max_iters=deepfool_max_iter, adj=adj)
    elif attack == "hop_skip_jump":
        x_adv = hop_skip_jump(model, x, y, n_queries=hsj_queries, n_montecarlo=20, adj=adj)
    elif attack == "boundary":
        x_adv = boundary_attack(model, x, y, n_steps=boundary_steps, adj=adj)
    elif attack == "gaussian":
        x_adv = gaussian_noise(model, x, y, sigma=gaussian_sigma, adj=adj)
    elif attack == "feature_mask":
        x_adv = feature_mask(model, x, y, mask_fraction=mask_fraction, adj=adj)
    elif attack == "label_flip":
        # Training-time poison — flip the label tensor instead of the input
        y_flipped = random_label_flip(y, flip_fraction=label_flip_fraction)
        with torch.no_grad():
            adv_logits = clean_logits
        return {
            "attack": attack, "is_training_time": True,
            "label_flip_fraction": label_flip_fraction,
            "true_label": int(y.item()),
            "flipped_label": int(y_flipped.item()),
            "label_changed": bool(int(y.item()) != int(y_flipped.item())),
            "clean_prediction": clean_pred,
            "clean_confidence": clean_conf,
            "hint": "Effect surfaces during retraining — see Certification Dashboard re-measure.",
        }
    else:
        raise ValueError(f"Unknown attack: {attack}")

    with torch.no_grad():
        adv_logits = model(x_adv, adj)
        adv_pred = int(adv_logits.argmax(dim=-1).item())
        adv_conf = round(float(torch.softmax(adv_logits, dim=-1).max().item()), 4)

    return {
        "attack": attack,
        "true_label": int(y.item()),
        "clean_prediction": clean_pred,
        "clean_confidence": clean_conf,
        "adversarial_prediction": adv_pred,
        "adversarial_confidence": adv_conf,
        "fooled": clean_pred != adv_pred,
        "confidence_drop": round(clean_conf - adv_conf, 4),
        "l2_distortion": round(float(((x_adv - x) ** 2).sum().sqrt().item()), 4),
        "linf_distortion": round(float((x_adv - x).abs().max().item()), 4),
        "epsilon": epsilon, "pgd_steps": pgd_steps,
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


# ── Phase B status ──────────────────────────────────────────────────────

def phase_b_status_payload() -> dict:
    """Aggregate Phase B artefacts: Optuna best-trial summary, ONNX export
    latency benchmark, and the chapter 6 §6.4 progressive-distillation
    target deltas. Returned shape is stable so the React Phase B panel
    renders the same fields regardless of which artefacts are present."""
    from plugins.uav.uav_defense.automl import latest_results as _optuna_latest
    from plugins.uav.uav_defense.onnx_export import latest_results as _onnx_latest

    optuna = _optuna_latest()
    onnx = _onnx_latest()

    return {
        "phase": "B",
        "stages": {
            "automl": {
                "status": "ready" if optuna else "not_run",
                "models_searched": list(optuna.keys()),
                "best_per_model": {
                    k: {"value": v["best_value"], "params": v["best_params"]}
                    for k, v in optuna.items()
                },
            },
            "onnx_export": {
                "status": "ready" if onnx else "not_run",
                "models_exported": list(onnx.keys()),
                "edge_target_ms_per_frame": 5.0,
                "results": {
                    k: {
                        "median_latency_ms": v["latency_ms"]["median"],
                        "p95_latency_ms": v["latency_ms"]["p95"],
                        "meets_edge_target": v["latency_ms"]["median"] <= v["edge_target_ms_per_frame"],
                        "round_trip_ok": v["round_trip_ok"],
                    }
                    for k, v in onnx.items()
                },
            },
            "progressive_distillation": {
                "status": "framework_ready",
                "target_cw_kappa5_robust_acc": 0.85,
                "phase_a_baseline": 0.0,
                "curriculum_eps_255": [1, 2, 4, 6, 8],
                "module": "plugins.uav.uav_defense.distillation",
                "runner_hint": "python -m plugins.uav.uav_defense.train --phase b --distill",
            },
        },
    }
