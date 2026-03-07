"""
Explainability Studio (XAI) — backend engine
=============================================

Provides per-prediction and global explanations for IDS model decisions:
  - Feature importance (gradient-based saliency)
  - Attention map extraction (if model has attention layers)
  - Per-class feature contribution
  - Decision boundary sensitivity analysis
"""

import logging
import time
import uuid

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np

logger = logging.getLogger("robustidps.xai")


# ── Feature importance via gradient saliency ──────────────────────────────

def gradient_saliency(
    model: nn.Module,
    features: torch.Tensor,
    target_class: int | None = None,
) -> torch.Tensor:
    """
    Compute gradient-based saliency for each input feature.
    Returns tensor of shape [n_samples, n_features] with importance scores.
    """
    x = features.clone().detach().requires_grad_(True)
    logits = model(x)

    if target_class is not None:
        score = logits[:, target_class].sum()
    else:
        # Use predicted class for each sample
        preds = logits.argmax(-1)
        score = logits.gather(1, preds.unsqueeze(1)).sum()

    score.backward()
    saliency = x.grad.abs()
    return saliency.detach()


def integrated_gradients(
    model: nn.Module,
    features: torch.Tensor,
    baseline: torch.Tensor | None = None,
    steps: int = 30,
) -> torch.Tensor:
    """
    Integrated Gradients attribution.
    Returns tensor of shape [n_samples, n_features].
    """
    if baseline is None:
        baseline = torch.zeros_like(features)

    # Interpolation
    scaled_inputs = []
    for alpha in torch.linspace(0, 1, steps):
        scaled_inputs.append(baseline + alpha * (features - baseline))

    grads = []
    for inp in scaled_inputs:
        inp = inp.clone().detach().requires_grad_(True)
        logits = model(inp)
        preds = logits.argmax(-1)
        score = logits.gather(1, preds.unsqueeze(1)).sum()
        score.backward()
        grads.append(inp.grad.detach())

    avg_grad = torch.stack(grads).mean(dim=0)
    attribution = (features - baseline) * avg_grad
    return attribution.detach()


# ── Sensitivity analysis ──────────────────────────────────────────────────

def feature_sensitivity(
    model: nn.Module,
    features: torch.Tensor,
    labels: torch.Tensor | None = None,
    perturbation_range: list[float] | None = None,
) -> dict:
    """
    Measure how accuracy changes when individual features are perturbed.
    Returns per-feature sensitivity scores.
    """
    if perturbation_range is None:
        perturbation_range = [0.01, 0.05, 0.1, 0.2, 0.5]

    model.eval()
    device = next(model.parameters()).device
    features = features.to(device)

    with torch.no_grad():
        clean_logits = model(features)
        clean_preds = clean_logits.argmax(-1)
        if labels is None:
            labels = clean_preds

    n_features = features.shape[1]
    sensitivity = {}

    for fi in range(n_features):
        scores = []
        for eps in perturbation_range:
            perturbed = features.clone()
            perturbed[:, fi] += torch.randn(len(features), device=device) * eps
            with torch.no_grad():
                new_preds = model(perturbed).argmax(-1)
            flip_rate = (new_preds != clean_preds).float().mean().item()
            scores.append({"epsilon": eps, "flip_rate": round(flip_rate, 4)})
        sensitivity[fi] = scores

    return sensitivity


# ── Main XAI runner ───────────────────────────────────────────────────────

FEATURE_NAMES = [
    "flow_duration", "Header_Length", "Protocol Type", "Duration", "Rate",
    "Srate", "Drate", "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number",
    "ack_count", "syn_count", "fin_count", "urg_count", "rst_count",
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP",
    "DHCP", "ARP", "ICMP", "IPv", "LLC",
    "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number",
    "Magnitue", "Radius", "Covariance", "Variance", "Weight",
    "pkt_count", "pkt_size_avg", "pkt_size_std", "pkt_size_min", "pkt_size_max",
    "fwd_pkt_count", "bwd_pkt_count", "fwd_pkt_size_avg", "bwd_pkt_size_avg",
    "flow_bytes_per_sec", "flow_pkts_per_sec", "fwd_iat_avg", "bwd_iat_avg",
    "active_time", "idle_time",
    "bidirectional_packets", "bidirectional_bytes", "bidirectional_duration_ms",
    "src2dst_packets", "src2dst_bytes", "dst2src_packets", "dst2src_bytes",
    "fwd_header_len", "bwd_header_len", "down_up_ratio", "pkt_len_variance",
    "fwd_seg_size_avg", "bwd_seg_size_avg", "subflow_fwd_pkts", "subflow_fwd_bytes",
    "subflow_bwd_pkts", "subflow_bwd_bytes",
    "fwd_byts_b_avg", "fwd_pkts_b_avg", "fwd_blk_rate_avg",
    "bwd_byts_b_avg", "bwd_pkts_b_avg", "bwd_blk_rate_avg",
]


def run_explainability(
    model: nn.Module,
    features: torch.Tensor,
    labels: torch.Tensor | None = None,
    n_samples: int = 200,
    method: str = "all",
) -> dict:
    """
    Run XAI analysis on a model+dataset.

    Methods: "saliency", "integrated_gradients", "sensitivity", "all"
    """
    # Subsample
    if len(features) > n_samples:
        idx = torch.randperm(len(features))[:n_samples].sort().values
        features = features[idx]
        if labels is not None:
            labels = labels[idx]

    model.eval()
    device = next(model.parameters()).device
    features = features.to(device)
    if labels is not None:
        labels = labels.to(device)

    from models.surrogate import SurrogateIDS
    class_names = SurrogateIDS.CLASS_NAMES

    # Clean predictions
    with torch.no_grad():
        logits = model(features)
        probs = F.softmax(logits, dim=-1)
        preds = probs.argmax(-1)
        confs = probs.max(-1).values

    if labels is None:
        labels = preds.clone()

    n_features = features.shape[1]
    feat_names = FEATURE_NAMES[:n_features] if n_features <= len(FEATURE_NAMES) else \
        [f"feature_{i}" for i in range(n_features)]

    result = {
        "xai_id": str(uuid.uuid4())[:8],
        "n_samples": len(features),
        "method": method,
        "feature_names": feat_names,
        "class_names": class_names,
        "prediction_summary": {
            "accuracy": float((preds == labels).float().mean()),
            "mean_confidence": float(confs.mean()),
        },
    }

    t0 = time.perf_counter()

    # ── Gradient saliency ─────────────────────────────────────────────────
    if method in ("saliency", "all"):
        sal = gradient_saliency(model, features)
        # Global feature importance (mean absolute saliency)
        global_importance = sal.mean(dim=0).cpu().numpy()
        # Normalize to [0, 1]
        gi_max = global_importance.max()
        if gi_max > 0:
            global_importance = global_importance / gi_max

        # Top features
        top_idx = np.argsort(global_importance)[::-1][:20]
        top_features = [
            {"index": int(i), "name": feat_names[i], "importance": round(float(global_importance[i]), 4)}
            for i in top_idx
        ]

        # Per-class feature importance
        per_class_importance = {}
        for ci, cname in enumerate(class_names):
            mask = preds == ci
            if mask.sum() > 0:
                cls_sal = sal[mask].mean(dim=0).cpu().numpy()
                cls_max = cls_sal.max()
                if cls_max > 0:
                    cls_sal = cls_sal / cls_max
                cls_top = np.argsort(cls_sal)[::-1][:10]
                per_class_importance[cname] = [
                    {"index": int(i), "name": feat_names[i], "importance": round(float(cls_sal[i]), 4)}
                    for i in cls_top
                ]

        result["saliency"] = {
            "global_importance": top_features,
            "per_class_importance": per_class_importance,
            "heatmap": sal.mean(dim=0).cpu().tolist(),
        }

    # ── Integrated Gradients ──────────────────────────────────────────────
    if method in ("integrated_gradients", "all"):
        ig = integrated_gradients(model, features, steps=20)
        ig_global = ig.abs().mean(dim=0).cpu().numpy()
        ig_max = ig_global.max()
        if ig_max > 0:
            ig_global = ig_global / ig_max

        ig_top_idx = np.argsort(ig_global)[::-1][:20]
        result["integrated_gradients"] = {
            "global_attribution": [
                {"index": int(i), "name": feat_names[i], "attribution": round(float(ig_global[i]), 4)}
                for i in ig_top_idx
            ],
            "heatmap": ig.abs().mean(dim=0).cpu().tolist(),
        }

    # ── Sensitivity ───────────────────────────────────────────────────────
    if method in ("sensitivity", "all"):
        sens = feature_sensitivity(model, features, labels,
                                   perturbation_range=[0.05, 0.1, 0.2])
        # Rank features by max flip rate across epsilons
        max_flip = {}
        for fi, scores in sens.items():
            max_flip[fi] = max(s["flip_rate"] for s in scores)

        sens_ranked = sorted(max_flip.items(), key=lambda x: -x[1])[:20]
        result["sensitivity"] = {
            "top_sensitive_features": [
                {
                    "index": fi,
                    "name": feat_names[fi],
                    "max_flip_rate": round(flip, 4),
                    "detail": sens[fi],
                }
                for fi, flip in sens_ranked
            ],
        }

    result["time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return result
