"""
Adversarial Red Team Arena — backend engine
============================================

Generates adversarial perturbations against loaded IDS models and measures
robustness under different attack strategies (FGSM, PGD, DeepFool-approx,
Gaussian noise, feature masking).

Multi-dataset / multi-model mode adds:
- Cross-dataset attack transferability (adversarial examples from dataset A
  evaluated on dataset B)
- Cross-model robustness comparison (same attack, same data, multiple models)
- Evasion success matrix (which attack+model combos are most exploitable)
- Severity-weighted risk scoring (critical attack classes penalised more)
- Adaptive epsilon profiling (finds per-model breaking-point epsilon)
- Detection confidence erosion curves

All attacks operate on feature-space tensors — no raw packet manipulation.
"""

import logging
import time
import uuid
import copy
from dataclasses import dataclass, asdict

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np

logger = logging.getLogger("robustidps.redteam")

# Batch size cap for model inference (prevents OOM from N×N internal matrices)
_ARENA_BATCH = 512

# ── Attack implementations ────────────────────────────────────────────────

def fgsm_attack(model: nn.Module, x: torch.Tensor, y: torch.Tensor,
                eps: float = 0.1) -> torch.Tensor:
    """Fast Gradient Sign Method."""
    x_adv = x.clone().detach().requires_grad_(True)
    logits = model(x_adv)
    loss = F.cross_entropy(logits, y)
    loss.backward()
    perturbation = eps * x_adv.grad.sign()
    return (x + perturbation).detach()


def pgd_attack(model: nn.Module, x: torch.Tensor, y: torch.Tensor,
               eps: float = 0.1, alpha: float = 0.01, steps: int = 10) -> torch.Tensor:
    """Projected Gradient Descent (iterative FGSM)."""
    x_adv = x.clone().detach()
    x_orig = x.clone().detach()
    for _ in range(steps):
        x_adv.requires_grad_(True)
        logits = model(x_adv)
        loss = F.cross_entropy(logits, y)
        loss.backward()
        with torch.no_grad():
            x_adv = x_adv + alpha * x_adv.grad.sign()
            # Project back into eps-ball
            delta = torch.clamp(x_adv - x_orig, min=-eps, max=eps)
            x_adv = x_orig + delta
    return x_adv.detach()


def deepfool_approx(model: nn.Module, x: torch.Tensor,
                    max_iter: int = 10) -> torch.Tensor:
    """Simplified DeepFool — moves samples toward the nearest decision boundary."""
    x_adv = x.clone().detach()
    with torch.no_grad():
        orig_preds = model(x_adv).argmax(-1)

    for _ in range(max_iter):
        x_adv.requires_grad_(True)
        logits = model(x_adv)
        preds = logits.argmax(-1)
        # Only perturb correctly-classified
        mask = (preds == orig_preds)
        if not mask.any():
            break
        loss = F.cross_entropy(logits[mask], orig_preds[mask])
        loss.backward()
        with torch.no_grad():
            grad = x_adv.grad
            norm = grad.norm(dim=-1, keepdim=True).clamp(min=1e-8)
            x_adv = x_adv + 0.02 * (grad / norm)
    return x_adv.detach()


def gaussian_noise(x: torch.Tensor, sigma: float = 0.1) -> torch.Tensor:
    """Add Gaussian noise to input features."""
    return x + torch.randn_like(x) * sigma


def feature_mask(x: torch.Tensor, mask_ratio: float = 0.2) -> torch.Tensor:
    """Zero out a random fraction of features."""
    mask = torch.rand_like(x) > mask_ratio
    return x * mask.float()


ATTACKS = {
    "fgsm": {"fn": fgsm_attack, "label": "FGSM", "needs_grad": True},
    "pgd": {"fn": pgd_attack, "label": "PGD (10-step)", "needs_grad": True},
    "deepfool": {"fn": deepfool_approx, "label": "DeepFool (approx)", "needs_grad": True},
    "gaussian": {"fn": gaussian_noise, "label": "Gaussian Noise", "needs_grad": False},
    "feature_mask": {"fn": feature_mask, "label": "Feature Masking", "needs_grad": False},
}


# ── Arena runner ──────────────────────────────────────────────────────────

def run_arena(
    model: nn.Module,
    features: torch.Tensor,
    labels: torch.Tensor | None = None,
    attacks: list[str] | None = None,
    epsilon: float = 0.1,
    n_samples: int = 500,
) -> dict:
    """
    Run the adversarial red-team arena.

    Returns per-attack results including accuracy before/after, confidence
    shift, perturbation magnitude, and per-class breakdown.
    """
    if attacks is None:
        attacks = list(ATTACKS.keys())

    # Subsample if needed
    if len(features) > n_samples:
        idx = torch.randperm(len(features))[:n_samples].sort().values
        features = features[idx]
        if labels is not None:
            labels = labels[idx]

    model.eval()
    device = next(model.parameters()).device
    features = features.to(device)

    # ── Clean baseline ────────────────────────────────────────────────────
    with torch.no_grad():
        clean_logits = model(features)
        clean_probs = F.softmax(clean_logits, dim=-1)
        clean_preds = clean_probs.argmax(-1)
        clean_conf = clean_probs.max(-1).values

    if labels is None:
        labels = clean_preds.clone()
    else:
        labels = labels.to(device)

    clean_acc = (clean_preds == labels).float().mean().item()
    clean_conf_mean = clean_conf.mean().item()

    from models.surrogate import SurrogateIDS
    class_names = SurrogateIDS.CLASS_NAMES

    # Per-class clean accuracy
    clean_per_class = {}
    for ci, cname in enumerate(class_names):
        mask = labels == ci
        if mask.sum() > 0:
            clean_per_class[cname] = {
                "count": int(mask.sum()),
                "accuracy": float((clean_preds[mask] == labels[mask]).float().mean()),
            }

    # ── Run attacks ───────────────────────────────────────────────────────
    results = []
    for atk_key in attacks:
        if atk_key not in ATTACKS:
            continue
        atk = ATTACKS[atk_key]
        t0 = time.perf_counter()

        try:
            if atk["needs_grad"]:
                if atk_key == "deepfool":
                    adv_features = atk["fn"](model, features)
                else:
                    adv_features = atk["fn"](model, features, labels, eps=epsilon)
            else:
                if atk_key == "gaussian":
                    adv_features = atk["fn"](features, sigma=epsilon)
                else:
                    adv_features = atk["fn"](features, mask_ratio=epsilon)

            elapsed = time.perf_counter() - t0

            with torch.no_grad():
                adv_logits = model(adv_features)
                adv_probs = F.softmax(adv_logits, dim=-1)
                adv_preds = adv_probs.argmax(-1)
                adv_conf = adv_probs.max(-1).values

            adv_acc = (adv_preds == labels).float().mean().item()
            adv_conf_mean = adv_conf.mean().item()
            perturbation_norm = (adv_features - features).norm(dim=-1).mean().item()
            flipped = (adv_preds != clean_preds).float().mean().item()

            # Per-class adversarial accuracy
            per_class = {}
            for ci, cname in enumerate(class_names):
                mask = labels == ci
                if mask.sum() > 0:
                    per_class[cname] = {
                        "count": int(mask.sum()),
                        "clean_acc": float((clean_preds[mask] == labels[mask]).float().mean()),
                        "adv_acc": float((adv_preds[mask] == labels[mask]).float().mean()),
                        "flip_rate": float((adv_preds[mask] != clean_preds[mask]).float().mean()),
                    }

            results.append({
                "attack": atk_key,
                "label": atk["label"],
                "epsilon": epsilon,
                "accuracy_clean": round(clean_acc, 4),
                "accuracy_adversarial": round(adv_acc, 4),
                "accuracy_drop": round(clean_acc - adv_acc, 4),
                "confidence_clean": round(clean_conf_mean, 4),
                "confidence_adversarial": round(adv_conf_mean, 4),
                "confidence_drop": round(clean_conf_mean - adv_conf_mean, 4),
                "flip_rate": round(flipped, 4),
                "perturbation_l2": round(perturbation_norm, 4),
                "time_ms": round(elapsed * 1000, 1),
                "per_class": per_class,
            })

        except Exception as e:
            logger.warning("Attack %s failed: %s", atk_key, e)
            results.append({
                "attack": atk_key,
                "label": atk["label"],
                "error": str(e),
            })

    arena_id = str(uuid.uuid4())[:8]

    return {
        "arena_id": arena_id,
        "n_samples": len(features),
        "epsilon": epsilon,
        "clean_accuracy": round(clean_acc, 4),
        "clean_confidence": round(clean_conf_mean, 4),
        "clean_per_class": clean_per_class,
        "attacks": results,
        "robustness_score": round(
            sum(r.get("accuracy_adversarial", 0) for r in results if "error" not in r) /
            max(len([r for r in results if "error" not in r]), 1),
            4,
        ),
    }


# ── Batched forward for safe inference ───────────────────────────────────

def _batched_forward(model: nn.Module, x: torch.Tensor) -> torch.Tensor:
    """Run model in chunks to avoid OOM from models with N×N internals."""
    if x.shape[0] <= _ARENA_BATCH:
        return model(x)
    parts = []
    for s in range(0, x.shape[0], _ARENA_BATCH):
        parts.append(model(x[s:s + _ARENA_BATCH]))
    return torch.cat(parts, dim=0)


# ── Severity map for risk-weighted scoring ───────────────────────────────

# Maps class index → severity weight (higher = more critical to protect)
SEVERITY_WEIGHTS = {
    0: 0.1,     # Benign — low penalty if misclassified
    # DDoS variants — critical infrastructure threats
    1: 1.0, 2: 1.0, 3: 1.0, 4: 1.0, 5: 1.0, 6: 1.0,
    7: 1.0, 8: 1.0, 9: 1.0, 10: 1.0, 11: 1.0, 12: 1.0,
    # Reconnaissance — medium
    13: 0.5, 14: 0.5, 15: 0.5, 16: 0.5,
    # BruteForce — high
    17: 0.8, 18: 0.8, 19: 0.8, 20: 0.8,
    # Spoofing — medium-high
    21: 0.7, 22: 0.7, 23: 0.7,
    # Web attacks — high to critical
    24: 0.9, 25: 0.9, 26: 1.0, 27: 0.8,
    # Malware — critical
    28: 1.0, 29: 1.0, 30: 1.0,
    # DoS — high
    31: 0.8, 32: 0.8,
    # Mirai — critical
    33: 1.0,
}


# ── Adaptive epsilon profiling ───────────────────────────────────────────

def compute_epsilon_profile(
    model: nn.Module,
    features: torch.Tensor,
    labels: torch.Tensor,
    attack_key: str = "fgsm",
    epsilon_schedule: list[float] | None = None,
) -> dict:
    """
    Find the epsilon "breaking point" — sweep epsilon values and measure
    accuracy degradation curve. Returns accuracy at each epsilon plus
    the estimated threshold where accuracy drops below 50%.
    """
    if epsilon_schedule is None:
        epsilon_schedule = [0.0, 0.01, 0.02, 0.05, 0.08, 0.1, 0.15, 0.2, 0.3, 0.5]

    model.eval()
    device = next(model.parameters()).device
    features = features.to(device)
    labels = labels.to(device)

    # Subsample for speed
    n = min(300, len(features))
    idx = torch.randperm(len(features))[:n].sort().values
    feat_sub = features[idx]
    lab_sub = labels[idx]

    atk = ATTACKS.get(attack_key)
    if atk is None:
        return {"error": f"Unknown attack: {attack_key}"}

    curve = []
    breaking_eps = None

    for eps in epsilon_schedule:
        if eps == 0.0:
            with torch.no_grad():
                logits = _batched_forward(model, feat_sub)
                acc = (logits.argmax(-1) == lab_sub).float().mean().item()
        else:
            try:
                if atk["needs_grad"]:
                    if attack_key == "deepfool":
                        adv = atk["fn"](model, feat_sub)
                    else:
                        adv = atk["fn"](model, feat_sub, lab_sub, eps=eps)
                else:
                    if attack_key == "gaussian":
                        adv = atk["fn"](feat_sub, sigma=eps)
                    else:
                        adv = atk["fn"](feat_sub, mask_ratio=eps)
                with torch.no_grad():
                    logits = _batched_forward(model, adv)
                    acc = (logits.argmax(-1) == lab_sub).float().mean().item()
            except Exception:
                acc = 0.0

        curve.append({"epsilon": eps, "accuracy": round(acc, 4)})
        if breaking_eps is None and acc < 0.5:
            breaking_eps = eps

    return {
        "attack": attack_key,
        "epsilon_curve": curve,
        "breaking_epsilon": breaking_eps,
    }


# ── Cross-model robustness comparison ────────────────────────────────────

def compare_model_robustness(
    models: dict[str, nn.Module],
    features: torch.Tensor,
    labels: torch.Tensor | None,
    attacks: list[str] | None = None,
    epsilon: float = 0.1,
    n_samples: int = 500,
) -> dict:
    """
    Run the same attack suite on the same data across multiple models.
    Returns per-model robustness + cross-model comparison matrices.
    """
    if attacks is None:
        attacks = list(ATTACKS.keys())

    # Subsample
    if len(features) > n_samples:
        idx = torch.randperm(len(features))[:n_samples].sort().values
        features = features[idx]
        if labels is not None:
            labels = labels[idx]

    model_names = list(models.keys())
    per_model = {}

    for mname, mdl in models.items():
        mdl.eval()
        per_model[mname] = run_arena(
            copy.deepcopy(mdl), features.clone(),
            labels.clone() if labels is not None else None,
            attacks, epsilon, n_samples,
        )

    # Build evasion success matrix: attacks × models → flip_rate
    evasion_matrix = {}
    for atk_key in attacks:
        row = {}
        for mname in model_names:
            arena = per_model[mname]
            atk_result = next((a for a in arena["attacks"] if a["attack"] == atk_key), None)
            row[mname] = round(atk_result["flip_rate"], 4) if atk_result and "error" not in atk_result else None
        evasion_matrix[atk_key] = row

    # Severity-weighted risk score per model
    from models.surrogate import SurrogateIDS
    class_names = SurrogateIDS.CLASS_NAMES
    risk_scores = {}
    for mname in model_names:
        arena = per_model[mname]
        weighted_loss = 0.0
        total_weight = 0.0
        for atk_result in arena["attacks"]:
            if "error" in atk_result:
                continue
            per_class = atk_result.get("per_class", {})
            for ci, cname in enumerate(class_names):
                if cname in per_class:
                    w = SEVERITY_WEIGHTS.get(ci, 0.5)
                    drop = per_class[cname]["clean_acc"] - per_class[cname]["adv_acc"]
                    weighted_loss += w * max(drop, 0)
                    total_weight += w
        risk_scores[mname] = round(weighted_loss / max(total_weight, 1e-8), 4)

    # Rank models by robustness
    ranking = sorted(model_names, key=lambda m: per_model[m]["robustness_score"], reverse=True)

    return {
        "model_names": model_names,
        "per_model_results": per_model,
        "evasion_matrix": evasion_matrix,
        "risk_scores": risk_scores,
        "robustness_ranking": ranking,
    }


# ── Cross-dataset attack transferability ─────────────────────────────────

def compute_attack_transferability(
    model: nn.Module,
    datasets: list[dict],
    attack_key: str = "fgsm",
    epsilon: float = 0.1,
    n_samples: int = 300,
) -> dict:
    """
    Generate adversarial examples on dataset A, evaluate on dataset B.
    Measures how well attacks transfer across domain distributions.

    datasets: list of {"name": str, "features": Tensor, "labels": Tensor|None}
    """
    model.eval()
    device = next(model.parameters()).device
    atk = ATTACKS.get(attack_key)
    if atk is None:
        return {"error": f"Unknown attack: {attack_key}"}

    names = [d["name"] for d in datasets]
    n_ds = len(datasets)

    # Pre-compute adversarial examples for each dataset
    adv_cache = {}
    clean_preds_cache = {}
    for i, ds in enumerate(datasets):
        feat = ds["features"].to(device)
        lab = ds["labels"]
        if lab is not None:
            lab = lab.to(device)

        # Subsample
        n = min(n_samples, len(feat))
        idx = torch.randperm(len(feat))[:n].sort().values
        feat = feat[idx]
        if lab is not None:
            lab = lab[idx]

        # Clean preds
        with torch.no_grad():
            clean_logits = _batched_forward(model, feat)
            clean_preds = clean_logits.argmax(-1)
        if lab is None:
            lab = clean_preds.clone()

        # Generate adversarial
        try:
            if atk["needs_grad"]:
                if attack_key == "deepfool":
                    adv = atk["fn"](model, feat)
                else:
                    adv = atk["fn"](model, feat, lab, eps=epsilon)
            else:
                if attack_key == "gaussian":
                    adv = atk["fn"](feat, sigma=epsilon)
                else:
                    adv = atk["fn"](feat, mask_ratio=epsilon)
        except Exception:
            adv = feat  # fallback to clean on failure

        adv_cache[i] = {"features": feat, "adv": adv, "labels": lab, "clean_preds": clean_preds}
        clean_preds_cache[i] = clean_preds

    # Build transferability matrix: source → target
    transfer_matrix = {}
    for src_i in range(n_ds):
        src_name = names[src_i]
        adv_perturbation = adv_cache[src_i]["adv"] - adv_cache[src_i]["features"]

        for tgt_i in range(n_ds):
            tgt_name = names[tgt_i]
            tgt_feat = adv_cache[tgt_i]["features"]
            tgt_lab = adv_cache[tgt_i]["labels"]
            tgt_clean_preds = clean_preds_cache[tgt_i]

            # Apply source perturbation to target data (truncate/pad to match)
            n_apply = min(len(adv_perturbation), len(tgt_feat))
            transferred = tgt_feat[:n_apply] + adv_perturbation[:n_apply]

            with torch.no_grad():
                trans_logits = _batched_forward(model, transferred)
                trans_preds = trans_logits.argmax(-1)

            # Metrics
            transfer_acc = (trans_preds == tgt_lab[:n_apply]).float().mean().item()
            flip_rate = (trans_preds != tgt_clean_preds[:n_apply]).float().mean().item()
            clean_acc = (tgt_clean_preds[:n_apply] == tgt_lab[:n_apply]).float().mean().item()

            key = f"{src_name}|{tgt_name}"
            transfer_matrix[key] = {
                "source": src_name,
                "target": tgt_name,
                "clean_accuracy": round(clean_acc, 4),
                "transferred_accuracy": round(transfer_acc, 4),
                "accuracy_drop": round(clean_acc - transfer_acc, 4),
                "flip_rate": round(flip_rate, 4),
                "is_self": src_i == tgt_i,
            }

    return {
        "attack": attack_key,
        "epsilon": epsilon,
        "dataset_names": names,
        "transfer_matrix": transfer_matrix,
    }


# ── Detection confidence erosion curve ───────────────────────────────────

def compute_confidence_erosion(
    model: nn.Module,
    features: torch.Tensor,
    labels: torch.Tensor,
    attacks: list[str] | None = None,
    epsilon_steps: list[float] | None = None,
) -> dict:
    """
    Track how detection confidence erodes across epsilon values for each attack.
    Critical for understanding at what point the model becomes unreliable.
    """
    if attacks is None:
        attacks = ["fgsm", "pgd"]
    if epsilon_steps is None:
        epsilon_steps = [0.0, 0.02, 0.05, 0.1, 0.15, 0.2, 0.3]

    model.eval()
    device = next(model.parameters()).device
    features = features.to(device)
    labels = labels.to(device)

    n = min(300, len(features))
    idx = torch.randperm(len(features))[:n].sort().values
    feat = features[idx]
    lab = labels[idx]

    erosion = {}
    for atk_key in attacks:
        atk = ATTACKS.get(atk_key)
        if atk is None:
            continue
        curve = []
        for eps in epsilon_steps:
            if eps == 0.0:
                with torch.no_grad():
                    logits = _batched_forward(model, feat)
                    probs = F.softmax(logits, dim=-1)
                    conf = probs.max(-1).values.mean().item()
                    acc = (logits.argmax(-1) == lab).float().mean().item()
            else:
                try:
                    if atk["needs_grad"]:
                        if atk_key == "deepfool":
                            adv = atk["fn"](model, feat)
                        else:
                            adv = atk["fn"](model, feat, lab, eps=eps)
                    else:
                        if atk_key == "gaussian":
                            adv = atk["fn"](feat, sigma=eps)
                        else:
                            adv = atk["fn"](feat, mask_ratio=eps)
                    with torch.no_grad():
                        logits = _batched_forward(model, adv)
                        probs = F.softmax(logits, dim=-1)
                        conf = probs.max(-1).values.mean().item()
                        acc = (logits.argmax(-1) == lab).float().mean().item()
                except Exception:
                    conf = 0.0
                    acc = 0.0
            curve.append({
                "epsilon": eps,
                "confidence": round(conf, 4),
                "accuracy": round(acc, 4),
            })
        erosion[atk_key] = curve

    return {"erosion_curves": erosion}


# ── Full multi-run orchestrator ──────────────────────────────────────────

def run_multi_arena(
    models: dict[str, nn.Module],
    datasets: list[dict],
    attacks: list[str] | None = None,
    epsilon: float = 0.1,
    n_samples: int = 500,
) -> dict:
    """
    Full multi-dataset × multi-model red team analysis.

    datasets: list of {"name": str, "features": Tensor, "labels": Tensor|None}
    models: dict of model_name → nn.Module

    Returns comprehensive comparison with:
    - Per-model × per-dataset arena results
    - Cross-model robustness comparison per dataset
    - Cross-dataset attack transferability per model
    - Epsilon profiles for each model
    - Confidence erosion curves
    - Evasion success heatmap
    - Severity-weighted risk scores
    """
    if attacks is None:
        attacks = list(ATTACKS.keys())

    model_names = list(models.keys())
    dataset_names = [d["name"] for d in datasets]
    t0 = time.perf_counter()

    # ── 1. Per-model × per-dataset arena runs ────────────────────────────
    arena_matrix = {}  # key: "model|dataset"
    for mname, mdl in models.items():
        for ds in datasets:
            lab = ds["labels"]
            arena = run_arena(
                copy.deepcopy(mdl),
                ds["features"].clone(),
                lab.clone() if lab is not None else None,
                attacks, epsilon, n_samples,
            )
            arena["model_used"] = mname
            arena["dataset_name"] = ds["name"]
            arena_matrix[f"{mname}|{ds['name']}"] = arena

    # ── 2. Cross-model comparison per dataset ────────────────────────────
    cross_model = {}
    for ds in datasets:
        lab = ds["labels"]
        cmp = compare_model_robustness(
            {m: copy.deepcopy(models[m]) for m in model_names},
            ds["features"].clone(),
            lab.clone() if lab is not None else None,
            attacks, epsilon, n_samples,
        )
        cross_model[ds["name"]] = cmp

    # ── 3. Cross-dataset attack transferability (per model, FGSM only for speed)
    cross_dataset = {}
    for mname, mdl in models.items():
        if len(datasets) >= 2:
            trans = compute_attack_transferability(
                copy.deepcopy(mdl), datasets,
                attack_key="fgsm", epsilon=epsilon,
                n_samples=min(n_samples, 300),
            )
            cross_dataset[mname] = trans

    # ── 4. Epsilon profiles (primary attack on first dataset) ────────────
    epsilon_profiles = {}
    if len(datasets) > 0:
        ds0 = datasets[0]
        lab0 = ds0["labels"]
        for mname, mdl in models.items():
            feat = ds0["features"].clone()
            lab = lab0.clone() if lab0 is not None else None
            device = next(mdl.parameters()).device
            feat = feat.to(device)
            if lab is None:
                with torch.no_grad():
                    lab = _batched_forward(mdl, feat[:min(300, len(feat))]).argmax(-1)
                    # Extend if needed
                    if len(lab) < len(feat):
                        lab_full = _batched_forward(mdl, feat).argmax(-1)
                        lab = lab_full
            else:
                lab = lab.to(device)
            epsilon_profiles[mname] = compute_epsilon_profile(
                mdl, feat, lab, attack_key="fgsm",
            )

    # ── 5. Confidence erosion (first dataset, all models) ────────────────
    erosion_profiles = {}
    if len(datasets) > 0:
        ds0 = datasets[0]
        lab0 = ds0["labels"]
        for mname, mdl in models.items():
            feat = ds0["features"].clone()
            lab = lab0.clone() if lab0 is not None else None
            device = next(mdl.parameters()).device
            feat = feat.to(device)
            if lab is None:
                with torch.no_grad():
                    lab = _batched_forward(mdl, feat[:min(300, len(feat))]).argmax(-1)
                    if len(lab) < len(feat):
                        lab = _batched_forward(mdl, feat).argmax(-1)
            else:
                lab = lab.to(device)
            erosion_profiles[mname] = compute_confidence_erosion(
                mdl, feat, lab, attacks=["fgsm", "pgd"],
            )

    # ── 6. Build summary heatmap: model × dataset → robustness score ────
    robustness_heatmap = []
    for mname in model_names:
        for ds_name in dataset_names:
            key = f"{mname}|{ds_name}"
            arena = arena_matrix.get(key, {})
            robustness_heatmap.append({
                "model": mname,
                "dataset": ds_name,
                "robustness_score": arena.get("robustness_score", 0),
                "clean_accuracy": arena.get("clean_accuracy", 0),
            })

    elapsed = time.perf_counter() - t0

    return {
        "multi_arena_id": str(uuid.uuid4())[:8],
        "n_models": len(model_names),
        "n_datasets": len(datasets),
        "model_names": model_names,
        "dataset_names": dataset_names,
        "epsilon": epsilon,
        "attacks_used": attacks,
        "arena_matrix": arena_matrix,
        "cross_model_comparison": cross_model,
        "cross_dataset_transferability": cross_dataset,
        "epsilon_profiles": epsilon_profiles,
        "confidence_erosion": erosion_profiles,
        "robustness_heatmap": robustness_heatmap,
        "time_ms": round(elapsed * 1000, 1),
    }
