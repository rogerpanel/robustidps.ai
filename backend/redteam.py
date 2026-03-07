"""
Adversarial Red Team Arena — backend engine
============================================

Generates adversarial perturbations against loaded IDS models and measures
robustness under different attack strategies (FGSM, PGD, DeepFool-approx,
Gaussian noise, feature masking).

All attacks operate on feature-space tensors — no raw packet manipulation.
"""

import logging
import time
import uuid
from dataclasses import dataclass, asdict

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np

logger = logging.getLogger("robustidps.redteam")

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
