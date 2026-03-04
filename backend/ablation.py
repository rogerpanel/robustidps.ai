"""
Ablation study — disable surrogate branches and measure accuracy impact.

Three modes:
  1. Single-branch ablation: disable each branch one at a time
  2. Pairwise ablation: disable every pair of branches
  3. Incremental ablation: cumulatively disable branches by impact order

Reproduces the dissertation ablation table (Chapter 8).
"""

import torch
from sklearn.metrics import precision_recall_fscore_support


def _eval_model(model, features, labels, full_preds, disabled=None):
    """Run model with optional disabled branches and return metrics dict."""
    with torch.no_grad():
        if disabled:
            logits = model(features, disabled_branches=disabled)
        else:
            logits = model(features)
        preds = logits.argmax(-1)

    disabled_list = sorted(disabled) if disabled else []

    if labels is not None:
        acc = (preds == labels).float().mean().item()
        # Compute per-class metrics
        p_np = preds.cpu().numpy()
        l_np = labels.cpu().numpy()
        prec, rec, f1, _ = precision_recall_fscore_support(
            l_np, p_np, average="weighted", zero_division=0
        )
    else:
        # No ground truth — measure agreement with full model
        acc = (preds == full_preds).float().mean().item()
        prec, rec, f1 = 0.0, 0.0, 0.0

    return {
        "accuracy": acc,
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "disabled": disabled_list,
    }


def run_ablation(model, features: torch.Tensor,
                 labels: torch.Tensor | None = None) -> dict:
    """
    Full ablation study: single, pairwise, and incremental.

    Returns:
        {
            "single": { "Full System": {...}, "Branch Name": {...}, ... },
            "pairwise": { "Branch A + Branch B": {...}, ... },
            "incremental": [ {"step": 0, "disabled": [], ...}, ... ],
        }
    """
    model.eval()
    n_branches = getattr(model, 'N_BRANCHES', 7)
    branch_names = getattr(model, 'BRANCH_NAMES', [f"Branch {i}" for i in range(n_branches)])

    # ── Full system baseline ─────────────────────────────────────────────
    with torch.no_grad():
        full_logits = model(features)
        full_preds = full_logits.argmax(-1)

    full_metrics = _eval_model(model, features, labels, full_preds, disabled=None)
    full_acc = full_metrics["accuracy"]
    full_metrics["accuracy_drop"] = 0.0

    single = {"Full System": full_metrics}

    # ── 1. Single-branch ablation ────────────────────────────────────────
    branch_impacts = []
    for i in range(n_branches):
        metrics = _eval_model(model, features, labels, full_preds, disabled={i})
        metrics["accuracy_drop"] = round(full_acc - metrics["accuracy"], 6)
        single[branch_names[i]] = metrics
        branch_impacts.append((i, metrics["accuracy_drop"]))

    # ── 2. Pairwise ablation ─────────────────────────────────────────────
    pairwise = {}
    for i in range(n_branches):
        for j in range(i + 1, n_branches):
            key = f"{branch_names[i]} + {branch_names[j]}"
            metrics = _eval_model(model, features, labels, full_preds, disabled={i, j})
            metrics["accuracy_drop"] = round(full_acc - metrics["accuracy"], 6)
            pairwise[key] = metrics

    # ── 3. Incremental ablation (by descending impact) ───────────────────
    # Sort branches by single-ablation impact (most impactful first)
    branch_impacts.sort(key=lambda x: x[1], reverse=True)

    incremental = []
    disabled_set = set()
    incremental.append({
        "step": 0,
        "disabled": [],
        "disabled_names": [],
        "accuracy": full_acc,
        "accuracy_drop": 0.0,
    })

    for step, (branch_idx, _) in enumerate(branch_impacts, start=1):
        disabled_set.add(branch_idx)
        metrics = _eval_model(model, features, labels, full_preds, disabled=disabled_set)
        incremental.append({
            "step": step,
            "disabled": sorted(disabled_set),
            "disabled_names": [branch_names[b] for b in sorted(disabled_set)],
            "accuracy": metrics["accuracy"],
            "accuracy_drop": round(full_acc - metrics["accuracy"], 6),
        })

    return {
        "single": single,
        "pairwise": pairwise,
        "incremental": incremental,
    }
