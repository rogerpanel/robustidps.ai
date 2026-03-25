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
            metrics = _eval_model(model, features, labels, full_preds, disabled={i, j})
            metrics["accuracy_drop"] = round(full_acc - metrics["accuracy"], 6)
            # Use index-based key for frontend heatmap lookup
            key = f"{i}-{j}"
            metrics["name_i"] = branch_names[i]
            metrics["name_j"] = branch_names[j]
            metrics["branch_i"] = i
            metrics["branch_j"] = j
            # Interaction = pair drop - (individual drops summed)
            drop_i = single[branch_names[i]]["accuracy_drop"]
            drop_j = single[branch_names[j]]["accuracy_drop"]
            metrics["interaction"] = round(metrics["accuracy_drop"] - (drop_i + drop_j), 6)
            metrics["pair_accuracy"] = metrics["accuracy"]
            metrics["pair_drop"] = metrics["accuracy_drop"]
            pairwise[key] = metrics

    # ── 3. Incremental ablation (by descending impact) ───────────────────
    # Sort branches by single-ablation impact (most impactful first)
    branch_impacts.sort(key=lambda x: x[1], reverse=True)

    # Incremental BUILD-UP: start with nothing, add methods one at a time
    # (most impactful added first)
    incremental = []
    added_set = set()
    all_disabled = set(range(n_branches))

    # Step 0: no methods active (all disabled)
    metrics_none = _eval_model(model, features, labels, full_preds, disabled=all_disabled)
    prev_acc = metrics_none["accuracy"]
    incremental.append({
        "step": 0,
        "label": "No methods",
        "added": None,
        "added_idx": -1,
        "accuracy": prev_acc,
        "gain": 0.0,
    })

    for step, (branch_idx, _) in enumerate(branch_impacts, start=1):
        added_set.add(branch_idx)
        still_disabled = all_disabled - added_set
        metrics = _eval_model(model, features, labels, full_preds,
                              disabled=still_disabled if still_disabled else None)
        acc = metrics["accuracy"]
        incremental.append({
            "step": step,
            "label": f"+{branch_names[branch_idx]}",
            "added": branch_names[branch_idx],
            "added_idx": branch_idx,
            "accuracy": acc,
            "gain": round(acc - prev_acc, 6),
        })
        prev_acc = acc

    return {
        "single": single,
        "pairwise": pairwise,
        "incremental": incremental,
    }
