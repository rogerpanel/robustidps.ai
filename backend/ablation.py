"""
Ablation study — disable each surrogate branch one at a time and
measure the accuracy drop.  Reproduces the dissertation ablation table.
"""

import torch


def run_ablation(model, features: torch.Tensor,
                 labels: torch.Tensor | None = None) -> dict:
    results = {}

    with torch.no_grad():
        model.eval()
        full_logits = model(features)
        full_preds = full_logits.argmax(-1)
        if labels is not None:
            full_acc = (full_preds == labels).float().mean().item()
        else:
            full_acc = 1.0
        results["Full System"] = {
            "accuracy": full_acc,
            "accuracy_drop": 0.0,
            "disabled": [],
        }

    for i, name in enumerate(model.BRANCH_NAMES):
        with torch.no_grad():
            ablated_logits = model(features, disabled_branches={i})
            ablated_preds = ablated_logits.argmax(-1)
            if labels is not None:
                acc = (ablated_preds == labels).float().mean().item()
            else:
                acc = (ablated_preds == full_preds).float().mean().item()
            results[name] = {
                "accuracy": acc,
                "accuracy_drop": full_acc - acc,
                "disabled": [i],
            }

    return results
