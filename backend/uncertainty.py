"""
MC-Dropout uncertainty decomposition.

Maps to dissertation Chapter 2 — Stochastic Transformer (Method 6):
  * Epistemic uncertainty  = variance of predictive means across MC samples
  * Aleatoric uncertainty  = mean of predictive variances across MC samples
  * ECE                    = Expected Calibration Error
"""

import torch
import numpy as np


def compute_ece(confidence: torch.Tensor, predictions: torch.Tensor,
                labels: torch.Tensor | None, n_bins: int = 15) -> float:
    """Expected Calibration Error."""
    if labels is None:
        return 0.0
    conf_np = confidence.cpu().numpy()
    pred_np = predictions.cpu().numpy()
    lbl_np = labels.cpu().numpy()
    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    for lo, hi in zip(bin_boundaries[:-1], bin_boundaries[1:]):
        mask = (conf_np > lo) & (conf_np <= hi)
        if mask.sum() == 0:
            continue
        avg_conf = conf_np[mask].mean()
        avg_acc = (pred_np[mask] == lbl_np[mask]).mean()
        ece += mask.sum() / len(conf_np) * abs(avg_acc - avg_conf)
    return float(ece)


def predict_with_uncertainty(model, features: torch.Tensor,
                             labels: torch.Tensor | None = None,
                             n_mc: int = 50) -> dict:
    model.train()  # enable dropout
    mc_preds = []
    with torch.no_grad():
        for _ in range(n_mc):
            logits = model(features)
            probs = torch.softmax(logits, dim=-1)
            mc_preds.append(probs)
    model.eval()

    stacked = torch.stack(mc_preds)              # [n_mc, batch, n_classes]
    mean_pred = stacked.mean(0)                   # [batch, n_classes]
    epistemic = stacked.var(0).sum(-1)            # [batch]
    aleatoric = (stacked * (1 - stacked)).mean(0).sum(-1)  # [batch]

    predictions = mean_pred.argmax(-1)            # [batch]
    confidence = mean_pred.max(-1).values         # [batch]

    ece = compute_ece(confidence, predictions, labels)

    return {
        "predictions": predictions,
        "confidence": confidence,
        "epistemic": epistemic,
        "aleatoric": aleatoric,
        "ece": ece,
        "mean_probs": mean_pred,
    }
