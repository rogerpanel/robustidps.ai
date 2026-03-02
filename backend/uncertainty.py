"""
MC-Dropout uncertainty decomposition.

Maps to dissertation Chapter 2 — Stochastic Transformer (Method 6):
  * Epistemic uncertainty  = variance of predictive means across MC samples
  * Aleatoric uncertainty  = mean of predictive variances across MC samples
  * ECE                    = Expected Calibration Error
"""

import os

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


CHUNK_SIZE = int(os.environ.get("CHUNK_SIZE", "5000"))


def _mc_chunk(model, chunk: torch.Tensor, n_mc: int):
    """Run MC Dropout on a single chunk and return summary tensors."""
    model.train()
    mc_preds = []
    with torch.no_grad():
        for _ in range(n_mc):
            logits = model(chunk)
            probs = torch.softmax(logits, dim=-1)
            mc_preds.append(probs)
    model.eval()

    stacked = torch.stack(mc_preds)                # [n_mc, chunk_size, C]
    mean_pred = stacked.mean(0)                     # [chunk_size, C]
    epistemic = stacked.var(0).sum(-1)              # [chunk_size]
    aleatoric = (stacked * (1 - stacked)).mean(0).sum(-1)
    predictions = mean_pred.argmax(-1)
    confidence = mean_pred.max(-1).values
    return predictions, confidence, epistemic, aleatoric, mean_pred


def predict_with_uncertainty(model, features: torch.Tensor,
                             labels: torch.Tensor | None = None,
                             n_mc: int = 50) -> dict:
    """MC-Dropout inference with automatic chunking for large inputs."""
    n = features.size(0)
    all_preds, all_conf, all_epi, all_ale, all_mean = [], [], [], [], []

    for start in range(0, n, CHUNK_SIZE):
        end = min(start + CHUNK_SIZE, n)
        chunk = features[start:end]
        p, c, e, a, m = _mc_chunk(model, chunk, n_mc)
        all_preds.append(p)
        all_conf.append(c)
        all_epi.append(e)
        all_ale.append(a)
        all_mean.append(m)

    predictions = torch.cat(all_preds)
    confidence = torch.cat(all_conf)
    epistemic = torch.cat(all_epi)
    aleatoric = torch.cat(all_ale)
    mean_pred = torch.cat(all_mean)

    ece = compute_ece(confidence, predictions, labels)

    return {
        "predictions": predictions,
        "confidence": confidence,
        "epistemic": epistemic,
        "aleatoric": aleatoric,
        "ece": ece,
        "mean_probs": mean_pred,
    }
