"""Randomized smoothing (Cohen, Rosenfeld & Kolter, ICML 2019).

Certified l_2 radius:  R = (sigma/2) (Phi^-1(p_A) - Phi^-1(p_B))
with the Clopper-Pearson lower bound on p_A under confidence 1 - alpha.
"""
from __future__ import annotations

import math

import torch
from scipy.stats import beta as beta_dist, norm as norm_dist


def clopper_pearson_lower(k: int, n: int, alpha: float) -> float:
    """One-sided Clopper-Pearson lower bound on a binomial success probability."""
    if k == 0:
        return 0.0
    return float(beta_dist.ppf(alpha, k, n - k + 1))


@torch.no_grad()
def smooth_predict(
    model: torch.nn.Module,
    x: torch.Tensor,
    sigma: float,
    n_samples: int = 200,
    batch_size: int = 50,
    adj: torch.Tensor | None = None,
) -> tuple[torch.Tensor, torch.Tensor]:
    """Vote-aggregated smoothed prediction. Returns (top_class[b], counts[b, K]).

    Each of the b input samples is independently smoothed with n_samples Gaussian
    perturbations of std sigma. Optimised for the Phase-A single-sample
    certification call but supports small batches.
    """
    if x.dim() == 2:
        x = x.unsqueeze(0)
    b = x.shape[0]
    counts: torch.Tensor | None = None
    for sample_idx in range(b):
        x_one = x[sample_idx:sample_idx + 1]
        adj_one = adj[sample_idx:sample_idx + 1] if (adj is not None and adj.dim() == 3) else adj
        local_counts = None
        for start in range(0, n_samples, batch_size):
            bs = min(batch_size, n_samples - start)
            noise = torch.randn(bs, *x_one.shape[1:], device=x.device) * sigma
            x_noisy = x_one.expand(bs, *x_one.shape[1:]) + noise
            adj_rep = adj_one.expand(bs, -1, -1) if (adj_one is not None and adj_one.dim() == 3) else adj_one
            logits = model(x_noisy, adj_rep) if adj_rep is not None else model(x_noisy)
            preds = logits.argmax(dim=-1)
            if local_counts is None:
                local_counts = torch.zeros(logits.shape[-1], dtype=torch.long, device=x.device)
            local_counts += torch.bincount(preds, minlength=local_counts.shape[0])
        if counts is None:
            counts = torch.zeros(b, local_counts.shape[0], dtype=torch.long, device=x.device)
        counts[sample_idx] = local_counts
    top = counts.argmax(dim=-1)
    return top, counts


def certified_radius(
    counts_top: int,
    n_samples: int,
    sigma: float,
    alpha: float = 1e-3,
) -> float:
    """Cohen-style certified l_2 radius for the top-class vote count."""
    p_a = clopper_pearson_lower(counts_top, n_samples, alpha)
    if p_a <= 0.5:
        return 0.0
    return float((sigma / 2.0) * (norm_dist.ppf(p_a) - norm_dist.ppf(1 - p_a)))


def smooth_accuracy(model, dataset, sigma: float, n_samples: int = 200, alpha: float = 1e-3) -> dict:
    """Average certified radius and accuracy over a dataset slice."""
    correct = 0
    radii = []
    for x, adj, y in dataset:
        top, counts = smooth_predict(model, x.unsqueeze(0), sigma, n_samples, adj=adj)
        if top.item() == y.item():
            correct += 1
        radii.append(certified_radius(int(counts[0, top].item()), n_samples, sigma, alpha))
    return {
        "smoothed_accuracy": correct / max(1, len(dataset)),
        "mean_certified_radius": sum(radii) / max(1, len(radii)),
        "median_certified_radius": sorted(radii)[len(radii) // 2] if radii else 0.0,
    }
