"""Gaussian-noise + feature-masking baselines.

Not adversarial in the strict sense — Gaussian is i.i.d. noise at a
chosen sigma, FeatureMask randomly zeros out a fraction of feature
dimensions. Useful as null-attack baselines on the Perception Tester
to show that the model's robustness to *random* perturbation is much
higher than to gradient-driven ones.
"""
from __future__ import annotations

import torch


def gaussian_noise(
    model: torch.nn.Module,
    x: torch.Tensor,
    y: torch.Tensor,
    sigma: float = 0.05,
    adj: torch.Tensor | None = None,
) -> torch.Tensor:
    if x.dim() == 2:
        x = x.unsqueeze(0)
    return (x + torch.randn_like(x) * sigma).detach()


def feature_mask(
    model: torch.nn.Module,
    x: torch.Tensor,
    y: torch.Tensor,
    mask_fraction: float = 0.2,
    adj: torch.Tensor | None = None,
) -> torch.Tensor:
    if x.dim() == 2:
        x = x.unsqueeze(0)
    mask = (torch.rand_like(x) > mask_fraction).float()
    return (x * mask).detach()
