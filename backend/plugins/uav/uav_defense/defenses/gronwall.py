"""Lipschitz-Gronwall certificate (Theorem 6.1 of chapter 6).

  ||h_1(T) - h_2(T)|| <= exp(L_g * T) * ||x_1 - x_2||

L_g is estimated by power iteration on the Jacobian of the network's
forward map. The implementation is a finite-difference surrogate so it
works on any nn.Module without backwards-graph instrumentation.
"""
from __future__ import annotations

import math

import torch


@torch.no_grad()
def estimate_lipschitz(
    model: torch.nn.Module,
    x: torch.Tensor,
    n_iters: int = 25,
    step: float = 1e-3,
    adj: torch.Tensor | None = None,
) -> float:
    """Max over n_iters random unit-norm input directions of the empirical
    Jacobian-norm ||f(x + step·v) − f(x)|| / step. A finite-difference
    surrogate for the operator-norm Lipschitz constant of the network
    around x. Works on any nn.Module without instrumenting its backwards
    graph, at the cost of being a lower-bound estimate.
    """
    if x.dim() == 2:
        x = x.unsqueeze(0)
    base = model(x, adj) if adj is not None else model(x)
    max_lipschitz = 0.0
    extra_dims = (1,) * (x.dim() - 1)
    for _ in range(n_iters):
        v = torch.randn_like(x)
        v_norm = v.flatten(1).norm(dim=-1).clamp(min=1e-9)
        v = v / v_norm.view(-1, *extra_dims)
        perturbed = model(x + step * v, adj) if adj is not None else model(x + step * v)
        delta = (perturbed - base).flatten(1).norm(dim=-1) / step
        max_lipschitz = max(max_lipschitz, float(delta.max().item()))
    return max_lipschitz


def gronwall_radius(lipschitz: float, horizon_T: float, epsilon_out: float) -> float:
    """Maximum input l_2 radius that keeps the T-horizon output deviation under epsilon_out."""
    if lipschitz <= 0:
        return float("inf")
    return float(epsilon_out / math.exp(lipschitz * horizon_T))
