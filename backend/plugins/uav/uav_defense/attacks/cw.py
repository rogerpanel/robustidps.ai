"""Carlini-Wagner l_2 attack (IEEE S&P 2017) with tanh change-of-variables."""
from __future__ import annotations

import torch
import torch.nn.functional as F


def cw(
    model: torch.nn.Module,
    x: torch.Tensor,
    y: torch.Tensor,
    kappa: float = 0.0,
    c: float = 1.0,
    n_steps: int = 200,
    lr: float = 0.01,
    adj: torch.Tensor | None = None,
) -> torch.Tensor:
    x_min, x_max = x.min(), x.max()
    span = (x_max - x_min).clamp(min=1e-6)
    x_norm = (x - x_min) / span
    w = torch.atanh((2 * x_norm - 1).clamp(-0.999, 0.999)).detach().requires_grad_(True)
    optimizer = torch.optim.Adam([w], lr=lr)

    for _ in range(n_steps):
        x_adv_norm = 0.5 * (torch.tanh(w) + 1)
        x_adv = x_adv_norm * span + x_min
        logits = model(x_adv, adj) if adj is not None else model(x_adv)
        true_logit = logits.gather(1, y.unsqueeze(1)).squeeze(1)
        other_logit, _ = logits.scatter(1, y.unsqueeze(1), float("-inf")).max(dim=1)
        f6 = (true_logit - other_logit + kappa).clamp(min=0)
        l2 = ((x_adv - x) ** 2).flatten(1).sum(dim=1)
        loss = (l2 + c * f6).mean()
        optimizer.zero_grad(); loss.backward(); optimizer.step()
    with torch.no_grad():
        x_adv = 0.5 * (torch.tanh(w) + 1) * span + x_min
    return x_adv.detach()
