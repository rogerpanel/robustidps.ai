"""PGD (Madry et al., ICLR 2018) with l_inf projection."""
from __future__ import annotations

import torch
import torch.nn.functional as F


def pgd(
    model: torch.nn.Module,
    x: torch.Tensor,
    y: torch.Tensor,
    epsilon: float,
    alpha: float | None = None,
    n_steps: int = 20,
    adj: torch.Tensor | None = None,
    random_start: bool = True,
) -> torch.Tensor:
    if alpha is None:
        alpha = epsilon / 4.0
    x_orig = x.clone().detach()
    if random_start:
        x_adv = x_orig + torch.empty_like(x_orig).uniform_(-epsilon, epsilon)
    else:
        x_adv = x_orig.clone()
    for _ in range(n_steps):
        x_adv = x_adv.detach().requires_grad_(True)
        logits = model(x_adv, adj) if adj is not None else model(x_adv)
        loss = F.cross_entropy(logits, y)
        grad = torch.autograd.grad(loss, x_adv)[0]
        x_adv = x_adv + alpha * grad.sign()
        x_adv = torch.max(torch.min(x_adv, x_orig + epsilon), x_orig - epsilon)
    return x_adv.detach()
