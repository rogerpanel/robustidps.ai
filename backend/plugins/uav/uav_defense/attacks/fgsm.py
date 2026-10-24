"""FGSM (Goodfellow, Shlens & Szegedy, ICLR 2015)."""
from __future__ import annotations

import torch
import torch.nn.functional as F


def fgsm(
    model: torch.nn.Module,
    x: torch.Tensor,
    y: torch.Tensor,
    epsilon: float,
    adj: torch.Tensor | None = None,
) -> torch.Tensor:
    x_adv = x.clone().detach().requires_grad_(True)
    logits = model(x_adv, adj) if adj is not None else model(x_adv)
    loss = F.cross_entropy(logits, y)
    grad = torch.autograd.grad(loss, x_adv)[0]
    return (x_adv + epsilon * grad.sign()).detach()
