"""BoundaryAttack (Brendel, Rauber & Bethge, ICLR 2018) — decision-based random walk."""
from __future__ import annotations

import torch


@torch.no_grad()
def _is_adv(model: torch.nn.Module, x: torch.Tensor, y_true: torch.Tensor, adj=None) -> torch.Tensor:
    logits = model(x, adj) if adj is not None else model(x)
    return logits.argmax(dim=-1) != y_true


def boundary_attack(
    model: torch.nn.Module,
    x: torch.Tensor,
    y: torch.Tensor,
    n_steps: int = 100,
    step_size: float = 0.05,
    spherical_step: float = 0.05,
    adj: torch.Tensor | None = None,
) -> torch.Tensor:
    x_adv = x + 0.5 * torch.randn_like(x)
    for _ in range(n_steps):
        eta = torch.randn_like(x_adv)
        eta = eta - ((eta * (x_adv - x)).flatten(1).sum(dim=-1).view(-1, *([1] * (x.dim() - 1))) *
                     (x_adv - x) / (x_adv - x).flatten(1).norm(dim=-1).clamp(min=1e-9).view(-1, *([1] * (x.dim() - 1))) ** 2)
        candidate = x_adv + spherical_step * eta + step_size * (x - x_adv)
        keep = _is_adv(model, candidate, y, adj)
        keep_view = keep.view(-1, *([1] * (x.dim() - 1))).float()
        x_adv = keep_view * candidate + (1 - keep_view) * x_adv
    return x_adv.detach()
