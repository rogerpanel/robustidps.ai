"""HopSkipJumpAttack (Chen, Jordan & Wainwright, IEEE S&P 2020) — decision-based."""
from __future__ import annotations

import torch


@torch.no_grad()
def _decision(model: torch.nn.Module, x: torch.Tensor, y_true: torch.Tensor, adj=None) -> torch.Tensor:
    logits = model(x, adj) if adj is not None else model(x)
    return (logits.argmax(dim=-1) != y_true).float()


def hop_skip_jump(
    model: torch.nn.Module,
    x: torch.Tensor,
    y: torch.Tensor,
    n_queries: int = 200,
    n_montecarlo: int = 50,
    adj: torch.Tensor | None = None,
) -> torch.Tensor:
    x_adv = x.clone().detach()
    delta_size = 0.1
    queries = 0
    while queries < n_queries:
        u = torch.randn(n_montecarlo, *x.shape, device=x.device)
        u = u / u.flatten(2).norm(dim=-1, keepdim=True).unsqueeze(-1).clamp(min=1e-9)
        candidates = (x_adv.unsqueeze(0) + delta_size * u).flatten(0, 1)
        y_rep = y.repeat(n_montecarlo)
        adj_rep = adj.repeat(n_montecarlo, 1, 1) if (adj is not None and adj.dim() == 3) else adj
        dec = _decision(model, candidates, y_rep, adj_rep).view(n_montecarlo, -1)
        weight = (2 * dec - 1).mean(dim=0).clamp(-1, 1)
        grad_est = (weight.view(-1, *([1] * (u.dim() - 2))) * u.mean(dim=0))
        x_adv = (x_adv + delta_size * grad_est.sign()).detach()
        queries += n_montecarlo
        delta_size *= 0.9
    return x_adv
