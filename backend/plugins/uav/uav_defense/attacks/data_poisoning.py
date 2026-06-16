"""Clean-label feature-collision poisoning (Shafahi et al., NeurIPS 2018)."""
from __future__ import annotations

import torch


def feature_collision_poison(
    feature_extractor: torch.nn.Module,
    base: torch.Tensor,
    target: torch.Tensor,
    beta: float = 0.25,
    n_steps: int = 100,
    lr: float = 0.01,
) -> torch.Tensor:
    """Optimize `base` so its features collide with `target`'s.

    The poisoned sample retains base's visual class but extractor(base) ≈
    extractor(target), inducing misclassification of target at inference.
    """
    poison = base.clone().detach().requires_grad_(True)
    optimizer = torch.optim.Adam([poison], lr=lr)
    with torch.no_grad():
        target_feat = feature_extractor(target)
    for _ in range(n_steps):
        feat = feature_extractor(poison)
        collision = ((feat - target_feat) ** 2).flatten(1).sum(dim=1)
        proximity = ((poison - base) ** 2).flatten(1).sum(dim=1)
        loss = (collision + beta * proximity).mean()
        optimizer.zero_grad(); loss.backward(); optimizer.step()
    return poison.detach()
