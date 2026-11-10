"""Label-flipping training-time attack (Biggio et al., ICML 2012 family).

Flips a fraction of training labels — pure random flip or targeted
class flip. Cheaper than feature-collision poisoning but coarser; the
classifier's clean accuracy degrades smoothly with flip fraction.
Returned as the modified label tensor; the dataset itself is unchanged.
"""
from __future__ import annotations

import torch


def random_label_flip(
    y: torch.Tensor,
    flip_fraction: float = 0.1,
    n_classes: int = 2,
    seed: int = 42,
) -> torch.Tensor:
    g = torch.Generator().manual_seed(seed)
    flipped = y.clone()
    n_flip = int(len(y) * flip_fraction)
    if n_flip == 0:
        return flipped
    idx = torch.randperm(len(y), generator=g)[:n_flip]
    for i in idx.tolist():
        new_label = int(torch.randint(0, n_classes, (1,), generator=g).item())
        while new_label == int(y[i].item()):
            new_label = int(torch.randint(0, n_classes, (1,), generator=g).item())
        flipped[i] = new_label
    return flipped


def targeted_label_flip(
    y: torch.Tensor,
    src_class: int = 1,
    dst_class: int = 0,
    flip_fraction: float = 0.5,
    seed: int = 42,
) -> torch.Tensor:
    g = torch.Generator().manual_seed(seed)
    flipped = y.clone()
    src_idx = (y == src_class).nonzero(as_tuple=True)[0]
    if len(src_idx) == 0:
        return flipped
    n_flip = int(len(src_idx) * flip_fraction)
    if n_flip == 0:
        return flipped
    perm = torch.randperm(len(src_idx), generator=g)[:n_flip]
    for j in perm.tolist():
        flipped[src_idx[j]] = dst_class
    return flipped
