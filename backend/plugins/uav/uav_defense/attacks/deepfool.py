"""DeepFool (Moosavi-Dezfooli, Fawzi & Frossard, CVPR 2016).

Iterative minimal-L2-perturbation attack — projects the input onto the
closest decision boundary at each step. Lighter than CW, stronger than
PGD per unit perturbation. Native multi-class formulation, well-suited
to the binary spoof/clean GNSS task.
"""
from __future__ import annotations

import torch


def deepfool(
    model: torch.nn.Module,
    x: torch.Tensor,
    y: torch.Tensor,
    max_iters: int = 50,
    overshoot: float = 0.02,
    adj: torch.Tensor | None = None,
) -> torch.Tensor:
    if x.dim() == 2:
        x = x.unsqueeze(0)
    perturbed = x.clone().detach()
    n_batch = x.shape[0]

    for sample_idx in range(n_batch):
        xi = perturbed[sample_idx:sample_idx + 1].clone().detach().requires_grad_(True)
        adj_i = adj[sample_idx:sample_idx + 1] if (adj is not None and adj.dim() == 3) else adj
        yi = int(y[sample_idx].item())

        for _ in range(max_iters):
            logits = model(xi, adj_i) if adj_i is not None else model(xi)
            current = int(logits.argmax(dim=-1).item())
            if current != yi:
                break

            # Gradient of f_k(x) - f_yi(x) for each non-yi class k
            n_classes = logits.shape[-1]
            grads = []
            for k in range(n_classes):
                if k == yi:
                    grads.append(None)
                    continue
                f_diff = logits[0, k] - logits[0, yi]
                g = torch.autograd.grad(f_diff, xi, retain_graph=(k < n_classes - 1))[0]
                grads.append((g.detach(), float(f_diff.item())))

            # Pick the class with the smallest |f_diff| / ||grad||
            best_k = None
            best_perturb = None
            best_ratio = float("inf")
            for k, gd in enumerate(grads):
                if gd is None:
                    continue
                g, f = gd
                g_norm = g.flatten().norm() + 1e-9
                ratio = abs(f) / float(g_norm)
                if ratio < best_ratio:
                    best_ratio = ratio
                    best_perturb = (abs(f) + 1e-9) / (float(g_norm) ** 2) * g
                    best_k = k

            if best_perturb is None:
                break
            xi = (xi.detach() + (1 + overshoot) * best_perturb).requires_grad_(True)

        perturbed[sample_idx] = xi.detach().squeeze(0)

    return perturbed
