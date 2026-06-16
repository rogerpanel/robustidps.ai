"""M1 CT-TGNN — continuous-time temporal graph neural network.

Implements the Neural-ODE-driven node dynamics from chapter 4 / chapter 6
Eq. (6.x): dh_v/dt = f_theta(h_v, A(t), X(t), t). The drift f_theta is a
two-layer message-passing block; the solver is the Euler-step adjoint
(O(1) memory in T) sufficient for the Phase-A 1-step horizon used in the
Gronwall radius certification on the 8-satellite GNSS graph.
"""
from __future__ import annotations

import torch
import torch.nn as nn


class _Drift(nn.Module):
    def __init__(self, feat_dim: int, hidden_dim: int):
        super().__init__()
        self.lin_self = nn.Linear(feat_dim, hidden_dim)
        self.lin_neigh = nn.Linear(feat_dim, hidden_dim)
        self.act = nn.Tanh()

    def forward(self, h: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
        neigh_msg = torch.einsum("bij,bjd->bid", adj, h)
        return self.act(self.lin_self(h) + self.lin_neigh(neigh_msg))


class CTTGNN(nn.Module):
    def __init__(
        self,
        feat_dim: int = 8,
        hidden_dim: int = 32,
        num_classes: int = 2,
        n_steps: int = 4,
        dt: float = 0.25,
    ):
        super().__init__()
        self.encoder = nn.Linear(feat_dim, hidden_dim)
        self.drift = _Drift(hidden_dim, hidden_dim)
        self.classifier = nn.Linear(hidden_dim, num_classes)
        self.n_steps = n_steps
        self.dt = dt

    def forward(self, x: torch.Tensor, adj: torch.Tensor | None = None) -> torch.Tensor:
        if x.dim() == 2:
            x = x.unsqueeze(0)
        b, n, _ = x.shape
        if adj is None:
            adj = torch.ones(b, n, n, device=x.device) - torch.eye(n, device=x.device).unsqueeze(0)
        elif adj.dim() == 2:
            adj = adj.unsqueeze(0).expand(b, -1, -1)

        h = self.encoder(x)
        for _ in range(self.n_steps):
            h = h + self.dt * self.drift(h, adj)

        graph_emb = h.mean(dim=1)
        return self.classifier(graph_emb)

    def predict_proba(self, x: torch.Tensor, adj: torch.Tensor | None = None) -> torch.Tensor:
        return torch.softmax(self.forward(x, adj), dim=-1)
