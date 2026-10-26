"""
SDE-based Temporal Graph Neural Network (SDE-TGNN)
====================================================

Stochastic Differential Equation Temporal Graph Neural Network
for network intrusion detection with uncertainty quantification.

Combines:
- Stochastic differential equations for noisy continuous dynamics
- Temporal graph neural networks for network topology evolution
- Drift-diffusion decomposition for robust feature learning

Based on: SDE-TGNN Models repository
Paper: PaperBA_main_v11a.tex

Author: Roger Nick Anaedevha
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple, Optional
import math


class SDEFunc(nn.Module):
    """
    SDE drift and diffusion functions.

    Models: dh = f(h, t)dt + g(h, t)dW
    where f is the drift and g is the diffusion.
    """

    def __init__(self, hidden_dim: int, num_layers: int = 3):
        super().__init__()

        # Drift network f(h, t)
        drift_layers = []
        for i in range(num_layers):
            in_dim = hidden_dim + 1 if i == 0 else hidden_dim
            drift_layers.extend([
                nn.Linear(in_dim, hidden_dim),
                nn.Tanh(),
            ])
        self.drift_net = nn.Sequential(*drift_layers)

        # Diffusion network g(h, t) - outputs scalar diffusion coefficient
        self.diffusion_net = nn.Sequential(
            nn.Linear(hidden_dim + 1, hidden_dim),
            nn.Tanh(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.Sigmoid(),  # Ensure positive diffusion
        )

    def drift(self, t: torch.Tensor, h: torch.Tensor) -> torch.Tensor:
        """Compute drift f(h, t)"""
        t_expanded = t.expand(h.size(0), 1) if t.dim() == 0 else t.unsqueeze(-1)
        h_t = torch.cat([h, t_expanded], dim=-1)
        return self.drift_net(h_t)

    def diffusion(self, t: torch.Tensor, h: torch.Tensor) -> torch.Tensor:
        """Compute diffusion g(h, t)"""
        t_expanded = t.expand(h.size(0), 1) if t.dim() == 0 else t.unsqueeze(-1)
        h_t = torch.cat([h, t_expanded], dim=-1)
        return self.diffusion_net(h_t)


class TemporalGraphConv(nn.Module):
    """Temporal graph convolution with time-aware message passing"""

    def __init__(self, in_dim: int, out_dim: int, time_dim: int = 16):
        super().__init__()
        self.node_transform = nn.Linear(in_dim, out_dim)
        self.time_embedding = nn.Sequential(
            nn.Linear(1, time_dim),
            nn.ReLU(),
            nn.Linear(time_dim, out_dim),
        )
        self.gate = nn.Sequential(
            nn.Linear(out_dim * 2, out_dim),
            nn.Sigmoid(),
        )

    def forward(
        self, x: torch.Tensor, adj: torch.Tensor, t: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """
        Args:
            x: Node features [num_nodes, in_dim]
            adj: Adjacency matrix [num_nodes, num_nodes]
            t: Time value (scalar)
        """
        h = self.node_transform(x)
        agg = torch.matmul(adj, h)

        if t is not None:
            t_val = t.view(1, 1) if t.dim() == 0 else t.unsqueeze(-1)
            t_embed = self.time_embedding(t_val).expand_as(h)
            gate_input = torch.cat([agg, t_embed], dim=-1)
            gate_val = self.gate(gate_input)
            return gate_val * agg + (1 - gate_val) * h

        return agg


class EulerMaruyamaSolver(nn.Module):
    """Euler-Maruyama solver for SDEs"""

    def __init__(self, sde_func: SDEFunc, n_steps: int = 10):
        super().__init__()
        self.sde_func = sde_func
        self.n_steps = n_steps

    def forward(
        self, h0: torch.Tensor, t_start: float = 0.0, t_end: float = 1.0
    ) -> torch.Tensor:
        """
        Solve SDE using Euler-Maruyama method.

        Args:
            h0: Initial state [batch_size, hidden_dim]
            t_start: Start time
            t_end: End time

        Returns:
            Final state [batch_size, hidden_dim]
        """
        dt = (t_end - t_start) / self.n_steps
        sqrt_dt = math.sqrt(abs(dt))

        h = h0
        t = torch.tensor(t_start, device=h0.device, dtype=h0.dtype)

        for _ in range(self.n_steps):
            drift = self.sde_func.drift(t, h)
            diffusion = self.sde_func.diffusion(t, h)

            # Brownian increment
            dW = torch.randn_like(h) * sqrt_dt

            # Euler-Maruyama update: h += f(h,t)*dt + g(h,t)*dW
            h = h + drift * dt + diffusion * dW
            t = t + dt

        return h


class SDETGNNModel(nn.Module):
    """
    SDE-based Temporal Graph Neural Network

    Architecture:
    1. Feature encoder -> latent space
    2. Construct implicit graph from flow features
    3. Temporal graph convolutions
    4. SDE evolution for continuous stochastic dynamics
    5. Decoder for classification

    For the demo, operates on per-flow features by constructing
    a mini-batch graph from the batch of flows.
    """

    def __init__(
        self,
        input_dim: int = 83,
        hidden_dim: int = 256,
        num_classes: int = 34,
        n_graph_layers: int = 2,
        sde_steps: int = 10,
        dropout: float = 0.2,
    ):
        super().__init__()

        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_classes = num_classes

        # Feature encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.BatchNorm1d(hidden_dim),
        )

        # Graph construction: learn pairwise similarity for adjacency
        self.edge_predictor = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid(),
        )

        # Temporal graph convolution layers
        self.tgnn_layers = nn.ModuleList([
            TemporalGraphConv(hidden_dim, hidden_dim)
            for _ in range(n_graph_layers)
        ])

        # SDE module
        self.sde_func = SDEFunc(hidden_dim, num_layers=3)
        self.sde_solver = EulerMaruyamaSolver(self.sde_func, n_steps=sde_steps)

        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, num_classes),
        )

    def _construct_graph(self, h: torch.Tensor) -> torch.Tensor:
        """
        Construct adjacency matrix from encoded features.
        Uses k-nearest neighbors in latent space.

        Args:
            h: Encoded features [batch_size, hidden_dim]
        Returns:
            adj: Adjacency matrix [batch_size, batch_size]
        """
        n = h.size(0)
        if n <= 1:
            return torch.ones(1, 1, device=h.device)

        # Cosine similarity as adjacency
        h_norm = F.normalize(h, p=2, dim=-1)
        adj = torch.mm(h_norm, h_norm.t())

        # Threshold to create sparse graph (top-k neighbors)
        k = min(10, n - 1)
        topk_vals, topk_idx = adj.topk(k + 1, dim=-1)  # +1 for self-loop
        mask = torch.zeros_like(adj)
        mask.scatter_(1, topk_idx, 1.0)
        adj = adj * mask

        # Normalize
        deg = adj.sum(dim=-1, keepdim=True).clamp(min=1.0)
        adj = adj / deg

        return adj

    def forward(self, x: torch.Tensor, disabled_branches: set = None) -> torch.Tensor:
        """
        Forward pass.

        Args:
            x: Input features [batch_size, input_dim]
            disabled_branches: Ignored (compatibility with SurrogateIDS interface)

        Returns:
            logits: [batch_size, num_classes]
        """
        # Encode features
        h = self.encoder(x)

        # Construct implicit graph
        adj = self._construct_graph(h.detach())

        # Temporal graph convolutions
        t = torch.tensor(0.0, device=x.device)
        for tgnn_layer in self.tgnn_layers:
            h = F.relu(tgnn_layer(h, adj, t))
            t = t + 0.5

        # SDE evolution for stochastic dynamics
        if self.training:
            h = self.sde_solver(h)
        else:
            # Deterministic at inference (drift only)
            dt = 1.0 / self.sde_solver.n_steps
            t = torch.tensor(0.0, device=x.device)
            for _ in range(self.sde_solver.n_steps):
                h = h + self.sde_func.drift(t, h) * dt
                t = t + dt

        # Decode
        logits = self.decoder(h)
        return logits
