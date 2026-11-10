"""
SODE-Guard — Stochastic ODE Defense with E-GraphSAGE Encoder.

An Ito stochastic differential equation framework for adversarial perturbation
defense. Despite the source repo's "ExtractGuard" name, the README clarifies
this model targets ADVERSARIAL PERTURBATION DEFENSE — it is NOT a model
extraction defense.

Pipeline (pure-PyTorch approximation; no torchsde / torchdiffeq required):
    1. 83 -> 128 dense embedding
    2. 2 x E-GraphSAGE-style edge-feature graph blocks (gated combine,
       GELU + LayerNorm + residual)
    3. 5 sequential Euler-Maruyama SDE steps with learned drift and
       diffusion MLPs. We deliberately SHARE the SDE-step parameters across
       all 5 steps so the model behaves like a discretised time-homogeneous
       SDE; this also keeps the parameter count down without hurting the
       expressive depth provided by the repeated application.
    4. Linear classifier 128 -> 34
    5. Anti-concentration certificate: cert = 1 / (1 + ||diffusion||_2)
       computed at the final SDE step. Higher cert means tighter
       anti-concentration / more robust prediction.

Source: https://github.com/rogerpanel/SODE-ExtractGuard-Models

Author: Roger Nick Anaedevha
"""
from __future__ import annotations

import math
import torch
import torch.nn as nn
import torch.nn.functional as F

from .surrogate import SurrogateIDS


# ---------------------------------------------------------------------------
# E-GraphSAGE-style block (pattern duplicated from ssl_anomaly.py to avoid
# cross-file coupling — keeping each new model self-contained).
# ---------------------------------------------------------------------------

class _EGraphSAGEBlock(nn.Module):
    """Edge-feature graph block with gated combine + residual.

    Treats each row of the batch as an edge feature vector. Synthetic
    src/dst role embeddings allow the layer to mimic E-GraphSAGE inductive
    aggregation without an explicit edge index.
    """

    def __init__(self, in_dim: int, hidden_dim: int = 128, dropout: float = 0.1):
        super().__init__()
        self.edge_proj = nn.Linear(in_dim, hidden_dim)
        self.node_src = nn.Linear(in_dim, hidden_dim)
        self.node_dst = nn.Linear(in_dim, hidden_dim)
        self.attn = nn.Linear(hidden_dim * 3, 1)
        self.combine = nn.Linear(hidden_dim * 3, hidden_dim)
        self.norm = nn.LayerNorm(hidden_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        e = self.edge_proj(x)
        u = self.node_src(x)
        v = self.node_dst(x)
        cat = torch.cat([u, v, e], dim=-1)
        a = torch.sigmoid(self.attn(cat))
        h = F.gelu(self.combine(cat)) * a + e
        return self.dropout(self.norm(h))


# ---------------------------------------------------------------------------
# Single Euler-Maruyama SDE step
# ---------------------------------------------------------------------------

class _SDEStep(nn.Module):
    """One discretised Ito SDE step: h_next = h + f(h,t)*dt + g(h,t)*sqrt(dt)*eps.

    `chaos_degree` scales the diffusion magnitude; the platform exposes a
    setter on the wrapper that propagates here. During eval() the noise is
    zeroed so inference is deterministic.
    """

    def __init__(self, dim: int, time_dim: int = 8, hidden: int = 64, chaos_degree: int = 4):
        super().__init__()
        self.dim = dim
        self.time_dim = time_dim
        self.chaos_degree = chaos_degree
        self.drift = nn.Sequential(
            nn.Linear(dim + time_dim, hidden),
            nn.GELU(),
            nn.Linear(hidden, dim),
        )
        self.diffusion = nn.Sequential(
            nn.Linear(dim + time_dim, hidden),
            nn.GELU(),
            nn.Linear(hidden, dim),
            nn.Tanh(),  # bound base diffusion in [-1, 1]; chaos_degree scales it
        )
        # Last-step diffusion vector, exposed so SODEGuardModel can derive
        # the anti-concentration certificate without re-running the diffusion
        # MLP.
        self.last_diffusion: torch.Tensor | None = None

    @staticmethod
    def _time_embed(t: float, dim: int, batch: int, device: torch.device) -> torch.Tensor:
        # Simple sinusoidal time embedding shared across the batch.
        freqs = torch.arange(dim, device=device).float()
        freqs = torch.exp(-math.log(10000.0) * freqs / max(dim, 1))
        phase = t * freqs
        emb = torch.cat([torch.sin(phase), torch.cos(phase)])[:dim]
        return emb.unsqueeze(0).expand(batch, -1)

    def forward(self, h: torch.Tensor, t: float, dt: float) -> torch.Tensor:
        B = h.size(0)
        te = self._time_embed(t, self.time_dim, B, h.device)
        ht = torch.cat([h, te], dim=-1)
        f = self.drift(ht)
        g = self.diffusion(ht) * float(self.chaos_degree)
        self.last_diffusion = g
        if self.training:
            eps = torch.randn_like(h)
        else:
            eps = torch.zeros_like(h)
        return h + f * dt + g * math.sqrt(dt) * eps


# ---------------------------------------------------------------------------
# SODE-Guard detector
# ---------------------------------------------------------------------------

class SODEGuardModel(nn.Module):
    """SODE-Guard detector: graph + SDE evolution + anti-concentration cert."""

    N_SDE_STEPS = 5
    DT = 0.05

    def __init__(
        self,
        in_dim: int = 83,
        hidden_dim: int = 128,
        n_classes: int = 34,
        chaos_degree: int = 4,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.embed = nn.Sequential(
            nn.Linear(in_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
        )
        # Two graph blocks: first consumes raw [B,83], second consumes [B,128].
        self.graph1 = _EGraphSAGEBlock(in_dim, hidden_dim, dropout=dropout)
        self.graph2 = _EGraphSAGEBlock(hidden_dim, hidden_dim, dropout=dropout)
        # Shared SDE step (time-homogeneous discretisation).
        self.sde_step = _SDEStep(hidden_dim, chaos_degree=chaos_degree)
        self.head = nn.Linear(hidden_dim, n_classes)
        # Side-channel anti-concentration certificate per sample.
        self.last_cert: torch.Tensor | None = None

    def set_chaos_degree(self, degree: int) -> None:
        self.sde_step.chaos_degree = int(degree)

    def _trunk(self, x: torch.Tensor) -> torch.Tensor:
        h = self.embed(x)
        h = h + self.graph1(x)
        h = h + self.graph2(h)
        # Sequential SDE evolution.
        t = 0.0
        for _ in range(self.N_SDE_STEPS):
            h = self.sde_step(h, t=t, dt=self.DT)
            t += self.DT
        # Anti-concentration certificate from the final diffusion vector.
        g = self.sde_step.last_diffusion
        if g is not None:
            diffusion_norm = g.norm(dim=-1, keepdim=True)              # [B, 1]
            # 1 / (1 + ||g||) — bounded in (0, 1], no divide-by-zero.
            self.last_cert = 1.0 / (1.0 + diffusion_norm)
        return h

    def forward(self, x: torch.Tensor, disabled_branches=None) -> torch.Tensor:
        del disabled_branches  # accepted for platform contract; no ablation surface
        h = self._trunk(x)
        return self.head(h)

    def forward_with_cert(self, x: torch.Tensor) -> dict[str, torch.Tensor]:
        h = self._trunk(x)
        logits = self.head(h)
        cert = self.last_cert if self.last_cert is not None else torch.zeros(x.size(0), 1, device=x.device)
        return {"logits": logits, "anti_concentration": cert}


# ---------------------------------------------------------------------------
# Platform-compatible wrapper
# ---------------------------------------------------------------------------

class SODEGuardWrapper(nn.Module):
    """Platform wrapper for SODEGuardModel (83 -> 34 contract).

    `set_chaos_degree(degree)` scales the diffusion magnitude during training.
    Inference is unaffected because Euler-Maruyama noise is zeroed in eval()
    mode (see `_SDEStep.forward`).
    """

    N_FEATURES = 83
    N_CLASSES = 34
    BRANCH_NAMES = SurrogateIDS.BRANCH_NAMES
    CLASS_NAMES = SurrogateIDS.CLASS_NAMES
    SEVERITY_MAP = SurrogateIDS.SEVERITY_MAP

    def __init__(self, dropout: float = 0.1):
        super().__init__()
        self.model = SODEGuardModel(dropout=dropout)

    def forward(self, x, disabled_branches=None):
        return self.model(x, disabled_branches)

    def forward_with_cert(self, x):
        return self.model.forward_with_cert(x)

    def set_chaos_degree(self, degree: int) -> None:
        """Scale diffusion magnitude (training only; inference uses zero noise)."""
        self.model.set_chaos_degree(degree)

    @classmethod
    def severity_for(cls, label: str) -> str:
        return SurrogateIDS.severity_for(label)
