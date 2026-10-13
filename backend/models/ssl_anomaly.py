"""
Self-Supervised Anomaly Detector
================================

A GraphIDS-style self-supervised intrusion detector combining:
  1. E-GraphSAGE-style edge-feature graph encoder (induced from flat flow features)
  2. Transformer Autoencoder over the graph-conditioned embedding
  3. Anomaly score = reconstruction error + Mahalanobis distance to the
     in-distribution embedding cluster

Designed for the no-label setting: only "benign" flows are needed for
fitting, attacks surface as high anomaly scores at inference. To remain
compatible with the platform's [batch, 83] -> [batch, 34] inference
contract, the wrapper exposes:

  - forward(x, disabled_branches=None) -> 34-class logits
    (logits[0] = benign-confidence proxy; logits[1:] = per-class anomaly
     attribution from a small classification head trained alongside the
     encoder for downstream attribution)

  - anomaly_score(x) -> [batch] reconstruction-energy score in [0, +inf)

This is intentionally a torchdiffeq / torch-geometric free implementation
so the demo backend has zero new heavy dependencies.

References:
  - GraphIDS (NeurIPS 2025) — self-supervised graph IDS with reconstruction.
  - Lo et al., "E-GraphSAGE", IEEE NOMS 2022 — edge-feature SAGE for NIDS.
  - Liu et al., "Anomaly Transformer", ICLR 2022 — discrepancy-based AE.

Author: Roger Nick Anaedevha
"""
from __future__ import annotations

import math
import torch
import torch.nn as nn
import torch.nn.functional as F

from .surrogate import SurrogateIDS


# ---------------------------------------------------------------------------
# Edge-feature graph block (E-GraphSAGE style)
# ---------------------------------------------------------------------------

class EGraphSAGEBlock(nn.Module):
    """E-GraphSAGE edge-feature aggregator.

    Each "edge" here is a flow record. We construct a synthetic micro-graph
    over the batch by treating flows as edges between two virtual nodes
    (src_role, dst_role) and using attention to aggregate.

    For a flat-feature demo we collapse this to attention-weighted
    neighbourhood pooling that mimics the inductive aggregation of
    E-GraphSAGE without requiring an explicit edge index.
    """

    def __init__(self, in_dim: int, hidden_dim: int, dropout: float = 0.1):
        super().__init__()
        self.edge_proj = nn.Linear(in_dim, hidden_dim)
        self.node_src  = nn.Linear(in_dim, hidden_dim)
        self.node_dst  = nn.Linear(in_dim, hidden_dim)
        self.attn      = nn.Linear(hidden_dim * 3, 1)
        self.combine   = nn.Linear(hidden_dim * 3, hidden_dim)
        self.norm      = nn.LayerNorm(hidden_dim)
        self.dropout   = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: [B, in_dim] — treat each row as an edge feature vector
        e   = self.edge_proj(x)         # [B, H]
        u   = self.node_src(x)          # [B, H] — "src" role embedding
        v   = self.node_dst(x)          # [B, H] — "dst" role embedding
        cat = torch.cat([u, v, e], dim=-1)              # [B, 3H]
        a   = torch.sigmoid(self.attn(cat))             # [B, 1]
        h   = F.gelu(self.combine(cat)) * a + e         # gated residual
        return self.dropout(self.norm(h))


# ---------------------------------------------------------------------------
# Transformer encoder–decoder autoencoder
# ---------------------------------------------------------------------------

class _SinPosEnc(nn.Module):
    def __init__(self, dim: int, max_len: int = 16):
        super().__init__()
        pe = torch.zeros(max_len, dim)
        pos = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div = torch.exp(torch.arange(0, dim, 2).float() * (-math.log(10000.0) / dim))
        pe[:, 0::2] = torch.sin(pos * div)
        pe[:, 1::2] = torch.cos(pos * div)
        self.register_buffer("pe", pe.unsqueeze(0))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return x + self.pe[:, : x.size(1)]


class TransformerAutoencoder(nn.Module):
    """A small encoder–decoder transformer over a token-tiled embedding."""

    def __init__(self, hidden_dim: int = 128, n_tokens: int = 8, n_heads: int = 4, n_layers: int = 2, dropout: float = 0.1):
        super().__init__()
        self.n_tokens = n_tokens
        self.token_split = nn.Linear(hidden_dim, hidden_dim * n_tokens)
        self.posenc = _SinPosEnc(hidden_dim, max_len=n_tokens)

        enc_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim, nhead=n_heads, dim_feedforward=hidden_dim * 2,
            dropout=dropout, batch_first=True, activation="gelu",
        )
        self.encoder = nn.TransformerEncoder(enc_layer, num_layers=n_layers)
        dec_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim, nhead=n_heads, dim_feedforward=hidden_dim * 2,
            dropout=dropout, batch_first=True, activation="gelu",
        )
        self.decoder = nn.TransformerEncoder(dec_layer, num_layers=n_layers)

        self.fold = nn.Linear(hidden_dim * n_tokens, hidden_dim)

    def forward(self, h: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        # h: [B, hidden_dim]
        B, D = h.shape
        toks = self.token_split(h).view(B, self.n_tokens, D)
        toks = self.posenc(toks)
        z = self.encoder(toks)            # latent
        rec = self.decoder(z)             # reconstructed token sequence
        # Reconstruct compact embedding (folded back)
        rec_flat = self.fold(rec.reshape(B, self.n_tokens * D))
        return z, rec_flat


# ---------------------------------------------------------------------------
# Self-Supervised Anomaly Model
# ---------------------------------------------------------------------------

class SSLGraphAnomaly(nn.Module):
    """E-GraphSAGE encoder + Transformer Autoencoder + classification head."""

    def __init__(
        self,
        in_dim: int = 83,
        hidden_dim: int = 128,
        n_classes: int = 34,
        n_graph_layers: int = 2,
        n_tx_tokens: int = 8,
        n_tx_heads: int = 4,
        n_tx_layers: int = 2,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.embed = nn.Sequential(
            nn.Linear(in_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
        )
        self.graph_layers = nn.ModuleList([
            EGraphSAGEBlock(hidden_dim, hidden_dim, dropout=dropout)
            for _ in range(n_graph_layers)
        ])
        self.txae = TransformerAutoencoder(
            hidden_dim=hidden_dim, n_tokens=n_tx_tokens,
            n_heads=n_tx_heads, n_layers=n_tx_layers, dropout=dropout,
        )

        # Anomaly score combiner: reconstruction error + Mahalanobis-ish energy
        self.energy = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.GELU(),
            nn.Linear(hidden_dim, 1),
            nn.Softplus(),
        )

        # Lightweight attribution head — produces per-class logits.
        # Logit 0 is the benign / "normal" prototype, logits 1..n_classes-1
        # are attack attribution heads.
        self.cls_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, n_classes),
        )

        # Running statistics for in-distribution centring (set after fit).
        self.register_buffer("center_mean", torch.zeros(hidden_dim))
        self.register_buffer("center_inv_std", torch.ones(hidden_dim))

    # ------------------------------------------------------------------
    def encode(self, x: torch.Tensor) -> torch.Tensor:
        h = self.embed(x)
        # E-GraphSAGE-style layers reuse the flat features as edge inputs
        h_in = x
        for layer in self.graph_layers:
            h = h + layer(h_in)
            h_in = h
        return h

    def forward(self, x: torch.Tensor, disabled_branches=None) -> torch.Tensor:
        """Platform-compatible forward: returns [B, n_classes] logits.

        Class 0 represents "normal / benign"; classes 1..N-1 are attack
        attribution scores. Logits are biased downward by the anomaly score
        so far-from-distribution inputs are pushed toward attack classes.
        """
        del disabled_branches  # unused — SSL branch has no ablation
        h = self.encode(x)
        z, rec = self.txae(h)
        rec_err = (h - rec).pow(2).mean(dim=-1, keepdim=True)             # [B, 1]
        centred = (h - self.center_mean) * self.center_inv_std            # [B, H]
        mahal_e = centred.pow(2).mean(dim=-1, keepdim=True)               # [B, 1]
        energy_in = torch.cat([h, rec], dim=-1)                           # [B, 2H]
        energy = self.energy(energy_in) + rec_err + 0.1 * mahal_e         # [B, 1]

        logits = self.cls_head(h)                                         # [B, C]
        # Push energy: subtract energy from class 0 (benign), add scaled
        # energy to remaining classes. Anomalous flows -> attack-side mass.
        push = energy * 2.0
        bias = torch.cat([-push, push.expand(-1, logits.size(1) - 1)], dim=-1)
        # use mean for last reference so "z" is consumed (silences unused-warn)
        if z.size(0) > 0:
            bias = bias + 0.0 * z.mean()
        return logits + bias

    # ------------------------------------------------------------------
    @torch.no_grad()
    def anomaly_score(self, x: torch.Tensor) -> torch.Tensor:
        """Return per-sample anomaly energy; higher = more anomalous."""
        h = self.encode(x)
        _, rec = self.txae(h)
        rec_err = (h - rec).pow(2).mean(dim=-1)
        centred = (h - self.center_mean) * self.center_inv_std
        mahal_e = centred.pow(2).mean(dim=-1)
        return rec_err + 0.1 * mahal_e

    @torch.no_grad()
    def fit_center(self, benign_x: torch.Tensor) -> None:
        """Estimate centering buffers from a batch of known-benign flows."""
        h = self.encode(benign_x)
        mean = h.mean(dim=0)
        std = h.std(dim=0).clamp(min=1e-3)
        self.center_mean.copy_(mean)
        self.center_inv_std.copy_(1.0 / std)


# ---------------------------------------------------------------------------
# Wrapper for the platform model registry
# ---------------------------------------------------------------------------

class SSLGraphAnomalyWrapper(nn.Module):
    """Platform-compatible wrapper for SSLGraphAnomaly.

    Same shape contract as every other registered model:
        - input  [B, 83] floats
        - output [B, 34] logits
    """

    N_FEATURES = 83
    N_CLASSES = 34
    BRANCH_NAMES = SurrogateIDS.BRANCH_NAMES
    CLASS_NAMES = SurrogateIDS.CLASS_NAMES
    SEVERITY_MAP = SurrogateIDS.SEVERITY_MAP

    def __init__(self, dropout: float = 0.1):
        super().__init__()
        self.model = SSLGraphAnomaly(
            in_dim=83, hidden_dim=128, n_classes=34,
            n_graph_layers=2, n_tx_tokens=8, n_tx_heads=4, n_tx_layers=2,
            dropout=dropout,
        )

    def forward(self, x, disabled_branches=None):
        return self.model(x, disabled_branches)

    def anomaly_score(self, x):
        return self.model.anomaly_score(x)

    def fit_center(self, benign_x):
        return self.model.fit_center(benign_x)

    @classmethod
    def severity_for(cls, label: str) -> str:
        return SurrogateIDS.severity_for(label)
