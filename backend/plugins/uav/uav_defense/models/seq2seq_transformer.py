"""Seq2Seq Transformer baseline (Aigner et al., arXiv:2510.19890, 2025).

Reference TEXBAT spoof-detection baseline (0.16% reported error). Compact
Phase-A surrogate: single encoder block over flattened CAF sequences.
"""
from __future__ import annotations

import torch
import torch.nn as nn


class Seq2SeqTransformer(nn.Module):
    def __init__(
        self,
        feat_dim: int = 8,
        d_model: int = 64,
        n_heads: int = 4,
        n_layers: int = 2,
        num_classes: int = 2,
    ):
        super().__init__()
        self.embed = nn.Linear(feat_dim, d_model)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=n_heads, dim_feedforward=2 * d_model,
            batch_first=True, dropout=0.0,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=n_layers)
        self.head = nn.Linear(d_model, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if x.dim() == 2:
            x = x.unsqueeze(0)
        h = self.embed(x)
        h = self.encoder(h)
        return self.head(h.mean(dim=1))

    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        return torch.softmax(self.forward(x), dim=-1)
