"""M4 MambaShield — selective state-space block for long telemetry streams.

Lightweight Phase-A surrogate of the full selective SSM. Achieves O(L log L)
behaviour via FFT-based depthwise convolution over the time axis, which is
sufficient for the chapter 6 Phase-A demonstration that long video / IMU
streams can be processed under the 5 W airframe budget.
"""
from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F


class _SSMBlock(nn.Module):
    def __init__(self, d_model: int, conv_kernel: int = 16):
        super().__init__()
        self.in_proj = nn.Linear(d_model, d_model)
        self.gate = nn.Linear(d_model, d_model)
        self.kernel = nn.Parameter(torch.randn(d_model, conv_kernel) * 0.05)
        self.out_proj = nn.Linear(d_model, d_model)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        b, t, d = x.shape
        u = self.in_proj(x)
        k = F.pad(self.kernel, (0, t - self.kernel.shape[-1])) if t > self.kernel.shape[-1] else self.kernel[:, :t]
        U = torch.fft.rfft(u.transpose(1, 2), n=t, dim=-1)
        K = torch.fft.rfft(k, n=t, dim=-1)
        Y = U * K.unsqueeze(0)
        y = torch.fft.irfft(Y, n=t, dim=-1).transpose(1, 2)
        gate = torch.sigmoid(self.gate(x))
        return self.out_proj(y * gate)


class MambaShield(nn.Module):
    def __init__(
        self,
        feat_dim: int = 8,
        d_model: int = 64,
        num_classes: int = 2,
        n_blocks: int = 2,
    ):
        super().__init__()
        self.embed = nn.Linear(feat_dim, d_model)
        self.blocks = nn.ModuleList([_SSMBlock(d_model) for _ in range(n_blocks)])
        self.norm = nn.LayerNorm(d_model)
        self.head = nn.Linear(d_model, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if x.dim() == 2:
            x = x.unsqueeze(0)
        h = self.embed(x)
        for blk in self.blocks:
            h = h + blk(h)
        h = self.norm(h.mean(dim=1))
        return self.head(h)

    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        return torch.softmax(self.forward(x), dim=-1)
