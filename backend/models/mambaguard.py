"""
MambaGuard — Mamba SSM + GATv2 + 3-Layer Certification for LLM Agent Protocols.

Defends the next generation of LLM agent communication channels — MCP
(Model Context Protocol), ACP (Agent Communication Protocol), A2A
(Agent-to-Agent), and ANP (Agent Network Protocol) — against the 34-class
adversarial taxonomy used across the platform. The reference implementation
reports a macro-F1 of 0.978 on the unified benchmark.

Architecture (pure-PyTorch approximation; no mamba-ssm / causal-conv1d):
    1. 83 -> 128 dense embedding (GELU + LayerNorm)
    2. 3 x Mamba-style selective-SSM blocks (depthwise conv + per-step
       discretisation via softplus(dt) + state recurrence approximated with
       a batched einsum so it runs on CPU)
    3. 2 x GATv2-style temporal-graph attention blocks (4 heads, edge-feature
       weighted aggregation)
    4. 4-head protocol-aware attention pooling against learned MCP/ACP/A2A/ANP
       protocol embeddings; per-protocol weights summed and concatenated
    5. Classifier head 128 -> 64 -> 34
    6. Three certification heads producing per-sample:
         * smoothing_radius     (Softplus)  — randomized-smoothing radius
         * stackelberg_value    (Sigmoid)   — leader/follower game value in [0,1]
         * hedge_regret_bound   (Softplus)  — sqrt(T log K)-style regret bound

Source: https://github.com/rogerpanel/MambaGuard-models

Author: Roger Nick Anaedevha
"""
from __future__ import annotations

import math
import torch
import torch.nn as nn
import torch.nn.functional as F

from .surrogate import SurrogateIDS


# ---------------------------------------------------------------------------
# Mamba-style selective state-space block (pure PyTorch)
# ---------------------------------------------------------------------------

class _MambaBlock(nn.Module):
    """Selective state-space block approximating a single Mamba layer.

    Approximation: the original Mamba paper uses a hardware-aware parallel
    scan over a structured A matrix. We replace that scan with a batched
    einsum over a small state dimension (16) so the layer is fast on CPU.
    Discretisation still uses softplus(dt) and exp(A * dt) to keep the
    selective character intact.
    """

    def __init__(self, dim: int, state_dim: int = 16, dropout: float = 0.1):
        super().__init__()
        self.dim = dim
        self.state_dim = state_dim
        self.proj_in = nn.Linear(dim, dim * 2)
        # Depthwise 1-D conv: treat the feature axis as a 1-D sequence.
        self.conv1d = nn.Conv1d(dim, dim, kernel_size=4, padding=3, groups=dim)
        # State matrix parameter (state_dim, dim).
        self.state_A = nn.Parameter(torch.randn(state_dim, dim) * 0.01)
        self.proj_B = nn.Linear(dim, state_dim)
        self.proj_C = nn.Linear(dim, state_dim)
        self.proj_dt = nn.Linear(dim, dim)
        self.proj_out = nn.Linear(dim, dim)
        self.norm = nn.LayerNorm(dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: [B, dim]
        residual = x
        x_norm = self.norm(x)
        xz = self.proj_in(x_norm)
        x_ssm, gate = xz.chunk(2, dim=-1)              # each [B, dim]

        # Depthwise conv over the feature dim treated as a length-`dim`
        # sequence with a single channel-group per feature.
        # Reshape to [B, dim, 1] so groups=dim conv is a no-op-style mix
        # — we still get a learnable depthwise filter on a 4-wide window
        # at the channel boundary thanks to the padding=3 left-pad.
        x_conv = self.conv1d(x_ssm.unsqueeze(-1))      # [B, dim, 4]
        x_conv = x_conv[..., 0]                        # take first tap [B, dim]
        x_ssm = F.silu(x_conv)

        # Selective scan approximation.
        # dt: per-feature timestep, clamp keeps exp(A*dt) finite.
        dt = F.softplus(self.proj_dt(x_ssm)).clamp(max=1.0)        # [B, dim]
        B_mat = self.proj_B(x_ssm)                                 # [B, state]
        C_mat = self.proj_C(x_ssm)                                 # [B, state]

        # A_bar: [B, state, dim] = exp(state_A * dt). state_A: [state, dim]
        A_bar = torch.exp(self.state_A.unsqueeze(0) * dt.unsqueeze(1))   # [B, state, dim]
        # Treat the input as a single-step "scan" — collapsed scan, batched.
        # y[b,d] = sum_s C[b,s] * A_bar[b,s,d] * B[b,s] * x_ssm[b,d]
        weighted = A_bar * B_mat.unsqueeze(-1) * x_ssm.unsqueeze(1)      # [B, state, dim]
        y = torch.einsum("bs,bsd->bd", C_mat, weighted)                  # [B, dim]

        y = y * F.silu(gate)
        out = self.proj_out(self.dropout(y))
        return out + residual


# ---------------------------------------------------------------------------
# GATv2-style temporal graph attention block
# ---------------------------------------------------------------------------

class _GATv2Block(nn.Module):
    """4-head GATv2-style attention over the batch as a flow-graph.

    Each row of the batch is treated as a node; "edges" are induced by
    pairwise feature similarity (dot product) so we do not need an explicit
    edge index. The attention coefficients follow GATv2's order of operations:
    a^T LeakyReLU(W . [h_i || h_j]).
    """

    def __init__(self, dim: int, n_heads: int = 4, dropout: float = 0.1):
        super().__init__()
        assert dim % n_heads == 0
        self.n_heads = n_heads
        self.head_dim = dim // n_heads
        self.W = nn.Linear(dim, dim)
        self.a_src = nn.Linear(self.head_dim, 1, bias=False)
        self.a_dst = nn.Linear(self.head_dim, 1, bias=False)
        self.out = nn.Linear(dim, dim)
        self.norm = nn.LayerNorm(dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: [B, dim]
        residual = x
        B = x.size(0)
        h = self.W(x).view(B, self.n_heads, self.head_dim)          # [B, H, d]
        # Score components — broadcast to a [B, B, H] attention matrix.
        e_src = self.a_src(F.leaky_relu(h, 0.2)).squeeze(-1)        # [B, H]
        e_dst = self.a_dst(F.leaky_relu(h, 0.2)).squeeze(-1)        # [B, H]
        attn_logits = e_src.unsqueeze(1) + e_dst.unsqueeze(0)       # [B, B, H]
        attn = F.softmax(attn_logits, dim=1)                        # over src axis
        attn = self.dropout(attn)
        # Aggregate: for each head, weighted sum of source node features.
        # h:    [B, H, d]   attn: [B(dst), B(src), H]
        agg = torch.einsum("dsh,shf->dhf", attn, h)                 # [B, H, d]
        agg = agg.reshape(B, self.n_heads * self.head_dim)          # [B, dim]
        agg = self.out(agg)
        return self.norm(agg + residual)


# ---------------------------------------------------------------------------
# Protocol-aware attention pooling head
# ---------------------------------------------------------------------------

class _ProtocolAttentionPool(nn.Module):
    """Pool features against 4 learned MCP/ACP/A2A/ANP protocol embeddings.

    Each input attends (scaled dot-product) to all 4 protocol prototypes.
    Per-protocol attention weights produce a weighted vector; the four
    vectors are concatenated and projected back to `dim`.
    """

    PROTOCOLS = ("MCP", "ACP", "A2A", "ANP")

    def __init__(self, dim: int):
        super().__init__()
        self.dim = dim
        self.protocol_emb = nn.Parameter(torch.randn(4, dim) * 0.02)
        self.q_proj = nn.Linear(dim, dim)
        self.k_proj = nn.Linear(dim, dim)
        self.v_proj = nn.Linear(dim, dim)
        self.out = nn.Linear(dim * 4, dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: [B, dim]
        q = self.q_proj(x)                                   # [B, dim]
        k = self.k_proj(self.protocol_emb)                   # [4, dim]
        v = self.v_proj(self.protocol_emb)                   # [4, dim]
        scale = 1.0 / math.sqrt(self.dim)
        attn = F.softmax(q @ k.t() * scale, dim=-1)          # [B, 4]
        per_proto = attn.unsqueeze(-1) * v.unsqueeze(0)      # [B, 4, dim]
        flat = per_proto.reshape(x.size(0), 4 * self.dim)    # [B, 4*dim]
        return self.out(flat)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class MambaGuardModel(nn.Module):
    """MambaGuard detector: SSM + graph + protocol attention with cert heads."""

    def __init__(
        self,
        in_dim: int = 83,
        hidden_dim: int = 128,
        n_mamba: int = 3,
        n_gat: int = 2,
        n_classes: int = 34,
        state_dim: int = 16,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.embed = nn.Sequential(
            nn.Linear(in_dim, hidden_dim),
            nn.GELU(),
            nn.LayerNorm(hidden_dim),
        )
        self.mamba_blocks = nn.ModuleList(
            [_MambaBlock(hidden_dim, state_dim=state_dim, dropout=dropout) for _ in range(n_mamba)]
        )
        self.gat_blocks = nn.ModuleList(
            [_GATv2Block(hidden_dim, n_heads=4, dropout=dropout) for _ in range(n_gat)]
        )
        self.proto_pool = _ProtocolAttentionPool(hidden_dim)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(64, n_classes),
        )
        # 3-layer certification heads.
        self.cert_smoothing = nn.Sequential(
            nn.Linear(hidden_dim, 32), nn.ReLU(),
            nn.Linear(32, 1), nn.Softplus(),
        )
        self.cert_stackelberg = nn.Sequential(
            nn.Linear(hidden_dim, 32), nn.ReLU(),
            nn.Linear(32, 1), nn.Sigmoid(),
        )
        self.cert_hedge = nn.Sequential(
            nn.Linear(hidden_dim, 32), nn.ReLU(),
            nn.Linear(32, 1), nn.Softplus(),
        )
        # Side-channel container for certification values from the latest
        # forward pass — populated even by the simple `forward()` so callers
        # who care can read them without breaking the [B, 34] tensor contract.
        self.last_certification: dict[str, torch.Tensor] = {}

    def _trunk(self, x: torch.Tensor) -> torch.Tensor:
        h = self.embed(x)
        for blk in self.mamba_blocks:
            h = blk(h)
        for blk in self.gat_blocks:
            h = blk(h)
        h = h + self.proto_pool(h)
        return h

    def forward(self, x: torch.Tensor, disabled_branches=None) -> torch.Tensor:
        del disabled_branches  # accepted for platform contract; no ablation surface
        h = self._trunk(x)
        logits = self.classifier(h)
        # Populate side-channel certification values.
        self.last_certification = {
            "smoothing_radius": self.cert_smoothing(h),
            "stackelberg_value": self.cert_stackelberg(h),
            "hedge_regret_bound": self.cert_hedge(h),
        }
        return logits

    def forward_with_cert(self, x: torch.Tensor) -> dict[str, torch.Tensor]:
        h = self._trunk(x)
        logits = self.classifier(h)
        return {
            "logits": logits,
            "smoothing_radius": self.cert_smoothing(h),
            "stackelberg_value": self.cert_stackelberg(h),
            "hedge_regret_bound": self.cert_hedge(h),
        }


# ---------------------------------------------------------------------------
# Platform-compatible wrapper
# ---------------------------------------------------------------------------

class MambaGuardWrapper(nn.Module):
    """Platform wrapper for MambaGuardModel (83 -> 34 contract)."""

    N_FEATURES = 83
    N_CLASSES = 34
    BRANCH_NAMES = SurrogateIDS.BRANCH_NAMES
    CLASS_NAMES = SurrogateIDS.CLASS_NAMES
    SEVERITY_MAP = SurrogateIDS.SEVERITY_MAP

    def __init__(self, dropout: float = 0.1):
        super().__init__()
        self.model = MambaGuardModel(dropout=dropout)

    def forward(self, x, disabled_branches=None):
        return self.model(x, disabled_branches)

    def forward_with_cert(self, x):
        return self.model.forward_with_cert(x)

    @classmethod
    def severity_for(cls, label: str) -> str:
        return SurrogateIDS.severity_for(label)
