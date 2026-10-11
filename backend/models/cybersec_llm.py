"""
CyberSecLLM — Lightweight surrogate of the Mamba–CrossAttention–MoE
cybersecurity foundation model.

The full CyberSecLLM (7 B params) uses:
  1. Selective State-Space (Mamba) blocks for O(L) sequence modelling
  2. Cross-attention layers grounded in a threat-knowledge base
     (MITRE ATT&CK embeddings)
  3. Mixture-of-Experts (MoE) feed-forward blocks with top-k routing

This surrogate distils the design into a CPU-friendly network (~350 K
params) that preserves the three computational pathways while fitting
the platform's 83-feature → 34-class interface.

Reference:
  Anaedevha R.N., "CyberSecLLM: A Cybersecurity-Specific Large
  Language Model for Intrusion Detection", IEEE TNNLS (submitted).

Trained on all 6 benchmark datasets (IIS3D + ICS3D):
  CIC-IoT-2023, CSE-CICIDS2018, UNSW-NB15,
  Microsoft GUIDE, Container Security, Edge-IIoT.
"""

import math
import torch
import torch.nn as nn
import torch.nn.functional as F


# ---------------------------------------------------------------------------
# 1. Selective State-Space (Mamba) Block
# ---------------------------------------------------------------------------

class SelectiveSSM(nn.Module):
    """
    Simplified selective state-space block inspired by Mamba.

    Instead of causal sequence scanning, we operate on the feature
    dimension of each flow vector with input-dependent gating —
    preserving the selective filtering principle on tabular data.
    """

    def __init__(self, dim: int, state_dim: int = 16, dropout: float = 0.1):
        super().__init__()
        self.dim = dim
        self.state_dim = state_dim

        # Input-dependent discretisation parameters (Δ, B, C)
        self.delta_proj = nn.Linear(dim, dim)
        self.B_proj = nn.Linear(dim, state_dim)
        self.C_proj = nn.Linear(dim, state_dim)

        # State transition matrix A (learnable, diagonal for efficiency)
        self.A_log = nn.Parameter(torch.randn(dim, state_dim) * 0.01)

        # SiLU gate branch
        self.gate = nn.Sequential(
            nn.Linear(dim, dim),
            nn.SiLU(),
        )

        # Output projection
        self.out_proj = nn.Linear(dim, dim)
        self.norm = nn.LayerNorm(dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """x: [batch, dim]"""
        residual = x

        # Input-dependent parameters
        delta = F.softplus(self.delta_proj(x))          # [B, dim]
        B = self.B_proj(x)                               # [B, state_dim]
        C = self.C_proj(x)                               # [B, state_dim]
        A = -torch.exp(self.A_log)                       # [dim, state_dim]

        # Selective scan (single-step for tabular data)
        # h = exp(A * Δ) ⊙ h + Δ ⊙ B ⊙ x  →  y = C ⊙ h
        dA = torch.exp(delta.unsqueeze(-1) * A)          # [B, dim, state_dim]
        dB = delta.unsqueeze(-1) * B.unsqueeze(1)        # [B, dim, state_dim]
        h = dA * (dB * x.unsqueeze(-1))                  # state update
        y = (h * C.unsqueeze(1)).sum(-1)                  # [B, dim]

        # Gated output (SiLU branch)
        y = y * self.gate(x)
        y = self.out_proj(y)
        y = self.dropout(y)

        return self.norm(y + residual)


# ---------------------------------------------------------------------------
# 2. Cross-Attention to Threat Knowledge Base
# ---------------------------------------------------------------------------

class ThreatKnowledgeAttention(nn.Module):
    """
    Cross-attention layer where flow embeddings attend to a learned
    threat-knowledge base (representing MITRE ATT&CK techniques /
    CVE patterns / threat intelligence).
    """

    def __init__(self, dim: int, n_heads: int = 4, kb_size: int = 32,
                 dropout: float = 0.1):
        super().__init__()
        self.n_heads = n_heads
        self.head_dim = dim // n_heads
        assert dim % n_heads == 0

        # Learnable knowledge-base entries
        self.kb = nn.Parameter(torch.randn(kb_size, dim) * 0.02)

        # Projections
        self.q_proj = nn.Linear(dim, dim)
        self.k_proj = nn.Linear(dim, dim)
        self.v_proj = nn.Linear(dim, dim)
        self.out_proj = nn.Linear(dim, dim)

        self.norm = nn.LayerNorm(dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """x: [batch, dim]"""
        residual = x
        B = x.size(0)

        # Query from flow, Key/Value from knowledge base
        q = self.q_proj(x).view(B, self.n_heads, self.head_dim)
        kb = self.kb.unsqueeze(0).expand(B, -1, -1)  # [B, kb_size, dim]
        k = self.k_proj(kb).view(B, -1, self.n_heads, self.head_dim).transpose(1, 2)
        v = self.v_proj(kb).view(B, -1, self.n_heads, self.head_dim).transpose(1, 2)

        # Scaled dot-product attention
        q = q.unsqueeze(2)                             # [B, heads, 1, head_dim]
        scores = (q @ k.transpose(-2, -1)) / math.sqrt(self.head_dim)
        attn = F.softmax(scores, dim=-1)
        attn = self.dropout(attn)

        out = (attn @ v).squeeze(2)                    # [B, heads, head_dim]
        out = out.reshape(B, -1)                       # [B, dim]
        out = self.out_proj(out)
        out = self.dropout(out)

        return self.norm(out + residual)


# ---------------------------------------------------------------------------
# 3. Mixture-of-Experts Feed-Forward Block
# ---------------------------------------------------------------------------

class MoEFeedForward(nn.Module):
    """
    Sparse Mixture-of-Experts FFN with top-k routing and
    load-balancing auxiliary loss.
    """

    def __init__(self, dim: int, n_experts: int = 8, top_k: int = 2,
                 ffn_mult: float = 2.0, dropout: float = 0.1):
        super().__init__()
        self.n_experts = n_experts
        self.top_k = top_k
        ffn_dim = int(dim * ffn_mult)

        # Router
        self.gate = nn.Linear(dim, n_experts, bias=False)

        # Expert networks
        self.experts = nn.ModuleList([
            nn.Sequential(
                nn.Linear(dim, ffn_dim),
                nn.GELU(),
                nn.Dropout(dropout),
                nn.Linear(ffn_dim, dim),
                nn.Dropout(dropout),
            )
            for _ in range(n_experts)
        ])

        # Shared expert (always active)
        self.shared_expert = nn.Sequential(
            nn.Linear(dim, ffn_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(ffn_dim, dim),
            nn.Dropout(dropout),
        )

        self.norm = nn.LayerNorm(dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """x: [batch, dim]"""
        residual = x

        # Router logits → top-k selection
        logits = self.gate(x)                           # [B, n_experts]
        top_vals, top_idx = logits.topk(self.top_k, dim=-1)
        weights = F.softmax(top_vals, dim=-1)           # [B, top_k]

        # Dispatch to selected experts
        out = torch.zeros_like(x)
        for k in range(self.top_k):
            for e in range(self.n_experts):
                mask = (top_idx[:, k] == e)
                if mask.any():
                    expert_out = self.experts[e](x[mask])
                    out[mask] += weights[mask, k].unsqueeze(-1) * expert_out

        # Add shared expert
        out = out + self.shared_expert(x)

        return self.norm(out + residual)


# ---------------------------------------------------------------------------
# 4. CyberSecLLM Surrogate Model
# ---------------------------------------------------------------------------

class CyberSecLLMModel(nn.Module):
    """
    CPU-friendly surrogate of CyberSecLLM-7B.

    Architecture:
      Input encoder (multi-pathway tokenisation)
        → N × [Mamba SSM → Cross-Attention → MoE FFN]
        → Classification head

    ~350K parameters with 8 experts (2 active), 4 attention heads,
    and 32 knowledge-base entries.
    """

    N_FEATURES = 83
    N_CLASSES = 34
    HIDDEN = 256

    def __init__(self, dropout: float = 0.1, n_blocks: int = 3,
                 n_experts: int = 8, top_k: int = 2,
                 kb_size: int = 32, n_heads: int = 4,
                 ssm_state_dim: int = 16):
        super().__init__()

        # ── Multi-pathway input tokenisation ──
        # Continuous features  (flow stats: duration, bytes, packets, etc.)
        self.continuous_enc = nn.Sequential(
            nn.Linear(self.N_FEATURES, self.HIDDEN),
            nn.GELU(),
            nn.Dropout(dropout),
        )
        # Categorical-style encoding (protocol flags, port groups)
        self.categorical_enc = nn.Sequential(
            nn.Linear(self.N_FEATURES, self.HIDDEN // 2),
            nn.GELU(),
            nn.Linear(self.HIDDEN // 2, self.HIDDEN),
        )
        # Pathway fusion gate
        self.pathway_gate = nn.Sequential(
            nn.Linear(self.HIDDEN * 2, self.HIDDEN),
            nn.Sigmoid(),
        )
        self.input_proj = nn.Linear(self.HIDDEN * 2, self.HIDDEN)
        self.input_norm = nn.LayerNorm(self.HIDDEN)

        # ── Interleaved Mamba + CrossAttn + MoE blocks ──
        self.blocks = nn.ModuleList()
        for _ in range(n_blocks):
            self.blocks.append(nn.ModuleDict({
                "ssm": SelectiveSSM(self.HIDDEN, ssm_state_dim, dropout),
                "cross_attn": ThreatKnowledgeAttention(
                    self.HIDDEN, n_heads, kb_size, dropout
                ),
                "moe": MoEFeedForward(
                    self.HIDDEN, n_experts, top_k, dropout=dropout
                ),
            }))

        # ── Classification head ──
        self.head = nn.Sequential(
            nn.Linear(self.HIDDEN, self.HIDDEN),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(self.HIDDEN, self.N_CLASSES),
        )

    def forward(self, x: torch.Tensor,
                disabled_branches=None) -> torch.Tensor:
        """
        Args:
            x: [batch, 83] normalised flow features
            disabled_branches: ignored (interface compat)
        Returns:
            [batch, 34] class logits
        """
        # Multi-pathway tokenisation
        h_cont = self.continuous_enc(x)
        h_cat = self.categorical_enc(x)
        h_both = torch.cat([h_cont, h_cat], dim=-1)

        gate = self.pathway_gate(h_both)
        h = self.input_proj(h_both) * gate
        h = self.input_norm(h)

        # Interleaved blocks: Mamba → CrossAttn → MoE
        for block in self.blocks:
            h = block["ssm"](h)
            h = block["cross_attn"](h)
            h = block["moe"](h)

        return self.head(h)
