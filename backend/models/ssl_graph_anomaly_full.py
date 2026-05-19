"""
SSL-GraphAnomaly Full Pipeline
==============================

Faithful PyTorch-only re-implementation of the 6-component SSL-GraphAnomaly
pipeline from:

    https://github.com/rogerpanel/SSL-GraphAnomaly-Models

The reference repo composes six building blocks; the existing
``backend/models/ssl_anomaly.py`` already ships a 4-component stub
(``SSLGraphAnomalyWrapper``). This module adds the remaining three components
as a richer parallel wrapper -- the stub stays in place untouched as a
fallback under its original registry id.

Component map
-------------
    1. E-GraphSAGE edge-feature block      -> :class:`_EGraphSAGEBlock`
    2. Stacked E-GraphSAGE trunk           -> ``SSLGraphAnomalyFullModel.graph_layers``
    3. Attention-gated streaming block     -> :class:`_AttentionGatedStreamingBlock`   (NEW)
    4. Discrepancy Transformer AE          -> :class:`_DiscrepancyTransformerAE`
    5. Mahalanobis energy + contrastive    -> :class:`_MahalanobisEnergyHead`
                                              + ``contrastive_recon_loss`` helper      (NEW)
    6. Split-conformal certification head  -> :class:`SplitConformalCertifier`         (NEW)

Conformal certificate
---------------------
The :class:`SplitConformalCertifier` provides a *distribution-free*
marginal-coverage guarantee on the benign false-alarm rate. Concretely, given
``n`` exchangeable held-out benign energy scores and a target level
``alpha`` (e.g. ``alpha = 0.01``), it sets the decision threshold to the
``ceil((1 - alpha) * (n + 1)) / n`` empirical quantile of the calibration
scores (Vovk et al., 2005; Angelopoulos & Bates, 2022).

By the marginal-coverage theorem the long-run benign false-alarm rate then
satisfies::

    P(score_new > threshold)  <=  alpha + 1 / (n + 1)

The single assumption is *exchangeability* between the calibration set and
future benign flows -- a much weaker assumption than i.i.d. and one that
holds for non-adversarial traffic under stationary network conditions.

Operationally the SOC dial works as follows: an operator lowers ``alpha``
from ``0.01`` -> ``0.001``; ``set_alpha`` recomputes the conformal quantile,
the threshold *tightens* (rises), fewer benign flows trip the alarm, the
returned ``empirical_upper_bound`` updates accordingly, and the new
guaranteed FAR ceiling is exposed to the dashboard.

# Author: Roger Nick Anaedevha
"""
from __future__ import annotations

import math
from typing import Optional

import torch
import torch.nn as nn
import torch.nn.functional as F

from .surrogate import SurrogateIDS


# ---------------------------------------------------------------------------
# 1. E-GraphSAGE edge-feature block
# ---------------------------------------------------------------------------

class _EGraphSAGEBlock(nn.Module):
    """E-GraphSAGE edge-feature aggregator with attention-gated combine.

    Mirrors the pattern from ``ssl_anomaly.EGraphSAGEBlock`` (intentionally
    re-implemented here -- not imported -- so this module is a drop-in
    fallback even if the stub is later deleted).

    Each flow is treated as an edge between a virtual src/dst role pair.
    Without a real edge index we use attention-gated pooling that mimics
    the inductive E-GraphSAGE aggregation.
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
# 3. Attention-gated streaming block (NEW)
# ---------------------------------------------------------------------------

class _AttentionGatedStreamingBlock(nn.Module):
    """Single-pass attention-gated block tuned for streaming inference.

    Unlike the batched E-GraphSAGE block, this variant requires no
    neighbourhood lookup. For each streamed flow embedding ``x`` it:

      - computes a sigmoid attention gate ``a = sigmoid(W_a x)``
      - projects to key / value spaces ``k = W_k x``, ``v = W_v x``
      - emits ``LayerNorm(a * v + (1 - a) * x)`` -- a -> 1 trusts the
        learned value, a -> 0 falls back to identity

    An EMA buffer of recent embeddings is maintained via
    :meth:`update_streaming_buffer` so downstream logic can fetch a
    cheap context vector for drift detection.
    """

    def __init__(self, hidden_dim: int = 128, beta: float = 0.99):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.beta = float(beta)
        self.attn_gate = nn.Linear(hidden_dim, hidden_dim)
        self.key_proj = nn.Linear(hidden_dim, hidden_dim)
        self.value_proj = nn.Linear(hidden_dim, hidden_dim)
        self.norm = nn.LayerNorm(hidden_dim)
        self.register_buffer("ema", torch.zeros(hidden_dim))
        # Track whether EMA has been initialised so the first update seeds it.
        self.register_buffer("ema_initialised", torch.zeros(1))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: [B, hidden_dim]
        a = torch.sigmoid(self.attn_gate(x))
        _k = self.key_proj(x)  # retained for parity with the reference repo
        v = self.value_proj(x)
        out = self.norm(a * v + (1.0 - a) * x)
        # Silence unused-warn for k while keeping it in the graph cheaply.
        if _k.size(0) > 0:
            out = out + 0.0 * _k.mean()
        return out

    @torch.no_grad()
    def update_streaming_buffer(self, x: torch.Tensor) -> None:
        """EMA-update the streaming context buffer with mean(x) over batch."""
        if x.dim() == 1:
            sample = x.detach()
        else:
            sample = x.detach().mean(dim=0)
        if float(self.ema_initialised.item()) < 0.5:
            self.ema.copy_(sample)
            self.ema_initialised.fill_(1.0)
        else:
            self.ema.mul_(self.beta).add_(sample, alpha=(1.0 - self.beta))


# ---------------------------------------------------------------------------
# 4. Discrepancy Transformer AE
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


class _DiscrepancyTransformerAE(nn.Module):
    """Token-tiled transformer encoder--decoder over a flow embedding.

    Returns ``(latent, reconstruction)``. The reconstruction is folded back
    to the original hidden dimension so downstream Mahalanobis / energy
    heads can compare ``(h, h_rec)`` directly.
    """

    def __init__(
        self,
        hidden_dim: int = 128,
        n_tokens: int = 8,
        n_heads: int = 4,
        n_layers: int = 2,
        dropout: float = 0.1,
    ):
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
        B, D = h.shape
        toks = self.token_split(h).view(B, self.n_tokens, D)
        toks = self.posenc(toks)
        z = self.encoder(toks)
        rec = self.decoder(z)
        rec_flat = self.fold(rec.reshape(B, self.n_tokens * D))
        return z, rec_flat


# ---------------------------------------------------------------------------
# 5. Mahalanobis energy head + contrastive/recon loss helpers
# ---------------------------------------------------------------------------

class _MahalanobisEnergyHead(nn.Module):
    """Per-sample energy = reconstruction error + 0.1 * Mahalanobis distance.

    Diagonal-covariance Mahalanobis is used (running mean / inverse std over
    the benign hidden distribution). Buffers are set by
    :meth:`fit_center` from a benign batch prior to deployment.
    """

    def __init__(self, hidden_dim: int = 128):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.register_buffer("center_mean", torch.zeros(hidden_dim))
        self.register_buffer("center_inv_std", torch.ones(hidden_dim))

    @torch.no_grad()
    def fit_center(self, benign_embeddings: torch.Tensor) -> None:
        mean = benign_embeddings.mean(dim=0)
        std = benign_embeddings.std(dim=0).clamp(min=1e-3)
        self.center_mean.copy_(mean)
        self.center_inv_std.copy_(1.0 / std)

    def energy(self, h: torch.Tensor, h_rec: torch.Tensor) -> torch.Tensor:
        rec_err = (h - h_rec).pow(2).mean(dim=-1)
        centred = (h - self.center_mean) * self.center_inv_std
        mahal_e = centred.pow(2).mean(dim=-1)
        return rec_err + 0.1 * mahal_e


def contrastive_recon_loss(
    h: torch.Tensor,
    h_rec: torch.Tensor,
    benign_mask: Optional[torch.Tensor] = None,
    temperature: float = 0.2,
    lambda_recon: float = 1.0,
    lambda_contrast: float = 0.5,
) -> torch.Tensor:
    """Component-5 training helper: reconstruction + InfoNCE contrastive loss.

    Args:
        h:           [B, H] encoder output
        h_rec:       [B, H] AE reconstruction
        benign_mask: optional [B] bool tensor marking benign rows. If None,
                     every row is treated as benign (pure SSL regime).
        temperature: InfoNCE temperature.
        lambda_recon / lambda_contrast: scalar mixing weights.

    Returns a scalar loss tensor suitable for ``.backward()``.
    """
    recon = (h - h_rec).pow(2).mean()

    h_n = F.normalize(h, dim=-1)
    sim = h_n @ h_n.t() / max(temperature, 1e-6)
    B = h.size(0)
    # Self-similarity is masked out of both numerator and denominator.
    eye = torch.eye(B, device=h.device, dtype=torch.bool)
    sim = sim.masked_fill(eye, float("-inf"))
    # Positive set: other benign rows. If no mask supplied, treat all as benign.
    if benign_mask is None:
        pos_mask = ~eye
    else:
        bm = benign_mask.bool().view(-1, 1)
        pos_mask = (bm & bm.t()) & ~eye

    log_prob = sim - torch.logsumexp(sim, dim=-1, keepdim=True)
    pos_count = pos_mask.float().sum(dim=-1).clamp(min=1.0)
    contrast = -(log_prob * pos_mask.float()).sum(dim=-1) / pos_count
    contrast = contrast.mean()

    return lambda_recon * recon + lambda_contrast * contrast


# ---------------------------------------------------------------------------
# 6. Split-conformal certifier (NEW)
# ---------------------------------------------------------------------------

class SplitConformalCertifier(nn.Module):
    """Split-conformal anomaly certifier with a target FAR ``alpha``.

    Maintains a FIFO buffer of benign calibration scores and exposes
    :meth:`is_anomalous` plus a finite-sample :meth:`coverage_bound`. See
    the module docstring for the marginal-coverage guarantee statement.
    """

    def __init__(self, max_calibration_size: int = 5000, alpha: float = 0.01):
        super().__init__()
        if not (0.0 < alpha < 1.0):
            raise ValueError(f"alpha must be in (0, 1); got {alpha}")
        self.max_calibration_size = int(max_calibration_size)
        # Stored as a python float on a buffer so it survives ``.to(device)``.
        self.register_buffer("alpha_buf", torch.tensor(float(alpha)))
        # Calibration ring buffer (sentinel value -inf marks unfilled slots).
        self.register_buffer(
            "calibration_scores",
            torch.full((self.max_calibration_size,), float("-inf")),
        )
        self.register_buffer("n_calibrated", torch.zeros(1, dtype=torch.long))
        self.register_buffer("write_ptr", torch.zeros(1, dtype=torch.long))
        # Threshold defaults to +inf -> nothing is flagged until calibration.
        self.register_buffer("threshold", torch.tensor(float("inf")))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _active_scores(self) -> torch.Tensor:
        n = int(self.n_calibrated.item())
        if n <= 0:
            return self.calibration_scores.new_empty(0)
        return self.calibration_scores[:n]

    def _recompute_threshold(self) -> None:
        n = int(self.n_calibrated.item())
        if n <= 0:
            self.threshold.fill_(float("inf"))
            return
        alpha = float(self.alpha_buf.item())
        # Conformal quantile index per Angelopoulos & Bates (2022).
        q_level = math.ceil((1.0 - alpha) * (n + 1)) / n
        if q_level >= 1.0:
            # Not enough data for the desired alpha; fall back to the max.
            scores = self._active_scores()
            self.threshold.fill_(float(scores.max().item()))
            return
        scores = self._active_scores()
        # ``torch.quantile`` uses linear interpolation -- matches the
        # standard split-conformal definition for finite n.
        thr = torch.quantile(scores, q_level)
        self.threshold.copy_(thr.detach())

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    @torch.no_grad()
    def update_calibration(self, benign_scores: torch.Tensor) -> None:
        """Append benign energy scores to the calibration ring buffer.

        FIFO eviction: once the buffer is full the oldest entry is
        overwritten. After insertion the conformal threshold is recomputed.
        """
        if benign_scores.dim() == 0:
            benign_scores = benign_scores.view(1)
        scores = benign_scores.detach().to(self.calibration_scores.device).flatten()
        cap = self.max_calibration_size
        ptr = int(self.write_ptr.item())
        n = int(self.n_calibrated.item())
        for s in scores:
            self.calibration_scores[ptr] = s
            ptr = (ptr + 1) % cap
            if n < cap:
                n += 1
        self.write_ptr.fill_(ptr)
        self.n_calibrated.fill_(n)
        self._recompute_threshold()

    @torch.no_grad()
    def is_anomalous(self, score: torch.Tensor) -> torch.Tensor:
        """Boolean tensor: ``score > self.threshold``."""
        return score > self.threshold

    def coverage_bound(self) -> dict:
        """Return the marginal-coverage finite-sample bound.

        ``empirical_upper_bound = alpha + 1 / (n + 1)`` holds under the
        exchangeability assumption between calibration set and future
        benign flows (Vovk et al. 2005). With ``n = 0`` we return ``1.0``
        -- no guarantee can be made before calibration.
        """
        n = int(self.n_calibrated.item())
        alpha = float(self.alpha_buf.item())
        if n <= 0:
            ub = 1.0
        else:
            ub = alpha + 1.0 / (n + 1)
        return {
            "alpha": alpha,
            "n_calibration": n,
            "threshold": float(self.threshold.item()),
            "empirical_upper_bound": ub,
        }

    @torch.no_grad()
    def set_alpha(self, alpha: float) -> None:
        """Set a new target FAR ``alpha`` in ``(0, 1)`` and re-fit threshold."""
        if not (0.0 < float(alpha) < 1.0):
            raise ValueError(f"alpha must be in (0, 1); got {alpha}")
        self.alpha_buf.fill_(float(alpha))
        self._recompute_threshold()


# ---------------------------------------------------------------------------
# Full SSL-GraphAnomaly detector
# ---------------------------------------------------------------------------

class SSLGraphAnomalyFullModel(nn.Module):
    """Six-component detector combining all SSL-GraphAnomaly blocks.

    Architecture (input dim 83 -> hidden 128 -> 34-class logits):

        embed (83 -> 128)
          |
          v
        2 x E-GraphSAGE   ---+
          |                  |  (skip)
          v                  |
        Attention-Gated Streaming Block
          |    <----- summed with the SAGE trunk
          v
        Discrepancy Transformer AE  -> (z, rec)
          |
          v
        Mahalanobis Energy Head    -> energy
          |
          v
        Cls head (128 -> 64 -> 34) + energy-biased logit push
    """

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
        conformal_buffer: int = 5000,
        conformal_alpha: float = 0.01,
    ):
        super().__init__()
        self.in_dim = in_dim
        self.hidden_dim = hidden_dim
        self.n_classes = n_classes

        self.embed = nn.Sequential(
            nn.Linear(in_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
        )
        self.graph_layers = nn.ModuleList([
            _EGraphSAGEBlock(in_dim, hidden_dim, dropout=dropout)
            for _ in range(n_graph_layers)
        ])
        self.streaming_block = _AttentionGatedStreamingBlock(hidden_dim=hidden_dim)
        self.txae = _DiscrepancyTransformerAE(
            hidden_dim=hidden_dim, n_tokens=n_tx_tokens,
            n_heads=n_tx_heads, n_layers=n_tx_layers, dropout=dropout,
        )
        self.mahalanobis_head = _MahalanobisEnergyHead(hidden_dim=hidden_dim)
        self.certifier = SplitConformalCertifier(
            max_calibration_size=conformal_buffer, alpha=conformal_alpha,
        )

        # Lightweight 128 -> 64 -> 34 attribution head.
        self.cls_head = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(64, n_classes),
        )

    # ------------------------------------------------------------------
    def encode(self, x: torch.Tensor) -> torch.Tensor:
        h = self.embed(x)
        h_in = x
        for layer in self.graph_layers:
            h = h + layer(h_in)
            h_in = h
        # Parallel attention-gated streaming skip path summed back into trunk.
        h_stream = self.streaming_block(h)
        h = h + h_stream
        return h

    def _energy_and_logits(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        h = self.encode(x)
        z, rec = self.txae(h)
        energy = self.mahalanobis_head.energy(h, rec)  # [B]
        logits = self.cls_head(h)                      # [B, C]
        push = energy.unsqueeze(-1) * 2.0
        bias = torch.cat([-push, push.expand(-1, logits.size(1) - 1)], dim=-1)
        if z.size(0) > 0:
            bias = bias + 0.0 * z.mean()
        return logits + bias, energy, h

    def forward(self, x: torch.Tensor, disabled_branches=None) -> torch.Tensor:
        del disabled_branches  # SSL trunk has no branch ablation
        logits, _, _ = self._energy_and_logits(x)
        return logits

    @torch.no_grad()
    def forward_with_certificate(self, x: torch.Tensor) -> dict:
        logits, energy, _ = self._energy_and_logits(x)
        is_anom = self.certifier.is_anomalous(energy)
        return {
            "logits": logits,
            "energy": energy,
            "is_anomalous": is_anom,
            "coverage_bound": self.certifier.coverage_bound(),
        }

    @torch.no_grad()
    def calibrate_on(self, benign_x: torch.Tensor) -> None:
        """Two-step calibration: fit Mahalanobis centre AND conformal buffer.

        Should be called on a *held-out* benign set immediately before
        deployment. Calling it on the training set would violate the
        exchangeability assumption that backs the coverage bound.
        """
        h = self.encode(benign_x)
        # Step 1: Mahalanobis centring on benign embeddings.
        self.mahalanobis_head.fit_center(h)
        # Step 2: energy scores -> conformal calibration buffer.
        _, rec = self.txae(h)
        energy = self.mahalanobis_head.energy(h, rec)
        self.certifier.update_calibration(energy)
        # Update the streaming EMA so the deployed model starts warm.
        self.streaming_block.update_streaming_buffer(h)


# ---------------------------------------------------------------------------
# Platform-compatible wrapper
# ---------------------------------------------------------------------------

class SSLGraphAnomalyFullWrapper(nn.Module):
    """Platform wrapper exposing the standard [B, 83] -> [B, 34] contract.

    Adds the certificate-aware helpers (``forward_with_certificate``,
    ``calibrate_on``, ``set_alpha``, ``coverage_bound``) on top of the
    base classification interface.
    """

    N_FEATURES = 83
    N_CLASSES = 34
    BRANCH_NAMES = SurrogateIDS.BRANCH_NAMES
    CLASS_NAMES = SurrogateIDS.CLASS_NAMES
    SEVERITY_MAP = SurrogateIDS.SEVERITY_MAP

    def __init__(self, dropout: float = 0.1):
        super().__init__()
        self.model = SSLGraphAnomalyFullModel(
            in_dim=self.N_FEATURES,
            hidden_dim=128,
            n_classes=self.N_CLASSES,
            n_graph_layers=2,
            n_tx_tokens=8,
            n_tx_heads=4,
            n_tx_layers=2,
            dropout=dropout,
        )

    def forward(self, x: torch.Tensor, disabled_branches=None) -> torch.Tensor:
        return self.model(x, disabled_branches)

    def forward_with_certificate(self, x: torch.Tensor) -> dict:
        return self.model.forward_with_certificate(x)

    def calibrate_on(self, benign_x: torch.Tensor) -> None:
        return self.model.calibrate_on(benign_x)

    def set_alpha(self, alpha: float) -> None:
        return self.model.certifier.set_alpha(alpha)

    def coverage_bound(self) -> dict:
        return self.model.certifier.coverage_bound()

    @classmethod
    def severity_for(cls, label: str) -> str:
        return SurrogateIDS.severity_for(label)
