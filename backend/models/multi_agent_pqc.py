"""
Multi-Agent PQC-IDS — Integrated into RobustIDPS.ai platform.

Multi-agent cooperative intrusion detection with PQC-aware traffic
classification. Four specialized agents with attention-weighted fusion.

Source: https://github.com/rogerpanel/Multi-Agent-PQC-models
Dataset: https://doi.org/10.34740/kaggle/dsv/15424420

Author: Roger Nick Anaedevha
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, Tuple

from .surrogate import SurrogateIDS


# ---------------------------------------------------------------------------
# Individual agent modules
# ---------------------------------------------------------------------------


class TrafficAnalystAgent(nn.Module):
    """Agent 1: Flow-level attack classification."""

    def __init__(
        self, n_features: int = 83, n_classes: int = 34, hidden: int = 128
    ):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(n_features, hidden),
            nn.BatchNorm1d(hidden),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden, hidden // 2),
            nn.ReLU(),
            nn.Linear(hidden // 2, n_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class PQCSpecialistAgent(nn.Module):
    """Agent 2: PQC algorithm identification from traffic features."""

    def __init__(
        self, n_features: int = 83, n_pqc_classes: int = 14, hidden: int = 128
    ):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(n_features, hidden),
            nn.BatchNorm1d(hidden),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden, hidden // 2),
            nn.ReLU(),
            nn.Linear(hidden // 2, n_pqc_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class AnomalyDetectorAgent(nn.Module):
    """Agent 3: Autoencoder-based anomaly detection.

    The anomaly score for a sample is the mean squared reconstruction error.
    """

    def __init__(self, n_features: int = 83, bottleneck: int = 16):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(n_features, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, bottleneck),
        )
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck, 32),
            nn.ReLU(),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, n_features),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        z = self.encoder(x)
        recon = self.decoder(z)
        return recon

    def anomaly_score(self, x: torch.Tensor) -> torch.Tensor:
        """Per-sample mean squared reconstruction error."""
        recon = self.forward(x)
        return ((x - recon) ** 2).mean(dim=-1)


class CoordinatorAgent(nn.Module):
    """Agent 4: Attention-weighted fusion of specialist outputs.

    Receives the concatenated logits from all three specialist agents and
    produces final attack/PQC classification logits plus attention weights.
    """

    def __init__(
        self,
        n_attack_classes: int = 34,
        n_pqc_classes: int = 14,
        n_agents: int = 3,
        hidden: int = 64,
    ):
        super().__init__()
        # Input: attack logits + pqc logits + anomaly score
        input_dim = n_attack_classes + n_pqc_classes + 1
        self.attention = nn.Sequential(
            nn.Linear(input_dim, hidden),
            nn.ReLU(),
            nn.Linear(hidden, n_agents),
        )
        self.final_attack = nn.Sequential(
            nn.Linear(input_dim, hidden),
            nn.ReLU(),
            nn.Linear(hidden, n_attack_classes),
        )
        self.final_pqc = nn.Sequential(
            nn.Linear(input_dim, hidden),
            nn.ReLU(),
            nn.Linear(hidden, n_pqc_classes),
        )

    def forward(
        self,
        attack_logits: torch.Tensor,
        pqc_logits: torch.Tensor,
        anomaly_scores: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        combined = torch.cat(
            [attack_logits, pqc_logits, anomaly_scores.unsqueeze(-1)], dim=-1
        )
        weights = F.softmax(self.attention(combined), dim=-1)  # (batch, 3)
        final_attack = self.final_attack(combined)
        final_pqc = self.final_pqc(combined)
        return final_attack, final_pqc, weights


# ---------------------------------------------------------------------------
# Composite multi-agent system
# ---------------------------------------------------------------------------


class MultiAgentPQCIDS(nn.Module):
    """Complete Multi-Agent PQC-Aware Intrusion Detection System.

    Forward pass returns a dictionary with both final (coordinator-fused)
    and raw (per-agent) outputs so that every agent can be supervised
    independently during training.
    """

    N_FEATURES = 83
    N_ATTACK_CLASSES = 34
    N_PQC_CLASSES = 14

    def __init__(self):
        super().__init__()
        self.traffic_analyst = TrafficAnalystAgent(
            self.N_FEATURES, self.N_ATTACK_CLASSES
        )
        self.pqc_specialist = PQCSpecialistAgent(
            self.N_FEATURES, self.N_PQC_CLASSES
        )
        self.anomaly_detector = AnomalyDetectorAgent(self.N_FEATURES)
        self.coordinator = CoordinatorAgent(
            self.N_ATTACK_CLASSES, self.N_PQC_CLASSES
        )

    def forward(self, x: torch.Tensor) -> Dict[str, torch.Tensor]:
        attack_logits = self.traffic_analyst(x)
        pqc_logits = self.pqc_specialist(x)
        anomaly_scores = self.anomaly_detector.anomaly_score(x)

        final_attack, final_pqc, agent_weights = self.coordinator(
            attack_logits, pqc_logits, anomaly_scores
        )

        return {
            "attack_logits": final_attack,
            "pqc_logits": final_pqc,
            "agent_weights": agent_weights,
            "anomaly_scores": anomaly_scores,
            "raw_attack": attack_logits,
            "raw_pqc": pqc_logits,
        }


# ---------------------------------------------------------------------------
# Platform-compatible wrapper
# ---------------------------------------------------------------------------


class MultiAgentPQCWrapper(nn.Module):
    """Platform-compatible wrapper for the Multi-Agent PQC-IDS model.

    Adapts the multi-agent system to the standard 83->34 demo interface
    used by the model registry.
    """

    N_FEATURES = 83
    N_CLASSES = 34
    BRANCH_NAMES = SurrogateIDS.BRANCH_NAMES
    CLASS_NAMES = SurrogateIDS.CLASS_NAMES
    SEVERITY_MAP = SurrogateIDS.SEVERITY_MAP

    def __init__(self, dropout: float = 0.2):
        super().__init__()
        self.model = MultiAgentPQCIDS()

    def forward(self, x, disabled_branches=None):
        """Return 34-class attack logits (platform-compatible)."""
        outputs = self.model(x)
        return outputs["attack_logits"]

    def forward_full(self, x):
        """Return full multi-agent outputs including PQC classification."""
        return self.model(x)

    @classmethod
    def severity_for(cls, label: str) -> str:
        return SurrogateIDS.severity_for(label)
