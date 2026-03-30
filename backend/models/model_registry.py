"""
Model Registry
===============

Central registry for all available IDS models.
Each model is wrapped to provide a uniform interface:
  - Input:  [batch_size, 83] float tensor
  - Output: [batch_size, 34] logits
  - forward(x, disabled_branches=None)

Author: Roger Nick Anaedevha
"""

import torch
import torch.nn as nn
from pathlib import Path
from typing import Dict, Optional

from .surrogate import SurrogateIDS
from .clrl_models import (
    CLRLUnifiedWrapper,
    CPOPolicyWrapper,
    ValueNetWrapper,
    CostValueNetWrapper,
    UnifiedFIMWrapper,
)
from .multi_agent_pqc import MultiAgentPQCWrapper

WEIGHTS_DIR = Path(__file__).parent.parent / "weights"


# ---------------------------------------------------------------------------
# Wrappers — adapt each research model to the 83→34 demo interface
# ---------------------------------------------------------------------------

class NeuralODEWrapper(nn.Module):
    """Wraps TemporalAdaptiveNeuralODE for demo inference."""

    N_FEATURES = 83
    N_CLASSES = 34
    BRANCH_NAMES = SurrogateIDS.BRANCH_NAMES
    CLASS_NAMES = SurrogateIDS.CLASS_NAMES
    SEVERITY_MAP = SurrogateIDS.SEVERITY_MAP

    def __init__(self, dropout: float = 0.2):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(83, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
        )
        # ODE dynamics (simplified for demo — avoids torchdiffeq dependency)
        self.ode_layers = nn.Sequential(
            nn.Linear(128, 256),
            nn.Tanh(),
            nn.Linear(256, 256),
            nn.Tanh(),
            nn.Linear(256, 128),
        )
        self.time_modulation = nn.Sequential(
            nn.Linear(1, 128),
            nn.Sigmoid(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(128, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 34),
        )

    def forward(self, x, disabled_branches=None):
        h = self.encoder(x)
        # Simulate ODE integration at t=0 and t=1
        t = torch.ones(x.size(0), 1, device=x.device)
        h = h + self.ode_layers(h)  # one Euler step
        h = h * self.time_modulation(t)
        return self.decoder(h)

    @classmethod
    def severity_for(cls, label: str) -> str:
        return SurrogateIDS.severity_for(label)


class OptimalTransportWrapper(nn.Module):
    """Wraps MultiCloudDomainAdapter / PPFOTDetector for demo inference."""

    N_FEATURES = 83
    N_CLASSES = 34
    BRANCH_NAMES = SurrogateIDS.BRANCH_NAMES
    CLASS_NAMES = SurrogateIDS.CLASS_NAMES
    SEVERITY_MAP = SurrogateIDS.SEVERITY_MAP

    def __init__(self, dropout: float = 0.2):
        super().__init__()
        self.feature_extractor = nn.Sequential(
            nn.Linear(83, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, 128),
        )
        # Cloud-specific adapters (3 clouds)
        self.cloud_adapters = nn.ModuleList([
            nn.Sequential(
                nn.Linear(128, 128),
                nn.BatchNorm1d(128),
                nn.ReLU(),
            )
            for _ in range(3)
        ])
        self.classifier = nn.Sequential(
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 34),
        )

    def forward(self, x, disabled_branches=None):
        h = self.feature_extractor(x)
        # Use adapter 0 for inference (source cloud)
        h = self.cloud_adapters[0](h)
        return self.classifier(h)

    @classmethod
    def severity_for(cls, label: str) -> str:
        return SurrogateIDS.severity_for(label)


class FedGTDWrapper(nn.Module):
    """Wraps FedGTD graph model for demo inference on flat features."""

    N_FEATURES = 83
    N_CLASSES = 34
    BRANCH_NAMES = SurrogateIDS.BRANCH_NAMES
    CLASS_NAMES = SurrogateIDS.CLASS_NAMES
    SEVERITY_MAP = SurrogateIDS.SEVERITY_MAP

    def __init__(self, dropout: float = 0.2):
        super().__init__()
        # Encode flat features to graph node embedding
        self.node_encoder = nn.Sequential(
            nn.Linear(83, 256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, 128),
        )
        # Graph message passing (simulated via MLP attention)
        self.graph_layers = nn.ModuleList([
            nn.Sequential(
                nn.Linear(128, 128),
                nn.ReLU(),
                nn.Dropout(dropout),
            )
            for _ in range(3)
        ])
        # Self-attention for graph aggregation
        self.attention = nn.Sequential(
            nn.Linear(128, 64),
            nn.Tanh(),
            nn.Linear(64, 1),
        )
        # Knowledge distillation temperature
        self.temperature = nn.Parameter(torch.tensor(1.0))
        self.classifier = nn.Sequential(
            nn.Linear(128, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 34),
        )

    def forward(self, x, disabled_branches=None):
        h = self.node_encoder(x)
        for layer in self.graph_layers:
            # Message passing + residual
            msg = layer(h)
            h = h + msg
        # Feature-level attention gating (per sample)
        attn_weights = torch.sigmoid(self.attention(h))  # [batch, 1]
        h = h * attn_weights
        logits = self.classifier(h)
        return logits / self.temperature.clamp(min=0.1)

    @classmethod
    def severity_for(cls, label: str) -> str:
        return SurrogateIDS.severity_for(label)


class CyberSecLLMWrapper(nn.Module):
    """Wraps CyberSecLLM surrogate (Mamba + CrossAttention + MoE)."""

    N_FEATURES = 83
    N_CLASSES = 34
    BRANCH_NAMES = SurrogateIDS.BRANCH_NAMES
    CLASS_NAMES = SurrogateIDS.CLASS_NAMES
    SEVERITY_MAP = SurrogateIDS.SEVERITY_MAP

    def __init__(self, dropout: float = 0.1):
        super().__init__()
        from .cybersec_llm import CyberSecLLMModel
        self.model = CyberSecLLMModel(
            dropout=dropout, n_blocks=3, n_experts=8, top_k=2,
            kb_size=32, n_heads=4, ssm_state_dim=16,
        )

    def forward(self, x, disabled_branches=None):
        return self.model(x, disabled_branches)

    @classmethod
    def severity_for(cls, label: str) -> str:
        return SurrogateIDS.severity_for(label)


class SDETGNNWrapper(nn.Module):
    """Wraps SDETGNNModel for demo inference."""

    N_FEATURES = 83
    N_CLASSES = 34
    BRANCH_NAMES = SurrogateIDS.BRANCH_NAMES
    CLASS_NAMES = SurrogateIDS.CLASS_NAMES
    SEVERITY_MAP = SurrogateIDS.SEVERITY_MAP

    def __init__(self, dropout: float = 0.2):
        super().__init__()
        from .sde_tgnn import SDETGNNModel
        self.model = SDETGNNModel(
            input_dim=83,
            hidden_dim=256,
            num_classes=34,
            n_graph_layers=2,
            sde_steps=10,
            dropout=dropout,
        )

    def forward(self, x, disabled_branches=None):
        return self.model(x, disabled_branches)

    @classmethod
    def severity_for(cls, label: str) -> str:
        return SurrogateIDS.severity_for(label)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

MODEL_INFO = {
    "surrogate": {
        "name": "SurrogateIDS (7-Branch Ensemble)",
        "description": "Lightweight MLP simulating the 7-method ensemble. Fast inference with ablation support.",
        "paper": "Dissertation Chapter 8 — Unified System",
        "class": SurrogateIDS,
        "weight_file": "surrogate.pt",
        "has_ablation": True,
        "category": "ensemble",
    },
    "neural_ode": {
        "name": "Neural ODE (TA-BN-ODE + Point Process)",
        "description": "Temporal Adaptive Batch Normalization Neural ODE with Hawkes point process for continuous-time intrusion detection.",
        "paper": "Temporal Adaptive Neural ODEs with Deep Spatio-Temporal Point Processes",
        "class": NeuralODEWrapper,
        "weight_file": "neural_ode.pt",
        "has_ablation": False,
        "category": "temporal",
    },
    "optimal_transport": {
        "name": "Optimal Transport (PPFOT-IDS)",
        "description": "Privacy-preserving federated optimal transport for multi-cloud domain adaptation with differential privacy.",
        "paper": "Differentially Private Optimal Transport for Multi-Cloud Intrusion Detection",
        "class": OptimalTransportWrapper,
        "weight_file": "optimal_transport.pt",
        "has_ablation": False,
        "category": "federated",
    },
    "fedgtd": {
        "name": "FedGTD (Federated Graph Temporal Dynamics)",
        "description": "Graph-based federated learning with temporal dynamics, knowledge distillation, and Byzantine robustness.",
        "paper": "Federated Graph Temporal Dynamics for Distributed IDS",
        "class": FedGTDWrapper,
        "weight_file": "fedgtd.pt",
        "has_ablation": False,
        "category": "federated",
    },
    "sde_tgnn": {
        "name": "SDE-TGNN (Stochastic Differential Equation TGNN)",
        "description": "Stochastic differential equation temporal graph neural network with drift-diffusion dynamics for robust detection.",
        "paper": "SDE-TGNN: Stochastic Differential Equation Temporal Graph Neural Networks",
        "class": SDETGNNWrapper,
        "weight_file": "sde_tgnn.pt",
        "has_ablation": False,
        "category": "temporal",
    },
    "cybersec_llm": {
        "name": "CyberSecLLM (Mamba–CrossAttn–MoE)",
        "description": "Cybersecurity foundation model surrogate combining selective state-space (Mamba), cross-attention to MITRE ATT&CK knowledge base, and sparse mixture-of-experts. Trained on all 6 datasets.",
        "paper": "CyberSecLLM: A Cybersecurity-Specific Large Language Model for Intrusion Detection (IEEE TNNLS)",
        "class": CyberSecLLMWrapper,
        "weight_file": "cybersec_llm.pt",
        "has_ablation": False,
        "category": "foundation",
    },
    # ── CL-RL Model (Continual Learning + Reinforcement Learning) ────────
    # The unified CL-RL model is the 6th individual model (alongside the 5 core
    # models above + the 7-in-1 Surrogate).  Its 4 sub-models (CPO Policy,
    # Value Net, Cost Value Net, Unified FIM) are internal components that
    # together form the CL-RL framework and are exposed for advanced users.
    "clrl_unified": {
        "name": "CL-RL Unified (Continual Learning + Reinforcement Learning)",
        "description": "Enhanced 7-branch ensemble with MC Dropout uncertainty estimation, RL state vector construction, and unified FIM computation. Integrates continual learning (EWC) with constrained RL (CPO) for adversarially robust, adaptive intrusion detection.",
        "paper": "Continual Learning and Constrained RL for Adversarially Robust NIDS",
        "class": CLRLUnifiedWrapper,
        "weight_file": "clrl_unified.pt",
        "has_ablation": True,
        "category": "clrl",
        "sub_models": ["cpo_policy", "value_net", "cost_value_net", "unified_fim"],
    },
    "cpo_policy": {
        "name": "CPO Response Agent (Constrained Policy Optimisation)",
        "description": "Constrained Policy Optimisation agent with 5 graduated response actions (Monitor → Quarantine). Uses trust-region updates with false-positive constraint satisfaction.",
        "paper": "Continual Learning and Constrained RL for Adversarially Robust NIDS",
        "class": CPOPolicyWrapper,
        "weight_file": "cpo_policy.pt",
        "has_ablation": False,
        "category": "clrl",
        "parent_model": "clrl_unified",
    },
    "value_net": {
        "name": "Value Network (Reward Estimator)",
        "description": "Reward value estimator for the CPO agent. Estimates expected cumulative reward for GAE advantage computation during policy updates.",
        "paper": "Continual Learning and Constrained RL for Adversarially Robust NIDS",
        "class": ValueNetWrapper,
        "weight_file": "value_net.pt",
        "has_ablation": False,
        "category": "clrl",
        "parent_model": "clrl_unified",
    },
    "cost_value_net": {
        "name": "Cost Value Network (Constraint Estimator)",
        "description": "False-positive cost estimator for CPO constraint satisfaction. Estimates cumulative FP cost for Lagrangian dual variable updates (ε_fp < 0.1%).",
        "paper": "Continual Learning and Constrained RL for Adversarially Robust NIDS",
        "class": CostValueNetWrapper,
        "weight_file": "cost_value_net.pt",
        "has_ablation": False,
        "category": "clrl",
        "parent_model": "clrl_unified",
    },
    "unified_fim": {
        "name": "Unified FIM Model (Fisher Information-Regularised)",
        "description": "Fisher Information-regularised detection network. Balances detection preservation (β=0.7) with policy plasticity (1−β=0.3) via unified FIM from both EWC and CPO trust regions.",
        "paper": "Continual Learning and Constrained RL for Adversarially Robust NIDS",
        "class": UnifiedFIMWrapper,
        "weight_file": "unified_fim.pt",
        "has_ablation": False,
        "category": "clrl",
        "parent_model": "clrl_unified",
    },
    # ── Multi-Agent PQC-IDS ─────────────────────────────────────────────
    "multi_agent_pqc": {
        "name": "Multi-Agent PQC-IDS",
        "description": "4-agent cooperative IDS with PQC-aware traffic classification. Agents: Traffic Analyst, PQC Specialist, Anomaly Detector, Coordinator.",
        "paper": "Multi-Agent PQC-Aware Intrusion Detection for Post-Quantum Network Security",
        "class": MultiAgentPQCWrapper,
        "weight_file": "multi_agent_pqc.pt",
        "has_ablation": False,
        "category": "pqc",
    },
}


def list_models() -> list:
    """Return metadata for all registered models."""
    result = []
    for key, info in MODEL_INFO.items():
        weight_path = WEIGHTS_DIR / info["weight_file"]
        entry = {
            "id": key,
            "name": info["name"],
            "description": info["description"],
            "paper": info["paper"],
            "has_ablation": info["has_ablation"],
            "category": info["category"],
            "weights_available": weight_path.exists(),
        }
        if "sub_models" in info:
            entry["sub_models"] = info["sub_models"]
        if "parent_model" in info:
            entry["parent_model"] = info["parent_model"]
        result.append(entry)
    return result


def load_model(model_id: str, device: str = "cpu", dropout: float = 0.05) -> nn.Module:
    """
    Load a model by its registry ID.

    Args:
        model_id: Key in MODEL_INFO
        device: Device to load onto
        dropout: Dropout rate

    Returns:
        Loaded model in eval mode
    """
    if model_id not in MODEL_INFO:
        raise ValueError(f"Unknown model: {model_id}. Available: {list(MODEL_INFO.keys())}")

    info = MODEL_INFO[model_id]
    model_cls = info["class"]
    m = model_cls(dropout=dropout)

    weight_path = WEIGHTS_DIR / info["weight_file"]
    if weight_path.exists():
        state = torch.load(weight_path, map_location=device, weights_only=True)
        m.load_state_dict(state)

    m.to(device)
    m.eval()
    return m
