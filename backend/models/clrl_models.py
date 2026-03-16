"""
CL-RL Model Wrappers for the Model Registry.

Six new models from the CL-RL paper:
  1. CLRLUnifiedWrapper   — Combined CL-RL enhanced SurrogateIDS (complements 7 branches)
  2. CPOPolicyWrapper     — CPO Response Agent (PolicyNetwork)
  3. ValueNetWrapper      — Reward Value Estimator
  4. CostValueNetWrapper  — Cost/Constraint Value Estimator
  5. UnifiedFIMWrapper    — Unified Fisher Information Model

Each wrapper adapts the CL-RL model to the standard 83→34 demo interface
used by the model registry.

Author: Roger Nick Anaedevha
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Optional

from .surrogate import SurrogateIDS
from .policy_network import PolicyNetwork, ValueNetwork, CostValueNetwork


# ── 1. CL-RL Unified Framework ────────────────────────────────────────────

class CLRLUnifiedWrapper(nn.Module):
    """
    CL-RL Unified Model: Enhanced SurrogateIDS + RL State Construction + MC Dropout.

    This is the ONE combined model that complements all 7 surrogate branches.
    It adds:
      - MC Dropout uncertainty estimation (T=20 forward passes)
      - RL state vector construction (55-dim) for the CPO agent
      - Shared feature extraction for unified FIM computation
      - Expandable classifier head for continual learning
    """

    N_FEATURES = 83
    N_CLASSES = 34
    BRANCH_NAMES = SurrogateIDS.BRANCH_NAMES
    CLASS_NAMES = SurrogateIDS.CLASS_NAMES
    SEVERITY_MAP = SurrogateIDS.SEVERITY_MAP

    def __init__(self, dropout: float = 0.1):
        super().__init__()
        self.mc_dropout_rate = dropout
        self.mc_samples = 20
        self.num_branches = 7
        self.num_classes = 34

        # 7 parallel branches (same as SurrogateIDS but with BatchNorm)
        branch_hidden = [512, 256, 128]
        self.branches = nn.ModuleList()
        for _ in range(self.num_branches):
            layers = []
            prev_dim = 83
            for h_dim in branch_hidden:
                layers.extend([
                    nn.Linear(prev_dim, h_dim),
                    nn.BatchNorm1d(h_dim),
                    nn.ReLU(inplace=True),
                    nn.Dropout(p=dropout),
                ])
                prev_dim = h_dim
            self.branches.append(nn.Sequential(*layers))

        # Feature fusion: 7 branches × 128 = 896 → 256
        self.fusion = nn.Sequential(
            nn.Linear(128 * self.num_branches, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(inplace=True),
            nn.Dropout(p=dropout),
        )

        # Classification head with MC Dropout
        self.classifier = nn.Sequential(
            nn.Linear(256, 128),
            nn.ReLU(inplace=True),
            nn.Dropout(p=dropout),
            nn.Linear(128, 34),
        )

    def forward(self, x, disabled_branches=None):
        """Standard forward: returns class logits [batch, 34]."""
        branch_outputs = []
        for i, branch in enumerate(self.branches):
            if disabled_branches and i in disabled_branches:
                branch_outputs.append(
                    torch.zeros(x.size(0), 128, device=x.device)
                )
            else:
                branch_outputs.append(branch(x))

        concatenated = torch.cat(branch_outputs, dim=1)
        features = self.fusion(concatenated)
        logits = self.classifier(features)
        return logits

    def forward_with_features(self, x, disabled_branches=None):
        """Returns (logits, shared_features) for RL state construction."""
        branch_outputs = []
        for i, branch in enumerate(self.branches):
            if disabled_branches and i in disabled_branches:
                branch_outputs.append(
                    torch.zeros(x.size(0), 128, device=x.device)
                )
            else:
                branch_outputs.append(branch(x))

        concatenated = torch.cat(branch_outputs, dim=1)
        features = self.fusion(concatenated)
        logits = self.classifier(features)
        return logits, features

    def predict_with_uncertainty(self, x, num_samples=None):
        """
        MC Dropout inference for uncertainty estimation.

        Returns dict with: probabilities, predictions,
        epistemic_uncertainty, aleatoric_uncertainty, features
        """
        T = num_samples or self.mc_samples
        self.train()  # Enable dropout

        all_probs = []
        all_features = []
        with torch.no_grad():
            for _ in range(T):
                logits, features = self.forward_with_features(x)
                probs = F.softmax(logits, dim=-1)
                all_probs.append(probs)
                all_features.append(features)

        self.eval()

        stacked_probs = torch.stack(all_probs, dim=0)
        mean_probs = stacked_probs.mean(dim=0)
        mean_features = torch.stack(all_features, dim=0).mean(dim=0)

        # Epistemic: mutual information = H[E[p]] - E[H[p]]
        entropy_of_mean = -torch.sum(
            mean_probs * torch.log(mean_probs + 1e-10), dim=-1
        )
        mean_of_entropy = -torch.mean(
            torch.sum(stacked_probs * torch.log(stacked_probs + 1e-10), dim=-1),
            dim=0,
        )
        epistemic = entropy_of_mean - mean_of_entropy
        aleatoric = mean_of_entropy

        return {
            "probabilities": mean_probs,
            "predictions": mean_probs.argmax(dim=-1),
            "epistemic_uncertainty": epistemic,
            "aleatoric_uncertainty": aleatoric,
            "features": mean_features,
        }

    def construct_rl_state(self, x):
        """Construct the 55-dimensional RL state vector."""
        result = self.predict_with_uncertainty(x)

        components = [result["probabilities"]]
        uncertainty = torch.stack(
            [result["epistemic_uncertainty"], result["aleatoric_uncertainty"]],
            dim=-1,
        )
        components.append(uncertainty)

        state = torch.cat(components, dim=-1)
        target_dim = 55
        if state.shape[-1] < target_dim:
            pad = torch.zeros(
                state.shape[0], target_dim - state.shape[-1],
                device=state.device,
            )
            state = torch.cat([state, pad], dim=-1)
        elif state.shape[-1] > target_dim:
            state = state[:, :target_dim]

        return state

    def get_shared_parameters(self):
        """Get parameters from shared layers (for unified FIM)."""
        shared = []
        for name, param in self.named_parameters():
            if "fusion" in name or any(
                f"branches.{i}" in name for i in range(3)
            ):
                shared.append(param)
        return shared

    @classmethod
    def severity_for(cls, label: str) -> str:
        return SurrogateIDS.severity_for(label)


# ── 2. CPO Policy Agent ───────────────────────────────────────────────────

class CPOPolicyWrapper(nn.Module):
    """
    CPO Response Agent: Maps 83 flow features → 34 class logits.

    Internally constructs a 55-dim RL state via a lightweight encoder,
    then passes through the policy network to get response action logits.
    For the registry interface, we adapt this to output 34-dim by
    mapping actions to class-specific response scores.
    """

    N_FEATURES = 83
    N_CLASSES = 34
    BRANCH_NAMES = SurrogateIDS.BRANCH_NAMES
    CLASS_NAMES = SurrogateIDS.CLASS_NAMES
    SEVERITY_MAP = SurrogateIDS.SEVERITY_MAP

    def __init__(self, dropout: float = 0.1):
        super().__init__()
        # Feature encoder: 83 → 55 (RL state dim)
        self.state_encoder = nn.Sequential(
            nn.Linear(83, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 55),
            nn.ReLU(),
        )
        # Policy network: 55 → 5 actions
        self.policy = PolicyNetwork(state_dim=55, num_actions=5)
        # Response-to-classification head: maps (features, actions) → 34 classes
        self.response_head = nn.Sequential(
            nn.Linear(55 + 5, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 34),
        )

    def forward(self, x, disabled_branches=None):
        state = self.state_encoder(x)
        action_logits = self.policy(state)
        action_probs = F.softmax(action_logits, dim=-1)
        combined = torch.cat([state, action_probs], dim=-1)
        return self.response_head(combined)

    def get_policy_output(self, x):
        """Get raw policy action distribution for RL use."""
        state = self.state_encoder(x)
        action_logits = self.policy(state)
        return {
            "state": state,
            "action_logits": action_logits,
            "action_probs": F.softmax(action_logits, dim=-1),
        }

    @classmethod
    def severity_for(cls, label: str) -> str:
        return SurrogateIDS.severity_for(label)


# ── 3. Value Network (Reward Estimator) ──────────────────────────────────

class ValueNetWrapper(nn.Module):
    """
    Reward Value Estimator: Maps flow features → value-informed class logits.

    Uses the value network to estimate the expected reward of the current
    state, then modulates class predictions based on value estimates.
    """

    N_FEATURES = 83
    N_CLASSES = 34
    BRANCH_NAMES = SurrogateIDS.BRANCH_NAMES
    CLASS_NAMES = SurrogateIDS.CLASS_NAMES
    SEVERITY_MAP = SurrogateIDS.SEVERITY_MAP

    def __init__(self, dropout: float = 0.1):
        super().__init__()
        self.state_encoder = nn.Sequential(
            nn.Linear(83, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 55),
            nn.ReLU(),
        )
        self.value_net = ValueNetwork(state_dim=55)
        # Value-modulated classifier
        self.classifier = nn.Sequential(
            nn.Linear(55 + 1, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 34),
        )

    def forward(self, x, disabled_branches=None):
        state = self.state_encoder(x)
        value = self.value_net(state).unsqueeze(-1)
        combined = torch.cat([state, value], dim=-1)
        return self.classifier(combined)

    @classmethod
    def severity_for(cls, label: str) -> str:
        return SurrogateIDS.severity_for(label)


# ── 4. Cost Value Network (Constraint Estimator) ─────────────────────────

class CostValueNetWrapper(nn.Module):
    """
    Cost/Constraint Value Estimator: Maps flow features → cost-aware class logits.

    Uses the cost value network to estimate false-positive cost, producing
    constraint-aware classification scores.
    """

    N_FEATURES = 83
    N_CLASSES = 34
    BRANCH_NAMES = SurrogateIDS.BRANCH_NAMES
    CLASS_NAMES = SurrogateIDS.CLASS_NAMES
    SEVERITY_MAP = SurrogateIDS.SEVERITY_MAP

    def __init__(self, dropout: float = 0.1):
        super().__init__()
        self.state_encoder = nn.Sequential(
            nn.Linear(83, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 55),
            nn.ReLU(),
        )
        self.cost_value_net = CostValueNetwork(state_dim=55)
        # Cost-modulated classifier
        self.classifier = nn.Sequential(
            nn.Linear(55 + 1, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 34),
        )

    def forward(self, x, disabled_branches=None):
        state = self.state_encoder(x)
        cost_value = self.cost_value_net(state).unsqueeze(-1)
        combined = torch.cat([state, cost_value], dim=-1)
        return self.classifier(combined)

    @classmethod
    def severity_for(cls, label: str) -> str:
        return SurrogateIDS.severity_for(label)


# ── 5. Unified FIM Model ─────────────────────────────────────────────────

class UnifiedFIMWrapper(nn.Module):
    """
    Unified FIM Model: Fisher Information-regularised detection network.

    Uses unified FIM-weighted feature extraction that balances detection
    preservation (EWC) and policy plasticity (CPO trust region).
    The FIM-weighted features improve robustness during continual updates.
    """

    N_FEATURES = 83
    N_CLASSES = 34
    BRANCH_NAMES = SurrogateIDS.BRANCH_NAMES
    CLASS_NAMES = SurrogateIDS.CLASS_NAMES
    SEVERITY_MAP = SurrogateIDS.SEVERITY_MAP

    def __init__(self, dropout: float = 0.1):
        super().__init__()
        # FIM-weighted feature extractor
        self.encoder = nn.Sequential(
            nn.Linear(83, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(dropout),
        )
        # Detection branch (beta=0.7 weight)
        self.detection_head = nn.Sequential(
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 34),
        )
        # Policy branch (beta=0.3 weight)
        self.policy_head = nn.Sequential(
            nn.Linear(256, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 34),
        )
        self.beta = nn.Parameter(torch.tensor(0.7))

    def forward(self, x, disabled_branches=None):
        features = self.encoder(x)
        det_logits = self.detection_head(features)
        pol_logits = self.policy_head(features)
        beta = torch.sigmoid(self.beta)
        return beta * det_logits + (1 - beta) * pol_logits

    @classmethod
    def severity_for(cls, label: str) -> str:
        return SurrogateIDS.severity_for(label)
