"""
Policy and Value networks for the Constrained RL Response Agent.

Architecture (CL-RL Paper Section IV-B):
  - Policy: MLP with hidden dims [256, 128], ReLU activation
  - Value: Separate MLP for reward value and cost value estimation
  - Input: 55-dimensional state vector from SurrogateIDS
  - Output: 5 discrete actions (Monitor, RateLimit, Reset, Block, Quarantine)

Author: Roger Nick Anaedevha
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.distributions import Categorical
from typing import Tuple


ACTION_NAMES = ["Monitor", "RateLimit", "Reset", "Block", "Quarantine"]
ACTION_SEVERITY = [0.0, 0.5, 1.0, 2.0, 5.0]


class PolicyNetwork(nn.Module):
    """
    Policy network for the CPO response agent.

    Maps the 55-dim state vector to a distribution over 5 response actions.
    """

    N_FEATURES = 55
    N_ACTIONS = 5

    def __init__(
        self,
        state_dim: int = 55,
        num_actions: int = 5,
        hidden_dims: list = None,
    ):
        super().__init__()
        if hidden_dims is None:
            hidden_dims = [256, 128]

        self.state_dim = state_dim
        self.num_actions = num_actions

        layers = []
        prev_dim = state_dim
        for h_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.ReLU(inplace=True),
            ])
            prev_dim = h_dim
        layers.append(nn.Linear(prev_dim, num_actions))
        self.network = nn.Sequential(*layers)

    def forward(self, state: torch.Tensor) -> torch.Tensor:
        """Return action logits."""
        return self.network(state)

    def get_distribution(self, state: torch.Tensor) -> Categorical:
        """Get action probability distribution."""
        logits = self.forward(state)
        return Categorical(logits=logits)

    def get_action(
        self, state: torch.Tensor, deterministic: bool = False
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Sample action from policy.

        Returns:
            action: Selected action index.
            log_prob: Log probability of the selected action.
        """
        dist = self.get_distribution(state)
        if deterministic:
            action = dist.probs.argmax(dim=-1)
        else:
            action = dist.sample()
        log_prob = dist.log_prob(action)
        return action, log_prob

    def evaluate_actions(
        self, states: torch.Tensor, actions: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Evaluate log-probs and entropy for given state-action pairs.

        Returns:
            log_probs, entropy
        """
        dist = self.get_distribution(states)
        log_probs = dist.log_prob(actions)
        entropy = dist.entropy()
        return log_probs, entropy


class ValueNetwork(nn.Module):
    """
    Value network for estimating reward values.

    Used by CPO for computing advantages.
    """

    def __init__(
        self,
        state_dim: int = 55,
        hidden_dims: list = None,
    ):
        super().__init__()
        if hidden_dims is None:
            hidden_dims = [256, 128]

        layers = []
        prev_dim = state_dim
        for h_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.ReLU(inplace=True),
            ])
            prev_dim = h_dim
        layers.append(nn.Linear(prev_dim, 1))
        self.network = nn.Sequential(*layers)

    def forward(self, state: torch.Tensor) -> torch.Tensor:
        """Return scalar value estimate."""
        return self.network(state).squeeze(-1)


class CostValueNetwork(nn.Module):
    """
    Cost value network for estimating cumulative false-positive cost.

    Separate from the reward value network to enable independent
    constraint margin estimation for CPO.
    """

    def __init__(
        self,
        state_dim: int = 55,
        hidden_dims: list = None,
    ):
        super().__init__()
        if hidden_dims is None:
            hidden_dims = [256, 128]

        layers = []
        prev_dim = state_dim
        for h_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.ReLU(inplace=True),
            ])
            prev_dim = h_dim
        layers.append(nn.Linear(prev_dim, 1))
        self.network = nn.Sequential(*layers)

    def forward(self, state: torch.Tensor) -> torch.Tensor:
        """Return scalar cost value estimate."""
        return self.network(state).squeeze(-1)
