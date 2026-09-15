"""
CMDP Environment for Autonomous Network Intrusion Response.

Implements the Constrained Markov Decision Process from CL-RL Paper Section IV-B:
  - State space: 55-dimensional vector (detection probs + uncertainty + metadata)
  - Action space: 5 graduated response levels
  - Reward: R(s,a) = w_det * 1[mitigated] - w_fp * 1[benign blocked] - w_sev * sev(a)
  - Constraint: J_C(pi) = E[sum gamma^t * 1[benign blocked at t]] <= eps_fp

Action Space:
  0: Monitor     - Log event, no network intervention (severity 0)
  1: RateLimit   - Throttle traffic from source IP (severity 0.5)
  2: Reset       - Send TCP RST to terminate connection (severity 1)
  3: Block       - Inject iptables DROP rule (severity 2)
  4: Quarantine  - Isolate source IP from internal segments (severity 5)

Author: Roger Nick Anaedevha
"""

import numpy as np
from typing import Dict, Optional, Tuple

ACTION_NAMES = ["Monitor", "RateLimit", "Reset", "Block", "Quarantine"]
ACTION_SEVERITY = np.array([0.0, 0.5, 1.0, 2.0, 5.0])


class NIDSResponseEnv:
    """
    Simulated CMDP environment for the RL response agent.

    Replays traffic from captured datasets, providing the RL agent with
    detection outputs and metadata, and evaluating response actions
    against ground truth labels.
    """

    def __init__(
        self,
        features: np.ndarray,
        labels: np.ndarray,
        detection_probs: Optional[np.ndarray] = None,
        epistemic_uncertainty: Optional[np.ndarray] = None,
        aleatoric_uncertainty: Optional[np.ndarray] = None,
        config: Optional[dict] = None,
    ):
        self.features = features
        self.labels = labels
        self.n_samples = len(labels)
        self.is_attack = (labels > 0).astype(np.float32)

        if detection_probs is not None:
            self.detection_probs = detection_probs
        else:
            num_classes = max(int(labels.max()) + 1, 34)
            self.detection_probs = self._simulate_detection_probs(
                labels, num_classes
            )

        self.epistemic = (
            epistemic_uncertainty
            if epistemic_uncertainty is not None
            else np.random.exponential(0.1, self.n_samples).astype(np.float32)
        )
        self.aleatoric = (
            aleatoric_uncertainty
            if aleatoric_uncertainty is not None
            else np.random.exponential(0.05, self.n_samples).astype(np.float32)
        )

        cfg = config or {}
        reward_cfg = cfg.get("reward", {})
        constraint_cfg = cfg.get("constraints", {})

        self.w_det = reward_cfg.get("w_det", 10.0)
        self.w_fp = reward_cfg.get("w_fp", 50.0)
        self.w_sev = np.array(reward_cfg.get("w_sev", [0, 0.5, 1, 2, 5]))
        self.epsilon_fp = constraint_cfg.get("epsilon_fp", 0.001)
        self.block_confidence_threshold = constraint_cfg.get(
            "block_confidence_threshold", 0.95
        )
        self.gamma = cfg.get("training", {}).get("discount_gamma", 0.99)

        # Episode state
        self.current_idx = 0
        self.episode_length = min(1000, self.n_samples)
        self.cumulative_cost = 0.0
        self.episode_rewards = []
        self.episode_costs = []
        self.blocks_in_window = 0
        self.step_count = 0

    def reset(self) -> np.ndarray:
        """Reset environment for a new episode."""
        self.current_idx = np.random.randint(
            0, max(1, self.n_samples - self.episode_length)
        )
        self.cumulative_cost = 0.0
        self.episode_rewards = []
        self.episode_costs = []
        self.blocks_in_window = 0
        self.step_count = 0
        return self._get_state()

    def step(
        self, action: int
    ) -> Tuple[np.ndarray, float, float, bool, Dict]:
        """Execute response action and return (state, reward, cost, done, info)."""
        idx = self.current_idx
        is_attack = bool(self.is_attack[idx])
        action = int(action)

        # Hard constraint: Block/Quarantine require high confidence
        max_prob = float(self.detection_probs[idx].max())
        if action >= 3 and max_prob < self.block_confidence_threshold:
            action = min(action, 2)

        if action >= 3:
            self.blocks_in_window += 1

        # Compute reward (Equation 9)
        threat_mitigated = is_attack and action >= 1
        benign_blocked = (not is_attack) and action >= 3

        reward = 0.0
        if threat_mitigated:
            reward += self.w_det
        if benign_blocked:
            reward -= self.w_fp
        reward -= self.w_sev[action]

        # Cost (Equation 10)
        cost = 1.0 if benign_blocked else 0.0
        self.cumulative_cost += cost
        self.episode_rewards.append(reward)
        self.episode_costs.append(cost)

        # Advance
        self.current_idx += 1
        self.step_count += 1
        done = (
            self.step_count >= self.episode_length
            or self.current_idx >= self.n_samples
        )

        info = {
            "is_attack": is_attack,
            "action_name": ACTION_NAMES[action],
            "action_severity": float(ACTION_SEVERITY[action]),
            "threat_mitigated": threat_mitigated,
            "benign_blocked": benign_blocked,
            "cumulative_cost": self.cumulative_cost,
            "detection_confidence": max_prob,
        }

        next_state = self._get_state() if not done else np.zeros(55, dtype=np.float32)
        return next_state, reward, cost, done, info

    def _get_state(self) -> np.ndarray:
        """Construct the 55-dimensional state vector."""
        idx = self.current_idx
        if idx >= self.n_samples:
            return np.zeros(55, dtype=np.float32)

        components = []

        # Detection probabilities (pad/truncate to 34)
        probs = self.detection_probs[idx]
        if len(probs) < 34:
            probs = np.pad(probs, (0, 34 - len(probs)))
        elif len(probs) > 34:
            probs = probs[:34]
        components.append(probs)

        # Uncertainty (2 dims)
        components.append(
            np.array([self.epistemic[idx], self.aleatoric[idx]], dtype=np.float32)
        )

        # Flow metadata (13 dims)
        flow_feat = (
            self.features[idx][:13]
            if len(self.features[idx]) >= 13
            else np.zeros(13, dtype=np.float32)
        )
        components.append(flow_feat.astype(np.float32))

        # Context features (4 dims)
        context = np.array([
            np.random.uniform(0, 1),
            min(self.step_count / 100.0, 1.0),
            np.random.uniform(0.1, 0.9),
            np.random.uniform(0.2, 0.8),
        ], dtype=np.float32)
        components.append(context)

        # Pad/truncate to 55
        state = np.concatenate(components)
        if len(state) < 55:
            state = np.pad(state, (0, 55 - len(state)))
        elif len(state) > 55:
            state = state[:55]

        return state.astype(np.float32)

    def _simulate_detection_probs(
        self, labels: np.ndarray, num_classes: int
    ) -> np.ndarray:
        """Simulate realistic detection probabilities from ground truth."""
        probs = np.zeros((len(labels), num_classes), dtype=np.float32)
        for i, label in enumerate(labels):
            label = int(label)
            probs[i, label] = np.random.uniform(0.7, 0.99)
            remaining = 1.0 - probs[i, label]
            noise = np.random.dirichlet(np.ones(num_classes - 1)) * remaining
            other_idx = [j for j in range(num_classes) if j != label]
            for j, oi in enumerate(other_idx):
                probs[i, oi] = noise[j]
        return probs

    def get_episode_stats(self) -> Dict:
        """Get statistics for the completed episode."""
        total_steps = len(self.episode_rewards)
        if total_steps == 0:
            return {}

        return {
            "total_reward": sum(self.episode_rewards),
            "total_cost": sum(self.episode_costs),
            "mean_reward": float(np.mean(self.episode_rewards)),
            "fp_blocking_rate": sum(self.episode_costs) / total_steps,
            "constraint_violated": (
                sum(self.episode_costs) / total_steps > self.epsilon_fp
            ),
            "num_steps": total_steps,
        }
