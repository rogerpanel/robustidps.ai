"""
CL-RL Evaluation Metrics.

Implements metrics from CL-RL Paper Section III and V:
  - Average Accuracy (AA)
  - Backward Transfer (BWT)
  - Forward Transfer (FWT)
  - RL: Threat Mitigation Rate, FP Blocking Rate, Constraint Violations

Author: Roger Nick Anaedevha
"""

import numpy as np
from typing import Dict, List, Optional


class ContinualMetrics:
    """
    Compute continual learning evaluation metrics.

    Tracks accuracy matrix a_{T,t} where a_{T,t} is accuracy on task t
    after training through task T.

    Equations 1-3:
      AA  = (1/T) * sum a_{T,t}
      BWT = (1/(T-1)) * sum (a_{T,t} - a_{t,t})
      FWT = (1/(T-1)) * sum (a_{t,t} - a_tilde_t)
    """

    def __init__(self):
        self.accuracy_matrix: Dict[int, Dict[int, float]] = {}
        self.random_baselines: Dict[int, float] = {}

    def record_accuracy(
        self, training_task: int, eval_task: int, accuracy: float
    ) -> None:
        if training_task not in self.accuracy_matrix:
            self.accuracy_matrix[training_task] = {}
        self.accuracy_matrix[training_task][eval_task] = accuracy

    def set_random_baseline(self, task: int, accuracy: float) -> None:
        self.random_baselines[task] = accuracy

    def compute_average_accuracy(self) -> float:
        if not self.accuracy_matrix:
            return 0.0
        T = max(self.accuracy_matrix.keys())
        final_accs = self.accuracy_matrix.get(T, {})
        if not final_accs:
            return 0.0
        return float(np.mean(list(final_accs.values())))

    def compute_backward_transfer(self) -> float:
        if len(self.accuracy_matrix) < 2:
            return 0.0
        T = max(self.accuracy_matrix.keys())
        bwt_values = []
        for t in range(1, T):
            if (
                T in self.accuracy_matrix
                and t in self.accuracy_matrix[T]
                and t in self.accuracy_matrix
                and t in self.accuracy_matrix[t]
            ):
                a_Tt = self.accuracy_matrix[T][t]
                a_tt = self.accuracy_matrix[t][t]
                bwt_values.append(a_Tt - a_tt)
        return float(np.mean(bwt_values)) if bwt_values else 0.0

    def compute_forward_transfer(self) -> float:
        if len(self.accuracy_matrix) < 2:
            return 0.0
        T = max(self.accuracy_matrix.keys())
        fwt_values = []
        for t in range(2, T + 1):
            if (
                t in self.accuracy_matrix
                and t in self.accuracy_matrix[t]
                and t in self.random_baselines
            ):
                a_tt = self.accuracy_matrix[t][t]
                a_tilde = self.random_baselines[t]
                fwt_values.append(a_tt - a_tilde)
        return float(np.mean(fwt_values)) if fwt_values else 0.0

    def compute_all_metrics(self) -> Dict[str, float]:
        return {
            "average_accuracy": round(self.compute_average_accuracy(), 4),
            "backward_transfer": round(self.compute_backward_transfer(), 4),
            "forward_transfer": round(self.compute_forward_transfer(), 4),
        }

    def get_accuracy_matrix(self) -> Dict:
        return dict(self.accuracy_matrix)


class RLMetrics:
    """
    RL response agent evaluation metrics.

    From Section V-B:
      - Threat Mitigation Rate (%)
      - False-Positive Blocking Rate (%)
      - Mean Time To Respond (ms)
      - Safety Constraint Violations (count)
    """

    def __init__(self):
        self.episode_stats: List[Dict] = []

    def record_episode(self, stats: Dict) -> None:
        self.episode_stats.append(stats)

    def compute_summary(self) -> Dict[str, float]:
        if not self.episode_stats:
            return {}

        n = len(self.episode_stats)
        mitigation_rates = [s.get("mitigation_rate", 0) for s in self.episode_stats]
        fp_rates = [s.get("fp_blocking_rate", 0) for s in self.episode_stats]
        rewards = [s.get("mean_reward", 0) for s in self.episode_stats]
        violations = sum(1 for s in self.episode_stats if s.get("constraint_violated", False))

        return {
            "mitigation_rate": round(float(np.mean(mitigation_rates)), 4),
            "fp_blocking_rate": round(float(np.mean(fp_rates)), 6),
            "mean_reward": round(float(np.mean(rewards)), 4),
            "constraint_violations": violations,
            "total_episodes": n,
            "violation_rate": round(violations / n, 4),
        }

    def reset(self):
        self.episode_stats = []


class DriftDetector:
    """
    KL-Divergence Drift Detector.

    Monitors class-marginal distribution shift between validation set
    predictions and incoming batches.

    Three operational regimes:
      - Stable:  D_KL < tau_1 = 0.05
      - Monitor: tau_1 <= D_KL < tau_2
      - Drift:   D_KL >= tau_2 = 0.15
    """

    def __init__(
        self,
        num_classes: int = 34,
        tau_1: float = 0.05,
        tau_2: float = 0.15,
        smoothing: float = 1e-8,
    ):
        self.num_classes = num_classes
        self.tau_1 = tau_1
        self.tau_2 = tau_2
        self.smoothing = smoothing
        self.reference_distribution: Optional[np.ndarray] = None
        self.drift_history: list = []

    def set_reference_from_predictions(self, predictions: np.ndarray) -> np.ndarray:
        """Set reference distribution from model predictions."""
        self.reference_distribution = self._compute_marginal(predictions)
        return self.reference_distribution

    def check_drift(self, new_predictions: np.ndarray) -> Dict:
        """Check for distribution drift in new predictions."""
        if self.reference_distribution is None:
            return {"status": "stable", "kl_divergence": 0.0}

        new_dist = self._compute_marginal(new_predictions)
        kl_div = self._kl_divergence(self.reference_distribution, new_dist)

        if kl_div < self.tau_1:
            status = "stable"
        elif kl_div < self.tau_2:
            status = "monitor"
        else:
            status = "drift"

        entry = {
            "kl_divergence": round(float(kl_div), 6),
            "status": status,
            "num_samples": len(new_predictions),
        }
        self.drift_history.append(entry)
        return entry

    def get_drift_summary(self) -> Dict:
        if not self.drift_history:
            return {"total_checks": 0}

        kl_values = [h["kl_divergence"] for h in self.drift_history]
        statuses = [h["status"] for h in self.drift_history]

        return {
            "total_checks": len(self.drift_history),
            "mean_kl": round(float(np.mean(kl_values)), 6),
            "max_kl": round(float(np.max(kl_values)), 6),
            "drift_count": statuses.count("drift"),
            "monitor_count": statuses.count("monitor"),
            "stable_count": statuses.count("stable"),
            "tau_1": self.tau_1,
            "tau_2": self.tau_2,
        }

    def _compute_marginal(self, predictions: np.ndarray) -> np.ndarray:
        counts = np.bincount(predictions.astype(int), minlength=self.num_classes)
        return (counts + self.smoothing) / (counts.sum() + self.smoothing * self.num_classes)

    def _kl_divergence(self, p: np.ndarray, q: np.ndarray) -> float:
        p = np.clip(p, self.smoothing, None)
        q = np.clip(q, self.smoothing, None)
        p = p / p.sum()
        q = q / q.sum()
        return float(np.sum(p * np.log(p / q)))
