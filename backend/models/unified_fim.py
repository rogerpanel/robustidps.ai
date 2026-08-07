"""
Unified Fisher Information Framework.

Implements CL-RL Paper Section IV-C (Equation 12):

  F_hat_k^unified = beta * F_hat_k^det + (1-beta) * [F_pi]_kk

Where:
  - F_hat_k^det: Detection-side FIM from EWC
  - [F_pi]_kk: Policy-side FIM
  - beta = 0.7: Balances detection preservation vs policy plasticity

Author: Roger Nick Anaedevha
"""

import logging
from typing import Dict, Optional

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader

logger = logging.getLogger(__name__)


class UnifiedFIM:
    """
    Unified Fisher Information Matrix computation.

    Combines detection-side and policy-side Fisher information
    for shared layers, enabling:
      1. EWC knowledge preservation (detection)
      2. Trust-region constraint satisfaction (CPO)
    through a single shared computation.

    Args:
        beta: Mixing coefficient (0.7 = prioritise detection). Eq. 12.
    """

    def __init__(self, beta: float = 0.7):
        self.beta = beta
        self.unified_fisher: Dict[str, torch.Tensor] = {}
        self.detection_fisher: Dict[str, torch.Tensor] = {}
        self.policy_fisher: Dict[str, torch.Tensor] = {}

    def compute_detection_fisher(
        self,
        model: nn.Module,
        dataloader: DataLoader,
        device: str,
        shared_param_names: Optional[list] = None,
    ) -> Dict[str, torch.Tensor]:
        """
        Compute detection-side FIM F_hat^det.

        F_k^det = (1/|D|) * sum (d log p(y|x) / d theta_k)^2
        """
        model.eval()
        fisher: Dict[str, torch.Tensor] = {}

        for name, param in model.named_parameters():
            if param.requires_grad:
                if shared_param_names is None or name in shared_param_names:
                    fisher[name] = torch.zeros_like(param.data)

        total_samples = 0
        for features, labels in dataloader:
            features = features.to(device)
            labels = labels.to(device)
            batch_size = features.shape[0]

            model.zero_grad()
            output = model(features)
            logits = output[0] if isinstance(output, tuple) else output
            log_probs = F.log_softmax(logits, dim=-1)
            nll = F.nll_loss(log_probs, labels, reduction="sum")
            nll.backward()

            for name, param in model.named_parameters():
                if name in fisher and param.grad is not None:
                    fisher[name] += param.grad.data.pow(2) * batch_size

            total_samples += batch_size

        for name in fisher:
            fisher[name] /= max(total_samples, 1)

        self.detection_fisher = fisher
        return fisher

    def compute_policy_fisher(
        self,
        policy: nn.Module,
        states: torch.Tensor,
        actions: torch.Tensor,
        device: str,
    ) -> Dict[str, torch.Tensor]:
        """
        Compute policy-side FIM F_pi.

        [F_pi]_ij = E[ (d log pi(a|s) / d theta_i) * (d log pi(a|s) / d theta_j) ]
        """
        policy.eval()
        fisher: Dict[str, torch.Tensor] = {}

        for name, param in policy.named_parameters():
            if param.requires_grad:
                fisher[name] = torch.zeros_like(param.data)

        states = states.to(device)
        actions = actions.to(device)
        batch_size = min(1024, len(states))

        total_samples = 0
        for i in range(0, len(states), batch_size):
            batch_states = states[i : i + batch_size]
            batch_actions = actions[i : i + batch_size]

            policy.zero_grad()
            logits = policy(batch_states)
            log_probs = F.log_softmax(logits, dim=-1)
            selected_log_probs = log_probs.gather(
                1, batch_actions.unsqueeze(1)
            ).squeeze(1)
            loss = -selected_log_probs.sum()
            loss.backward()

            for name, param in policy.named_parameters():
                if name in fisher and param.grad is not None:
                    fisher[name] += param.grad.data.pow(2) * len(batch_states)

            total_samples += len(batch_states)

        for name in fisher:
            fisher[name] /= max(total_samples, 1)

        self.policy_fisher = fisher
        return fisher

    def compute_unified(
        self,
        detection_fisher: Optional[Dict[str, torch.Tensor]] = None,
        policy_fisher: Optional[Dict[str, torch.Tensor]] = None,
    ) -> Dict[str, torch.Tensor]:
        """
        Compute unified FIM: F_hat_k^unified = beta * F_det + (1-beta) * F_pi

        Equation 12 from the paper.
        """
        det_fisher = detection_fisher or self.detection_fisher
        pol_fisher = policy_fisher or self.policy_fisher

        unified = {}
        all_params = set(list(det_fisher.keys()) + list(pol_fisher.keys()))

        for name in all_params:
            if name in det_fisher and name in pol_fisher:
                # Shared layer: Equation 12
                unified[name] = (
                    self.beta * det_fisher[name]
                    + (1 - self.beta) * pol_fisher[name]
                )
            elif name in det_fisher:
                unified[name] = det_fisher[name]
            else:
                unified[name] = pol_fisher[name]

        self.unified_fisher = unified
        logger.info(
            "Unified FIM computed: %d parameters, beta=%.2f",
            len(unified), self.beta,
        )
        return unified

    def get_trust_region_matrix(self) -> Dict[str, torch.Tensor]:
        """Get FIM for CPO trust region computation."""
        if self.unified_fisher:
            return self.unified_fisher
        return self.policy_fisher

    def get_ewc_importance(self) -> Dict[str, torch.Tensor]:
        """Get FIM for EWC knowledge preservation."""
        if self.unified_fisher:
            return self.unified_fisher
        return self.detection_fisher

    def compute_parameter_importance_summary(self) -> Dict:
        """Summarise parameter importance across layers."""
        summary = {}
        fisher = self.unified_fisher or self.detection_fisher

        for name, values in fisher.items():
            summary[name] = {
                "mean": values.mean().item(),
                "max": values.max().item(),
                "std": values.std().item(),
                "nonzero_pct": (values > 1e-8).float().mean().item() * 100,
            }

        return summary

    def get_status(self) -> Dict:
        """Get current FIM status for API responses."""
        return {
            "beta": self.beta,
            "has_detection_fisher": bool(self.detection_fisher),
            "has_policy_fisher": bool(self.policy_fisher),
            "has_unified_fisher": bool(self.unified_fisher),
            "detection_params": len(self.detection_fisher),
            "policy_params": len(self.policy_fisher),
            "unified_params": len(self.unified_fisher),
        }
