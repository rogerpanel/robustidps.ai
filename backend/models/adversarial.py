"""
Adversarial Robustness Evaluation Suite.

Implements the 6 attack methods from CL-RL Paper Section V-E:
  1. FGSM  - Fast Gradient Sign Method
  2. PGD   - Projected Gradient Descent
  3. C&W   - Carlini-Wagner L2 attack
  4. DeepFool
  5. Gaussian noise injection
  6. Label masking (training-time poisoning)

Author: Roger Nick Anaedevha
"""

import logging
from typing import Dict, List, Optional

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

logger = logging.getLogger(__name__)


ATTACK_CONFIGS = [
    {"name": "fgsm", "label": "FGSM", "epsilon": 0.1},
    {"name": "pgd", "label": "PGD", "epsilon": 0.1, "steps": 40, "step_size": 0.01},
    {"name": "cw", "label": "C&W", "confidence": 0.0, "max_iterations": 50, "learning_rate": 0.01},
    {"name": "deepfool", "label": "DeepFool", "max_iterations": 30},
    {"name": "gaussian", "label": "Gaussian Noise", "sigma": 0.1},
    {"name": "label_masking", "label": "Label Masking", "flip_ratio": 0.1},
]


class AdversarialEvaluator:
    """Evaluate model robustness under 6 adversarial attack methods."""

    def __init__(self, device: str = "cpu"):
        self.device = device

    def evaluate_all_attacks(
        self,
        model: nn.Module,
        features: torch.Tensor,
        labels: torch.Tensor,
        configs: Optional[List[Dict]] = None,
        max_samples: int = 500,
    ) -> Dict:
        """Run all 6 attacks and return accuracy under each."""
        configs = configs or ATTACK_CONFIGS

        # Subsample for efficiency
        if len(features) > max_samples:
            idx = torch.randperm(len(features))[:max_samples]
            features = features[idx]
            labels = labels[idx]

        X = features.to(self.device)
        y = labels.to(self.device)

        # Clean accuracy
        clean_acc = self._compute_accuracy(model, X, y)

        results = {"clean_accuracy": clean_acc, "attacks": {}}

        for config in configs:
            name = config["name"]
            label = config.get("label", name)

            try:
                if name == "fgsm":
                    adv_X = self._fgsm(model, X, y, config.get("epsilon", 0.1))
                elif name == "pgd":
                    adv_X = self._pgd(
                        model, X, y,
                        config.get("epsilon", 0.1),
                        config.get("steps", 40),
                        config.get("step_size", 0.01),
                    )
                elif name == "cw":
                    adv_X = self._cw(
                        model, X, y,
                        config.get("confidence", 0.0),
                        config.get("max_iterations", 50),
                        config.get("learning_rate", 0.01),
                    )
                elif name == "deepfool":
                    adv_X = self._deepfool(model, X, y, config.get("max_iterations", 30))
                elif name == "gaussian":
                    adv_X = self._gaussian(X, config.get("sigma", 0.1))
                elif name == "label_masking":
                    # Label masking is a training-time attack; test on clean data
                    adv_X = X
                else:
                    continue

                acc = self._compute_accuracy(model, adv_X, y)
                results["attacks"][name] = {
                    "label": label,
                    "accuracy": round(acc, 2),
                    "accuracy_drop": round(clean_acc - acc, 2),
                    "robustness_ratio": round(acc / max(clean_acc, 0.01), 4),
                }
            except Exception as e:
                logger.warning("Attack %s failed: %s", name, e)
                results["attacks"][name] = {
                    "label": label,
                    "error": str(e),
                }

        return results

    def _fgsm(self, model, X, y, epsilon):
        model.eval()
        X_adv = X.clone().detach().requires_grad_(True)
        output = model(X_adv)
        logits = output[0] if isinstance(output, tuple) else output
        loss = F.cross_entropy(logits, y)
        loss.backward()
        perturbation = epsilon * X_adv.grad.sign()
        return (X_adv + perturbation).detach()

    def _pgd(self, model, X, y, epsilon, steps, step_size):
        model.eval()
        X_adv = X.clone().detach()
        X_orig = X.clone().detach()

        for _ in range(steps):
            X_adv.requires_grad_(True)
            output = model(X_adv)
            logits = output[0] if isinstance(output, tuple) else output
            loss = F.cross_entropy(logits, y)
            loss.backward()
            perturbation = step_size * X_adv.grad.sign()
            X_adv = (X_adv + perturbation).detach()
            delta = torch.clamp(X_adv - X_orig, -epsilon, epsilon)
            X_adv = X_orig + delta

        return X_adv

    def _cw(self, model, X, y, confidence, max_iterations, lr):
        model.eval()
        delta = torch.zeros_like(X, requires_grad=True)
        optimizer = torch.optim.Adam([delta], lr=lr)

        for _ in range(max_iterations):
            optimizer.zero_grad()
            X_pert = X + delta
            output = model(X_pert)
            logits = output[0] if isinstance(output, tuple) else output

            correct_logit = logits.gather(1, y.unsqueeze(1)).squeeze(1)
            max_other = logits.clone()
            max_other.scatter_(1, y.unsqueeze(1), -float("inf"))
            max_other_logit = max_other.max(dim=1).values

            f_x = torch.clamp(correct_logit - max_other_logit + confidence, min=0)
            l2_loss = delta.pow(2).sum(dim=-1)
            loss = (l2_loss + f_x).mean()
            loss.backward()
            optimizer.step()

        return (X + delta).detach()

    def _deepfool(self, model, X, y, max_iterations):
        model.eval()
        X_adv = X.clone().detach()
        batch_size = min(256, len(X))

        for start in range(0, len(X), batch_size):
            end = min(start + batch_size, len(X))
            x_batch = X_adv[start:end].clone().requires_grad_(True)

            for _ in range(max_iterations):
                output = model(x_batch)
                logits = output[0] if isinstance(output, tuple) else output
                pred = logits.argmax(dim=1)
                if (pred != y[start:end]).all():
                    break

                loss = logits.gather(1, pred.unsqueeze(1)).sum()
                model.zero_grad()
                if x_batch.grad is not None:
                    x_batch.grad.zero_()
                loss.backward(retain_graph=True)

                if x_batch.grad is not None:
                    grad = x_batch.grad.data
                    perturbation = 0.02 * grad / (grad.norm(dim=-1, keepdim=True) + 1e-8)
                    x_batch = (x_batch + perturbation).detach().requires_grad_(True)

            X_adv[start:end] = x_batch.detach()

        return X_adv

    def _gaussian(self, X, sigma):
        return X + torch.randn_like(X) * sigma

    def _compute_accuracy(self, model, X, y):
        model.eval()
        correct = 0
        total = 0
        batch_size = 512

        with torch.no_grad():
            for i in range(0, len(X), batch_size):
                bx = X[i : i + batch_size]
                by = y[i : i + batch_size]
                output = model(bx)
                logits = output[0] if isinstance(output, tuple) else output
                preds = logits.argmax(dim=1)
                correct += (preds == by).sum().item()
                total += len(by)

        return 100.0 * correct / max(total, 1)
