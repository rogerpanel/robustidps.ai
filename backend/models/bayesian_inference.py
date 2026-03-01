"""
Bayesian Uncertainty Quantification
=====================================

Bayesian deep learning for epistemic uncertainty quantification
in intrusion detection.

Key Features:
- Structured variational inference
- Monte Carlo dropout
- PAC-Bayesian bounds
- Uncertainty-aware predictions
- Calibration techniques

Based on: Paper 6 - Bayesian Inference for IDS

Author: Roger Nick Anaedevha
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple, Optional
import math


class BayesianLinear(nn.Module):
    """
    Bayesian linear layer with variational inference

    Learns distributions over weights rather than point estimates.
    """

    def __init__(
        self,
        in_features: int,
        out_features: int,
        prior_scale: float = 1.0
    ):
        super().__init__()

        self.in_features = in_features
        self.out_features = out_features
        self.prior_scale = prior_scale

        # Weight mean and log variance
        self.weight_mean = nn.Parameter(
            torch.randn(out_features, in_features) * 0.01
        )
        self.weight_logvar = nn.Parameter(
            torch.randn(out_features, in_features) * 0.01 - 5.0
        )

        # Bias mean and log variance
        self.bias_mean = nn.Parameter(torch.zeros(out_features))
        self.bias_logvar = nn.Parameter(torch.zeros(out_features) - 5.0)

        # Prior parameters (Gaussian)
        self.register_buffer('prior_mean', torch.zeros(1))
        self.register_buffer('prior_logvar', torch.ones(1) * math.log(prior_scale ** 2))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass with reparameterization trick

        Args:
            x: Input [batch_size, in_features]

        Returns:
            Output [batch_size, out_features]
        """
        if self.training:
            # Sample weights using reparameterization
            weight_std = torch.exp(0.5 * self.weight_logvar)
            weight_eps = torch.randn_like(self.weight_mean)
            weight = self.weight_mean + weight_eps * weight_std

            bias_std = torch.exp(0.5 * self.bias_logvar)
            bias_eps = torch.randn_like(self.bias_mean)
            bias = self.bias_mean + bias_eps * bias_std
        else:
            # Use mean weights for inference
            weight = self.weight_mean
            bias = self.bias_mean

        return F.linear(x, weight, bias)

    def kl_divergence(self) -> torch.Tensor:
        """
        Compute KL divergence between posterior and prior

        KL(q(w) || p(w))
        """
        # Weight KL
        weight_kl = -0.5 * torch.sum(
            1 + self.weight_logvar - self.prior_logvar
            - ((self.weight_mean - self.prior_mean) ** 2 + torch.exp(self.weight_logvar))
            / torch.exp(self.prior_logvar)
        )

        # Bias KL
        bias_kl = -0.5 * torch.sum(
            1 + self.bias_logvar - self.prior_logvar
            - ((self.bias_mean - self.prior_mean) ** 2 + torch.exp(self.bias_logvar))
            / torch.exp(self.prior_logvar)
        )

        return weight_kl + bias_kl


class MCDropout(nn.Module):
    """Monte Carlo Dropout for uncertainty estimation"""

    def __init__(self, p: float = 0.5):
        super().__init__()
        self.p = p

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Apply dropout even during inference for MC sampling"""
        return F.dropout(x, p=self.p, training=True)


class TemperatureScaling(nn.Module):
    """
    Temperature scaling for confidence calibration

    Post-processing method to calibrate model predictions.
    """

    def __init__(self):
        super().__init__()
        self.temperature = nn.Parameter(torch.ones(1))

    def forward(self, logits: torch.Tensor) -> torch.Tensor:
        """
        Scale logits by learned temperature

        Args:
            logits: Model logits [batch_size, num_classes]

        Returns:
            Calibrated logits
        """
        return logits / self.temperature

    def fit(
        self,
        logits: torch.Tensor,
        labels: torch.Tensor,
        num_iterations: int = 50
    ):
        """
        Fit temperature parameter on validation set

        Args:
            logits: Validation logits
            labels: True labels
            num_iterations: Number of optimization steps
        """
        optimizer = torch.optim.LBFGS([self.temperature], lr=0.01, max_iter=num_iterations)

        def eval_loss():
            loss = F.cross_entropy(self(logits), labels)
            loss.backward()
            return loss

        optimizer.step(eval_loss)


class StructuredVariationalInference(nn.Module):
    """
    Structured variational inference layer

    Efficient Bayesian inference with structured approximations.
    """

    def __init__(
        self,
        in_features: int,
        out_features: int,
        num_mc_samples: int = 10
    ):
        super().__init__()

        self.num_mc_samples = num_mc_samples

        # Mean function
        self.mean_layer = nn.Linear(in_features, out_features)

        # Log variance function
        self.logvar_layer = nn.Linear(in_features, out_features)

    def forward(
        self,
        x: torch.Tensor,
        return_uncertainty: bool = False
    ) -> Tuple[torch.Tensor, Optional[torch.Tensor]]:
        """
        Args:
            x: Input [batch_size, in_features]
            return_uncertainty: Whether to compute uncertainty

        Returns:
            (mean_output, uncertainty) if return_uncertainty else mean_output
        """
        mean = self.mean_layer(x)

        if not return_uncertainty:
            return mean, None

        # Compute variance
        logvar = self.logvar_layer(x)
        var = torch.exp(logvar)

        return mean, var


class BayesianUncertaintyNet(nn.Module):
    """
    Complete Bayesian neural network with uncertainty quantification

    Uses variational inference for epistemic uncertainty
    and calibration for aleatoric uncertainty.
    """

    def __init__(
        self,
        input_dim: int = 64,
        hidden_dims: list = [256, 128, 64],
        num_classes: int = 13,
        num_mc_samples: int = 10,
        prior_scale: float = 1.0,
        kl_weight: float = 0.01,
        enable_calibration: bool = True
    ):
        super().__init__()

        self.num_mc_samples = num_mc_samples
        self.kl_weight = kl_weight
        self.enable_calibration = enable_calibration

        # Bayesian layers
        self.bayesian_layers = nn.ModuleList()

        dims = [input_dim] + hidden_dims
        for i in range(len(dims) - 1):
            self.bayesian_layers.append(
                BayesianLinear(dims[i], dims[i + 1], prior_scale)
            )

        # Output layers
        self.output_mean = nn.Linear(hidden_dims[-1], num_classes)
        self.output_logvar = nn.Linear(hidden_dims[-1], num_classes)

        # Binary classification head
        self.binary_mean = nn.Linear(hidden_dims[-1], 1)
        self.binary_logvar = nn.Linear(hidden_dims[-1], 1)

        # MC Dropout
        self.mc_dropout = MCDropout(p=0.5)

        # Temperature scaling for calibration
        if enable_calibration:
            self.temperature_scaling = TemperatureScaling()

    def forward_single(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        """Single forward pass"""
        h = x

        # Bayesian layers with activations
        for layer in self.bayesian_layers:
            h = layer(h)
            h = F.relu(h)
            h = self.mc_dropout(h)

        # Output predictions
        multiclass_mean = self.output_mean(h)
        multiclass_logvar = self.output_logvar(h)

        binary_mean = self.binary_mean(h)
        binary_logvar = self.binary_logvar(h)

        return binary_mean, binary_logvar, multiclass_mean, multiclass_logvar

    def forward(
        self,
        x: torch.Tensor,
        return_uncertainty: bool = True
    ) -> dict:
        """
        Forward pass with uncertainty quantification

        Args:
            x: Input [batch_size, input_dim]
            return_uncertainty: Whether to estimate uncertainty via MC sampling

        Returns:
            Dictionary with predictions and uncertainties
        """
        if not return_uncertainty or not self.training:
            # Single forward pass
            binary_mean, binary_logvar, multiclass_mean, multiclass_logvar = self.forward_single(x)

            # Apply temperature scaling if enabled
            if self.enable_calibration and hasattr(self, 'temperature_scaling'):
                multiclass_mean = self.temperature_scaling(multiclass_mean)

            return {
                'binary_mean': binary_mean,
                'multiclass_mean': multiclass_mean,
                'binary_uncertainty': torch.exp(binary_logvar),
                'multiclass_uncertainty': torch.exp(multiclass_logvar)
            }

        # Monte Carlo sampling for uncertainty estimation
        binary_samples = []
        multiclass_samples = []

        for _ in range(self.num_mc_samples):
            binary_mean, _, multiclass_mean, _ = self.forward_single(x)
            binary_samples.append(binary_mean)
            multiclass_samples.append(multiclass_mean)

        # Stack samples
        binary_samples = torch.stack(binary_samples)  # [num_samples, batch_size, 1]
        multiclass_samples = torch.stack(multiclass_samples)  # [num_samples, batch_size, num_classes]

        # Compute mean and variance
        binary_pred = binary_samples.mean(0)
        binary_uncertainty = binary_samples.var(0)

        multiclass_pred = multiclass_samples.mean(0)
        multiclass_uncertainty = multiclass_samples.var(0)

        # Apply calibration
        if self.enable_calibration:
            multiclass_pred = self.temperature_scaling(multiclass_pred)

        return {
            'binary_mean': binary_pred,
            'multiclass_mean': multiclass_pred,
            'binary_uncertainty': binary_uncertainty,
            'multiclass_uncertainty': multiclass_uncertainty,
            'binary_samples': binary_samples,
            'multiclass_samples': multiclass_samples
        }

    def compute_kl_loss(self) -> torch.Tensor:
        """Compute total KL divergence for ELBO"""
        kl_loss = 0.0
        for layer in self.bayesian_layers:
            if isinstance(layer, BayesianLinear):
                kl_loss += layer.kl_divergence()
        return kl_loss * self.kl_weight

    def pac_bayes_bound(
        self,
        train_loss: torch.Tensor,
        num_samples: int,
        delta: float = 0.05
    ) -> torch.Tensor:
        """
        Compute PAC-Bayesian generalization bound

        Args:
            train_loss: Training loss
            num_samples: Number of training samples
            delta: Confidence parameter

        Returns:
            Upper bound on expected risk
        """
        kl = self.compute_kl_loss()
        bound = train_loss + torch.sqrt(
            (kl + math.log(2 * math.sqrt(num_samples) / delta)) / (2 * num_samples)
        )
        return bound


# Example usage
if __name__ == "__main__":
    # Initialize model
    model = BayesianUncertaintyNet(
        input_dim=64,
        hidden_dims=[256, 128, 64],
        num_classes=13,
        num_mc_samples=10,
        enable_calibration=True
    )

    # Sample input
    batch_size = 32
    x = torch.randn(batch_size, 64)

    # Forward pass with uncertainty
    model.train()
    output = model(x, return_uncertainty=True)

    print("Predictions with uncertainty:")
    print(f"Binary mean shape: {output['binary_mean'].shape}")
    print(f"Binary uncertainty: {output['binary_uncertainty'].mean().item():.4f}")
    print(f"Multiclass mean shape: {output['multiclass_mean'].shape}")
    print(f"Multiclass uncertainty (avg): {output['multiclass_uncertainty'].mean().item():.4f}")

    # Compute KL loss for ELBO
    kl_loss = model.compute_kl_loss()
    print(f"\nKL divergence: {kl_loss.item():.4f}")

    # PAC-Bayes bound
    train_loss = torch.tensor(0.5)
    bound = model.pac_bayes_bound(train_loss, num_samples=10000)
    print(f"PAC-Bayes bound: {bound.item():.4f}")
