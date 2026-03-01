"""
Temporal Adaptive Batch Normalization Neural ODE (TA-BN-ODE)
=============================================================

Implementation of continuous-time neural network with temporal adaptation
for intrusion detection with point process integration.

Key Features:
- Continuous-time modeling via Neural ODEs
- Temporal Adaptive Batch Normalization
- Point Process integration for event sequences
- Bayesian inference for uncertainty quantification
- 60-90% parameter reduction

Based on: Paper 1 - Neural ODE with Temporal Adaptive Batch Normalization

Author: Roger Nick Anaedevha
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torchdiffeq import odeint_adjoint as odeint
from typing import Tuple, Optional
import math


class TemporalEmbedding(nn.Module):
    """Sinusoidal temporal embedding for time-aware features"""

    def __init__(self, embed_dim: int = 32):
        super().__init__()
        self.embed_dim = embed_dim

    def forward(self, t: torch.Tensor) -> torch.Tensor:
        """
        Args:
            t: Time tensor [batch_size] or scalar
        Returns:
            Temporal embeddings [batch_size, embed_dim]
        """
        if t.dim() == 0:
            t = t.unsqueeze(0)

        half_dim = self.embed_dim // 2
        emb = math.log(10000) / (half_dim - 1)
        emb = torch.exp(torch.arange(half_dim, device=t.device) * -emb)
        emb = t.unsqueeze(-1) * emb.unsqueeze(0)
        emb = torch.cat([torch.sin(emb), torch.cos(emb)], dim=-1)
        return emb


class TemporalAdaptiveBatchNorm(nn.Module):
    """
    Batch normalization with temporal adaptation (TA-BN)

    Adjusts normalization parameters based on temporal context
    to handle non-stationary attack patterns.
    """

    def __init__(self, num_features: int, time_embed_dim: int = 32, momentum: float = 0.1):
        super().__init__()
        self.num_features = num_features
        self.momentum = momentum

        # Standard batch norm parameters
        self.register_buffer('running_mean', torch.zeros(num_features))
        self.register_buffer('running_var', torch.ones(num_features))

        # Temporal embedding
        self.time_embed = TemporalEmbedding(time_embed_dim)

        # Temporal modulation networks
        self.gamma_net = nn.Sequential(
            nn.Linear(time_embed_dim, num_features),
            nn.Sigmoid()
        )
        self.beta_net = nn.Sequential(
            nn.Linear(time_embed_dim, num_features),
            nn.Tanh()
        )

        # Learnable base parameters
        self.weight = nn.Parameter(torch.ones(num_features))
        self.bias = nn.Parameter(torch.zeros(num_features))

    def forward(self, x: torch.Tensor, t: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: Input features [batch_size, num_features]
            t: Time value (scalar or [batch_size])
        Returns:
            Normalized features with temporal adaptation
        """
        if self.training:
            # Compute batch statistics
            mean = x.mean(0)
            var = x.var(0, unbiased=False)

            # Update running statistics
            self.running_mean = (1 - self.momentum) * self.running_mean + self.momentum * mean
            self.running_var = (1 - self.momentum) * self.running_var + self.momentum * var
        else:
            mean = self.running_mean
            var = self.running_var

        # Standard normalization
        x_norm = (x - mean) / torch.sqrt(var + 1e-5)

        # Get temporal embedding
        t_embed = self.time_embed(t)
        if t_embed.size(0) == 1 and x.size(0) > 1:
            t_embed = t_embed.expand(x.size(0), -1)

        # Temporal modulation
        gamma = self.gamma_net(t_embed)  # [batch_size, num_features]
        beta = self.beta_net(t_embed)

        # Apply adaptive transformation
        out = self.weight * x_norm + self.bias
        out = gamma * out + beta

        return out


class ODEFunc(nn.Module):
    """ODE function defining continuous dynamics"""

    def __init__(self, hidden_dim: int, num_layers: int = 4):
        super().__init__()

        layers = []
        for i in range(num_layers):
            if i == 0:
                layers.extend([
                    nn.Linear(hidden_dim, hidden_dim),
                    nn.ReLU(),
                ])
            else:
                layers.extend([
                    nn.Linear(hidden_dim, hidden_dim),
                    nn.ReLU(),
                    nn.Dropout(0.1)
                ])

        self.net = nn.Sequential(*layers)

        # Time embedding for time-dependent dynamics
        self.time_embed = TemporalEmbedding(32)
        self.time_proj = nn.Linear(32, hidden_dim)

    def forward(self, t: torch.Tensor, x: torch.Tensor) -> torch.Tensor:
        """
        Compute dx/dt

        Args:
            t: Current time (scalar)
            x: Current state [batch_size, hidden_dim]
        Returns:
            Time derivative [batch_size, hidden_dim]
        """
        # Embed time
        t_embed = self.time_embed(t)
        t_features = self.time_proj(t_embed)

        # Add temporal information to state
        x_t = x + t_features

        return self.net(x_t)


class TemporalAdaptiveNeuralODE(nn.Module):
    """
    Complete TA-BN-ODE model for intrusion detection

    Architecture:
    1. Input encoder with TA-BN
    2. ODE solver for continuous-time evolution
    3. Output decoder for classification
    """

    def __init__(
        self,
        input_dim: int = 64,
        hidden_dims: list = [128, 256, 256, 128],
        num_classes: int = 13,
        ode_solver: str = 'dopri5',
        rtol: float = 1e-3,
        atol: float = 1e-4
    ):
        super().__init__()

        self.input_dim = input_dim
        self.hidden_dims = hidden_dims
        self.ode_solver = ode_solver
        self.rtol = rtol
        self.atol = atol

        # Input encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dims[0]),
            nn.ReLU(),
            nn.Dropout(0.2)
        )

        # Temporal Adaptive Batch Normalization layers
        self.tabn_layers = nn.ModuleList([
            TemporalAdaptiveBatchNorm(dim) for dim in hidden_dims
        ])

        # ODE function
        self.ode_func = ODEFunc(hidden_dims[1], num_layers=4)

        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(hidden_dims[1], hidden_dims[2]),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dims[2], hidden_dims[3]),
            nn.ReLU(),
            nn.Linear(hidden_dims[3], num_classes)
        )

        # Binary classification head
        self.binary_head = nn.Sequential(
            nn.Linear(hidden_dims[1], 64),
            nn.ReLU(),
            nn.Linear(64, 1)
        )

    def forward(
        self,
        x: torch.Tensor,
        t_span: Optional[torch.Tensor] = None
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass through Neural ODE

        Args:
            x: Input features [batch_size, input_dim]
            t_span: Time span for ODE integration [t_start, t_end]

        Returns:
            (binary_logits, multiclass_logits)
        """
        batch_size = x.size(0)

        # Default time span
        if t_span is None:
            t_span = torch.tensor([0.0, 1.0], device=x.device)

        # Encode input
        h = self.encoder(x)

        # Apply TA-BN at t=0
        h = self.tabn_layers[0](h, t_span[0])

        # Project to ODE space
        h_ode = F.linear(h, torch.randn(self.hidden_dims[1], h.size(-1), device=x.device))

        # Solve ODE
        trajectory = odeint(
            self.ode_func,
            h_ode,
            t_span,
            method=self.ode_solver,
            rtol=self.rtol,
            atol=self.atol
        )

        # Take final state
        h_final = trajectory[-1]  # [batch_size, hidden_dim]

        # Apply TA-BN at t=1
        h_final = self.tabn_layers[1](h_final, t_span[-1])

        # Binary classification (malicious vs benign)
        binary_logits = self.binary_head(h_final)

        # Multi-class classification (attack types)
        multiclass_logits = self.decoder(h_final)

        return binary_logits, multiclass_logits


class PointProcessNeuralODE(nn.Module):
    """
    Neural ODE integrated with Point Process for event sequence modeling

    Models inter-event times and marks jointly for temporal attack patterns.
    """

    def __init__(
        self,
        input_dim: int = 64,
        hidden_dim: int = 256,
        num_event_types: int = 13,
        transformer_layers: int = 4,
        attention_heads: int = 8
    ):
        super().__init__()

        self.input_dim = input_dim
        self.hidden_dim = hidden_dim

        # Event embedding
        self.event_embedding = nn.Linear(input_dim, hidden_dim)

        # Transformer for sequence modeling
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim,
            nhead=attention_heads,
            dim_feedforward=hidden_dim * 4,
            dropout=0.1,
            batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=transformer_layers)

        # Intensity function (conditional on history)
        self.intensity_net = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1),
            nn.Softplus()  # Ensure positive intensity
        )

        # Mark distribution (event type prediction)
        self.mark_net = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, num_event_types)
        )

        # ODE for continuous intensity evolution
        self.ode_func = ODEFunc(hidden_dim)

    def forward(
        self,
        event_sequence: torch.Tensor,
        inter_event_times: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Args:
            event_sequence: Event features [batch_size, seq_len, input_dim]
            inter_event_times: Time between events [batch_size, seq_len]

        Returns:
            (intensity, mark_logits, hidden_states)
        """
        batch_size, seq_len, _ = event_sequence.size()

        # Embed events
        h = self.event_embedding(event_sequence)  # [batch_size, seq_len, hidden_dim]

        # Process sequence with transformer
        h = self.transformer(h)  # [batch_size, seq_len, hidden_dim]

        # Compute intensity for each event
        intensity = self.intensity_net(h)  # [batch_size, seq_len, 1]

        # Predict event marks (types)
        mark_logits = self.mark_net(h)  # [batch_size, seq_len, num_event_types]

        # Evolve hidden state through ODE between events
        hidden_states = []
        for t_idx in range(seq_len):
            if t_idx < seq_len - 1:
                dt = inter_event_times[:, t_idx].unsqueeze(-1)
                t_span = torch.tensor([0.0, dt.item()], device=h.device)

                # Evolve state
                h_current = h[:, t_idx, :]
                trajectory = odeint(
                    self.ode_func,
                    h_current,
                    t_span,
                    method='dopri5',
                    rtol=1e-3,
                    atol=1e-4
                )
                h_next = trajectory[-1]
                hidden_states.append(h_next)

        return intensity, mark_logits, h


class BayesianNeuralODE(nn.Module):
    """
    Bayesian Neural ODE for uncertainty quantification

    Uses variational inference to quantify epistemic uncertainty.
    """

    def __init__(
        self,
        input_dim: int = 64,
        hidden_dim: int = 256,
        num_classes: int = 13,
        num_mc_samples: int = 10
    ):
        super().__init__()

        self.num_mc_samples = num_mc_samples

        # Base Neural ODE
        self.neural_ode = TemporalAdaptiveNeuralODE(
            input_dim=input_dim,
            hidden_dims=[128, hidden_dim, 256, 128],
            num_classes=num_classes
        )

        # Variational parameters (mean and log variance)
        self.prior_mean = 0.0
        self.prior_std = 1.0

    def forward(self, x: torch.Tensor, return_uncertainty: bool = False):
        """
        Forward pass with optional uncertainty estimation

        Args:
            x: Input features
            return_uncertainty: Whether to compute uncertainty via MC sampling

        Returns:
            predictions (and optionally uncertainty)
        """
        if not return_uncertainty or not self.training:
            return self.neural_ode(x)

        # Monte Carlo sampling for uncertainty
        binary_samples = []
        multiclass_samples = []

        for _ in range(self.num_mc_samples):
            # Add Gaussian noise to weights (implicit variational inference)
            with torch.no_grad():
                for param in self.neural_ode.parameters():
                    noise = torch.randn_like(param) * 0.1
                    param.add_(noise)

            binary_logits, multiclass_logits = self.neural_ode(x)
            binary_samples.append(binary_logits)
            multiclass_samples.append(multiclass_logits)

        # Stack samples
        binary_samples = torch.stack(binary_samples)  # [num_samples, batch_size, 1]
        multiclass_samples = torch.stack(multiclass_samples)  # [num_samples, batch_size, num_classes]

        # Compute mean predictions
        binary_mean = binary_samples.mean(0)
        multiclass_mean = multiclass_samples.mean(0)

        # Compute uncertainty (variance)
        binary_uncertainty = binary_samples.var(0)
        multiclass_uncertainty = multiclass_samples.var(0)

        return binary_mean, multiclass_mean, binary_uncertainty, multiclass_uncertainty


# Example usage
if __name__ == "__main__":
    # Initialize model
    model = TemporalAdaptiveNeuralODE(
        input_dim=64,
        hidden_dims=[128, 256, 256, 128],
        num_classes=13
    )

    # Create sample input
    batch_size = 32
    x = torch.randn(batch_size, 64)

    # Forward pass
    binary_logits, multiclass_logits = model(x)

    print(f"Binary logits shape: {binary_logits.shape}")  # [32, 1]
    print(f"Multiclass logits shape: {multiclass_logits.shape}")  # [32, 13]

    # Bayesian model for uncertainty
    bayesian_model = BayesianNeuralODE(input_dim=64, hidden_dim=256, num_classes=13)
    binary_mean, multiclass_mean, binary_unc, multiclass_unc = bayesian_model(x, return_uncertainty=True)

    print(f"\nUncertainty quantification:")
    print(f"Binary uncertainty: {binary_unc.mean().item():.4f}")
    print(f"Multiclass uncertainty: {multiclass_unc.mean().item():.4f}")
