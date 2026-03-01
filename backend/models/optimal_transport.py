"""
Privacy-Preserving Federated Optimal Transport (PPFOT-IDS)
============================================================

Implementation of optimal transport-based domain adaptation
with differential privacy for cross-cloud IDS.

Key Features:
- Wasserstein distance computation via Sinkhorn algorithm
- Differential privacy (ε=0.85, δ=10^-5)
- Byzantine-robust aggregation
- Computational optimization via importance sparsification
- Adaptive scheduling for federated learning

Based on: Paper 2 - Optimal Transport with Privacy Preservation

Author: Roger Nick Anaedevha
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple, List, Optional, Dict
import math


class SinkhornDistance(nn.Module):
    """
    Compute Wasserstein distance using Sinkhorn algorithm

    Entropic regularization for efficient computation of
    optimal transport distance between distributions.
    """

    def __init__(
        self,
        reg: float = 0.1,
        max_iter: int = 100,
        threshold: float = 1e-6
    ):
        super().__init__()
        self.reg = reg
        self.max_iter = max_iter
        self.threshold = threshold

    def forward(
        self,
        source: torch.Tensor,
        target: torch.Tensor,
        cost_matrix: Optional[torch.Tensor] = None
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Compute Sinkhorn distance

        Args:
            source: Source distribution [batch_size, n_source, dim]
            target: Target distribution [batch_size, n_target, dim]
            cost_matrix: Optional pre-computed cost [n_source, n_target]

        Returns:
            (transport_distance, transport_plan)
        """
        batch_size = source.size(0)
        n_source = source.size(1)
        n_target = target.size(1)

        # Compute cost matrix if not provided (Euclidean distance)
        if cost_matrix is None:
            source_expanded = source.unsqueeze(2)  # [batch, n_source, 1, dim]
            target_expanded = target.unsqueeze(1)  # [batch, 1, n_target, dim]
            cost_matrix = torch.sum(
                (source_expanded - target_expanded) ** 2,
                dim=-1
            )  # [batch, n_source, n_target]

        # Initialize uniform distributions
        mu = torch.ones(batch_size, n_source, device=source.device) / n_source
        nu = torch.ones(batch_size, n_target, device=target.device) / n_target

        # Compute kernel matrix
        K = torch.exp(-cost_matrix / self.reg)  # [batch, n_source, n_target]

        # Sinkhorn iterations
        u = torch.ones_like(mu)
        v = torch.ones_like(nu)

        for _ in range(self.max_iter):
            u_prev = u.clone()

            # Update u
            u = mu / (K @ v.unsqueeze(-1)).squeeze(-1)

            # Update v
            v = nu / (K.transpose(1, 2) @ u.unsqueeze(-1)).squeeze(-1)

            # Check convergence
            if torch.max(torch.abs(u - u_prev)) < self.threshold:
                break

        # Compute transport plan
        transport_plan = u.unsqueeze(-1) * K * v.unsqueeze(1)  # [batch, n_source, n_target]

        # Compute Wasserstein distance
        distance = torch.sum(transport_plan * cost_matrix, dim=[1, 2])  # [batch]

        return distance, transport_plan


class DifferentialPrivacyMechanism(nn.Module):
    """
    Gaussian mechanism for differential privacy

    Adds calibrated noise to ensure (ε, δ)-differential privacy.
    """

    def __init__(
        self,
        epsilon: float = 0.85,
        delta: float = 1e-5,
        sensitivity: float = 1.0,
        clip_norm: float = 1.0
    ):
        super().__init__()
        self.epsilon = epsilon
        self.delta = delta
        self.sensitivity = sensitivity
        self.clip_norm = clip_norm

        # Compute noise multiplier
        self.noise_multiplier = self._compute_noise_multiplier()

    def _compute_noise_multiplier(self) -> float:
        """
        Compute noise multiplier for Gaussian mechanism

        σ = (Δf / ε) * sqrt(2 * ln(1.25 / δ))
        """
        return (self.sensitivity / self.epsilon) * math.sqrt(
            2 * math.log(1.25 / self.delta)
        )

    def clip_gradients(self, gradients: torch.Tensor) -> torch.Tensor:
        """Clip gradients to bound sensitivity"""
        grad_norm = torch.norm(gradients)
        if grad_norm > self.clip_norm:
            gradients = gradients * (self.clip_norm / grad_norm)
        return gradients

    def add_noise(self, tensor: torch.Tensor) -> torch.Tensor:
        """Add Gaussian noise for privacy"""
        noise = torch.randn_like(tensor) * self.noise_multiplier * self.sensitivity
        return tensor + noise


class ByzantineRobustAggregator(nn.Module):
    """
    Byzantine-robust aggregation for federated learning

    Uses coordinate-wise median and trimmed mean to defend
    against malicious clients.
    """

    def __init__(
        self,
        trimming_fraction: float = 0.25,
        anomaly_threshold: float = 0.9
    ):
        super().__init__()
        self.trimming_fraction = trimming_fraction
        self.anomaly_threshold = anomaly_threshold

    def coordinate_wise_median(
        self,
        updates: List[torch.Tensor]
    ) -> torch.Tensor:
        """Compute coordinate-wise median"""
        stacked = torch.stack(updates, dim=0)  # [num_clients, ...]
        median, _ = torch.median(stacked, dim=0)
        return median

    def trimmed_mean(
        self,
        updates: List[torch.Tensor],
        trim_fraction: Optional[float] = None
    ) -> torch.Tensor:
        """
        Compute trimmed mean (remove outliers)

        Args:
            updates: List of client updates
            trim_fraction: Fraction to trim (default: self.trimming_fraction)
        """
        if trim_fraction is None:
            trim_fraction = self.trimming_fraction

        stacked = torch.stack(updates, dim=0)  # [num_clients, ...]
        num_clients = stacked.size(0)
        num_trim = int(num_clients * trim_fraction)

        if num_trim == 0:
            return stacked.mean(0)

        # Sort along client dimension
        sorted_updates, _ = torch.sort(stacked, dim=0)

        # Remove top and bottom
        trimmed = sorted_updates[num_trim:-num_trim]

        return trimmed.mean(0)

    def detect_byzantine(
        self,
        updates: List[torch.Tensor],
        global_model: torch.Tensor
    ) -> List[bool]:
        """
        Detect Byzantine clients using distance from global model

        Returns:
            List of boolean flags (True = Byzantine)
        """
        distances = []
        for update in updates:
            dist = torch.norm(update - global_model).item()
            distances.append(dist)

        # Compute median and MAD (Median Absolute Deviation)
        median_dist = torch.tensor(distances).median().item()
        mad = torch.tensor([abs(d - median_dist) for d in distances]).median().item()

        # Mark as Byzantine if distance > median + threshold * MAD
        threshold_dist = median_dist + self.anomaly_threshold * mad
        is_byzantine = [d > threshold_dist for d in distances]

        return is_byzantine

    def aggregate(
        self,
        updates: List[torch.Tensor],
        global_model: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """
        Robust aggregation with Byzantine detection

        Args:
            updates: List of client model updates
            global_model: Current global model for anomaly detection

        Returns:
            Aggregated update
        """
        if global_model is not None:
            # Detect and filter Byzantine clients
            is_byzantine = self.detect_byzantine(updates, global_model)
            filtered_updates = [
                update for update, is_byz in zip(updates, is_byzantine)
                if not is_byz
            ]

            if len(filtered_updates) == 0:
                # All flagged as Byzantine, fallback to trimmed mean
                return self.trimmed_mean(updates)

            updates = filtered_updates

        # Use trimmed mean for robustness
        return self.trimmed_mean(updates)


class ImportanceSparsification(nn.Module):
    """
    Computational optimization via importance-based sparsification

    Reduces computation by focusing on important sample pairs.
    """

    def __init__(self, sparsity_ratio: float = 0.2):
        super().__init__()
        self.sparsity_ratio = sparsity_ratio

    def forward(
        self,
        source: torch.Tensor,
        target: torch.Tensor,
        cost_matrix: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Sparsify based on importance scores

        Args:
            source: Source samples [batch, n_source, dim]
            target: Target samples [batch, n_target, dim]
            cost_matrix: Transport cost [batch, n_source, n_target]

        Returns:
            (sparse_source, sparse_target, sparse_cost)
        """
        batch_size, n_source, n_target = cost_matrix.size()

        # Compute importance scores (inverse of cost)
        importance = 1.0 / (cost_matrix + 1e-8)  # [batch, n_source, n_target]

        # Keep top-k most important pairs
        k = int(n_source * n_target * self.sparsity_ratio)
        topk_values, topk_indices = torch.topk(
            importance.view(batch_size, -1),
            k,
            dim=1
        )

        # Create sparse mask
        mask = torch.zeros(batch_size, n_source * n_target, device=source.device)
        mask.scatter_(1, topk_indices, 1.0)
        mask = mask.view(batch_size, n_source, n_target)

        # Apply mask to cost
        sparse_cost = cost_matrix * mask

        return source, target, sparse_cost


class PPFOTDetector(nn.Module):
    """
    Privacy-Preserving Federated Optimal Transport IDS

    Complete model integrating:
    - Optimal transport for domain adaptation
    - Differential privacy
    - Byzantine robustness
    - Computational optimization
    """

    def __init__(
        self,
        input_dim: int = 64,
        hidden_dim: int = 256,
        num_classes: int = 13,
        epsilon: float = 0.85,
        delta: float = 1e-5,
        sinkhorn_reg: float = 0.1,
        enable_privacy: bool = True,
        enable_byzantine: bool = True,
        enable_sparsification: bool = True
    ):
        super().__init__()

        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.enable_privacy = enable_privacy
        self.enable_byzantine = enable_byzantine

        # Feature encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.BatchNorm1d(hidden_dim),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.BatchNorm1d(hidden_dim)
        )

        # Optimal transport
        self.sinkhorn = SinkhornDistance(reg=sinkhorn_reg)

        # Differential privacy
        if enable_privacy:
            self.dp_mechanism = DifferentialPrivacyMechanism(
                epsilon=epsilon,
                delta=delta
            )

        # Byzantine robustness
        if enable_byzantine:
            self.byzantine_aggregator = ByzantineRobustAggregator()

        # Importance sparsification
        if enable_sparsification:
            self.sparsifier = ImportanceSparsification()

        # Classifier
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim // 2, num_classes)
        )

        # Binary detector
        self.binary_head = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 1)
        )

    def encode_features(self, x: torch.Tensor) -> torch.Tensor:
        """Encode input features to latent space"""
        return self.encoder(x)

    def compute_transport_distance(
        self,
        source_features: torch.Tensor,
        target_features: torch.Tensor
    ) -> torch.Tensor:
        """
        Compute optimal transport distance between domains

        Args:
            source_features: Source domain features [batch, n_source, dim]
            target_features: Target domain features [batch, n_target, dim]

        Returns:
            Wasserstein distance
        """
        distance, _ = self.sinkhorn(source_features, target_features)
        return distance

    def adapt_features(
        self,
        source: torch.Tensor,
        target: torch.Tensor
    ) -> torch.Tensor:
        """
        Adapt source features to target domain

        Args:
            source: Source features [batch_size, dim]
            target: Target features [batch_size, dim]

        Returns:
            Adapted features
        """
        # Compute transport plan
        source_expanded = source.unsqueeze(1)  # [batch, 1, dim]
        target_expanded = target.unsqueeze(1)  # [batch, 1, dim]

        _, transport_plan = self.sinkhorn(source_expanded, target_expanded)

        # Apply transport plan to adapt features
        adapted = torch.bmm(transport_plan, target_expanded).squeeze(1)

        return adapted

    def forward(
        self,
        x: torch.Tensor,
        target_domain: Optional[torch.Tensor] = None
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass with optional domain adaptation

        Args:
            x: Input features [batch_size, input_dim]
            target_domain: Optional target domain samples for adaptation

        Returns:
            (binary_logits, multiclass_logits)
        """
        # Encode features
        features = self.encode_features(x)

        # Domain adaptation if target provided
        if target_domain is not None:
            target_features = self.encode_features(target_domain)
            features = self.adapt_features(features, target_features)

        # Classification
        binary_logits = self.binary_head(features)
        multiclass_logits = self.classifier(features)

        return binary_logits, multiclass_logits

    def federated_update(
        self,
        client_updates: List[torch.Tensor],
        global_model_state: torch.Tensor
    ) -> torch.Tensor:
        """
        Aggregate client updates with privacy and robustness

        Args:
            client_updates: List of client model updates
            global_model_state: Current global model parameters

        Returns:
            Aggregated update with privacy and Byzantine robustness
        """
        # Byzantine-robust aggregation
        if self.enable_byzantine:
            aggregated = self.byzantine_aggregator.aggregate(
                client_updates,
                global_model_state
            )
        else:
            aggregated = torch.stack(client_updates).mean(0)

        # Add differential privacy noise
        if self.enable_privacy:
            aggregated = self.dp_mechanism.add_noise(aggregated)

        return aggregated


# Example usage
if __name__ == "__main__":
    # Initialize model
    model = PPFOTDetector(
        input_dim=64,
        hidden_dim=256,
        num_classes=13,
        epsilon=0.85,
        delta=1e-5,
        enable_privacy=True,
        enable_byzantine=True
    )

    # Sample data
    batch_size = 32
    source_data = torch.randn(batch_size, 64)
    target_data = torch.randn(batch_size, 64)

    # Forward pass
    binary_logits, multiclass_logits = model(source_data)
    print(f"Binary logits: {binary_logits.shape}")
    print(f"Multiclass logits: {multiclass_logits.shape}")

    # Domain adaptation
    binary_adapted, multiclass_adapted = model(source_data, target_data)
    print(f"\nWith domain adaptation:")
    print(f"Binary logits: {binary_adapted.shape}")
    print(f"Multiclass logits: {multiclass_adapted.shape}")

    # Simulate federated learning
    num_clients = 5
    client_updates = [torch.randn(256) for _ in range(num_clients)]
    global_state = torch.randn(256)

    aggregated = model.federated_update(client_updates, global_state)
    print(f"\nFederated aggregation shape: {aggregated.shape}")
