"""
Federated Graph Temporal Dynamics (FedGTD)
===========================================

Graph-based federated learning with temporal dynamics modeling
for distributed intrusion detection.

Key Features:
- Graph neural networks for network topology
- Temporal dynamics via ODEs
- Federated learning across multiple organizations
- Knowledge distillation for model compression

Based on: Paper 4 - Federated Learning with Graph Temporal Dynamics

Author: Roger Nick Anaedevha
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torchdiffeq import odeint_adjoint as odeint
from typing import Tuple, Optional, List


class GraphConvLayer(nn.Module):
    """Graph convolutional layer"""

    def __init__(self, in_channels: int, out_channels: int):
        super().__init__()
        self.linear = nn.Linear(in_channels, out_channels)

    def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: Node features [num_nodes, in_channels]
            adj: Adjacency matrix [num_nodes, num_nodes]
        Returns:
            Updated node features [num_nodes, out_channels]
        """
        # Message passing: aggregate neighbor features
        support = self.linear(x)
        output = torch.matmul(adj, support)
        return output


class GraphODEFunc(nn.Module):
    """ODE function for graph dynamics"""

    def __init__(self, node_dim: int, hidden_dim: int):
        super().__init__()
        self.gcn1 = GraphConvLayer(node_dim, hidden_dim)
        self.gcn2 = GraphConvLayer(hidden_dim, node_dim)

    def forward(self, t: torch.Tensor, x_adj: Tuple[torch.Tensor, torch.Tensor]) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Args:
            t: Time (scalar)
            x_adj: (node_features, adjacency_matrix)
        Returns:
            Time derivative of node features
        """
        x, adj = x_adj

        # Graph convolutions
        h = F.relu(self.gcn1(x, adj))
        dx = self.gcn2(h, adj)

        # Adjacency doesn't change
        dadj = torch.zeros_like(adj)

        return (dx, dadj)


class GraphTemporalODE(nn.Module):
    """
    Graph Neural ODE for modeling temporal network dynamics

    Combines graph structure with continuous-time evolution.
    """

    def __init__(
        self,
        node_dim: int = 64,
        hidden_dim: int = 256,
        num_gnn_layers: int = 3
    ):
        super().__init__()

        self.node_dim = node_dim
        self.hidden_dim = hidden_dim

        # Initial graph embedding
        self.node_encoder = nn.Sequential(
            nn.Linear(node_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, node_dim)
        )

        # Graph ODE
        self.ode_func = GraphODEFunc(node_dim, hidden_dim)

        # Output projection
        self.output_proj = nn.Linear(node_dim, node_dim)

    def forward(
        self,
        node_features: torch.Tensor,
        adj_matrix: torch.Tensor,
        t_span: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """
        Args:
            node_features: [num_nodes, node_dim]
            adj_matrix: [num_nodes, num_nodes]
            t_span: Time span [t_start, t_end]

        Returns:
            Updated node features [num_nodes, node_dim]
        """
        if t_span is None:
            t_span = torch.tensor([0.0, 1.0], device=node_features.device)

        # Encode nodes
        x = self.node_encoder(node_features)

        # Solve ODE
        trajectory, _ = odeint(
            self.ode_func,
            (x, adj_matrix),
            t_span,
            method='dopri5'
        )

        # Take final state
        x_final = trajectory[-1]

        # Project output
        output = self.output_proj(x_final)

        return output


class KnowledgeDistillation(nn.Module):
    """Knowledge distillation for model compression"""

    def __init__(self, temperature: float = 3.0, alpha: float = 0.7):
        super().__init__()
        self.temperature = temperature
        self.alpha = alpha

    def distillation_loss(
        self,
        student_logits: torch.Tensor,
        teacher_logits: torch.Tensor,
        labels: torch.Tensor
    ) -> torch.Tensor:
        """
        Compute distillation loss

        Args:
            student_logits: Student model predictions
            teacher_logits: Teacher model predictions
            labels: Ground truth labels

        Returns:
            Combined distillation loss
        """
        # Soft targets from teacher
        soft_targets = F.softmax(teacher_logits / self.temperature, dim=-1)
        soft_student = F.log_softmax(student_logits / self.temperature, dim=-1)

        # Distillation loss (KL divergence)
        distill_loss = F.kl_div(
            soft_student,
            soft_targets,
            reduction='batchmean'
        ) * (self.temperature ** 2)

        # Hard targets loss
        hard_loss = F.cross_entropy(student_logits, labels)

        # Combine losses
        total_loss = self.alpha * distill_loss + (1 - self.alpha) * hard_loss

        return total_loss


class FedGTDModel(nn.Module):
    """
    Federated Graph Temporal Dynamics Model

    Complete federated learning model with graph structure
    and temporal dynamics.
    """

    def __init__(
        self,
        node_dim: int = 64,
        hidden_dim: int = 256,
        num_gnn_layers: int = 3,
        num_classes: int = 13,
        enable_distillation: bool = True
    ):
        super().__init__()

        self.node_dim = node_dim
        self.enable_distillation = enable_distillation

        # Graph temporal ODE
        self.graph_ode = GraphTemporalODE(
            node_dim=node_dim,
            hidden_dim=hidden_dim,
            num_gnn_layers=num_gnn_layers
        )

        # GNN layers for additional processing
        self.gnn_layers = nn.ModuleList([
            GraphConvLayer(node_dim, node_dim)
            for _ in range(num_gnn_layers)
        ])

        # Global pooling
        self.global_pool = nn.Sequential(
            nn.Linear(node_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim)
        )

        # Classifier
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim // 2, num_classes)
        )

        # Binary detector
        self.binary_head = nn.Linear(hidden_dim, 1)

        # Knowledge distillation
        if enable_distillation:
            self.distillation = KnowledgeDistillation()

    def forward(
        self,
        node_features: torch.Tensor,
        adj_matrix: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Args:
            node_features: [num_nodes, node_dim]
            adj_matrix: [num_nodes, num_nodes]

        Returns:
            (binary_logits, multiclass_logits)
        """
        # Graph temporal ODE
        x = self.graph_ode(node_features, adj_matrix)

        # Additional GNN layers
        for gnn_layer in self.gnn_layers:
            x = F.relu(gnn_layer(x, adj_matrix))

        # Global pooling (aggregate all nodes)
        graph_embedding = self.global_pool(x.mean(0, keepdim=True))  # [1, hidden_dim]

        # Classification
        binary_logits = self.binary_head(graph_embedding)
        multiclass_logits = self.classifier(graph_embedding)

        return binary_logits, multiclass_logits

    def federated_train_step(
        self,
        local_data: List[Tuple[torch.Tensor, torch.Tensor, torch.Tensor]],
        global_model_state: dict
    ) -> dict:
        """
        Federated training step

        Args:
            local_data: List of (node_features, adj_matrix, labels) for each client
            global_model_state: Current global model state dict

        Returns:
            Updated model state dict
        """
        local_updates = []

        for node_features, adj_matrix, labels in local_data:
            # Forward pass
            binary_logits, multiclass_logits = self(node_features, adj_matrix)

            # Compute loss (placeholder - actual training would optimize)
            loss = F.cross_entropy(multiclass_logits, labels)

            # Collect local model state
            local_updates.append(self.state_dict())

        # Aggregate (simple averaging)
        aggregated_state = {}
        for key in local_updates[0].keys():
            aggregated_state[key] = torch.stack([
                update[key] for update in local_updates
            ]).mean(0)

        return aggregated_state


# Example usage
if __name__ == "__main__":
    # Initialize model
    model = FedGTDModel(
        node_dim=64,
        hidden_dim=256,
        num_gnn_layers=3,
        num_classes=13
    )

    # Sample graph data
    num_nodes = 50
    node_features = torch.randn(num_nodes, 64)

    # Random adjacency matrix (normalized)
    adj_matrix = torch.rand(num_nodes, num_nodes)
    adj_matrix = (adj_matrix + adj_matrix.t()) / 2  # Symmetric
    adj_matrix = adj_matrix / adj_matrix.sum(1, keepdim=True)  # Row normalize

    # Forward pass
    binary_logits, multiclass_logits = model(node_features, adj_matrix)

    print(f"Node features: {node_features.shape}")
    print(f"Adjacency matrix: {adj_matrix.shape}")
    print(f"Binary logits: {binary_logits.shape}")
    print(f"Multiclass logits: {multiclass_logits.shape}")
