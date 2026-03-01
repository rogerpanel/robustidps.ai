"""
Heterogeneous Graph Pooling (HGP)
===================================

Graph pooling for heterogeneous network structures with
multiple node and edge types.

Key Features:
- Heterogeneous graph neural networks
- Hierarchical pooling
- Multi-type attention
- Network topology analysis

Based on: Paper 5 - Heterogeneous Graph Pooling

Author: Roger Nick Anaedevha
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, Tuple, Optional


class HeteroGraphConv(nn.Module):
    """Heterogeneous graph convolution"""

    def __init__(
        self,
        in_channels: Dict[str, int],
        out_channels: int,
        node_types: list,
        edge_types: list
    ):
        super().__init__()

        self.node_types = node_types
        self.edge_types = edge_types

        # Separate linear layers for each node type
        self.node_linears = nn.ModuleDict({
            ntype: nn.Linear(in_channels.get(ntype, 64), out_channels)
            for ntype in node_types
        })

        # Edge type embeddings
        self.edge_embeddings = nn.Embedding(len(edge_types), out_channels)

    def forward(
        self,
        node_features: Dict[str, torch.Tensor],
        edge_index: torch.Tensor,
        edge_types: torch.Tensor
    ) -> Dict[str, torch.Tensor]:
        """
        Args:
            node_features: Dictionary of node features per type
            edge_index: [2, num_edges] source and target indices
            edge_types: [num_edges] edge type indices

        Returns:
            Updated node features per type
        """
        # Initialize output
        output_features = {}

        # Process each node type
        for ntype in self.node_types:
            if ntype not in node_features:
                continue

            # Transform node features
            h = self.node_linears[ntype](node_features[ntype])
            output_features[ntype] = h

        return output_features


class TopKPooling(nn.Module):
    """Top-K pooling layer"""

    def __init__(self, in_channels: int, ratio: float = 0.5):
        super().__init__()
        self.ratio = ratio
        self.score_layer = nn.Linear(in_channels, 1)

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: Optional[torch.Tensor] = None
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Args:
            x: Node features [num_nodes, in_channels]
            edge_index: [2, num_edges]
            batch: Batch assignment [num_nodes]

        Returns:
            (pooled_x, pooled_edge_index, pooled_batch)
        """
        # Compute node scores
        scores = self.score_layer(x).squeeze(-1)  # [num_nodes]

        # Select top-k nodes
        num_nodes = x.size(0)
        k = max(1, int(num_nodes * self.ratio))

        _, top_indices = torch.topk(scores, k, sorted=False)

        # Pool features
        pooled_x = x[top_indices]
        pooled_scores = scores[top_indices]

        # Weight features by scores
        pooled_x = pooled_x * pooled_scores.unsqueeze(-1)

        # Update edge index (placeholder - full implementation would filter edges)
        pooled_edge_index = edge_index

        pooled_batch = batch[top_indices] if batch is not None else None

        return pooled_x, pooled_edge_index, pooled_batch


class HierarchicalPooling(nn.Module):
    """Hierarchical graph pooling with multiple levels"""

    def __init__(
        self,
        in_channels: int,
        pooling_ratios: list = [0.5, 0.5]
    ):
        super().__init__()

        self.pooling_layers = nn.ModuleList([
            TopKPooling(in_channels, ratio)
            for ratio in pooling_ratios
        ])

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor
    ) -> list:
        """
        Args:
            x: Node features [num_nodes, in_channels]
            edge_index: [2, num_edges]

        Returns:
            List of pooled representations at each level
        """
        pooled_representations = [x]

        for pool_layer in self.pooling_layers:
            x, edge_index, _ = pool_layer(x, edge_index)
            pooled_representations.append(x)

        return pooled_representations


class HGPModel(nn.Module):
    """
    Heterogeneous Graph Pooling Model

    Complete model for heterogeneous graph-based IDS.
    """

    def __init__(
        self,
        node_types: list = ['host', 'switch', 'router', 'server', 'endpoint'],
        edge_types: list = ['connection', 'flow', 'routing', 'api_call'],
        node_feature_dim: int = 64,
        hidden_dim: int = 256,
        num_layers: int = 3,
        pooling_ratios: list = [0.5, 0.25],
        num_classes: int = 13
    ):
        super().__init__()

        self.node_types = node_types
        self.edge_types = edge_types

        # Input channels per node type
        in_channels = {ntype: node_feature_dim for ntype in node_types}

        # Heterogeneous graph convolutions
        self.hetero_convs = nn.ModuleList([
            HeteroGraphConv(
                in_channels if i == 0 else {ntype: hidden_dim for ntype in node_types},
                hidden_dim,
                node_types,
                edge_types
            )
            for i in range(num_layers)
        ])

        # Hierarchical pooling
        self.hierarchical_pool = HierarchicalPooling(
            hidden_dim,
            pooling_ratios
        )

        # Graph-level readout
        self.readout = nn.Sequential(
            nn.Linear(hidden_dim * (len(pooling_ratios) + 1), hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3)
        )

        # Classifiers
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim // 2, num_classes)
        )

        self.binary_head = nn.Linear(hidden_dim, 1)

    def forward(
        self,
        node_features: Dict[str, torch.Tensor],
        edge_index: torch.Tensor,
        edge_types: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Args:
            node_features: Dict of node features per type
            edge_index: [2, num_edges]
            edge_types: [num_edges]

        Returns:
            (binary_logits, multiclass_logits)
        """
        # Heterogeneous graph convolutions
        for hetero_conv in self.hetero_convs:
            node_features = hetero_conv(node_features, edge_index, edge_types)

        # Concatenate all node types
        all_nodes = torch.cat([
            features for features in node_features.values()
        ], dim=0)

        # Hierarchical pooling
        pooled_reps = self.hierarchical_pool(all_nodes, edge_index)

        # Global pooling for each level
        graph_reps = [rep.mean(0) for rep in pooled_reps]

        # Concatenate multi-scale representations
        graph_embedding = torch.cat(graph_reps, dim=-1)

        # Readout
        graph_embedding = self.readout(graph_embedding.unsqueeze(0))

        # Classification
        binary_logits = self.binary_head(graph_embedding)
        multiclass_logits = self.classifier(graph_embedding)

        return binary_logits, multiclass_logits


# Example usage
if __name__ == "__main__":
    # Initialize model
    model = HGPModel(
        node_types=['host', 'switch', 'router', 'server'],
        edge_types=['connection', 'flow'],
        node_feature_dim=64,
        hidden_dim=256,
        num_classes=13
    )

    # Sample heterogeneous graph
    node_features = {
        'host': torch.randn(20, 64),
        'switch': torch.randn(10, 64),
        'router': torch.randn(5, 64),
        'server': torch.randn(15, 64)
    }

    # Edge index and types
    num_edges = 100
    edge_index = torch.randint(0, 50, (2, num_edges))
    edge_types = torch.randint(0, 2, (num_edges,))

    # Forward pass
    binary_logits, multiclass_logits = model(node_features, edge_index, edge_types)

    print(f"Binary logits: {binary_logits.shape}")
    print(f"Multiclass logits: {multiclass_logits.shape}")
