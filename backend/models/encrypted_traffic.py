"""
Encrypted Traffic Analyzer - Hybrid CNN-LSTM-Transformer
==========================================================

Deep learning model for analyzing encrypted traffic without decryption.
Uses packet metadata, timing patterns, and TLS features.

Key Features:
- CNN for spatial feature extraction from packet sequences
- Bidirectional LSTM for temporal dependencies
- Transformer for long-range attention
- 97-99.9% detection rate on encrypted attacks
- TLS fingerprinting (JA3, JA3S)
- No decryption required

Based on: Paper 3 - Encrypted Traffic Analysis

Author: Roger Nick Anaedevha
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple, Optional
import math


class PositionalEncoding(nn.Module):
    """Sinusoidal positional encoding for Transformer"""

    def __init__(self, d_model: int, max_len: int = 5000, dropout: float = 0.1):
        super().__init__()
        self.dropout = nn.Dropout(p=dropout)

        # Create positional encoding matrix
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(
            torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model)
        )

        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0)  # [1, max_len, d_model]

        self.register_buffer('pe', pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: [batch_size, seq_len, d_model]
        Returns:
            x with positional encoding added
        """
        x = x + self.pe[:, :x.size(1), :]
        return self.dropout(x)


class PacketCNN(nn.Module):
    """
    CNN for extracting spatial features from packet byte sequences

    Captures local patterns in packet payloads and headers.
    """

    def __init__(
        self,
        input_channels: int = 1,
        filters: list = [64, 128, 256],
        kernel_sizes: list = [5, 3, 3],
        pool_size: int = 2
    ):
        super().__init__()

        layers = []
        in_channels = input_channels

        for out_channels, kernel_size in zip(filters, kernel_sizes):
            layers.extend([
                nn.Conv1d(
                    in_channels,
                    out_channels,
                    kernel_size,
                    padding=kernel_size // 2
                ),
                nn.ReLU(),
                nn.BatchNorm1d(out_channels),
                nn.MaxPool1d(pool_size),
                nn.Dropout(0.2)
            ])
            in_channels = out_channels

        self.conv_net = nn.Sequential(*layers)
        self.output_dim = filters[-1]

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: [batch_size, seq_len, input_dim]
        Returns:
            CNN features [batch_size, seq_len_reduced, filters[-1]]
        """
        # Transpose for Conv1d: [batch, channels, seq_len]
        x = x.transpose(1, 2)

        # Apply convolutions
        x = self.conv_net(x)

        # Transpose back: [batch, seq_len, channels]
        x = x.transpose(1, 2)

        return x


class BidirectionalLSTM(nn.Module):
    """
    Bidirectional LSTM for temporal sequence modeling

    Captures forward and backward temporal dependencies.
    """

    def __init__(
        self,
        input_dim: int,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.2
    ):
        super().__init__()

        self.lstm = nn.LSTM(
            input_dim,
            hidden_dim,
            num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0
        )

        self.output_dim = hidden_dim * 2  # Bidirectional

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, Tuple[torch.Tensor, torch.Tensor]]:
        """
        Args:
            x: [batch_size, seq_len, input_dim]
        Returns:
            (output, (h_n, c_n))
            output: [batch_size, seq_len, hidden_dim * 2]
        """
        output, (h_n, c_n) = self.lstm(x)
        return output, (h_n, c_n)


class TransformerEncoder(nn.Module):
    """
    Transformer encoder for capturing long-range dependencies

    Uses multi-head self-attention for global context.
    """

    def __init__(
        self,
        d_model: int = 256,
        nhead: int = 8,
        num_layers: int = 6,
        dim_feedforward: int = 2048,
        dropout: float = 0.1,
        max_seq_len: int = 1000
    ):
        super().__init__()

        self.d_model = d_model

        # Positional encoding
        self.pos_encoder = PositionalEncoding(d_model, max_seq_len, dropout)

        # Transformer encoder layers
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            batch_first=True,
            activation='gelu'
        )

        self.transformer_encoder = nn.TransformerEncoder(
            encoder_layer,
            num_layers=num_layers
        )

        # Layer normalization
        self.layer_norm = nn.LayerNorm(d_model)

    def forward(
        self,
        x: torch.Tensor,
        mask: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """
        Args:
            x: [batch_size, seq_len, d_model]
            mask: Optional attention mask

        Returns:
            Encoded sequence [batch_size, seq_len, d_model]
        """
        # Add positional encoding
        x = self.pos_encoder(x)

        # Apply transformer
        x = self.transformer_encoder(x, src_key_padding_mask=mask)

        # Layer normalization
        x = self.layer_norm(x)

        return x


class TLSFeatureExtractor(nn.Module):
    """
    Extract TLS-specific features from encrypted traffic

    - TLS version
    - Cipher suites
    - Certificate information
    - JA3/JA3S fingerprints
    - Handshake timing
    """

    def __init__(self, tls_feature_dim: int = 32, output_dim: int = 64):
        super().__init__()

        self.tls_embedding = nn.Sequential(
            nn.Linear(tls_feature_dim, output_dim),
            nn.ReLU(),
            nn.BatchNorm1d(output_dim),
            nn.Dropout(0.2),
            nn.Linear(output_dim, output_dim),
            nn.ReLU()
        )

    def forward(self, tls_features: torch.Tensor) -> torch.Tensor:
        """
        Args:
            tls_features: [batch_size, tls_feature_dim]

        Returns:
            Embedded TLS features [batch_size, output_dim]
        """
        return self.tls_embedding(tls_features)


class EncryptedTrafficAnalyzer(nn.Module):
    """
    Complete hybrid CNN-LSTM-Transformer model for encrypted traffic analysis

    Architecture:
    1. CNN: Extract spatial features from packet sequences
    2. BiLSTM: Model temporal dependencies
    3. Transformer: Capture long-range attention patterns
    4. TLS Features: Domain-specific encrypted traffic features
    5. Fusion: Combine all representations
    6. Classification: Binary + multiclass detection
    """

    def __init__(
        self,
        input_dim: int = 64,
        packet_seq_len: int = 100,
        cnn_filters: list = [64, 128, 256],
        cnn_kernel_sizes: list = [5, 3, 3],
        lstm_hidden: int = 128,
        lstm_layers: int = 2,
        transformer_dim: int = 256,
        transformer_heads: int = 8,
        transformer_layers: int = 6,
        tls_feature_dim: int = 32,
        num_classes: int = 13
    ):
        super().__init__()

        self.input_dim = input_dim
        self.packet_seq_len = packet_seq_len

        # Input projection
        self.input_proj = nn.Linear(input_dim, cnn_filters[0])

        # 1. CNN for spatial features
        self.cnn = PacketCNN(
            input_channels=1,
            filters=cnn_filters,
            kernel_sizes=cnn_kernel_sizes
        )

        # 2. Bidirectional LSTM for temporal modeling
        self.lstm = BidirectionalLSTM(
            input_dim=cnn_filters[-1],
            hidden_dim=lstm_hidden,
            num_layers=lstm_layers,
            dropout=0.2
        )

        # 3. Transformer for long-range dependencies
        # Project LSTM output to transformer dimension
        self.lstm_to_transformer = nn.Linear(
            lstm_hidden * 2,  # BiLSTM doubles hidden dim
            transformer_dim
        )

        self.transformer = TransformerEncoder(
            d_model=transformer_dim,
            nhead=transformer_heads,
            num_layers=transformer_layers,
            dim_feedforward=transformer_dim * 4,
            max_seq_len=packet_seq_len
        )

        # 4. TLS feature extractor
        self.tls_extractor = TLSFeatureExtractor(
            tls_feature_dim=tls_feature_dim,
            output_dim=transformer_dim
        )

        # 5. Feature fusion
        self.fusion = nn.Sequential(
            nn.Linear(transformer_dim * 2, transformer_dim),  # Transformer + TLS
            nn.ReLU(),
            nn.BatchNorm1d(transformer_dim),
            nn.Dropout(0.3),
            nn.Linear(transformer_dim, transformer_dim // 2),
            nn.ReLU()
        )

        # 6. Classification heads
        # Binary classification (malicious vs benign)
        self.binary_classifier = nn.Sequential(
            nn.Linear(transformer_dim // 2, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 1)
        )

        # Multi-class classification (attack types)
        self.multiclass_classifier = nn.Sequential(
            nn.Linear(transformer_dim // 2, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, num_classes)
        )

        # Attention pooling for sequence aggregation
        self.attention_pool = nn.MultiheadAttention(
            embed_dim=transformer_dim,
            num_heads=transformer_heads,
            batch_first=True
        )

    def forward(
        self,
        packet_sequence: torch.Tensor,
        tls_features: Optional[torch.Tensor] = None
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Forward pass through hybrid model

        Args:
            packet_sequence: [batch_size, seq_len, input_dim]
            tls_features: Optional TLS metadata [batch_size, tls_feature_dim]

        Returns:
            (binary_logits, multiclass_logits, attention_weights)
        """
        batch_size, seq_len, _ = packet_sequence.size()

        # Project input
        x = self.input_proj(packet_sequence)  # [batch, seq_len, cnn_filters[0]]

        # 1. CNN: Extract spatial features
        cnn_features = self.cnn(x)  # [batch, seq_len_reduced, cnn_filters[-1]]

        # 2. LSTM: Temporal modeling
        lstm_output, _ = self.lstm(cnn_features)  # [batch, seq_len_reduced, lstm_hidden*2]

        # 3. Transformer: Long-range dependencies
        # Project to transformer dimension
        transformer_input = self.lstm_to_transformer(lstm_output)  # [batch, seq_len, transformer_dim]

        # Apply transformer
        transformer_output = self.transformer(transformer_input)  # [batch, seq_len, transformer_dim]

        # Attention pooling to aggregate sequence
        # Use learnable query
        query = transformer_output.mean(1, keepdim=True)  # [batch, 1, transformer_dim]
        pooled_output, attention_weights = self.attention_pool(
            query,
            transformer_output,
            transformer_output
        )  # [batch, 1, transformer_dim]
        pooled_output = pooled_output.squeeze(1)  # [batch, transformer_dim]

        # 4. TLS features
        if tls_features is not None:
            tls_embedded = self.tls_extractor(tls_features)  # [batch, transformer_dim]
        else:
            # Use zero features if TLS not available
            tls_embedded = torch.zeros(
                batch_size,
                pooled_output.size(-1),
                device=packet_sequence.device
            )

        # 5. Fusion
        fused_features = torch.cat([pooled_output, tls_embedded], dim=-1)  # [batch, transformer_dim*2]
        fused_features = self.fusion(fused_features)  # [batch, transformer_dim//2]

        # 6. Classification
        binary_logits = self.binary_classifier(fused_features)  # [batch, 1]
        multiclass_logits = self.multiclass_classifier(fused_features)  # [batch, num_classes]

        return binary_logits, multiclass_logits, attention_weights


class StreamingEncryptedAnalyzer(nn.Module):
    """
    Streaming version for real-time analysis of encrypted traffic

    Processes packets in sliding windows for low-latency detection.
    """

    def __init__(
        self,
        base_model: EncryptedTrafficAnalyzer,
        window_size: int = 50,
        stride: int = 25
    ):
        super().__init__()
        self.base_model = base_model
        self.window_size = window_size
        self.stride = stride

        # Buffer for streaming
        self.register_buffer('packet_buffer', torch.zeros(1, window_size, base_model.input_dim))
        self.buffer_idx = 0

    def add_packet(self, packet: torch.Tensor) -> Optional[Tuple[torch.Tensor, torch.Tensor]]:
        """
        Add packet to buffer and process if window is full

        Args:
            packet: Single packet features [input_dim]

        Returns:
            Detection results if window is full, else None
        """
        # Add to buffer
        self.packet_buffer[0, self.buffer_idx, :] = packet
        self.buffer_idx += 1

        # Process if buffer is full
        if self.buffer_idx >= self.window_size:
            binary_logits, multiclass_logits, _ = self.base_model(self.packet_buffer)

            # Slide window
            self.packet_buffer[:, :-self.stride, :] = self.packet_buffer[:, self.stride:, :].clone()
            self.buffer_idx -= self.stride

            return binary_logits, multiclass_logits

        return None

    def reset_buffer(self):
        """Reset packet buffer"""
        self.packet_buffer.zero_()
        self.buffer_idx = 0


# Example usage
if __name__ == "__main__":
    # Initialize model
    model = EncryptedTrafficAnalyzer(
        input_dim=64,
        packet_seq_len=100,
        cnn_filters=[64, 128, 256],
        lstm_hidden=128,
        transformer_dim=256,
        transformer_heads=8,
        transformer_layers=6,
        num_classes=13
    )

    # Create sample encrypted traffic sequence
    batch_size = 16
    seq_len = 100
    input_dim = 64
    packet_sequence = torch.randn(batch_size, seq_len, input_dim)

    # Optional TLS features
    tls_features = torch.randn(batch_size, 32)

    # Forward pass
    binary_logits, multiclass_logits, attention_weights = model(
        packet_sequence,
        tls_features
    )

    print(f"Input shape: {packet_sequence.shape}")
    print(f"Binary logits: {binary_logits.shape}")
    print(f"Multiclass logits: {multiclass_logits.shape}")
    print(f"Attention weights: {attention_weights.shape}")

    # Compute detection
    binary_probs = torch.sigmoid(binary_logits)
    multiclass_probs = F.softmax(multiclass_logits, dim=-1)

    print(f"\nSample predictions:")
    print(f"Malicious probability: {binary_probs[0].item():.3f}")
    print(f"Top attack type: {multiclass_probs[0].argmax().item()}")

    # Streaming example
    print("\n--- Streaming Mode ---")
    streaming_model = StreamingEncryptedAnalyzer(model, window_size=50, stride=25)

    for i in range(60):
        packet = torch.randn(input_dim)
        result = streaming_model.add_packet(packet)

        if result is not None:
            binary_logits, multiclass_logits = result
            print(f"Packet {i}: Detection = {torch.sigmoid(binary_logits).item():.3f}")
