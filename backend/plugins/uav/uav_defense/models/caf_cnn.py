"""CAF-CNN baseline (Borhani-Darian et al., EURASIP J. Adv. Signal Process., 2024).

Operates on cross-ambiguity-function (CAF) feature maps treated as 2D images.
Used as the published GNSS-spoofing baseline against which CT-TGNN is
benchmarked in chapter 6 Fig. 6.x (Mission-Completion-Rate vs J/S).
"""
from __future__ import annotations

import torch
import torch.nn as nn


class CAFCNN(nn.Module):
    def __init__(self, in_channels: int = 1, num_classes: int = 2):
        super().__init__()
        self.features = nn.Sequential(
            nn.Conv2d(in_channels, 16, kernel_size=3, padding=1), nn.ReLU(inplace=True),
            nn.MaxPool2d(2),
            nn.Conv2d(16, 32, kernel_size=3, padding=1), nn.ReLU(inplace=True),
            nn.AdaptiveAvgPool2d((2, 2)),
        )
        self.classifier = nn.Linear(32 * 2 * 2, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if x.dim() == 3:
            x = x.unsqueeze(1)
        h = self.features(x)
        h = h.flatten(1)
        return self.classifier(h)

    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        return torch.softmax(self.forward(x), dim=-1)
