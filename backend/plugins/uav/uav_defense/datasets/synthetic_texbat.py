"""Calibrated TEXBAT-like synthetic generator.

Produces 8-satellite cross-ambiguity-function (CAF) feature batches matching
the dimensionality used in chapter 6 §6.6 for the M1 CT-TGNN smoke test
(8 satellites x 8-dim CAF features, hidden H=32).

The clean class is a stable centre-of-correlation peak; the spoofed class
adds a coherent secondary peak whose offset and amplitude are drawn so the
classifier task is non-trivial but learnable in ~1 min CPU.
"""
from __future__ import annotations

import numpy as np
import torch
from torch.utils.data import Dataset


class SyntheticTEXBAT(Dataset):
    NUM_SATELLITES = 8
    CAF_DIM = 8

    def __init__(self, n_samples: int = 1024, spoof_ratio: float = 0.5, seed: int = 42):
        rng = np.random.default_rng(seed)
        self.n = n_samples
        labels = (rng.random(n_samples) < spoof_ratio).astype(np.int64)
        x = np.zeros((n_samples, self.NUM_SATELLITES, self.CAF_DIM), dtype=np.float32)

        for i in range(n_samples):
            primary_peak = rng.normal(0.0, 0.05, size=(self.NUM_SATELLITES, self.CAF_DIM))
            primary_peak[:, 3:5] += 1.0
            if labels[i] == 1:
                offset = int(rng.integers(0, self.CAF_DIM))
                amplitude = float(rng.uniform(0.35, 0.65))
                spoof_sats = rng.choice(self.NUM_SATELLITES, size=4, replace=False)
                for s in spoof_sats:
                    primary_peak[s, offset] += amplitude
            x[i] = primary_peak

        self.x = torch.from_numpy(x)
        self.y = torch.from_numpy(labels)

        adj = np.ones((self.NUM_SATELLITES + 1, self.NUM_SATELLITES + 1), dtype=np.float32)
        np.fill_diagonal(adj, 0.0)
        self.adjacency = torch.from_numpy(adj)

    def __len__(self) -> int:
        return self.n

    def __getitem__(self, idx: int):
        return self.x[idx], self.adjacency, self.y[idx]
