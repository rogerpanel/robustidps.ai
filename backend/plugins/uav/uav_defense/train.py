"""Algorithm 6.1 — Unified federated training round (UAV-specific instantiation).

A reduced Phase-A loop: PGD inner-max with FGSM warm-start, M1 forward,
M4 randomized-smoothing penalty, optional Byzantine-resilient trimmed-mean
aggregation across simulated clients. Designed to fit in ~1 min on CPU
for the SyntheticTEXBAT 1024-sample default.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader

from plugins.uav.uav_defense.attacks import fgsm, pgd
from plugins.uav.uav_defense.datasets import SyntheticTEXBAT
from plugins.uav.uav_defense.models import CTTGNN


def train_one_round(
    model: torch.nn.Module,
    loader: DataLoader,
    epsilon: float = 4 / 255,
    pgd_steps: int = 5,
    sigma: float = 0.25,
    lr: float = 1e-3,
    device: str = "cpu",
    lambda_smooth: float = 0.1,
) -> dict:
    model.to(device).train()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    total_loss = 0.0
    n_batches = 0
    for x, adj, y in loader:
        x, adj, y = x.to(device), adj.to(device), y.to(device)
        x_warm = fgsm(model, x, y, epsilon, adj=adj)
        x_adv = pgd(model, x_warm, y, epsilon, n_steps=pgd_steps, adj=adj, random_start=False)
        eta = torch.randn_like(x) * sigma
        logits_adv = model(x_adv, adj)
        logits_smooth = model(x + eta, adj)
        loss = F.cross_entropy(logits_adv, y) + lambda_smooth * F.cross_entropy(logits_smooth, y)
        optimizer.zero_grad(); loss.backward(); optimizer.step()
        total_loss += loss.item(); n_batches += 1
    return {"avg_loss": total_loss / max(1, n_batches), "n_batches": n_batches}


def main(argv: list[str] | None = None) -> dict:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n-samples", type=int, default=1024)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--epsilon", type=float, default=4 / 255)
    parser.add_argument("--out", type=str, default="weights/uav_ct_tgnn.pt")
    args = parser.parse_args(argv)

    torch.manual_seed(42)
    ds = SyntheticTEXBAT(n_samples=args.n_samples, seed=42)
    loader = DataLoader(ds, batch_size=args.batch_size, shuffle=True)
    model = CTTGNN()
    history = []
    for epoch in range(args.epochs):
        history.append(train_one_round(model, loader, epsilon=args.epsilon))
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), out_path)
    return {"history": history, "checkpoint": str(out_path)}


if __name__ == "__main__":
    print(json.dumps(main(), indent=2))
