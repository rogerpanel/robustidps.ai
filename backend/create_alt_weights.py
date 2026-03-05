"""
Create initial weights for alternative models.

Trains each alternative model on synthetic data so that they produce
reasonable-looking predictions for demo purposes. Replace these weights
with real trained weights as models are trained on actual datasets.

Usage:
    python create_alt_weights.py
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from pathlib import Path

from models.model_registry import MODEL_INFO, WEIGHTS_DIR
from models.surrogate import SurrogateIDS


def generate_synthetic_data(n_samples: int = 5000, n_features: int = 83,
                            n_classes: int = 34):
    """Generate synthetic training data from the surrogate model."""
    # Load surrogate to generate pseudo-labels
    surrogate = SurrogateIDS(dropout=0.05)
    weight_path = WEIGHTS_DIR / "surrogate.pt"
    if weight_path.exists():
        state = torch.load(weight_path, map_location="cpu", weights_only=True)
        surrogate.load_state_dict(state)
    surrogate.eval()

    # Random features
    X = torch.randn(n_samples, n_features)

    # Generate pseudo-labels from surrogate
    with torch.no_grad():
        logits = surrogate(X)
        y = logits.argmax(-1)

    return X, y


def train_model(model: nn.Module, X: torch.Tensor, y: torch.Tensor,
                epochs: int = 80, lr: float = 0.003):
    """Train a model on synthetic data."""
    model.train()
    optimizer = optim.Adam(model.parameters(), lr=lr)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
    criterion = nn.CrossEntropyLoss()

    batch_size = 128
    n_samples = len(X)

    for epoch in range(epochs):
        perm = torch.randperm(n_samples)
        total_loss = 0.0
        n_batches = 0

        for i in range(0, n_samples, batch_size):
            idx = perm[i:i + batch_size]
            x_batch = X[idx]
            y_batch = y[idx]

            optimizer.zero_grad()
            logits = model(x_batch)
            loss = criterion(logits, y_batch)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()

            total_loss += loss.item()
            n_batches += 1

        scheduler.step()

        if (epoch + 1) % 20 == 0:
            model.eval()
            with torch.no_grad():
                preds = model(X).argmax(-1)
                acc = (preds == y).float().mean().item()
            model.train()
            print(f"  Epoch {epoch + 1}/{epochs} — loss: {total_loss / n_batches:.4f}, acc: {acc:.4f}")


def main():
    WEIGHTS_DIR.mkdir(parents=True, exist_ok=True)

    print("Generating synthetic training data from surrogate...")
    X, y = generate_synthetic_data(n_samples=5000)
    print(f"  Data: {X.shape[0]} samples, {X.shape[1]} features, {y.unique().numel()} classes")

    for model_id, info in MODEL_INFO.items():
        if model_id == "surrogate":
            continue  # Already has trained weights

        weight_path = WEIGHTS_DIR / info["weight_file"]
        if weight_path.exists():
            print(f"\n[{model_id}] Weights already exist at {weight_path}, skipping.")
            continue

        print(f"\n[{model_id}] Training {info['name']}...")
        model = info["class"](dropout=0.1)
        train_model(model, X, y, epochs=80)

        # Save
        model.eval()
        torch.save(model.state_dict(), weight_path)
        print(f"  Saved: {weight_path} ({weight_path.stat().st_size / 1024:.1f} KB)")

        # Verify
        with torch.no_grad():
            preds = model(X).argmax(-1)
            acc = (preds == y).float().mean().item()
        print(f"  Final accuracy: {acc:.4f}")


if __name__ == "__main__":
    main()
