#!/usr/bin/env python3
"""
Multi-Agent PQC-IDS Training Script.

Trains the 4-agent cooperative IDS with multi-task loss:
  - Attack classification (cross-entropy)
  - PQC algorithm identification (cross-entropy)
  - Autoencoder reconstruction (MSE)
  - Agent diversity regularisation

Usage:
    python scripts/train.py --config configs/default.yaml
    python scripts/train.py --csv data/dataset.csv --epochs 50 --batch-size 256

Author: Roger Nick Anaedevha
"""

import argparse
import os
import sys
import time
import json
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import f1_score, accuracy_score
from tqdm import tqdm

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from models.multi_agent_ids import (
    MultiAgentPQCIDS,
    ATTACK_CLASSES,
    PQC_CLASSES,
)


def load_config(config_path):
    """Load YAML configuration file."""
    import yaml
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def load_dataset(csv_path, attack_col="label", pqc_col="pqc_algorithm",
                 val_split=0.2, test_split=0.1, seed=42):
    """
    Load and preprocess CSV dataset.

    Args:
        csv_path: Path to CSV file.
        attack_col: Column name for attack labels.
        pqc_col: Column name for PQC algorithm labels.
        val_split: Fraction for validation set.
        test_split: Fraction for test set.
        seed: Random seed.

    Returns:
        Tuple of (train_loader, val_loader, test_loader, label_encoders).
    """
    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    print(f"  Shape: {df.shape}")

    # Separate features and labels
    label_cols = [attack_col]
    has_pqc = pqc_col in df.columns
    if has_pqc:
        label_cols.append(pqc_col)

    feature_cols = [c for c in df.columns if c not in label_cols]
    X = df[feature_cols].values.astype(np.float32)

    # Encode attack labels
    attack_enc = LabelEncoder()
    if attack_col in df.columns:
        y_attack = attack_enc.fit_transform(df[attack_col].values)
    else:
        raise ValueError(f"Attack label column '{attack_col}' not found in CSV.")

    # Encode PQC labels (optional)
    pqc_enc = LabelEncoder()
    if has_pqc:
        y_pqc = pqc_enc.fit_transform(df[pqc_col].values)
    else:
        y_pqc = np.zeros(len(X), dtype=np.int64)
        print("  Warning: No PQC label column found. Using dummy PQC labels.")

    # Normalise features
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    # Train / val / test split
    test_frac = test_split
    val_frac = val_split / (1.0 - test_frac)

    X_trainval, X_test, y_atk_trainval, y_atk_test, y_pqc_trainval, y_pqc_test = \
        train_test_split(X, y_attack, y_pqc, test_size=test_frac, random_state=seed, stratify=y_attack)

    X_train, X_val, y_atk_train, y_atk_val, y_pqc_train, y_pqc_val = \
        train_test_split(X_trainval, y_atk_trainval, y_pqc_trainval,
                         test_size=val_frac, random_state=seed, stratify=y_atk_trainval)

    print(f"  Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")

    def make_loader(X_np, y_atk_np, y_pqc_np, shuffle=True, batch_size=256):
        ds = TensorDataset(
            torch.tensor(X_np, dtype=torch.float32),
            torch.tensor(y_atk_np, dtype=torch.long),
            torch.tensor(y_pqc_np, dtype=torch.long),
        )
        return DataLoader(ds, batch_size=batch_size, shuffle=shuffle, num_workers=0)

    encoders = {"attack": attack_enc, "pqc": pqc_enc, "scaler": scaler}
    return (
        make_loader(X_train, y_atk_train, y_pqc_train),
        make_loader(X_val, y_atk_val, y_pqc_val, shuffle=False),
        make_loader(X_test, y_atk_test, y_pqc_test, shuffle=False),
        encoders,
    )


def compute_loss(outputs, y_attack, y_pqc, x_input, loss_weights):
    """
    Compute multi-task loss.

    Args:
        outputs: Dict from MultiAgentPQCIDS.forward().
        y_attack: Ground-truth attack labels (B,).
        y_pqc: Ground-truth PQC labels (B,).
        x_input: Original input features for reconstruction loss.
        loss_weights: Dict with attack_weight, pqc_weight, recon_weight, diversity_weight.

    Returns:
        Tuple of (total_loss, loss_dict).
    """
    # Attack classification loss
    attack_loss = F.cross_entropy(outputs["raw_attack"], y_attack)

    # PQC identification loss
    pqc_loss = F.cross_entropy(outputs["raw_pqc"], y_pqc)

    # Autoencoder reconstruction loss (anomaly_scores is MSE per sample)
    recon_loss = outputs["anomaly_scores"].mean()

    # Agent diversity regularisation: encourage different attention weights
    # Penalise when one agent dominates (entropy maximisation)
    w = outputs["agent_weights"]  # (B, 3)
    entropy = -(w * (w + 1e-8).log()).sum(dim=-1).mean()
    max_entropy = np.log(3)
    diversity_loss = max_entropy - entropy  # minimise to maximise entropy

    total = (loss_weights["attack"] * attack_loss +
             loss_weights["pqc"] * pqc_loss +
             loss_weights["recon"] * recon_loss +
             loss_weights["diversity"] * diversity_loss)

    loss_dict = {
        "total": total.item(),
        "attack": attack_loss.item(),
        "pqc": pqc_loss.item(),
        "recon": recon_loss.item(),
        "diversity": diversity_loss.item(),
    }
    return total, loss_dict


def train_one_epoch(model, loader, optimizer, device, loss_weights, log_every=10):
    """Train for one epoch."""
    model.train()
    total_loss = 0.0
    n_batches = 0
    all_preds = []
    all_labels = []

    pbar = tqdm(loader, desc="Train", leave=False)
    for batch_idx, (x, y_atk, y_pqc) in enumerate(pbar):
        x, y_atk, y_pqc = x.to(device), y_atk.to(device), y_pqc.to(device)

        optimizer.zero_grad()
        outputs = model(x)
        loss, loss_dict = compute_loss(outputs, y_atk, y_pqc, x, loss_weights)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()

        total_loss += loss_dict["total"]
        n_batches += 1

        preds = outputs["attack_logits"].argmax(dim=-1).cpu().numpy()
        all_preds.extend(preds)
        all_labels.extend(y_atk.cpu().numpy())

        if batch_idx % log_every == 0:
            pbar.set_postfix({
                "loss": f"{loss_dict['total']:.4f}",
                "atk": f"{loss_dict['attack']:.4f}",
                "pqc": f"{loss_dict['pqc']:.4f}",
            })

    avg_loss = total_loss / max(n_batches, 1)
    acc = accuracy_score(all_labels, all_preds)
    f1 = f1_score(all_labels, all_preds, average="macro", zero_division=0)
    return avg_loss, acc, f1


@torch.no_grad()
def evaluate(model, loader, device, loss_weights):
    """Evaluate model on a data loader."""
    model.eval()
    total_loss = 0.0
    n_batches = 0
    all_preds = []
    all_labels = []
    all_pqc_preds = []
    all_pqc_labels = []

    for x, y_atk, y_pqc in loader:
        x, y_atk, y_pqc = x.to(device), y_atk.to(device), y_pqc.to(device)
        outputs = model(x)
        _, loss_dict = compute_loss(outputs, y_atk, y_pqc, x, loss_weights)

        total_loss += loss_dict["total"]
        n_batches += 1

        all_preds.extend(outputs["attack_logits"].argmax(dim=-1).cpu().numpy())
        all_labels.extend(y_atk.cpu().numpy())
        all_pqc_preds.extend(outputs["raw_pqc"].argmax(dim=-1).cpu().numpy())
        all_pqc_labels.extend(y_pqc.cpu().numpy())

    avg_loss = total_loss / max(n_batches, 1)
    acc = accuracy_score(all_labels, all_preds)
    f1 = f1_score(all_labels, all_preds, average="macro", zero_division=0)
    pqc_acc = accuracy_score(all_pqc_labels, all_pqc_preds)
    return avg_loss, acc, f1, pqc_acc


def build_scheduler(optimizer, name, params, epochs):
    """Build learning rate scheduler."""
    if name == "cosine":
        return torch.optim.lr_scheduler.CosineAnnealingLR(
            optimizer, T_max=params.get("T_max", epochs))
    elif name == "step":
        return torch.optim.lr_scheduler.StepLR(
            optimizer, step_size=params.get("step_size", 30),
            gamma=params.get("gamma", 0.1))
    elif name == "plateau":
        return torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, mode="max", patience=params.get("patience", 10),
            factor=params.get("factor", 0.5))
    else:
        return None


def main():
    parser = argparse.ArgumentParser(description="Train Multi-Agent PQC-IDS")
    parser.add_argument("--config", type=str, default=None, help="Path to YAML config file")
    parser.add_argument("--csv", type=str, default=None, help="Path to CSV dataset")
    parser.add_argument("--epochs", type=int, default=100, help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=256, help="Batch size")
    parser.add_argument("--lr", type=float, default=0.001, help="Learning rate")
    parser.add_argument("--dropout", type=float, default=0.1, help="Dropout rate")
    parser.add_argument("--device", type=str, default="auto", help="Device (cpu/cuda/auto)")
    parser.add_argument("--save-dir", type=str, default="checkpoints", help="Checkpoint directory")
    parser.add_argument("--attack-col", type=str, default="label", help="Attack label column name")
    parser.add_argument("--pqc-col", type=str, default="pqc_algorithm", help="PQC label column name")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    # Load config if provided
    cfg = {}
    if args.config:
        cfg = load_config(args.config)

    # Resolve parameters (CLI overrides config)
    csv_path = args.csv or cfg.get("data", {}).get("csv_path")
    if not csv_path:
        print("Error: No CSV path provided. Use --csv or set data.csv_path in config.")
        sys.exit(1)

    epochs = args.epochs if args.epochs != 100 else cfg.get("training", {}).get("epochs", 100)
    batch_size = args.batch_size if args.batch_size != 256 else cfg.get("training", {}).get("batch_size", 256)
    lr = args.lr if args.lr != 0.001 else cfg.get("training", {}).get("learning_rate", 0.001)
    dropout = args.dropout if args.dropout != 0.1 else cfg.get("model", {}).get("dropout", 0.1)
    save_dir = Path(args.save_dir)
    seed = args.seed

    # Device
    if args.device == "auto":
        device = "cuda" if torch.cuda.is_available() else "cpu"
    else:
        device = args.device
    print(f"Device: {device}")

    # Seed
    torch.manual_seed(seed)
    np.random.seed(seed)

    # Loss weights
    loss_cfg = cfg.get("loss", {})
    loss_weights = {
        "attack": loss_cfg.get("attack_weight", 1.0),
        "pqc": loss_cfg.get("pqc_weight", 0.5),
        "recon": loss_cfg.get("recon_weight", 0.3),
        "diversity": loss_cfg.get("diversity_weight", 0.1),
    }

    # Load data
    train_loader, val_loader, test_loader, encoders = load_dataset(
        csv_path,
        attack_col=args.attack_col,
        pqc_col=args.pqc_col,
        val_split=cfg.get("data", {}).get("val_split", 0.2),
        test_split=cfg.get("data", {}).get("test_split", 0.1),
        seed=seed,
    )

    # Build model
    model = MultiAgentPQCIDS(dropout=dropout).to(device)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"Model parameters: {total_params:,}")

    # Optimiser and scheduler
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr,
                                   weight_decay=cfg.get("training", {}).get("weight_decay", 1e-4))
    sched_name = cfg.get("training", {}).get("scheduler", "cosine")
    sched_params = cfg.get("training", {}).get("scheduler_params", {})
    scheduler = build_scheduler(optimizer, sched_name, sched_params, epochs)

    # Checkpoint setup
    save_dir.mkdir(parents=True, exist_ok=True)
    save_every = cfg.get("checkpoint", {}).get("save_every", 10)
    best_f1 = 0.0
    log_every = cfg.get("logging", {}).get("log_every", 10)

    # Training loop
    print(f"\nStarting training for {epochs} epochs...")
    print(f"  Loss weights: {loss_weights}")
    print(f"  Scheduler: {sched_name}")
    print("-" * 70)

    history = []
    for epoch in range(1, epochs + 1):
        t0 = time.time()

        train_loss, train_acc, train_f1 = train_one_epoch(
            model, train_loader, optimizer, device, loss_weights, log_every)

        val_loss, val_acc, val_f1, val_pqc_acc = evaluate(
            model, val_loader, device, loss_weights)

        elapsed = time.time() - t0

        # Step scheduler
        if scheduler is not None:
            if sched_name == "plateau":
                scheduler.step(val_f1)
            else:
                scheduler.step()

        current_lr = optimizer.param_groups[0]["lr"]

        print(f"Epoch {epoch:3d}/{epochs} | "
              f"Train Loss: {train_loss:.4f} Acc: {train_acc:.4f} F1: {train_f1:.4f} | "
              f"Val Loss: {val_loss:.4f} Acc: {val_acc:.4f} F1: {val_f1:.4f} PQC-Acc: {val_pqc_acc:.4f} | "
              f"LR: {current_lr:.6f} | {elapsed:.1f}s")

        history.append({
            "epoch": epoch,
            "train_loss": train_loss, "train_acc": train_acc, "train_f1": train_f1,
            "val_loss": val_loss, "val_acc": val_acc, "val_f1": val_f1,
            "val_pqc_acc": val_pqc_acc, "lr": current_lr,
        })

        # Save best model
        if val_f1 > best_f1:
            best_f1 = val_f1
            torch.save({
                "epoch": epoch,
                "model_state_dict": model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
                "val_f1": val_f1,
                "val_acc": val_acc,
            }, save_dir / "best_model.pt")
            print(f"  -> New best model saved (F1={val_f1:.4f})")

        # Periodic checkpoint
        if epoch % save_every == 0:
            torch.save({
                "epoch": epoch,
                "model_state_dict": model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
            }, save_dir / f"checkpoint_epoch{epoch:03d}.pt")

    # Final evaluation on test set
    print("\n" + "=" * 70)
    print("Final evaluation on test set:")
    test_loss, test_acc, test_f1, test_pqc_acc = evaluate(
        model, test_loader, device, loss_weights)
    print(f"  Test Loss: {test_loss:.4f}")
    print(f"  Test Accuracy: {test_acc:.4f}")
    print(f"  Test Macro-F1: {test_f1:.4f}")
    print(f"  Test PQC Accuracy: {test_pqc_acc:.4f}")

    # Save final model
    torch.save(model.state_dict(), save_dir / "final_model.pt")
    print(f"\nFinal model saved to {save_dir / 'final_model.pt'}")

    # Save training history
    with open(save_dir / "history.json", "w") as f:
        json.dump(history, f, indent=2)
    print(f"Training history saved to {save_dir / 'history.json'}")

    print(f"\nBest validation F1: {best_f1:.4f}")
    print("Training complete.")


if __name__ == "__main__":
    main()
