#!/usr/bin/env python3
"""
Multi-Agent PQC-IDS Evaluation Script.

Evaluates a trained model checkpoint with per-class metrics, confusion matrix,
and agent weight analysis.

Usage:
    python scripts/evaluate.py --checkpoint checkpoints/best_model.pt --csv data/dataset.csv
    python scripts/evaluate.py --checkpoint checkpoints/best_model.pt --csv data/test.csv --plot

Author: Roger Nick Anaedevha
"""

import argparse
import sys
import json
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    classification_report,
    confusion_matrix,
)
from torch.utils.data import DataLoader, TensorDataset

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from models.multi_agent_ids import (
    MultiAgentPQCIDS,
    ATTACK_CLASSES,
    PQC_CLASSES,
)


def load_data(csv_path, attack_col="label", pqc_col="pqc_algorithm", batch_size=512):
    """Load evaluation dataset from CSV."""
    print(f"Loading data from {csv_path}...")
    df = pd.read_csv(csv_path)
    print(f"  Samples: {len(df)}")

    label_cols = [attack_col]
    has_pqc = pqc_col in df.columns
    if has_pqc:
        label_cols.append(pqc_col)

    feature_cols = [c for c in df.columns if c not in label_cols]
    X = df[feature_cols].values.astype(np.float32)

    attack_enc = LabelEncoder()
    y_attack = attack_enc.fit_transform(df[attack_col].values)

    pqc_enc = LabelEncoder()
    if has_pqc:
        y_pqc = pqc_enc.fit_transform(df[pqc_col].values)
    else:
        y_pqc = np.zeros(len(X), dtype=np.int64)

    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    ds = TensorDataset(
        torch.tensor(X, dtype=torch.float32),
        torch.tensor(y_attack, dtype=torch.long),
        torch.tensor(y_pqc, dtype=torch.long),
    )
    loader = DataLoader(ds, batch_size=batch_size, shuffle=False, num_workers=0)
    return loader, attack_enc, pqc_enc


@torch.no_grad()
def run_evaluation(model, loader, device):
    """Run model on all data and collect predictions."""
    model.eval()
    all_attack_preds = []
    all_attack_labels = []
    all_pqc_preds = []
    all_pqc_labels = []
    all_agent_weights = []
    all_anomaly_scores = []

    for x, y_atk, y_pqc in loader:
        x = x.to(device)
        outputs = model(x)

        all_attack_preds.extend(outputs["attack_logits"].argmax(dim=-1).cpu().numpy())
        all_attack_labels.extend(y_atk.numpy())
        all_pqc_preds.extend(outputs["raw_pqc"].argmax(dim=-1).cpu().numpy())
        all_pqc_labels.extend(y_pqc.numpy())
        all_agent_weights.append(outputs["agent_weights"].cpu().numpy())
        all_anomaly_scores.extend(outputs["anomaly_scores"].squeeze(-1).cpu().numpy())

    return {
        "attack_preds": np.array(all_attack_preds),
        "attack_labels": np.array(all_attack_labels),
        "pqc_preds": np.array(all_pqc_preds),
        "pqc_labels": np.array(all_pqc_labels),
        "agent_weights": np.concatenate(all_agent_weights, axis=0),
        "anomaly_scores": np.array(all_anomaly_scores),
    }


def print_metrics(results, attack_enc):
    """Print comprehensive evaluation metrics."""
    y_true = results["attack_labels"]
    y_pred = results["attack_preds"]

    print("\n" + "=" * 70)
    print("ATTACK CLASSIFICATION METRICS")
    print("=" * 70)

    # Overall metrics
    acc = accuracy_score(y_true, y_pred)
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    macro_prec = precision_score(y_true, y_pred, average="macro", zero_division=0)
    macro_rec = recall_score(y_true, y_pred, average="macro", zero_division=0)

    print(f"\nOverall Accuracy:     {acc:.4f}")
    print(f"Macro F1-Score:       {macro_f1:.4f}")
    print(f"Weighted F1-Score:    {weighted_f1:.4f}")
    print(f"Macro Precision:      {macro_prec:.4f}")
    print(f"Macro Recall:         {macro_rec:.4f}")

    # Per-class report
    present_labels = sorted(set(y_true) | set(y_pred))
    target_names = [attack_enc.inverse_transform([i])[0] if i < len(attack_enc.classes_)
                    else f"Class-{i}" for i in present_labels]

    print(f"\nPer-Class Classification Report:")
    print("-" * 70)
    report = classification_report(y_true, y_pred, labels=present_labels,
                                    target_names=target_names, zero_division=0)
    print(report)

    # PQC metrics
    pqc_true = results["pqc_labels"]
    pqc_pred = results["pqc_preds"]
    pqc_acc = accuracy_score(pqc_true, pqc_pred)
    pqc_f1 = f1_score(pqc_true, pqc_pred, average="macro", zero_division=0)

    print("\n" + "=" * 70)
    print("PQC IDENTIFICATION METRICS")
    print("=" * 70)
    print(f"PQC Accuracy:         {pqc_acc:.4f}")
    print(f"PQC Macro F1-Score:   {pqc_f1:.4f}")

    # Agent weight analysis
    weights = results["agent_weights"]
    print("\n" + "=" * 70)
    print("AGENT WEIGHT ANALYSIS")
    print("=" * 70)
    agent_names = ["Traffic Analyst", "PQC Specialist", "Anomaly Detector"]
    for i, name in enumerate(agent_names):
        w = weights[:, i]
        print(f"  {name:20s}: mean={w.mean():.4f}, std={w.std():.4f}, "
              f"min={w.min():.4f}, max={w.max():.4f}")

    # Anomaly score analysis
    anomaly = results["anomaly_scores"]
    print(f"\nAnomaly Scores: mean={anomaly.mean():.4f}, std={anomaly.std():.4f}, "
          f"median={np.median(anomaly):.4f}, max={anomaly.max():.4f}")

    return {
        "accuracy": acc,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "macro_precision": macro_prec,
        "macro_recall": macro_rec,
        "pqc_accuracy": pqc_acc,
        "pqc_macro_f1": pqc_f1,
    }


def plot_confusion_matrix(results, attack_enc, save_path="confusion_matrix.png"):
    """Plot and save confusion matrix."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("Warning: matplotlib not available. Skipping confusion matrix plot.")
        return

    y_true = results["attack_labels"]
    y_pred = results["attack_preds"]
    present_labels = sorted(set(y_true) | set(y_pred))
    target_names = [attack_enc.inverse_transform([i])[0] if i < len(attack_enc.classes_)
                    else f"Class-{i}" for i in present_labels]

    cm = confusion_matrix(y_true, y_pred, labels=present_labels)
    cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True).clip(min=1)

    fig, ax = plt.subplots(figsize=(16, 14))
    im = ax.imshow(cm_norm, interpolation="nearest", cmap="Blues")
    ax.set_title("Multi-Agent PQC-IDS Confusion Matrix (normalised)", fontsize=14)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

    tick_marks = np.arange(len(target_names))
    ax.set_xticks(tick_marks)
    ax.set_xticklabels(target_names, rotation=90, fontsize=7)
    ax.set_yticks(tick_marks)
    ax.set_yticklabels(target_names, fontsize=7)
    ax.set_xlabel("Predicted", fontsize=12)
    ax.set_ylabel("True", fontsize=12)

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    print(f"\nConfusion matrix saved to {save_path}")
    plt.close()


def plot_agent_weights(results, save_path="agent_weights.png"):
    """Plot agent weight distribution."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("Warning: matplotlib not available. Skipping agent weight plot.")
        return

    weights = results["agent_weights"]
    agent_names = ["Traffic Analyst", "PQC Specialist", "Anomaly Detector"]

    fig, axes = plt.subplots(1, 3, figsize=(15, 4))
    for i, (ax, name) in enumerate(zip(axes, agent_names)):
        ax.hist(weights[:, i], bins=50, alpha=0.7, color=f"C{i}")
        ax.set_title(f"{name} Weight", fontsize=11)
        ax.set_xlabel("Weight")
        ax.set_ylabel("Count")
        ax.axvline(weights[:, i].mean(), color="red", linestyle="--", label=f"mean={weights[:, i].mean():.3f}")
        ax.legend()

    plt.suptitle("Coordinator Agent Weight Distributions", fontsize=13)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    print(f"Agent weight plot saved to {save_path}")
    plt.close()


def main():
    parser = argparse.ArgumentParser(description="Evaluate Multi-Agent PQC-IDS")
    parser.add_argument("--checkpoint", type=str, required=True, help="Path to model checkpoint")
    parser.add_argument("--csv", type=str, required=True, help="Path to evaluation CSV")
    parser.add_argument("--attack-col", type=str, default="label", help="Attack label column")
    parser.add_argument("--pqc-col", type=str, default="pqc_algorithm", help="PQC label column")
    parser.add_argument("--batch-size", type=int, default=512, help="Batch size")
    parser.add_argument("--device", type=str, default="auto", help="Device")
    parser.add_argument("--dropout", type=float, default=0.1, help="Dropout (for model init)")
    parser.add_argument("--plot", action="store_true", help="Generate plots")
    parser.add_argument("--output-dir", type=str, default=".", help="Output directory for results")
    args = parser.parse_args()

    # Device
    if args.device == "auto":
        device = "cuda" if torch.cuda.is_available() else "cpu"
    else:
        device = args.device
    print(f"Device: {device}")

    # Load model
    print(f"Loading model from {args.checkpoint}...")
    model = MultiAgentPQCIDS(dropout=args.dropout).to(device)
    checkpoint = torch.load(args.checkpoint, map_location=device, weights_only=True)
    if "model_state_dict" in checkpoint:
        model.load_state_dict(checkpoint["model_state_dict"])
        print(f"  Loaded from epoch {checkpoint.get('epoch', '?')}, "
              f"val_f1={checkpoint.get('val_f1', '?')}")
    else:
        model.load_state_dict(checkpoint)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"  Parameters: {total_params:,}")

    # Load data
    loader, attack_enc, pqc_enc = load_data(
        args.csv, args.attack_col, args.pqc_col, args.batch_size)

    # Run evaluation
    results = run_evaluation(model, loader, device)

    # Print metrics
    metrics = print_metrics(results, attack_enc)

    # Save metrics
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with open(output_dir / "eval_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"\nMetrics saved to {output_dir / 'eval_metrics.json'}")

    # Plots
    if args.plot:
        plot_confusion_matrix(results, attack_enc,
                              save_path=str(output_dir / "confusion_matrix.png"))
        plot_agent_weights(results,
                           save_path=str(output_dir / "agent_weights.png"))

    print("\nEvaluation complete.")


if __name__ == "__main__":
    main()
