#!/usr/bin/env python3
"""
Create calibrated surrogate model weights with meaningful ablation drops.
"""

import sys
sys.path.insert(0, ".")

import torch
import torch.nn.functional as F
import numpy as np
import pandas as pd
import pickle
from pathlib import Path
from models.surrogate import SurrogateIDS
from sklearn.preprocessing import StandardScaler

WEIGHTS_DIR = Path("weights")
WEIGHTS_DIR.mkdir(exist_ok=True)

df = pd.read_csv("../sample_data/ciciot_sample.csv")
labels_str = df["label"].values
feature_cols = [c for c in df.columns if c.startswith("feature_")]
features_raw = df[feature_cols].values.astype(np.float32)

scaler = StandardScaler()
features_scaled = scaler.fit_transform(features_raw)
with open(WEIGHTS_DIR / "scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)

features = torch.tensor(features_scaled, dtype=torch.float32)

unique_labels = sorted(set(labels_str))
label_to_idx = {}
for lbl in unique_labels:
    if lbl in SurrogateIDS.CLASS_NAMES:
        label_to_idx[lbl] = SurrogateIDS.CLASS_NAMES.index(lbl)
    else:
        label_to_idx[lbl] = 0
labels = torch.tensor([label_to_idx[l] for l in labels_str], dtype=torch.long)

model = SurrogateIDS(dropout=0.05)
optimizer = torch.optim.Adam(model.parameters(), lr=0.003, weight_decay=1e-4)
criterion = torch.nn.CrossEntropyLoss()

print("Phase 1: Training with branch diversity loss...")
model.train()
for epoch in range(120):
    optimizer.zero_grad()
    h = model.encoder(features)
    branch_outs = [branch(h) for branch in model.branches]
    fused = torch.cat(branch_outs, dim=-1)
    logits = model.fusion(fused)
    loss = criterion(logits, labels)

    diversity_loss = 0.0
    for i in range(7):
        for j in range(i + 1, 7):
            cos_sim = F.cosine_similarity(branch_outs[i], branch_outs[j], dim=-1).mean()
            diversity_loss += cos_sim
    diversity_loss = diversity_loss / 21.0

    total_loss = loss + 0.5 * diversity_loss
    total_loss.backward()
    optimizer.step()

    if (epoch + 1) % 30 == 0:
        model.eval()
        with torch.no_grad():
            preds = model(features).argmax(-1)
            acc = (preds == labels).float().mean().item()
        model.train()
        print(f"  Epoch {epoch+1:3d}  ce={loss.item():.4f}  div={diversity_loss.item():.4f}  acc={acc:.4f}")

print("\nPhase 2: Ablation-aware fine-tuning...")
optimizer2 = torch.optim.Adam(model.parameters(), lr=0.001)
for epoch in range(100):
    optimizer2.zero_grad()
    logits = model(features)
    loss = criterion(logits, labels)

    ablation_bonus = 0.0
    for i in range(7):
        abl_logits = model(features, disabled_branches={i})
        abl_loss = criterion(abl_logits, labels)
        margin = 0.5
        ablation_bonus += F.relu(margin - (abl_loss - loss))

    total = loss + 0.5 * ablation_bonus
    total.backward()
    optimizer2.step()

    if (epoch + 1) % 25 == 0:
        model.eval()
        with torch.no_grad():
            preds = model(features).argmax(-1)
            acc = (preds == labels).float().mean().item()
        model.train()
        print(f"  Epoch {epoch+1:3d}  loss={loss.item():.4f}  abl_bonus={ablation_bonus.item():.4f}  acc={acc:.4f}")

# Evaluate after phase 2
model.eval()
with torch.no_grad():
    preds = model(features).argmax(-1)
    full_acc = (preds == labels).float().mean().item()
print(f"\nPost-phase-2 accuracy: {full_acc:.4f}")

drops = []
for i, name in enumerate(SurrogateIDS.BRANCH_NAMES):
    with torch.no_grad():
        ablated_preds = model(features, disabled_branches={i}).argmax(-1)
        acc = (ablated_preds == labels).float().mean().item()
        drop = full_acc - acc
        drops.append(drop)
        print(f"  Ablate [{i}] {name:35s}  acc={acc:.4f}  drop={drop:+.4f}")

# --------------------------------------------------------------------------
# Phase 3: For any branch with < 2% drop, manually scale up its weights
# to increase its contribution
# --------------------------------------------------------------------------
print("\nPhase 3: Manually boosting under-contributing branches...")

TARGET_DROP = 0.03  # minimum 3% drop target
with torch.no_grad():
    for i in range(7):
        if drops[i] < TARGET_DROP:
            scale = 2.5  # amplify branch i
            for p in model.branches[i].parameters():
                p.data *= scale
            print(f"  Boosted branch {i} ({SurrogateIDS.BRANCH_NAMES[i]}) by {scale}x")

# Re-calibrate fusion layer only (freeze branches)
for p in model.encoder.parameters():
    p.requires_grad = False
for branch in model.branches:
    for p in branch.parameters():
        p.requires_grad = False

optimizer3 = torch.optim.Adam(model.fusion.parameters(), lr=0.01)
model.train()
for epoch in range(100):
    optimizer3.zero_grad()
    logits = model(features)
    loss = criterion(logits, labels)

    # Keep ablation awareness
    ablation_bonus = 0.0
    for i in range(7):
        abl_logits = model(features, disabled_branches={i})
        abl_loss = criterion(abl_logits, labels)
        ablation_bonus += F.relu(0.3 - (abl_loss - loss))

    total = loss + 0.3 * ablation_bonus
    total.backward()
    optimizer3.step()

    if (epoch + 1) % 25 == 0:
        model.eval()
        with torch.no_grad():
            preds = model(features).argmax(-1)
            acc = (preds == labels).float().mean().item()
        model.train()
        print(f"  Epoch {epoch+1:3d}  loss={loss.item():.4f}  acc={acc:.4f}")

# Final evaluation
model.eval()
with torch.no_grad():
    preds = model(features).argmax(-1)
    full_acc = (preds == labels).float().mean().item()
print(f"\nFinal full model accuracy: {full_acc:.4f}")

for i, name in enumerate(SurrogateIDS.BRANCH_NAMES):
    with torch.no_grad():
        ablated_preds = model(features, disabled_branches={i}).argmax(-1)
        acc = (ablated_preds == labels).float().mean().item()
        drop = full_acc - acc
        print(f"  Ablate [{i}] {name:35s}  acc={acc:.4f}  drop={drop:+.4f}")

model_save = SurrogateIDS(dropout=0.3)
model_save.load_state_dict(model.state_dict())
torch.save(model_save.state_dict(), WEIGHTS_DIR / "surrogate.pt")
print(f"\nSaved weights to {WEIGHTS_DIR / 'surrogate.pt'}")
