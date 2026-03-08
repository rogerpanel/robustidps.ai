"""
Federated Learning Simulator — backend engine
===============================================

Simulates privacy-preserving federated learning across multiple virtual
organisations (nodes). Each node trains on a local data partition, then
model updates are aggregated using FedAvg, FedProx, Weighted, or
FedGTD (Federated Graph Temporal Dynamics) strategies.

Optional differential privacy (noise injection) is applied to weight
updates before aggregation.
"""

import copy
import logging
import time
import uuid

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np

logger = logging.getLogger("robustidps.federated")


# ── Aggregation strategies ────────────────────────────────────────────────

def fedavg(global_model: nn.Module, node_models: list[nn.Module],
           weights: list[float] | None = None) -> dict:
    """Federated Averaging."""
    n = len(node_models)
    if weights is None:
        weights = [1.0 / n] * n
    else:
        total = sum(weights)
        weights = [w / total for w in weights]

    global_state = global_model.state_dict()
    avg_state = {}
    for key in global_state:
        avg_state[key] = sum(
            w * node_models[i].state_dict()[key].float()
            for i, w in enumerate(weights)
        ).to(global_state[key].dtype)
    return avg_state


def fedprox_loss(model: nn.Module, global_model: nn.Module, mu: float = 0.01) -> torch.Tensor:
    """Proximal term for FedProx (added to local loss)."""
    proximal = torch.tensor(0.0, device=next(model.parameters()).device)
    for w, w_g in zip(model.parameters(), global_model.parameters()):
        proximal += (w - w_g.detach()).pow(2).sum()
    return (mu / 2) * proximal


def _flatten_params(model: nn.Module) -> torch.Tensor:
    """Flatten all model parameters into a single 1-D tensor."""
    return torch.cat([p.detach().float().reshape(-1) for p in model.parameters()])


def fedgtd(
    global_model: nn.Module,
    node_models: list[nn.Module],
    round_num: int,
    total_rounds: int,
    prev_weights: list[float] | None = None,
    alpha: float = 0.6,
    beta: float = 0.3,
) -> tuple[dict, list[float]]:
    """
    Federated Graph Temporal Dynamics (FedGTD) aggregation.

    Combines two signals to compute per-node aggregation weights:

    1. **Graph similarity** — builds a pairwise cosine-similarity graph over
       each node's gradient update (delta from global).  Nodes whose updates
       are more aligned with the majority receive higher weight, suppressing
       outliers / potentially poisoned nodes.

    2. **Temporal momentum** — blends in the previous round's weights with
       exponential decay so that consistently good contributors accumulate
       influence while transient anomalies are dampened.

    Parameters
    ----------
    global_model : nn.Module
        The current global model before this round's aggregation.
    node_models : list[nn.Module]
        The locally-trained models from each node.
    round_num : int
        Current round number (1-indexed).
    total_rounds : int
        Total number of rounds (used to anneal temporal factor).
    prev_weights : list[float] | None
        Aggregation weights from the previous round (None for round 1).
    alpha : float
        Weight given to graph-similarity component vs. uniform baseline.
    beta : float
        Temporal momentum factor (0 = no memory, 1 = full memory).

    Returns
    -------
    agg_state : dict
        Aggregated state dict for the global model.
    weights : list[float]
        Final normalised weights (to feed as prev_weights next round).
    """
    n = len(node_models)

    # ── 1. Compute gradient-update vectors ────────────────────────────────
    global_flat = _flatten_params(global_model)
    deltas = [_flatten_params(m) - global_flat for m in node_models]

    # ── 2. Build cosine-similarity graph ──────────────────────────────────
    #    sim[i] = mean similarity of node i to all other nodes
    delta_stack = torch.stack(deltas)                       # (n, D)
    norms = delta_stack.norm(dim=1, keepdim=True).clamp(min=1e-8)
    normed = delta_stack / norms                            # unit vectors
    sim_matrix = normed @ normed.T                          # (n, n) cosine sim
    # Zero out self-similarity, average over neighbours
    sim_matrix.fill_diagonal_(0.0)
    graph_scores = sim_matrix.mean(dim=1)                   # (n,)
    # Shift to non-negative and normalise
    graph_scores = graph_scores - graph_scores.min()
    gs_sum = graph_scores.sum()
    if gs_sum > 0:
        graph_weights = (graph_scores / gs_sum).tolist()
    else:
        graph_weights = [1.0 / n] * n

    # ── 3. Blend with uniform baseline (alpha controls strength) ──────────
    blended = [(1.0 - alpha) * (1.0 / n) + alpha * gw for gw in graph_weights]

    # ── 4. Temporal momentum — anneal beta over rounds ────────────────────
    #    Early rounds rely more on graph signal; later rounds accumulate
    decay = beta * (1.0 - (round_num - 1) / max(total_rounds, 1))
    if prev_weights is not None and len(prev_weights) == n:
        final = [(1.0 - decay) * b + decay * pw
                 for b, pw in zip(blended, prev_weights)]
    else:
        final = blended

    # Normalise
    total = sum(final)
    final = [w / total for w in final]

    # ── 5. Weighted aggregation using computed weights ────────────────────
    global_state = global_model.state_dict()
    agg_state = {}
    for key in global_state:
        agg_state[key] = sum(
            final[i] * node_models[i].state_dict()[key].float()
            for i in range(n)
        ).to(global_state[key].dtype)

    return agg_state, final


# ── Differential privacy ─────────────────────────────────────────────────

def add_dp_noise(local_state: dict, global_state: dict,
                 sigma: float = 0.01, clip_norm: float = 1.0) -> dict:
    """
    Apply differential privacy to the weight *update* (delta from global).
    Clips the update norm per-parameter, then adds calibrated Gaussian noise.
    """
    noisy = {}
    for key in local_state:
        param = local_state[key]
        if param.is_floating_point() and key in global_state:
            delta = param - global_state[key]
            # Clip the update (not the full weight)
            delta_norm = delta.norm()
            if delta_norm > clip_norm:
                delta = delta * (clip_norm / delta_norm)
            # Add noise proportional to clip_norm * sigma
            noise = torch.randn_like(delta) * (clip_norm * sigma)
            noisy[key] = global_state[key] + delta + noise
        else:
            noisy[key] = param
    return noisy


# ── Simulator ─────────────────────────────────────────────────────────────

NODE_NAMES = [
    "Enterprise-HQ", "Branch-Office-A", "Branch-Office-B",
    "Cloud-DC-1", "IoT-Gateway", "Remote-SOC",
]


def simulate_federated(
    model: nn.Module,
    features: torch.Tensor,
    labels: torch.Tensor | None = None,
    n_nodes: int = 4,
    rounds: int = 5,
    local_epochs: int = 3,
    lr: float = 0.0001,
    strategy: str = "fedavg",  # fedavg | fedprox | weighted | fedgtd
    dp_enabled: bool = False,
    dp_sigma: float = 0.01,
    dp_clip: float = 1.0,
    iid: bool = True,
) -> dict:
    """
    Run a federated learning simulation.

    Splits data across nodes, trains locally, aggregates, and tracks
    convergence over rounds.
    """
    device = next(model.parameters()).device
    features = features.to(device)
    n_nodes = min(n_nodes, len(NODE_NAMES))

    model.eval()
    with torch.no_grad():
        clean_logits = model(features)
        clean_preds = clean_logits.argmax(-1)
    if labels is None:
        labels = clean_preds.clone()
    else:
        labels = labels.to(device)

    n = len(features)

    # ── Partition data across nodes ───────────────────────────────────────
    if iid:
        # IID: random shuffle + split
        perm = torch.randperm(n)
        splits = torch.chunk(perm, n_nodes)
    else:
        # Non-IID: sort by label, each node gets different classes
        sorted_idx = labels.argsort()
        splits = torch.chunk(sorted_idx, n_nodes)

    node_data = []
    for i, idx in enumerate(splits):
        node_data.append({
            "name": NODE_NAMES[i],
            "features": features[idx],
            "labels": labels[idx],
            "n_samples": len(idx),
        })

    # ── Global model copy ─────────────────────────────────────────────────
    global_model = copy.deepcopy(model)
    global_model.to(device)

    from models.surrogate import SurrogateIDS
    class_names = SurrogateIDS.CLASS_NAMES

    # ── Baseline accuracy ─────────────────────────────────────────────────
    with torch.no_grad():
        global_model.eval()
        base_logits = global_model(features)
        base_acc = (base_logits.argmax(-1) == labels).float().mean().item()

    round_history = []
    prev_gtd_weights: list[float] | None = None   # FedGTD temporal state
    t0 = time.perf_counter()

    # ── Federated rounds ──────────────────────────────────────────────────
    for rnd in range(1, rounds + 1):
        node_results = []
        node_models = []
        node_weights = []

        for ni, nd in enumerate(node_data):
            # Clone global model for local training
            local_model = copy.deepcopy(global_model)
            local_model.train()
            # Use SGD with momentum for stable fine-tuning of pre-trained models
            optimizer = torch.optim.SGD(local_model.parameters(), lr=lr, momentum=0.9)

            local_x = nd["features"]
            local_y = nd["labels"]
            local_losses = []

            for epoch in range(local_epochs):
                optimizer.zero_grad()
                logits = local_model(local_x)
                loss = F.cross_entropy(logits, local_y)

                if strategy == "fedprox":
                    loss += fedprox_loss(local_model, global_model, mu=0.01)

                loss.backward()
                optimizer.step()
                local_losses.append(loss.item())

            # Evaluate local model
            local_model.eval()
            with torch.no_grad():
                local_preds = local_model(local_x).argmax(-1)
                local_acc = (local_preds == local_y).float().mean().item()
                # Also evaluate on full dataset
                full_preds = local_model(features).argmax(-1)
                full_acc = (full_preds == labels).float().mean().item()

            # Apply DP noise if enabled
            local_state = local_model.state_dict()
            if dp_enabled:
                local_state = add_dp_noise(local_state, global_model.state_dict(),
                                           sigma=dp_sigma, clip_norm=dp_clip)
                local_model.load_state_dict(local_state)

            node_models.append(local_model)
            node_weights.append(nd["n_samples"])

            node_results.append({
                "node": nd["name"],
                "n_samples": nd["n_samples"],
                "local_accuracy": round(local_acc, 4),
                "global_accuracy": round(full_acc, 4),
                "final_loss": round(local_losses[-1], 4),
                "loss_curve": [round(l, 4) for l in local_losses],
            })

        # ── Aggregate ─────────────────────────────────────────────────────
        if strategy == "fedgtd":
            agg_state, prev_gtd_weights = fedgtd(
                global_model, node_models,
                round_num=rnd, total_rounds=rounds,
                prev_weights=prev_gtd_weights,
            )
        elif strategy == "weighted":
            agg_state = fedavg(global_model, node_models, weights=node_weights)
        else:
            agg_state = fedavg(global_model, node_models)

        global_model.load_state_dict(agg_state)

        # Global evaluation after aggregation
        global_model.eval()
        with torch.no_grad():
            global_logits = global_model(features)
            global_preds = global_logits.argmax(-1)
            global_acc = (global_preds == labels).float().mean().item()
            global_conf = F.softmax(global_logits, dim=-1).max(-1).values.mean().item()

        round_history.append({
            "round": rnd,
            "global_accuracy": round(global_acc, 4),
            "global_confidence": round(global_conf, 4),
            "nodes": node_results,
        })

    elapsed = time.perf_counter() - t0

    # ── Final per-class metrics ───────────────────────────────────────────
    global_model.eval()
    with torch.no_grad():
        final_logits = global_model(features)
        final_preds = final_logits.argmax(-1)

    per_class = {}
    for ci, cname in enumerate(class_names):
        mask = labels == ci
        if mask.sum() > 0:
            per_class[cname] = {
                "count": int(mask.sum()),
                "accuracy": round(float((final_preds[mask] == labels[mask]).float().mean()), 4),
            }

    return {
        "sim_id": str(uuid.uuid4())[:8],
        "n_nodes": n_nodes,
        "n_rounds": rounds,
        "local_epochs": local_epochs,
        "strategy": strategy,
        "dp_enabled": dp_enabled,
        "dp_sigma": dp_sigma if dp_enabled else None,
        "iid": iid,
        "n_samples_total": n,
        "node_distribution": [
            {"node": nd["name"], "n_samples": nd["n_samples"]}
            for nd in node_data
        ],
        "baseline_accuracy": round(base_acc, 4),
        "final_accuracy": round(global_acc, 4),
        "accuracy_gain": round(global_acc - base_acc, 4),
        "rounds": round_history,
        "per_class": per_class,
        "time_ms": round(elapsed * 1000, 1),
    }
