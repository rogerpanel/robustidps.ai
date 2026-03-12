"""
Federated Learning Simulator — backend engine
===============================================

Simulates privacy-preserving federated learning across multiple virtual
organisations (nodes). Each node trains on a local data partition, then
model updates are aggregated using FedAvg, FedProx, Weighted, or
FedGTD (Federated Graph Temporal Dynamics) strategies.

FedGTD enhanced with:
- Byzantine-resilient aggregation (cosine similarity detection + trimmed mean)
- Stochastic game dynamics (SDE with Poisson jumps, Nash equilibrium)
- Martingale convergence analysis (Lyapunov function tracking)
- Knowledge distillation metrics
- Transfer learning capability analysis

Based on: "Byzantine-Resilient Stochastic Games for Federated Multi-Cloud
Intrusion Detection" (Anaedevha et al.)

Optional differential privacy (noise injection) is applied to weight
updates before aggregation.
"""

import copy
import logging
import math
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


# ── Byzantine-Resilient FedGTD (Algorithm 1 from paper) ──────────────────

def _detect_byzantine(
    deltas: list[torch.Tensor],
    tau: float = 0.3,
    proj_dim: int = 10,
) -> list[bool]:
    """
    Projection-based Byzantine detection via pairwise cosine similarity.

    Projects gradient updates into a low-dimensional subspace and flags
    nodes whose median similarity to peers falls below threshold tau.
    """
    n = len(deltas)
    if n < 3:
        return [False] * n

    delta_stack = torch.stack(deltas)  # (n, D)
    D = delta_stack.shape[1]

    # Project to lower-dimensional subspace for robust comparison
    actual_proj_dim = min(proj_dim, D)
    proj_matrix = torch.randn(D, actual_proj_dim, device=delta_stack.device)
    proj_matrix = proj_matrix / proj_matrix.norm(dim=0, keepdim=True).clamp(min=1e-8)
    projected = delta_stack @ proj_matrix  # (n, proj_dim)

    # Pairwise cosine similarity in projected space
    norms = projected.norm(dim=1, keepdim=True).clamp(min=1e-8)
    normed = projected / norms
    sim_matrix = normed @ normed.T  # (n, n)
    sim_matrix.fill_diagonal_(1.0)

    # Flag nodes with low median similarity
    flagged = []
    for i in range(n):
        peers = [sim_matrix[i, j].item() for j in range(n) if j != i]
        median_sim = sorted(peers)[len(peers) // 2]
        flagged.append(median_sim < tau)

    return flagged


def _trimmed_mean_aggregate(
    global_model: nn.Module,
    node_models: list[nn.Module],
    weights: list[float],
    trim_fraction: float = 0.1,
) -> dict:
    """
    Coordinate-wise trimmed mean aggregation.

    For each parameter coordinate, sorts values across nodes, trims top
    and bottom fraction, then takes weighted average of remaining values.
    """
    global_state = global_model.state_dict()
    n = len(node_models)
    trim_count = max(1, int(n * trim_fraction)) if n > 3 else 0

    agg_state = {}
    for key in global_state:
        params = torch.stack([m.state_dict()[key].float() for m in node_models])
        if trim_count > 0 and params.dim() > 0:
            sorted_params, _ = params.sort(dim=0)
            trimmed = sorted_params[trim_count:n - trim_count]
            # Renormalise weights for remaining nodes
            if trimmed.shape[0] > 0:
                agg_state[key] = trimmed.mean(dim=0).to(global_state[key].dtype)
            else:
                agg_state[key] = params.mean(dim=0).to(global_state[key].dtype)
        else:
            w_tensor = torch.tensor(weights, device=params.device).reshape(-1, *([1] * (params.dim() - 1)))
            agg_state[key] = (params * w_tensor).sum(dim=0).to(global_state[key].dtype)

    return agg_state


def fedgtd(
    global_model: nn.Module,
    node_models: list[nn.Module],
    round_num: int,
    total_rounds: int,
    prev_weights: list[float] | None = None,
    alpha: float = 0.6,
    beta: float = 0.3,
    byzantine_detection: bool = True,
    trim_fraction: float = 0.1,
) -> tuple[dict, list[float], dict]:
    """
    Enhanced Federated Graph Temporal Dynamics (FedGTD) aggregation.

    Implements Algorithm 1 from the FedGTD Stochastic Games paper:

    1. **Gradient clipping** — clips update norms per-node
    2. **Byzantine detection** — projection-based cosine similarity flagging
    3. **Graph similarity** — pairwise cosine-similarity graph for weighting
    4. **Temporal momentum** — exponentially decayed blending with history
    5. **Trimmed mean aggregation** — coordinate-wise robust aggregation
    6. **Reputation tracking** — nodes flagged as Byzantine lose reputation

    Returns
    -------
    agg_state : dict
        Aggregated state dict for the global model.
    weights : list[float]
        Final normalised weights (to feed as prev_weights next round).
    analytics : dict
        Enhanced analytics including Byzantine flags, reputation scores,
        similarity matrix, and game dynamics metrics.
    """
    n = len(node_models)

    # ── 1. Compute gradient-update vectors & clip ─────────────────────────
    global_flat = _flatten_params(global_model)
    deltas = [_flatten_params(m) - global_flat for m in node_models]

    # Clip gradient norms (domain-adaptive from paper Table 2)
    clip_norm = 1.0
    for i, d in enumerate(deltas):
        d_norm = d.norm()
        if d_norm > clip_norm:
            deltas[i] = d * (clip_norm / d_norm)

    # ── 2. Byzantine detection ────────────────────────────────────────────
    byzantine_flags = [False] * n
    reputation_scores = [1.0] * n
    if byzantine_detection and n >= 3:
        byzantine_flags = _detect_byzantine(deltas, tau=0.3)
        # Halve reputation of flagged nodes
        for i in range(n):
            if byzantine_flags[i]:
                reputation_scores[i] = 0.5

    # ── 3. Build cosine-similarity graph ──────────────────────────────────
    delta_stack = torch.stack(deltas)  # (n, D)
    norms = delta_stack.norm(dim=1, keepdim=True).clamp(min=1e-8)
    normed = delta_stack / norms
    sim_matrix = normed @ normed.T  # (n, n) cosine sim
    sim_matrix_np = sim_matrix.detach().cpu().numpy()

    # Zero out self-similarity for scoring
    sim_for_scoring = sim_matrix.clone()
    sim_for_scoring.fill_diagonal_(0.0)
    graph_scores = sim_for_scoring.mean(dim=1)  # (n,)

    # Shift to non-negative and normalise
    graph_scores = graph_scores - graph_scores.min()
    gs_sum = graph_scores.sum()
    if gs_sum > 0:
        graph_weights = (graph_scores / gs_sum).tolist()
    else:
        graph_weights = [1.0 / n] * n

    # Apply reputation penalty
    for i in range(n):
        graph_weights[i] *= reputation_scores[i]

    # Re-normalise
    gw_sum = sum(graph_weights)
    if gw_sum > 0:
        graph_weights = [w / gw_sum for w in graph_weights]

    # ── 4. Blend with uniform baseline (alpha controls strength) ──────────
    blended = [(1.0 - alpha) * (1.0 / n) + alpha * gw for gw in graph_weights]

    # ── 5. Temporal momentum — anneal beta over rounds ────────────────────
    decay = beta * (1.0 - (round_num - 1) / max(total_rounds, 1))
    if prev_weights is not None and len(prev_weights) == n:
        final = [(1.0 - decay) * b + decay * pw
                 for b, pw in zip(blended, prev_weights)]
    else:
        final = blended

    # Normalise
    total = sum(final)
    final = [w / total for w in final]

    # ── 6. Robust aggregation ─────────────────────────────────────────────
    if any(byzantine_flags) and n > 3:
        # Use trimmed mean for Byzantine-resilient aggregation
        agg_state = _trimmed_mean_aggregate(
            global_model, node_models, final, trim_fraction=trim_fraction,
        )
    else:
        # Standard weighted aggregation
        global_state = global_model.state_dict()
        agg_state = {}
        for key in global_state:
            agg_state[key] = sum(
                final[i] * node_models[i].state_dict()[key].float()
                for i in range(n)
            ).to(global_state[key].dtype)

    # ── Analytics ─────────────────────────────────────────────────────────
    analytics = {
        "byzantine_flags": byzantine_flags,
        "n_byzantine_detected": sum(byzantine_flags),
        "reputation_scores": [round(r, 3) for r in reputation_scores],
        "graph_weights": [round(w, 4) for w in graph_weights],
        "final_weights": [round(w, 4) for w in final],
        "temporal_decay": round(decay, 4),
        "similarity_matrix": [[round(float(sim_matrix_np[i][j]), 3) for j in range(n)] for i in range(n)],
        "gradient_norms": [round(d.norm().item(), 4) for d in deltas],
    }

    return agg_state, final, analytics


# ── Stochastic Game Dynamics (SDE + Nash Equilibrium) ────────────────────

def _compute_game_dynamics(
    node_models: list[nn.Module],
    global_model: nn.Module,
    round_num: int,
    total_rounds: int,
) -> dict:
    """
    Stochastic Differential Game dynamics from Theorem 1 of the paper.

    Models the attack/defense dynamics using an Euler-Maruyama SDE with
    compound Poisson jump processes.

    State update: dX = mu*dt + Sigma*dW + J*dN(lambda)
    """
    n = len(node_models)
    dt = 0.01
    jump_rate = 0.01
    jump_magnitude = 0.1

    global_flat = _flatten_params(global_model)

    # Compute drift (mu) = mean gradient direction
    deltas = [_flatten_params(m) - global_flat for m in node_models]
    delta_stack = torch.stack(deltas)
    mu = delta_stack.mean(dim=0)  # drift
    drift_magnitude = mu.norm().item()

    # Compute diffusion (Sigma) = std of gradients
    sigma = delta_stack.std(dim=0)
    diffusion_magnitude = sigma.mean().item()

    # Simulate Poisson jump
    poisson_event = np.random.poisson(jump_rate)
    jump_term = jump_magnitude * poisson_event

    # SDE state evolution (scalar summary)
    state_norm = global_flat.norm().item()
    dX = drift_magnitude * dt + diffusion_magnitude * math.sqrt(dt) * np.random.randn() + jump_term

    # Nash equilibrium approximation via payoff matrix
    # Payoff: U(i,j) = sqrt(1/rho)*R_detect - sqrt(rho)*C_fp
    nash_gap = 0.0
    game_value = 0.0
    defender_strategy = [1.0 / n] * n

    if n >= 2:
        # Build simplified payoff matrix from pairwise model performance
        norms = delta_stack.norm(dim=1)
        norm_vals = norms.detach().cpu().numpy()

        # Defender strategy: proportional to inverse update norm (stable nodes preferred)
        inv_norms = 1.0 / (norm_vals + 1e-8)
        defender_strategy = (inv_norms / inv_norms.sum()).tolist()

        # Nash gap: max deviation gain from current strategy
        mean_payoff = np.mean(norm_vals)
        nash_gap = float(np.max(np.abs(norm_vals - mean_payoff)) / (mean_payoff + 1e-8))

        # Game value: weighted payoff under Nash equilibrium
        game_value = float(np.sum(np.array(defender_strategy) * norm_vals))

    # Convergence progress (time ratio)
    t_ratio = round_num / max(total_rounds, 1)

    return {
        "drift_magnitude": round(drift_magnitude, 6),
        "diffusion_magnitude": round(diffusion_magnitude, 6),
        "poisson_jumps": poisson_event,
        "jump_term": round(jump_term, 6),
        "sde_state_delta": round(dX, 6),
        "state_norm": round(state_norm, 4),
        "nash_gap": round(nash_gap, 4),
        "game_value": round(game_value, 6),
        "defender_strategy": [round(s, 4) for s in defender_strategy],
        "time_ratio": round(t_ratio, 4),
    }


# ── Convergence Analysis (Theorem 4: Martingale/Lyapunov) ────────────────

class ConvergenceAnalyzer:
    """
    Martingale convergence analyzer implementing Theorem 4 from the paper.

    Tracks:
    - Lyapunov function V(t) = sum_d omega_d * ||theta_d - theta_d*||^2
    - Domain-adaptive learning rate schedule: eta_d(t) = eta_d^(0) * sqrt(rho_d) / (t+1)^{2/3}
    - Nash gap convergence
    - Supermartingale condition (V non-increasing)
    """

    def __init__(self):
        self.lyapunov_history: list[float] = []
        self.nash_gap_history: list[float] = []
        self.lr_history: list[float] = []
        self.convergence_detected = False
        self.convergence_round: int | None = None

    def compute_lyapunov(
        self,
        global_model: nn.Module,
        node_models: list[nn.Module],
        round_num: int,
        base_lr: float,
    ) -> dict:
        """Compute Lyapunov function value and convergence metrics."""
        global_flat = _flatten_params(global_model)
        n = len(node_models)

        # omega_d = 1/rho_d (uniform for simulation)
        omega = [1.0 / n] * n

        # V(t) = sum_d omega_d * ||theta_d - theta*||^2
        lyapunov = 0.0
        node_divergences = []
        for i, m in enumerate(node_models):
            local_flat = _flatten_params(m)
            div = (local_flat - global_flat).pow(2).sum().item()
            lyapunov += omega[i] * div
            node_divergences.append(round(div, 6))

        self.lyapunov_history.append(lyapunov)

        # Domain-adaptive LR schedule: eta(t) = eta_0 / (t+1)^{2/3}
        adaptive_lr = base_lr / ((round_num + 1) ** (2.0 / 3.0))
        self.lr_history.append(adaptive_lr)

        # Check supermartingale condition
        is_decreasing = True
        if len(self.lyapunov_history) >= 2:
            is_decreasing = self.lyapunov_history[-1] <= self.lyapunov_history[-2] * 1.05

        # Convergence rate estimation: fit V(t) ~ V(0)*exp(-r*t)
        convergence_rate = 0.0
        if len(self.lyapunov_history) >= 3 and self.lyapunov_history[0] > 0:
            ratios = []
            for j in range(1, len(self.lyapunov_history)):
                if self.lyapunov_history[j - 1] > 1e-10:
                    ratios.append(self.lyapunov_history[j] / self.lyapunov_history[j - 1])
            if ratios:
                avg_ratio = sum(ratios) / len(ratios)
                if avg_ratio > 0 and avg_ratio < 1:
                    convergence_rate = -math.log(avg_ratio)

        # Check convergence (Lyapunov non-increasing for 3 consecutive rounds)
        window = 3
        if len(self.lyapunov_history) >= window and not self.convergence_detected:
            recent = self.lyapunov_history[-window:]
            if all(recent[j] <= recent[j - 1] * 1.01 for j in range(1, window)):
                self.convergence_detected = True
                self.convergence_round = round_num

        return {
            "lyapunov_value": round(lyapunov, 6),
            "lyapunov_history": [round(v, 6) for v in self.lyapunov_history],
            "node_divergences": node_divergences,
            "adaptive_lr": round(adaptive_lr, 8),
            "is_supermartingale": is_decreasing,
            "convergence_rate": round(convergence_rate, 6),
            "convergence_detected": self.convergence_detected,
            "convergence_round": self.convergence_round,
        }


# ── Knowledge Distillation Metrics ───────────────────────────────────────

def _compute_distillation_metrics(
    global_model: nn.Module,
    node_models: list[nn.Module],
    features: torch.Tensor,
    labels: torch.Tensor,
    temperature: float = 3.0,
) -> dict:
    """
    Compute knowledge distillation metrics between global (teacher) and
    local (student) models.
    """
    global_model.eval()
    n = len(node_models)

    with torch.no_grad():
        teacher_logits = global_model(features)
        teacher_probs = F.softmax(teacher_logits / temperature, dim=-1)

    kd_losses = []
    agreement_rates = []
    confidence_gaps = []

    for m in node_models:
        m.eval()
        with torch.no_grad():
            student_logits = m(features)
            student_probs = F.softmax(student_logits / temperature, dim=-1)

            # KL divergence (distillation loss)
            kl = F.kl_div(
                student_probs.log().clamp(min=-100),
                teacher_probs,
                reduction='batchmean',
            ).item() * (temperature ** 2)
            kd_losses.append(kl)

            # Prediction agreement
            teacher_preds = teacher_logits.argmax(-1)
            student_preds = student_logits.argmax(-1)
            agreement = (teacher_preds == student_preds).float().mean().item()
            agreement_rates.append(agreement)

            # Confidence gap
            teacher_conf = F.softmax(teacher_logits, dim=-1).max(-1).values.mean().item()
            student_conf = F.softmax(student_logits, dim=-1).max(-1).values.mean().item()
            confidence_gaps.append(teacher_conf - student_conf)

    return {
        "kd_losses": [round(l, 4) for l in kd_losses],
        "mean_kd_loss": round(sum(kd_losses) / max(n, 1), 4),
        "agreement_rates": [round(a, 4) for a in agreement_rates],
        "mean_agreement": round(sum(agreement_rates) / max(n, 1), 4),
        "confidence_gaps": [round(g, 4) for g in confidence_gaps],
        "mean_confidence_gap": round(sum(confidence_gaps) / max(n, 1), 4),
    }


# ── Transfer Learning Analytics ──────────────────────────────────────────

def compute_transfer_metrics(
    model: nn.Module,
    source_features: torch.Tensor,
    source_labels: torch.Tensor,
    target_features: torch.Tensor,
    target_labels: torch.Tensor,
) -> dict:
    """
    Compute transfer learning capability metrics between source and target
    datasets/domains.

    Measures:
    - Direct transfer accuracy (model trained on source, evaluated on target)
    - Feature similarity (CKA-lite via linear kernel alignment)
    - Domain divergence (MMD approximation)
    - Transferability score (composite)
    """
    model.eval()
    device = next(model.parameters()).device
    source_features = source_features.to(device)
    target_features = target_features.to(device)

    # Generate pseudo-labels from model predictions if labels are missing
    if source_labels is None:
        with torch.no_grad():
            source_labels = model(source_features).argmax(-1)
    else:
        source_labels = source_labels.to(device)
    if target_labels is None:
        with torch.no_grad():
            target_labels = model(target_features).argmax(-1)
    else:
        target_labels = target_labels.to(device)

    with torch.no_grad():
        # Direct transfer accuracy
        source_logits = model(source_features)
        source_acc = (source_logits.argmax(-1) == source_labels).float().mean().item()

        target_logits = model(target_features)
        target_acc = (target_logits.argmax(-1) == target_labels).float().mean().item()

        # Feature representations (use logits as feature proxy)
        source_probs = F.softmax(source_logits, dim=-1)
        target_probs = F.softmax(target_logits, dim=-1)

        # CKA-lite: linear kernel alignment between source and target features
        # Subsample for efficiency
        max_samples = min(500, len(source_probs), len(target_probs))
        src_sub = source_probs[:max_samples]
        tgt_sub = target_probs[:max_samples]

        # Centering
        src_centered = src_sub - src_sub.mean(0)
        tgt_centered = tgt_sub - tgt_sub.mean(0)

        # Linear CKA
        src_gram = src_centered @ src_centered.T
        tgt_gram = tgt_centered @ tgt_centered.T

        hsic_st = (src_gram * tgt_gram).sum()
        hsic_ss = (src_gram * src_gram).sum()
        hsic_tt = (tgt_gram * tgt_gram).sum()

        cka = hsic_st / (torch.sqrt(hsic_ss * hsic_tt) + 1e-10)
        feature_similarity = cka.item()

        # MMD (Maximum Mean Discrepancy) approximation
        src_mean = source_probs.mean(0)
        tgt_mean = target_probs.mean(0)
        mmd = (src_mean - tgt_mean).pow(2).sum().sqrt().item()

        # Class distribution overlap (Jensen-Shannon divergence)
        n_classes = source_logits.shape[1]
        src_class_dist = torch.zeros(n_classes, device=device)
        tgt_class_dist = torch.zeros(n_classes, device=device)
        for c in range(n_classes):
            src_class_dist[c] = (source_labels == c).float().sum()
            tgt_class_dist[c] = (target_labels == c).float().sum()
        src_class_dist = src_class_dist / src_class_dist.sum().clamp(min=1)
        tgt_class_dist = tgt_class_dist / tgt_class_dist.sum().clamp(min=1)

        m_dist = 0.5 * (src_class_dist + tgt_class_dist)
        js_div = 0.5 * (
            F.kl_div(m_dist.log().clamp(min=-100), src_class_dist, reduction='sum').item()
            + F.kl_div(m_dist.log().clamp(min=-100), tgt_class_dist, reduction='sum').item()
        )
        class_overlap = max(0.0, 1.0 - js_div)

        # Composite transferability score
        transfer_score = (
            0.3 * min(feature_similarity, 1.0)
            + 0.3 * (1.0 - min(mmd, 1.0))
            + 0.2 * class_overlap
            + 0.2 * target_acc
        )

        # Confidence calibration on target
        target_conf = F.softmax(target_logits, dim=-1).max(-1).values
        mean_target_conf = target_conf.mean().item()

        # Per-class transfer accuracy
        per_class_transfer = {}
        from models.surrogate import SurrogateIDS
        class_names = SurrogateIDS.CLASS_NAMES
        for ci, cname in enumerate(class_names):
            src_mask = source_labels == ci
            tgt_mask = target_labels == ci
            pc = {}
            if src_mask.sum() > 0:
                pc["source_count"] = int(src_mask.sum())
                pc["source_accuracy"] = round((source_logits.argmax(-1)[src_mask] == source_labels[src_mask]).float().mean().item(), 4)
            if tgt_mask.sum() > 0:
                pc["target_count"] = int(tgt_mask.sum())
                pc["target_accuracy"] = round((target_logits.argmax(-1)[tgt_mask] == target_labels[tgt_mask]).float().mean().item(), 4)
            if pc:
                per_class_transfer[cname] = pc

    return {
        "source_accuracy": round(source_acc, 4),
        "target_accuracy": round(target_acc, 4),
        "accuracy_drop": round(source_acc - target_acc, 4),
        "feature_similarity_cka": round(min(max(feature_similarity, 0), 1), 4),
        "domain_divergence_mmd": round(mmd, 4),
        "class_distribution_overlap": round(class_overlap, 4),
        "transferability_score": round(min(max(transfer_score, 0), 1), 4),
        "target_mean_confidence": round(mean_target_conf, 4),
        "per_class_transfer": per_class_transfer,
    }


def compute_cross_model_transfer(
    models: dict[str, nn.Module],
    features: torch.Tensor,
    labels: torch.Tensor,
) -> dict:
    """
    Compute transfer learning similarity between multiple models on the
    same dataset (representation alignment).
    """
    device = features.device
    model_names = list(models.keys())
    n = len(model_names)

    # Generate pseudo-labels if labels are missing
    if labels is None:
        first_model = next(iter(models.values()))
        first_model.eval()
        with torch.no_grad():
            labels = first_model(features).argmax(-1)

    # Get predictions and features from each model
    model_outputs = {}
    for name, model in models.items():
        model.eval()
        with torch.no_grad():
            logits = model(features)
            probs = F.softmax(logits, dim=-1)
            preds = logits.argmax(-1)
            acc = (preds == labels).float().mean().item()
            model_outputs[name] = {
                "probs": probs,
                "preds": preds,
                "accuracy": acc,
            }

    # Pairwise prediction agreement matrix
    agreement_matrix = {}
    for i, m1 in enumerate(model_names):
        for j, m2 in enumerate(model_names):
            if i <= j:
                agree = (model_outputs[m1]["preds"] == model_outputs[m2]["preds"]).float().mean().item()
                agreement_matrix[f"{m1}|{m2}"] = round(agree, 4)

    # Pairwise representation similarity (CKA-lite)
    representation_similarity = {}
    max_samples = min(500, len(features))
    for i, m1 in enumerate(model_names):
        for j, m2 in enumerate(model_names):
            if i < j:
                p1 = model_outputs[m1]["probs"][:max_samples]
                p2 = model_outputs[m2]["probs"][:max_samples]
                p1c = p1 - p1.mean(0)
                p2c = p2 - p2.mean(0)
                g1 = p1c @ p1c.T
                g2 = p2c @ p2c.T
                hsic = (g1 * g2).sum()
                norm = torch.sqrt((g1 * g1).sum() * (g2 * g2).sum()) + 1e-10
                cka = (hsic / norm).item()
                representation_similarity[f"{m1}|{m2}"] = round(min(max(cka, 0), 1), 4)

    # Ensemble diversity (disagreement measure)
    if n >= 2:
        all_preds = torch.stack([model_outputs[m]["preds"] for m in model_names])
        diversity_pairs = []
        for i in range(n):
            for j in range(i + 1, n):
                disagree = (all_preds[i] != all_preds[j]).float().mean().item()
                diversity_pairs.append(disagree)
        ensemble_diversity = sum(diversity_pairs) / len(diversity_pairs)
    else:
        ensemble_diversity = 0.0

    return {
        "model_accuracies": {name: round(model_outputs[name]["accuracy"], 4) for name in model_names},
        "prediction_agreement": agreement_matrix,
        "representation_similarity": representation_similarity,
        "ensemble_diversity": round(ensemble_diversity, 4),
    }


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
    Run a federated learning simulation with enhanced analytics.

    Splits data across nodes, trains locally, aggregates, and tracks
    convergence over rounds. For FedGTD strategy, includes Byzantine
    detection, game dynamics, and convergence analysis.
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
        perm = torch.randperm(n)
        splits = torch.chunk(perm, n_nodes)
    else:
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
    prev_gtd_weights: list[float] | None = None
    convergence_analyzer = ConvergenceAnalyzer()
    game_dynamics_history = []
    distillation_history = []
    t0 = time.perf_counter()

    # ── Federated rounds ──────────────────────────────────────────────────
    for rnd in range(1, rounds + 1):
        node_results = []
        node_models = []
        node_weights = []

        for ni, nd in enumerate(node_data):
            local_model = copy.deepcopy(global_model)
            local_model.train()
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

            local_model.eval()
            with torch.no_grad():
                local_preds = local_model(local_x).argmax(-1)
                local_acc = (local_preds == local_y).float().mean().item()
                full_preds = local_model(features).argmax(-1)
                full_acc = (full_preds == labels).float().mean().item()

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
        round_analytics = {}
        if strategy == "fedgtd":
            agg_state, prev_gtd_weights, gtd_analytics = fedgtd(
                global_model, node_models,
                round_num=rnd, total_rounds=rounds,
                prev_weights=prev_gtd_weights,
            )
            round_analytics["fedgtd"] = gtd_analytics

            # Game dynamics
            game_dyn = _compute_game_dynamics(node_models, global_model, rnd, rounds)
            game_dynamics_history.append(game_dyn)
            round_analytics["game_dynamics"] = game_dyn
        elif strategy == "weighted":
            agg_state = fedavg(global_model, node_models, weights=node_weights)
        else:
            agg_state = fedavg(global_model, node_models)

        global_model.load_state_dict(agg_state)

        # Convergence analysis (all strategies)
        conv_metrics = convergence_analyzer.compute_lyapunov(
            global_model, node_models, rnd, lr,
        )
        round_analytics["convergence"] = conv_metrics

        # Knowledge distillation metrics
        kd_metrics = _compute_distillation_metrics(
            global_model, node_models, features, labels,
        )
        distillation_history.append(kd_metrics)
        round_analytics["distillation"] = kd_metrics

        # Global evaluation after aggregation
        global_model.eval()
        with torch.no_grad():
            global_logits = global_model(features)
            global_preds = global_logits.argmax(-1)
            global_acc = (global_preds == labels).float().mean().item()
            global_conf = F.softmax(global_logits, dim=-1).max(-1).values.mean().item()

        round_entry = {
            "round": rnd,
            "global_accuracy": round(global_acc, 4),
            "global_confidence": round(global_conf, 4),
            "nodes": node_results,
            "analytics": round_analytics,
        }
        round_history.append(round_entry)

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

    # ── Build enhanced result ─────────────────────────────────────────────
    result = {
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
        # Enhanced analytics
        "convergence_summary": {
            "lyapunov_history": convergence_analyzer.lyapunov_history,
            "converged": convergence_analyzer.convergence_detected,
            "convergence_round": convergence_analyzer.convergence_round,
        },
        "distillation_summary": {
            "mean_kd_loss_history": [d["mean_kd_loss"] for d in distillation_history],
            "mean_agreement_history": [d["mean_agreement"] for d in distillation_history],
        },
    }

    if strategy == "fedgtd" and game_dynamics_history:
        result["game_dynamics_summary"] = {
            "nash_gap_history": [g["nash_gap"] for g in game_dynamics_history],
            "drift_history": [g["drift_magnitude"] for g in game_dynamics_history],
            "diffusion_history": [g["diffusion_magnitude"] for g in game_dynamics_history],
            "final_defender_strategy": game_dynamics_history[-1]["defender_strategy"],
        }

    return result
