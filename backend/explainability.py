"""
Explainability Studio (XAI) — Advanced backend engine
=====================================================

Provides comprehensive per-prediction and global explanations for IDS model decisions:
  - Gradient Saliency (gradient-based feature importance)
  - Integrated Gradients (path-integrated attribution)
  - Sensitivity Analysis (perturbation-based)
  - SHAP-like Approximation (Shapley value estimation via sampling)
  - Layer-wise Relevance Propagation (LRP)
  - DeepLIFT (Deep Learning Important FeaTures)
  - Attention Analysis (attention weight extraction)
  - Feature Interaction Detection (pairwise interaction strengths)
  - Counterfactual Explanations (minimal perturbation for class flip)
  - Decision Path Tracing (layer-by-layer activation flow)
  - Comparative Model Analysis (cross-model attribution agreement)
"""

import logging
import time
import uuid
from typing import Optional

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np

logger = logging.getLogger("robustidps.xai")


# ── Helpers ───────────────────────────────────────────────────────────────

def _get_model_input_dim(model: nn.Module) -> int | None:
    """Detect the expected input dimension from the model's first Linear layer."""
    # Check common model attributes first
    if hasattr(model, 'N_FEATURES'):
        return model.N_FEATURES
    # Walk the model to find the first nn.Linear layer
    for module in model.modules():
        if isinstance(module, nn.Linear):
            return module.in_features
    return None


def _ensure_feature_dim(features: torch.Tensor, expected_dim: int) -> torch.Tensor:
    """Pad or truncate features to match the model's expected input dimension."""
    n_cols = features.shape[1]
    if n_cols == expected_dim:
        return features
    if n_cols < expected_dim:
        pad = torch.zeros(features.shape[0], expected_dim - n_cols,
                          dtype=features.dtype, device=features.device)
        return torch.cat([features, pad], dim=1)
    return features[:, :expected_dim]


# ── Feature importance via gradient saliency ──────────────────────────────

def gradient_saliency(
    model: nn.Module,
    features: torch.Tensor,
    target_class: int | None = None,
) -> torch.Tensor:
    """
    Compute gradient-based saliency for each input feature.
    Returns tensor of shape [n_samples, n_features] with importance scores.
    """
    x = features.clone().detach().requires_grad_(True)
    logits = model(x)

    if target_class is not None:
        score = logits[:, target_class].sum()
    else:
        preds = logits.argmax(-1)
        score = logits.gather(1, preds.unsqueeze(1)).sum()

    score.backward()
    saliency = x.grad.abs()
    return saliency.detach()


def integrated_gradients(
    model: nn.Module,
    features: torch.Tensor,
    baseline: torch.Tensor | None = None,
    steps: int = 30,
) -> torch.Tensor:
    """
    Integrated Gradients attribution.
    Returns tensor of shape [n_samples, n_features].
    """
    if baseline is None:
        baseline = torch.zeros_like(features)

    scaled_inputs = []
    for alpha in torch.linspace(0, 1, steps):
        scaled_inputs.append(baseline + alpha * (features - baseline))

    grads = []
    for inp in scaled_inputs:
        inp = inp.clone().detach().requires_grad_(True)
        logits = model(inp)
        preds = logits.argmax(-1)
        score = logits.gather(1, preds.unsqueeze(1)).sum()
        score.backward()
        grads.append(inp.grad.detach())

    avg_grad = torch.stack(grads).mean(dim=0)
    attribution = (features - baseline) * avg_grad
    return attribution.detach()


# ── Sensitivity analysis ──────────────────────────────────────────────────

def feature_sensitivity(
    model: nn.Module,
    features: torch.Tensor,
    labels: torch.Tensor | None = None,
    perturbation_range: list[float] | None = None,
) -> dict:
    """
    Measure how accuracy changes when individual features are perturbed.
    Returns per-feature sensitivity scores.
    """
    if perturbation_range is None:
        perturbation_range = [0.01, 0.05, 0.1, 0.2, 0.5]

    model.eval()
    device = next(model.parameters()).device
    features = features.to(device)

    with torch.no_grad():
        clean_logits = model(features)
        clean_preds = clean_logits.argmax(-1)
        if labels is None:
            labels = clean_preds

    n_features = features.shape[1]
    sensitivity = {}

    for fi in range(n_features):
        scores = []
        for eps in perturbation_range:
            perturbed = features.clone()
            perturbed[:, fi] += torch.randn(len(features), device=device) * eps
            with torch.no_grad():
                new_preds = model(perturbed).argmax(-1)
            flip_rate = (new_preds != clean_preds).float().mean().item()
            scores.append({"epsilon": eps, "flip_rate": round(flip_rate, 4)})
        sensitivity[fi] = scores

    return sensitivity


# ── SHAP-like Approximation (Kernel SHAP via sampling) ────────────────────

def shap_approximation(
    model: nn.Module,
    features: torch.Tensor,
    n_background: int = 50,
    n_coalitions: int = 100,
) -> torch.Tensor:
    """
    Approximate Shapley values using a sampling-based approach.
    Uses random coalition sampling to estimate marginal contributions.
    Returns tensor of shape [n_samples, n_features].
    """
    model.eval()
    device = next(model.parameters()).device
    features = features.to(device)
    n_samples, n_features = features.shape

    # Background reference (mean of dataset)
    bg = features.mean(dim=0, keepdim=True)

    shap_values = torch.zeros_like(features)

    with torch.no_grad():
        base_pred = model(bg).softmax(-1)

        for _ in range(n_coalitions):
            # Random permutation for each sample
            perm = torch.randperm(n_features, device=device)
            # Random split point
            split = torch.randint(1, n_features, (1,)).item()

            # Build coalition: features before split use actual, after use background
            mask = torch.zeros(n_features, device=device)
            mask[perm[:split]] = 1.0

            # With feature j
            x_with = bg.expand(n_samples, -1).clone()
            x_with[:, mask.bool()] = features[:, mask.bool()]

            # Without the last included feature
            last_feat = perm[split - 1].item()
            x_without = x_with.clone()
            x_without[:, last_feat] = bg[0, last_feat]

            pred_with = model(x_with).softmax(-1)
            pred_without = model(x_without).softmax(-1)

            # Marginal contribution for predicted class
            pred_class = model(features).argmax(-1)
            contrib = pred_with.gather(1, pred_class.unsqueeze(1)).squeeze() - \
                      pred_without.gather(1, pred_class.unsqueeze(1)).squeeze()
            shap_values[:, last_feat] += contrib

        shap_values /= n_coalitions

    return shap_values.detach()


# ── Layer-wise Relevance Propagation (LRP) ────────────────────────────────

def _gradient_x_input_fallback(
    model: nn.Module,
    features: torch.Tensor,
) -> torch.Tensor:
    """Gradient × input attribution as fallback for non-sequential models."""
    x = features.clone().detach().requires_grad_(True)
    logits = model(x)
    preds = logits.argmax(-1)
    score = logits.gather(1, preds.unsqueeze(1)).sum()
    score.backward()
    return (x.grad * features).abs().detach()


def lrp_propagation(
    model: nn.Module,
    features: torch.Tensor,
    epsilon: float = 1e-6,
) -> torch.Tensor:
    """
    Simplified LRP (epsilon-rule) for feedforward networks.
    Propagates relevance from output back to input features.
    Returns tensor of shape [n_samples, n_features].

    Falls back to gradient × input for models with parallel branches
    (e.g. SurrogateIDS) where flat layer traversal is invalid.
    """
    model.eval()
    device = next(model.parameters()).device
    features = features.to(device)

    # Forward pass, capturing activations
    activations = [features]
    weights = []
    biases = []
    x = features

    try:
        for layer in model.modules():
            if isinstance(layer, nn.Linear):
                weights.append(layer.weight.data.clone())
                biases.append(layer.bias.data.clone() if layer.bias is not None else torch.zeros(layer.out_features, device=device))
                x = layer(x)
                activations.append(x.clone().detach())
            elif isinstance(layer, (nn.ReLU, nn.LeakyReLU, nn.ELU, nn.GELU)):
                if isinstance(layer, nn.LeakyReLU):
                    x = F.leaky_relu(x, negative_slope=layer.negative_slope)
                elif isinstance(layer, nn.ELU):
                    x = F.elu(x)
                elif isinstance(layer, nn.GELU):
                    x = F.gelu(x)
                else:
                    x = F.relu(x)
                activations[-1] = x.clone().detach()
    except RuntimeError:
        # Model has parallel branches — flat traversal is invalid
        return _gradient_x_input_fallback(model, features)

    if len(weights) == 0:
        return torch.zeros_like(features)

    # Output relevance: use the predicted class output
    with torch.no_grad():
        logits = model(features)
        pred_class = logits.argmax(-1)
        R = torch.zeros_like(logits)
        R.scatter_(1, pred_class.unsqueeze(1), logits.gather(1, pred_class.unsqueeze(1)))

    # Backward pass through linear layers (epsilon-rule)
    for layer_idx in range(len(weights) - 1, -1, -1):
        W = weights[layer_idx]  # [out, in]
        a = activations[layer_idx]  # [batch, in]

        # z = a @ W^T + b (the pre-activation)
        z = a @ W.t() + biases[layer_idx].unsqueeze(0)
        z = z + epsilon * z.sign()
        z[z == 0] = epsilon

        # s = R / z
        s = R / z
        # c = s @ W
        c = s @ W
        # R_new = a * c
        R = a * c

    return R.abs().detach()


# ── DeepLIFT ──────────────────────────────────────────────────────────────

def deep_lift(
    model: nn.Module,
    features: torch.Tensor,
    baseline: torch.Tensor | None = None,
) -> torch.Tensor:
    """
    DeepLIFT (rescale rule) for feedforward networks.
    Computes difference-from-reference attributions.
    Returns tensor of shape [n_samples, n_features].
    """
    model.eval()
    device = next(model.parameters()).device
    features = features.to(device)

    if baseline is None:
        baseline = torch.zeros_like(features)
    baseline = baseline.to(device)

    # Approximate contribution using input-output gradient (works for all architectures)
    x = features.clone().detach().requires_grad_(True)
    logits = model(x)
    pred_class = logits.argmax(-1)
    target_score = logits.gather(1, pred_class.unsqueeze(1)).sum()
    target_score.backward()

    # DeepLIFT rescale: delta_input * gradient
    delta_input = features - baseline
    attribution = delta_input * x.grad.detach()

    return attribution.abs().detach()


# ── Attention Analysis ────────────────────────────────────────────────────

def extract_attention_weights(
    model: nn.Module,
    features: torch.Tensor,
) -> dict:
    """
    Extract attention weights from models with attention layers.
    For non-attention models, compute pseudo-attention via gradient-weighted activations.
    Returns dict with attention patterns and layer-wise information.
    """
    model.eval()
    device = next(model.parameters()).device
    features = features.to(device)

    attention_data = {
        "has_native_attention": False,
        "layer_attention": [],
        "pseudo_attention": None,
        "feature_attention_scores": [],
    }

    # Check for attention layers
    attention_layers = []
    for name, module in model.named_modules():
        if 'attention' in name.lower() or 'attn' in name.lower():
            attention_layers.append((name, module))
        elif isinstance(module, nn.MultiheadAttention):
            attention_layers.append((name, module))

    if attention_layers:
        attention_data["has_native_attention"] = True
        # Hook-based attention extraction
        attention_maps = {}

        def make_hook(layer_name):
            def hook_fn(module, input_args, output):
                if isinstance(output, tuple) and len(output) > 1:
                    attention_maps[layer_name] = output[1].detach().cpu()
                elif isinstance(output, torch.Tensor):
                    attention_maps[layer_name] = output.detach().cpu()
            return hook_fn

        hooks = []
        for name, module in attention_layers:
            hooks.append(module.register_forward_hook(make_hook(name)))

        with torch.no_grad():
            model(features)

        for h in hooks:
            h.remove()

        for name, attn in attention_maps.items():
            if attn.dim() >= 2:
                # Aggregate attention across heads and samples
                if attn.dim() == 4:  # [batch, heads, seq, seq]
                    avg_attn = attn.mean(dim=(0, 1)).numpy().tolist()
                elif attn.dim() == 3:  # [batch, seq, seq]
                    avg_attn = attn.mean(dim=0).numpy().tolist()
                else:
                    avg_attn = attn.mean(dim=0).numpy().tolist()
                attention_data["layer_attention"].append({
                    "layer_name": name,
                    "attention_matrix": avg_attn[:20] if isinstance(avg_attn, list) and len(avg_attn) > 20 else avg_attn,
                })

    # Pseudo-attention via gradient-weighted layer activations
    layer_activations = {}
    hooks = []

    def make_act_hook(name):
        def hook_fn(module, inp, output):
            if isinstance(output, torch.Tensor):
                layer_activations[name] = output.detach()
        return hook_fn

    for name, module in model.named_modules():
        if isinstance(module, (nn.Linear, nn.Conv1d)):
            hooks.append(module.register_forward_hook(make_act_hook(name)))

    x = features.clone().detach().requires_grad_(True)
    logits = model(x)
    pred = logits.argmax(-1)
    score = logits.gather(1, pred.unsqueeze(1)).sum()
    score.backward()

    for h in hooks:
        h.remove()

    # Compute pseudo-attention from gradient magnitudes
    grad_magnitude = x.grad.abs().mean(dim=0).cpu().numpy()
    grad_max = grad_magnitude.max()
    if grad_max > 0:
        pseudo_attention = (grad_magnitude / grad_max).tolist()
    else:
        pseudo_attention = grad_magnitude.tolist()
    attention_data["pseudo_attention"] = pseudo_attention

    # Layer-wise activation importance
    for name, act in layer_activations.items():
        importance = act.abs().mean(dim=0).cpu().numpy()
        imp_max = importance.max()
        if imp_max > 0:
            importance = importance / imp_max
        attention_data["feature_attention_scores"].append({
            "layer_name": name,
            "n_neurons": len(importance),
            "top_neurons": sorted(
                [{"index": int(i), "importance": round(float(v), 4)} for i, v in enumerate(importance)],
                key=lambda x: -x["importance"]
            )[:15],
        })

    return attention_data


# ── Feature Interaction Detection ─────────────────────────────────────────

def feature_interactions(
    model: nn.Module,
    features: torch.Tensor,
    top_k: int = 10,
) -> dict:
    """
    Detect pairwise feature interactions by measuring joint perturbation effects.
    Uses Friedman's H-statistic approximation.
    Returns interaction matrix and top interacting pairs.
    """
    model.eval()
    device = next(model.parameters()).device
    features = features.to(device)
    n_samples, n_features = features.shape

    # Limit to top features by variance to keep computation tractable
    feature_std = features.std(dim=0)
    if n_features > 30:
        top_feat_idx = feature_std.argsort(descending=True)[:30].sort().values
    else:
        top_feat_idx = torch.arange(n_features, device=device)

    k = len(top_feat_idx)
    interaction_matrix = torch.zeros(k, k, device=device)

    with torch.no_grad():
        base_pred = model(features).softmax(-1)
        pred_class = base_pred.argmax(-1)
        base_conf = base_pred.gather(1, pred_class.unsqueeze(1)).squeeze()

        for i_idx in range(k):
            fi = top_feat_idx[i_idx].item()
            for j_idx in range(i_idx + 1, k):
                fj = top_feat_idx[j_idx].item()

                # Perturb feature i only
                x_i = features.clone()
                x_i[:, fi] = features[:, fi].mean()
                pred_i = model(x_i).softmax(-1).gather(1, pred_class.unsqueeze(1)).squeeze()

                # Perturb feature j only
                x_j = features.clone()
                x_j[:, fj] = features[:, fj].mean()
                pred_j = model(x_j).softmax(-1).gather(1, pred_class.unsqueeze(1)).squeeze()

                # Perturb both
                x_ij = features.clone()
                x_ij[:, fi] = features[:, fi].mean()
                x_ij[:, fj] = features[:, fj].mean()
                pred_ij = model(x_ij).softmax(-1).gather(1, pred_class.unsqueeze(1)).squeeze()

                # H-statistic: interaction = f(ij) - f(i) - f(j) + f()
                interaction = (pred_ij - pred_i - pred_j + base_conf).abs().mean()
                interaction_matrix[i_idx, j_idx] = interaction
                interaction_matrix[j_idx, i_idx] = interaction

    # Extract top interacting pairs
    pairs = []
    for i_idx in range(k):
        for j_idx in range(i_idx + 1, k):
            val = interaction_matrix[i_idx, j_idx].item()
            if val > 0.001:
                pairs.append({
                    "feature_i": int(top_feat_idx[i_idx].item()),
                    "feature_j": int(top_feat_idx[j_idx].item()),
                    "interaction_strength": round(val, 5),
                })

    pairs.sort(key=lambda x: -x["interaction_strength"])

    return {
        "feature_indices": top_feat_idx.cpu().tolist(),
        "interaction_matrix": interaction_matrix.cpu().numpy().tolist(),
        "top_pairs": pairs[:top_k * 3],
        "total_interactions_detected": len(pairs),
    }


# ── Counterfactual Explanations ───────────────────────────────────────────

def counterfactual_explanations(
    model: nn.Module,
    features: torch.Tensor,
    n_counterfactuals: int = 5,
    max_iter: int = 100,
    lr: float = 0.05,
) -> dict:
    """
    Generate counterfactual explanations: minimal feature changes to flip the prediction.
    Uses gradient-based optimization to find closest counterfactual for each sample.
    """
    model.eval()
    device = next(model.parameters()).device
    features = features.to(device)
    n_samples = min(len(features), n_counterfactuals)

    # Select diverse samples (one per predicted class if possible)
    with torch.no_grad():
        logits = model(features)
        preds = logits.argmax(-1)
        probs = logits.softmax(-1)

    # Pick representative samples
    sample_idx = []
    unique_classes = preds.unique()
    for cls in unique_classes:
        mask = (preds == cls).nonzero(as_tuple=True)[0]
        if len(mask) > 0:
            sample_idx.append(mask[0].item())
        if len(sample_idx) >= n_counterfactuals:
            break
    # Fill remaining with random
    while len(sample_idx) < n_counterfactuals and len(sample_idx) < len(features):
        idx = torch.randint(len(features), (1,)).item()
        if idx not in sample_idx:
            sample_idx.append(idx)

    counterfactuals = []
    for si in sample_idx:
        original = features[si:si+1].clone()
        original_class = preds[si].item()
        original_conf = probs[si, original_class].item()

        # Find the second most likely class as target
        sorted_probs = probs[si].argsort(descending=True)
        target_class = sorted_probs[1].item() if sorted_probs[0].item() == original_class else sorted_probs[0].item()

        # Optimize counterfactual
        cf = original.clone().detach().requires_grad_(True)
        optimizer = torch.optim.Adam([cf], lr=lr)

        best_cf = None
        best_distance = float('inf')
        flipped = False

        for step in range(max_iter):
            optimizer.zero_grad()
            cf_logits = model(cf)
            cf_probs = cf_logits.softmax(-1)

            # Loss: maximize target class probability + minimize distance
            target_loss = -cf_probs[0, target_class]
            distance_loss = 0.1 * (cf - original).pow(2).sum()
            loss = target_loss + distance_loss
            loss.backward()
            optimizer.step()

            with torch.no_grad():
                cf_pred = model(cf).argmax(-1).item()
                dist = (cf - original).abs().sum().item()

            if cf_pred == target_class and dist < best_distance:
                best_cf = cf.clone().detach()
                best_distance = dist
                flipped = True

        if best_cf is None:
            best_cf = cf.detach()

        # Compute per-feature changes
        delta = (best_cf - original).squeeze().cpu().numpy()
        abs_delta = np.abs(delta)
        top_changes = np.argsort(abs_delta)[::-1][:10]

        cf_logits_final = model(best_cf).softmax(-1)

        counterfactuals.append({
            "sample_index": si,
            "original_class": original_class,
            "original_confidence": round(original_conf, 4),
            "target_class": target_class,
            "counterfactual_class": model(best_cf).argmax(-1).item(),
            "counterfactual_confidence": round(cf_logits_final[0, target_class].item(), 4),
            "flipped": flipped,
            "l1_distance": round(float(abs_delta.sum()), 4),
            "features_changed": int((abs_delta > 0.01).sum()),
            "top_changes": [
                {
                    "feature_index": int(fi),
                    "original_value": round(float(original[0, fi].cpu()), 4),
                    "counterfactual_value": round(float(best_cf[0, fi].cpu()), 4),
                    "delta": round(float(delta[fi]), 4),
                }
                for fi in top_changes
            ],
        })

    return {
        "n_counterfactuals": len(counterfactuals),
        "flip_success_rate": round(sum(1 for c in counterfactuals if c["flipped"]) / max(len(counterfactuals), 1), 4),
        "counterfactuals": counterfactuals,
    }


# ── Decision Path Tracing ─────────────────────────────────────────────────

def decision_path_tracing(
    model: nn.Module,
    features: torch.Tensor,
    n_traces: int = 5,
) -> dict:
    """
    Trace the decision path through the network: layer-by-layer activation flow,
    neuron activation patterns, and bottleneck detection.
    """
    model.eval()
    device = next(model.parameters()).device
    features = features.to(device)
    n_samples = min(len(features), n_traces)

    # Collect layer info
    layer_info = []
    layer_activations = {}
    hooks = []

    layer_idx = 0
    for name, module in model.named_modules():
        if isinstance(module, (nn.Linear, nn.Conv1d, nn.BatchNorm1d, nn.LayerNorm)):
            layer_info.append({
                "index": layer_idx,
                "name": name,
                "type": type(module).__name__,
                "params": sum(p.numel() for p in module.parameters()),
            })
            if isinstance(module, nn.Linear):
                layer_info[-1]["in_features"] = module.in_features
                layer_info[-1]["out_features"] = module.out_features

            def make_hook(idx):
                def hook_fn(mod, inp, out):
                    if isinstance(out, torch.Tensor):
                        layer_activations[idx] = out.detach()
                return hook_fn

            hooks.append(module.register_forward_hook(make_hook(layer_idx)))
            layer_idx += 1

    with torch.no_grad():
        logits = model(features[:n_samples])
        preds = logits.argmax(-1)
        probs = logits.softmax(-1)

    for h in hooks:
        h.remove()

    # Analyze activation patterns per layer
    layer_analysis = []
    for idx, info in enumerate(layer_info):
        if idx in layer_activations:
            act = layer_activations[idx]
            analysis = {
                **info,
                "mean_activation": round(float(act.mean()), 4),
                "std_activation": round(float(act.std()), 4),
                "sparsity": round(float((act.abs() < 0.01).float().mean()), 4),
                "dead_neurons": int((act.abs().max(dim=0).values < 0.001).sum()),
                "max_activation": round(float(act.max()), 4),
            }
            # Top activated neurons
            mean_act = act.abs().mean(dim=0)
            top_neurons = mean_act.argsort(descending=True)[:10]
            analysis["top_neurons"] = [
                {"index": int(n), "mean_activation": round(float(mean_act[n]), 4)}
                for n in top_neurons
            ]
            layer_analysis.append(analysis)

    # Per-sample decision traces
    traces = []
    for si in range(n_samples):
        trace = {
            "sample_index": si,
            "predicted_class": int(preds[si]),
            "confidence": round(float(probs[si].max()), 4),
            "class_probabilities": probs[si].cpu().numpy().tolist(),
            "layer_flow": [],
        }
        for idx in sorted(layer_activations.keys()):
            act = layer_activations[idx][si]
            trace["layer_flow"].append({
                "layer_index": idx,
                "n_active": int((act.abs() > 0.01).sum()),
                "total_neurons": len(act) if act.dim() == 1 else act.numel(),
                "energy": round(float(act.pow(2).sum()), 4),
                "top_5_values": sorted(act.abs().cpu().numpy().tolist(), reverse=True)[:5],
            })
        traces.append(trace)

    # Bottleneck detection
    bottlenecks = []
    for idx, analysis in enumerate(layer_analysis):
        if analysis.get("sparsity", 0) > 0.5 or analysis.get("dead_neurons", 0) > 0:
            bottlenecks.append({
                "layer_index": idx,
                "layer_name": analysis.get("name", f"layer_{idx}"),
                "reason": "high_sparsity" if analysis.get("sparsity", 0) > 0.5 else "dead_neurons",
                "severity": round(analysis.get("sparsity", 0), 3),
            })

    return {
        "n_layers": len(layer_analysis),
        "total_params": sum(info.get("params", 0) for info in layer_info),
        "layers": layer_analysis,
        "traces": traces,
        "bottlenecks": bottlenecks,
    }


# ── Comparative Model Analysis ────────────────────────────────────────────

def comparative_model_analysis(
    models: dict[str, nn.Module],
    features: torch.Tensor,
    labels: torch.Tensor | None = None,
) -> dict:
    """
    Compare explanations and decisions across multiple models.
    Measures agreement, attribution correlation, and decision divergence.
    """
    device = features.device
    n_samples, n_features = features.shape

    model_results = {}
    for name, model in models.items():
        model.eval()
        model_dev = next(model.parameters()).device
        feat = features.to(model_dev)

        with torch.no_grad():
            logits = model(feat)
            probs = logits.softmax(-1)
            preds = probs.argmax(-1)
            confs = probs.max(-1).values

        # Compute saliency for each model
        sal = gradient_saliency(model, feat)
        sal_global = sal.mean(dim=0).cpu().numpy()
        sal_max = sal_global.max()
        if sal_max > 0:
            sal_global = sal_global / sal_max

        model_results[name] = {
            "predictions": preds.cpu(),
            "confidences": confs.cpu(),
            "probabilities": probs.cpu(),
            "saliency": sal_global,
            "accuracy": float((preds.cpu() == (labels.cpu() if labels is not None else preds.cpu())).float().mean()),
            "mean_confidence": float(confs.mean()),
        }

    model_names = list(model_results.keys())

    # Pairwise agreement matrix
    agreement_matrix = {}
    for i, name_a in enumerate(model_names):
        for j, name_b in enumerate(model_names):
            if i < j:
                preds_a = model_results[name_a]["predictions"]
                preds_b = model_results[name_b]["predictions"]
                agreement = float((preds_a == preds_b).float().mean())
                agreement_matrix[f"{name_a}_vs_{name_b}"] = {
                    "agreement_rate": round(agreement, 4),
                    "disagreement_count": int((preds_a != preds_b).sum()),
                }

    # Attribution correlation (Spearman rank correlation between saliency maps)
    attribution_correlation = {}
    for i, name_a in enumerate(model_names):
        for j, name_b in enumerate(model_names):
            if i < j:
                sal_a = model_results[name_a]["saliency"]
                sal_b = model_results[name_b]["saliency"]
                # Rank correlation
                rank_a = np.argsort(np.argsort(-sal_a))
                rank_b = np.argsort(np.argsort(-sal_b))
                n = len(rank_a)
                d_sq = ((rank_a - rank_b) ** 2).sum()
                spearman = 1 - (6 * d_sq) / (n * (n ** 2 - 1)) if n > 1 else 0.0
                attribution_correlation[f"{name_a}_vs_{name_b}"] = round(float(spearman), 4)

    # Per-model summary
    model_summaries = {}
    for name in model_names:
        r = model_results[name]
        # Top features per model
        top_idx = np.argsort(r["saliency"])[::-1][:15]
        model_summaries[name] = {
            "accuracy": round(r["accuracy"], 4),
            "mean_confidence": round(r["mean_confidence"], 4),
            "top_features": [
                {"index": int(i), "importance": round(float(r["saliency"][i]), 4)}
                for i in top_idx
            ],
            "class_distribution": {},
        }
        # Class distribution
        preds = r["predictions"]
        for cls in preds.unique():
            count = int((preds == cls).sum())
            model_summaries[name]["class_distribution"][int(cls)] = count

    # Confidence correlation
    confidence_correlation = {}
    for i, name_a in enumerate(model_names):
        for j, name_b in enumerate(model_names):
            if i < j:
                conf_a = model_results[name_a]["confidences"].numpy()
                conf_b = model_results[name_b]["confidences"].numpy()
                corr = float(np.corrcoef(conf_a, conf_b)[0, 1]) if len(conf_a) > 1 else 0.0
                confidence_correlation[f"{name_a}_vs_{name_b}"] = round(corr, 4)

    # Decision divergence analysis: samples where models disagree
    disagreement_samples = []
    if len(model_names) >= 2:
        all_preds = torch.stack([model_results[name]["predictions"] for name in model_names])
        for si in range(n_samples):
            sample_preds = all_preds[:, si]
            if sample_preds.unique().numel() > 1:
                disagreement_samples.append({
                    "sample_index": si,
                    "predictions": {name: int(model_results[name]["predictions"][si]) for name in model_names},
                    "confidences": {name: round(float(model_results[name]["confidences"][si]), 4) for name in model_names},
                })
                if len(disagreement_samples) >= 50:
                    break

    return {
        "n_models": len(model_names),
        "model_names": model_names,
        "model_summaries": model_summaries,
        "agreement_matrix": agreement_matrix,
        "attribution_correlation": attribution_correlation,
        "confidence_correlation": confidence_correlation,
        "disagreement_samples": disagreement_samples,
        "total_disagreements": int((all_preds[0] != all_preds[1]).sum()) if len(model_names) >= 2 else 0,
    }


# ── Main XAI runner ───────────────────────────────────────────────────────

FEATURE_NAMES = [
    "flow_duration", "Header_Length", "Protocol Type", "Duration", "Rate",
    "Srate", "Drate", "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number",
    "ack_count", "syn_count", "fin_count", "urg_count", "rst_count",
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP",
    "DHCP", "ARP", "ICMP", "IPv", "LLC",
    "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number",
    "Magnitue", "Radius", "Covariance", "Variance", "Weight",
    "pkt_count", "pkt_size_avg", "pkt_size_std", "pkt_size_min", "pkt_size_max",
    "fwd_pkt_count", "bwd_pkt_count", "fwd_pkt_size_avg", "bwd_pkt_size_avg",
    "flow_bytes_per_sec", "flow_pkts_per_sec", "fwd_iat_avg", "bwd_iat_avg",
    "active_time", "idle_time",
    "bidirectional_packets", "bidirectional_bytes", "bidirectional_duration_ms",
    "src2dst_packets", "src2dst_bytes", "dst2src_packets", "dst2src_bytes",
    "fwd_header_len", "bwd_header_len", "down_up_ratio", "pkt_len_variance",
    "fwd_seg_size_avg", "bwd_seg_size_avg", "subflow_fwd_pkts", "subflow_fwd_bytes",
    "subflow_bwd_pkts", "subflow_bwd_bytes",
    "fwd_byts_b_avg", "fwd_pkts_b_avg", "fwd_blk_rate_avg",
    "bwd_byts_b_avg", "bwd_pkts_b_avg", "bwd_blk_rate_avg",
]


def run_explainability(
    model: nn.Module,
    features: torch.Tensor,
    labels: torch.Tensor | None = None,
    n_samples: int = 200,
    method: str = "all",
) -> dict:
    """
    Run XAI analysis on a model+dataset.

    Methods: "saliency", "integrated_gradients", "sensitivity", "shap",
             "lrp", "deeplift", "attention", "interactions", "counterfactual",
             "decision_path", "all", "comprehensive"
    """
    # Subsample
    if len(features) > n_samples:
        idx = torch.randperm(len(features))[:n_samples].sort().values
        features = features[idx]
        if labels is not None:
            labels = labels[idx]

    model.eval()
    device = next(model.parameters()).device
    features = features.to(device)
    if labels is not None:
        labels = labels.to(device)

    # Ensure features match model's expected input dimension
    expected_dim = _get_model_input_dim(model)
    if expected_dim is not None and features.shape[1] != expected_dim:
        logger.info("XAI: adjusting features from %d to %d dims", features.shape[1], expected_dim)
        features = _ensure_feature_dim(features, expected_dim)

    from models.surrogate import SurrogateIDS
    class_names = SurrogateIDS.CLASS_NAMES

    # Clean predictions
    with torch.no_grad():
        logits = model(features)
        probs = F.softmax(logits, dim=-1)
        preds = probs.argmax(-1)
        confs = probs.max(-1).values

    if labels is None:
        labels = preds.clone()

    n_features = features.shape[1]
    feat_names = FEATURE_NAMES[:n_features] if n_features <= len(FEATURE_NAMES) else \
        [f"feature_{i}" for i in range(n_features)]

    result = {
        "xai_id": str(uuid.uuid4())[:8],
        "n_samples": len(features),
        "method": method,
        "feature_names": feat_names,
        "class_names": class_names,
        "prediction_summary": {
            "accuracy": float((preds == labels).float().mean()),
            "mean_confidence": float(confs.mean()),
            "per_class_accuracy": {},
            "confidence_distribution": {
                "high": int((confs > 0.9).sum()),
                "medium": int(((confs > 0.7) & (confs <= 0.9)).sum()),
                "low": int((confs <= 0.7).sum()),
            },
        },
    }

    # Per-class accuracy
    for ci, cname in enumerate(class_names):
        mask = labels == ci
        if mask.sum() > 0:
            cls_acc = float((preds[mask] == labels[mask]).float().mean())
            result["prediction_summary"]["per_class_accuracy"][cname] = round(cls_acc, 4)

    run_all = method in ("all", "comprehensive")
    t0 = time.perf_counter()

    # ── Gradient saliency ─────────────────────────────────────────────────
    if method in ("saliency", "all", "comprehensive"):
        sal = gradient_saliency(model, features)
        global_importance = sal.mean(dim=0).cpu().numpy()
        gi_max = global_importance.max()
        if gi_max > 0:
            global_importance = global_importance / gi_max

        top_idx = np.argsort(global_importance)[::-1][:20]
        top_features = [
            {"index": int(i), "name": feat_names[i], "importance": round(float(global_importance[i]), 4)}
            for i in top_idx
        ]

        per_class_importance = {}
        for ci, cname in enumerate(class_names):
            mask = preds == ci
            if mask.sum() > 0:
                cls_sal = sal[mask].mean(dim=0).cpu().numpy()
                cls_max = cls_sal.max()
                if cls_max > 0:
                    cls_sal = cls_sal / cls_max
                cls_top = np.argsort(cls_sal)[::-1][:10]
                per_class_importance[cname] = [
                    {"index": int(i), "name": feat_names[i], "importance": round(float(cls_sal[i]), 4)}
                    for i in cls_top
                ]

        result["saliency"] = {
            "global_importance": top_features,
            "per_class_importance": per_class_importance,
            "heatmap": sal.mean(dim=0).cpu().tolist(),
        }

    # ── Integrated Gradients ──────────────────────────────────────────────
    if method in ("integrated_gradients", "all", "comprehensive"):
        ig = integrated_gradients(model, features, steps=20)
        ig_global = ig.abs().mean(dim=0).cpu().numpy()
        ig_max = ig_global.max()
        if ig_max > 0:
            ig_global = ig_global / ig_max

        ig_top_idx = np.argsort(ig_global)[::-1][:20]

        # Also compute per-class IG
        ig_per_class = {}
        for ci, cname in enumerate(class_names):
            mask = preds == ci
            if mask.sum() > 0:
                cls_ig = ig[mask].abs().mean(dim=0).cpu().numpy()
                cls_max = cls_ig.max()
                if cls_max > 0:
                    cls_ig = cls_ig / cls_max
                cls_top = np.argsort(cls_ig)[::-1][:10]
                ig_per_class[cname] = [
                    {"index": int(i), "name": feat_names[i], "attribution": round(float(cls_ig[i]), 4)}
                    for i in cls_top
                ]

        # Convergence delta (IG axiom check)
        ig_sum = ig.sum(dim=1).cpu().numpy()
        baseline = torch.zeros_like(features)
        with torch.no_grad():
            out_input = model(features).gather(1, preds.unsqueeze(1)).squeeze().cpu().numpy()
            out_baseline = model(baseline.to(device)).gather(1, preds.unsqueeze(1)).squeeze().cpu().numpy()
        completeness_delta = float(np.abs(ig_sum.mean() - (out_input - out_baseline).mean()))

        result["integrated_gradients"] = {
            "global_attribution": [
                {"index": int(i), "name": feat_names[i], "attribution": round(float(ig_global[i]), 4)}
                for i in ig_top_idx
            ],
            "per_class_attribution": ig_per_class,
            "heatmap": ig.abs().mean(dim=0).cpu().tolist(),
            "convergence_delta": round(completeness_delta, 6),
            "signed_attribution": ig.mean(dim=0).cpu().tolist(),
        }

    # ── Sensitivity ───────────────────────────────────────────────────────
    if method in ("sensitivity", "all", "comprehensive"):
        sens = feature_sensitivity(model, features, labels,
                                   perturbation_range=[0.05, 0.1, 0.2])
        max_flip = {}
        for fi, scores in sens.items():
            max_flip[fi] = max(s["flip_rate"] for s in scores)

        sens_ranked = sorted(max_flip.items(), key=lambda x: -x[1])[:20]

        # Compute sensitivity curve (global perturbation vs accuracy)
        sensitivity_curve = []
        for eps in [0.01, 0.02, 0.05, 0.1, 0.15, 0.2, 0.3, 0.5]:
            perturbed = features + torch.randn_like(features) * eps
            with torch.no_grad():
                p = model(perturbed).argmax(-1)
            acc = float((p == labels).float().mean())
            sensitivity_curve.append({"epsilon": eps, "accuracy": round(acc, 4)})

        result["sensitivity"] = {
            "top_sensitive_features": [
                {
                    "index": fi,
                    "name": feat_names[fi],
                    "max_flip_rate": round(flip, 4),
                    "detail": sens[fi],
                }
                for fi, flip in sens_ranked
            ],
            "global_sensitivity_curve": sensitivity_curve,
        }

    # ── SHAP Approximation ────────────────────────────────────────────────
    if method in ("shap", "all", "comprehensive"):
        shap_vals = shap_approximation(model, features, n_coalitions=80)
        shap_global = shap_vals.abs().mean(dim=0).cpu().numpy()
        shap_max = shap_global.max()
        if shap_max > 0:
            shap_global_norm = shap_global / shap_max
        else:
            shap_global_norm = shap_global

        shap_top_idx = np.argsort(shap_global_norm)[::-1][:20]

        # Direction of SHAP values (positive = pushes toward predicted class)
        shap_signed = shap_vals.mean(dim=0).cpu().numpy()

        # Per-class SHAP
        shap_per_class = {}
        for ci, cname in enumerate(class_names):
            mask = preds == ci
            if mask.sum() > 0:
                cls_shap = shap_vals[mask].abs().mean(dim=0).cpu().numpy()
                cls_max = cls_shap.max()
                if cls_max > 0:
                    cls_shap = cls_shap / cls_max
                cls_top = np.argsort(cls_shap)[::-1][:10]
                shap_per_class[cname] = [
                    {"index": int(i), "name": feat_names[i], "shap_value": round(float(cls_shap[i]), 4)}
                    for i in cls_top
                ]

        result["shap"] = {
            "global_importance": [
                {
                    "index": int(i), "name": feat_names[i],
                    "importance": round(float(shap_global_norm[i]), 4),
                    "direction": "positive" if shap_signed[i] > 0 else "negative",
                    "raw_shap": round(float(shap_global[i]), 6),
                }
                for i in shap_top_idx
            ],
            "per_class_shap": shap_per_class,
            "heatmap": shap_global_norm.tolist(),
            "signed_heatmap": shap_signed.tolist(),
        }

    # ── LRP ───────────────────────────────────────────────────────────────
    if method in ("lrp", "all", "comprehensive"):
        lrp_vals = lrp_propagation(model, features)
        lrp_global = lrp_vals.mean(dim=0).cpu().numpy()
        lrp_max = lrp_global.max()
        if lrp_max > 0:
            lrp_global_norm = lrp_global / lrp_max
        else:
            lrp_global_norm = lrp_global

        lrp_top_idx = np.argsort(lrp_global_norm)[::-1][:20]

        result["lrp"] = {
            "global_relevance": [
                {"index": int(i), "name": feat_names[i], "relevance": round(float(lrp_global_norm[i]), 4)}
                for i in lrp_top_idx
            ],
            "heatmap": lrp_global_norm.tolist(),
        }

    # ── DeepLIFT ──────────────────────────────────────────────────────────
    if method in ("deeplift", "all", "comprehensive"):
        dl_vals = deep_lift(model, features)
        dl_global = dl_vals.mean(dim=0).cpu().numpy()
        dl_max = dl_global.max()
        if dl_max > 0:
            dl_global_norm = dl_global / dl_max
        else:
            dl_global_norm = dl_global

        dl_top_idx = np.argsort(dl_global_norm)[::-1][:20]

        result["deeplift"] = {
            "global_attribution": [
                {"index": int(i), "name": feat_names[i], "attribution": round(float(dl_global_norm[i]), 4)}
                for i in dl_top_idx
            ],
            "heatmap": dl_global_norm.tolist(),
        }

    # ── Attention ─────────────────────────────────────────────────────────
    if method in ("attention", "all", "comprehensive"):
        attn = extract_attention_weights(model, features)
        result["attention"] = attn

    # ── Feature Interactions ──────────────────────────────────────────────
    if method in ("interactions", "comprehensive"):
        interactions = feature_interactions(model, features)
        # Add feature names to interaction pairs
        for pair in interactions["top_pairs"]:
            pair["feature_i_name"] = feat_names[pair["feature_i"]]
            pair["feature_j_name"] = feat_names[pair["feature_j"]]
        result["feature_interactions"] = interactions

    # ── Counterfactual ────────────────────────────────────────────────────
    if method in ("counterfactual", "comprehensive"):
        cf = counterfactual_explanations(model, features, n_counterfactuals=5)
        # Add class and feature names
        for item in cf["counterfactuals"]:
            item["original_class_name"] = class_names[item["original_class"]] if item["original_class"] < len(class_names) else f"class_{item['original_class']}"
            item["target_class_name"] = class_names[item["target_class"]] if item["target_class"] < len(class_names) else f"class_{item['target_class']}"
            for change in item["top_changes"]:
                fi = change["feature_index"]
                change["feature_name"] = feat_names[fi] if fi < len(feat_names) else f"feature_{fi}"
        result["counterfactual"] = cf

    # ── Decision Path ─────────────────────────────────────────────────────
    if method in ("decision_path", "comprehensive"):
        dp = decision_path_tracing(model, features, n_traces=5)
        # Add layer names from feature names where applicable
        for layer in dp["layers"]:
            if "in_features" in layer and layer["in_features"] == n_features:
                layer["input_feature_names"] = feat_names[:10]
        result["decision_path"] = dp

    # ── Cross-method attribution agreement ────────────────────────────────
    if run_all or method == "comprehensive":
        # Collect all method rankings for agreement analysis
        method_rankings = {}
        if "saliency" in result:
            method_rankings["saliency"] = [f["index"] for f in result["saliency"]["global_importance"][:15]]
        if "integrated_gradients" in result:
            method_rankings["integrated_gradients"] = [f["index"] for f in result["integrated_gradients"]["global_attribution"][:15]]
        if "shap" in result:
            method_rankings["shap"] = [f["index"] for f in result["shap"]["global_importance"][:15]]
        if "lrp" in result:
            method_rankings["lrp"] = [f["index"] for f in result["lrp"]["global_relevance"][:15]]
        if "deeplift" in result:
            method_rankings["deeplift"] = [f["index"] for f in result["deeplift"]["global_attribution"][:15]]

        # Compute pairwise rank agreement (Jaccard similarity of top-10)
        rank_agreement = {}
        method_keys = list(method_rankings.keys())
        for i in range(len(method_keys)):
            for j in range(i + 1, len(method_keys)):
                a_set = set(method_rankings[method_keys[i]][:10])
                b_set = set(method_rankings[method_keys[j]][:10])
                jaccard = len(a_set & b_set) / len(a_set | b_set) if (a_set | b_set) else 0
                rank_agreement[f"{method_keys[i]}_vs_{method_keys[j]}"] = round(jaccard, 4)

        # Consensus features (appear in top-10 of all methods)
        if method_rankings:
            all_top10 = [set(ranks[:10]) for ranks in method_rankings.values()]
            consensus = set.intersection(*all_top10) if all_top10 else set()
            consensus_features = [
                {"index": int(fi), "name": feat_names[fi]}
                for fi in sorted(consensus)
            ]
        else:
            consensus_features = []

        result["cross_method_agreement"] = {
            "methods_compared": method_keys,
            "pairwise_rank_agreement": rank_agreement,
            "consensus_top_features": consensus_features,
            "n_consensus": len(consensus_features),
        }

    result["time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return result


def run_comparative_explainability(
    models: dict[str, nn.Module],
    features: torch.Tensor,
    labels: torch.Tensor | None = None,
    n_samples: int = 200,
) -> dict:
    """
    Run comparative XAI analysis across multiple models.
    """
    if len(features) > n_samples:
        idx = torch.randperm(len(features))[:n_samples].sort().values
        features = features[idx]
        if labels is not None:
            labels = labels[idx]

    # Ensure features match models' expected input dimension
    for mname, mobj in models.items():
        expected_dim = _get_model_input_dim(mobj)
        if expected_dim is not None and features.shape[1] != expected_dim:
            logger.info("Comparative XAI: adjusting features from %d to %d dims for %s",
                        features.shape[1], expected_dim, mname)
            features = _ensure_feature_dim(features, expected_dim)
            break  # All models share the same input dim (83)

    t0 = time.perf_counter()

    comparison = comparative_model_analysis(models, features, labels)

    n_features = features.shape[1]
    feat_names = FEATURE_NAMES[:n_features] if n_features <= len(FEATURE_NAMES) else \
        [f"feature_{i}" for i in range(n_features)]

    # Add feature names to summaries
    for model_name, summary in comparison["model_summaries"].items():
        for feat in summary["top_features"]:
            fi = feat["index"]
            feat["name"] = feat_names[fi] if fi < len(feat_names) else f"feature_{fi}"

    comparison["feature_names"] = feat_names
    comparison["n_samples"] = len(features)
    comparison["time_ms"] = round((time.perf_counter() - t0) * 1000, 1)

    return comparison
