"""Phase-A evaluation: clean acc, PGD-20 robust acc, CW, HopSkipJump,
BoundaryAttack, certified l_2 radius, Lipschitz / Gronwall radius.

Produces a metrics.json structured to match Table 6.x of chapter 6.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch
from torch.utils.data import DataLoader

from plugins.uav.uav_defense.attacks import (
    fgsm, pgd, cw, hop_skip_jump, boundary_attack,
)
from plugins.uav.uav_defense.datasets import SyntheticTEXBAT
from plugins.uav.uav_defense.defenses import (
    certified_radius, estimate_lipschitz, gronwall_radius, smooth_predict,
)
from plugins.uav.uav_defense.models import CTTGNN


@torch.no_grad()
def _accuracy(model, x, y, adj=None) -> float:
    logits = model(x, adj) if adj is not None else model(x)
    return float((logits.argmax(dim=-1) == y).float().mean().item())


def evaluate(model: torch.nn.Module, dataset, device: str = "cpu", limit: int = 256) -> dict:
    model.to(device).eval()
    loader = DataLoader(dataset, batch_size=limit, shuffle=False)
    x, adj, y = next(iter(loader))
    x, adj, y = x.to(device), adj.to(device), y.to(device)

    clean_acc = _accuracy(model, x, y, adj)

    x_pgd = pgd(model, x, y, epsilon=4 / 255, n_steps=20, adj=adj)
    pgd_acc = _accuracy(model, x_pgd, y, adj)

    x_cw = cw(model, x[:32], y[:32], kappa=5.0, c=1.0, n_steps=100, adj=adj)
    cw_acc = _accuracy(model, x_cw, y[:32], adj)

    x_hsj = hop_skip_jump(model, x[:16], y[:16], n_queries=200, n_montecarlo=20, adj=adj)
    hsj_acc = _accuracy(model, x_hsj, y[:16], adj)

    x_ba = boundary_attack(model, x[:16], y[:16], n_steps=100, adj=adj)
    ba_acc = _accuracy(model, x_ba, y[:16], adj)

    sigma = 0.25
    top, counts = smooth_predict(model, x[:32], sigma=sigma, n_samples=200, adj=adj)
    rs_correct = (top == y[:32]).float().mean().item()
    radii = [certified_radius(int(counts[i, top[i]].item()), 200, sigma) for i in range(top.shape[0])]
    rs_radius = sum(radii) / max(1, len(radii))

    l_g = estimate_lipschitz(model, x[:16], adj=adj)
    g_radius = gronwall_radius(l_g, horizon_T=1.0, epsilon_out=0.5)

    return {
        "clean_accuracy": round(clean_acc, 4),
        "pgd20_robust_accuracy_eps4_255": round(pgd_acc, 4),
        "cw_kappa5_robust_accuracy": round(cw_acc, 4),
        "hop_skip_jump_robust_accuracy_q200": round(hsj_acc, 4),
        "boundary_attack_robust_accuracy_s100": round(ba_acc, 4),
        "certified_l2_radius_sigma_0_25": round(rs_radius, 4),
        "smoothed_accuracy_sigma_0_25": round(rs_correct, 4),
        "lipschitz_L_g": round(l_g, 4),
        "gronwall_radius_T1_eps_out_0_5": round(g_radius, 4),
        "phase": "A",
        "schema_version": 1,
    }


def main(argv: list[str] | None = None) -> dict:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", type=str, default="weights/uav_ct_tgnn.pt")
    parser.add_argument("--n-samples", type=int, default=512)
    parser.add_argument("--out", type=str, default="weights/uav_metrics.json")
    args = parser.parse_args(argv)

    torch.manual_seed(42)
    model = CTTGNN()
    ckpt = Path(args.checkpoint)
    if ckpt.exists():
        model.load_state_dict(torch.load(ckpt, map_location="cpu"))
    dataset = SyntheticTEXBAT(n_samples=args.n_samples, seed=7)
    metrics = evaluate(model, dataset)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(metrics, indent=2))
    return metrics


if __name__ == "__main__":
    print(json.dumps(main(), indent=2))
