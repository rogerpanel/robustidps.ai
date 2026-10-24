"""Optuna AutoML driver for CT-TGNN and MambaShield (chapter 6 Phase B).

Sweeps the small hyperparameter grids the chapter pins for the
shared-core models, returning the best trial's params + score.

Optuna is the platform's chosen search engine because (i) the chapter
explicitly names it, (ii) it's pure-Python with no native dependency,
and (iii) the same driver re-runs against the real TEXBAT IQ once that
loader is fleshed out — same interface, same trial storage.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader, random_split

from plugins.uav.uav_defense.attacks import pgd
from plugins.uav.uav_defense.datasets import SyntheticTEXBAT
from plugins.uav.uav_defense.models import CTTGNN, MambaShield

Model = Literal["ct_tgnn", "mamba_shield"]
TRIAL_LOG_PATH = Path("weights/uav_optuna_trials.json")


def _build_ct_tgnn(trial) -> CTTGNN:
    return CTTGNN(
        feat_dim=8,
        hidden_dim=trial.suggest_categorical("hidden_dim", [16, 32, 64]),
        n_steps=trial.suggest_int("n_steps", 2, 6),
        dt=trial.suggest_float("dt", 0.1, 0.5),
    )


def _build_mamba(trial) -> MambaShield:
    return MambaShield(
        feat_dim=8,
        d_model=trial.suggest_categorical("d_model", [32, 64, 128]),
        n_blocks=trial.suggest_int("n_blocks", 1, 3),
    )


def _objective_factory(model_kind: Model, n_samples: int, n_trials_pgd_steps: int):
    def _obj(trial):
        torch.manual_seed(trial.number)
        ds = SyntheticTEXBAT(n_samples=n_samples, seed=trial.number)
        n_train = int(0.8 * len(ds))
        train_ds, val_ds = random_split(ds, [n_train, len(ds) - n_train])
        train_loader = DataLoader(train_ds, batch_size=trial.suggest_categorical("batch_size", [32, 64, 128]), shuffle=True)

        if model_kind == "ct_tgnn":
            model = _build_ct_tgnn(trial)
            takes_adj = True
        else:
            model = _build_mamba(trial)
            takes_adj = False

        lr = trial.suggest_float("lr", 1e-4, 5e-3, log=True)
        epsilon = trial.suggest_float("epsilon", 2 / 255, 8 / 255)
        optimizer = torch.optim.Adam(model.parameters(), lr=lr)
        model.train()
        for _epoch in range(2):  # short for AutoML speed
            for x, adj, y in train_loader:
                x_adv = pgd(model, x, y, epsilon=epsilon,
                            n_steps=n_trials_pgd_steps,
                            adj=adj if takes_adj else None)
                logits = model(x_adv, adj) if takes_adj else model(x_adv)
                loss = F.cross_entropy(logits, y)
                optimizer.zero_grad(); loss.backward(); optimizer.step()

        # Evaluate robust accuracy on val under PGD-10
        model.eval()
        val_loader = DataLoader(val_ds, batch_size=128, shuffle=False)
        x_v, adj_v, y_v = next(iter(val_loader))
        x_adv = pgd(model, x_v, y_v, epsilon=4 / 255, n_steps=10,
                    adj=adj_v if takes_adj else None)
        with torch.no_grad():
            logits = model(x_adv, adj_v) if takes_adj else model(x_adv)
            robust_acc = float((logits.argmax(dim=-1) == y_v).float().mean().item())
        trial.set_user_attr("robust_acc_pgd10_eps4_255", robust_acc)
        return robust_acc
    return _obj


def run_search(
    model_kind: Model = "ct_tgnn",
    n_trials: int = 12,
    n_samples: int = 512,
    pgd_steps: int = 5,
) -> dict:
    import optuna

    study = optuna.create_study(direction="maximize",
                                study_name=f"uav_phase_b_{model_kind}")
    obj = _objective_factory(model_kind, n_samples, pgd_steps)
    study.optimize(obj, n_trials=n_trials, show_progress_bar=False)

    out = {
        "model_kind": model_kind,
        "n_trials": n_trials,
        "best_value": study.best_value,
        "best_params": study.best_params,
        "best_trial_user_attrs": study.best_trial.user_attrs,
        "all_trials": [
            {"number": t.number, "value": t.value, "params": t.params,
             "user_attrs": t.user_attrs, "state": t.state.name}
            for t in study.trials
        ],
    }

    TRIAL_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if TRIAL_LOG_PATH.exists():
        existing = json.loads(TRIAL_LOG_PATH.read_text())
    else:
        existing = {}
    existing[model_kind] = out
    TRIAL_LOG_PATH.write_text(json.dumps(existing, indent=2))
    return out


def latest_results() -> dict:
    if not TRIAL_LOG_PATH.exists():
        return {}
    try:
        return json.loads(TRIAL_LOG_PATH.read_text())
    except json.JSONDecodeError:
        return {}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="ct_tgnn", choices=["ct_tgnn", "mamba_shield"])
    parser.add_argument("--n-trials", type=int, default=12)
    parser.add_argument("--n-samples", type=int, default=512)
    parser.add_argument("--pgd-steps", type=int, default=5)
    args = parser.parse_args()
    print(json.dumps(run_search(args.model, args.n_trials, args.n_samples, args.pgd_steps), indent=2))
