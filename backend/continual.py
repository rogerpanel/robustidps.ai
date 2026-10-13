"""
Continual Learning Engine — Elastic Weight Consolidation (EWC)
==============================================================

Provides incremental model updates on new traffic data without catastrophic
forgetting of previously learned attack signatures.  The implementation uses
Kirkpatrick et al. (2017) EWC with an optional experience-replay buffer.

Key ideas:
  * After each update round the diagonal Fisher Information Matrix (FIM) is
    computed for the current task and stored alongside the optimised weights.
  * During the next fine-tuning step an EWC penalty is added to the loss so
    that parameters important for earlier tasks remain close to their previous
    values.
  * A small replay buffer (configurable) stores representative samples from
    past tasks and mixes them into training batches to further stabilise
    performance.
"""

import copy
import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset

logger = logging.getLogger("robustidps.continual")


# ---------------------------------------------------------------------------
#  Data structures
# ---------------------------------------------------------------------------

@dataclass
class UpdateRecord:
    """One entry in the continual-learning history."""
    update_id: str
    timestamp: float
    n_samples: int
    epochs: int
    ewc_lambda: float
    loss_before: float
    loss_after: float
    acc_before: float
    acc_after: float
    dataset_format: str
    replay_size: int


@dataclass
class ContinualState:
    """Persistent state of the continual-learning engine."""
    version: int = 0
    total_samples_seen: int = 0
    history: list[UpdateRecord] = field(default_factory=list)
    # Stored as CPU tensors
    fisher_diag: dict[str, torch.Tensor] = field(default_factory=dict)
    star_params: dict[str, torch.Tensor] = field(default_factory=dict)
    replay_features: Optional[torch.Tensor] = None
    replay_labels: Optional[torch.Tensor] = None


# ---------------------------------------------------------------------------
#  EWC helpers
# ---------------------------------------------------------------------------

def _compute_fisher(
    model: nn.Module,
    features: torch.Tensor,
    device: str,
    n_samples: int = 2000,
) -> dict[str, torch.Tensor]:
    """Estimate the diagonal Fisher Information Matrix via sampling."""
    model.eval()
    fisher: dict[str, torch.Tensor] = {}
    for n, p in model.named_parameters():
        if p.requires_grad:
            fisher[n] = torch.zeros_like(p, device="cpu")

    # Use a subset if dataset is large
    idx = torch.randperm(len(features))[:n_samples]
    subset = features[idx].to(device)

    model.zero_grad()
    for i in range(len(subset)):
        x = subset[i : i + 1]
        logits = model(x)
        log_probs = F.log_softmax(logits, dim=-1)
        # Sample from the model's own distribution
        label = torch.multinomial(torch.exp(log_probs), 1).squeeze()
        loss = F.nll_loss(log_probs, label.unsqueeze(0))
        loss.backward()

        for n, p in model.named_parameters():
            if p.requires_grad and p.grad is not None:
                fisher[n] += (p.grad.detach().cpu() ** 2)
                p.grad.zero_()

    # Normalise
    for n in fisher:
        fisher[n] /= len(subset)

    return fisher


def _ewc_penalty(
    model: nn.Module,
    fisher: dict[str, torch.Tensor],
    star_params: dict[str, torch.Tensor],
    device: str,
) -> torch.Tensor:
    """Compute the EWC penalty term: sum_i F_i (theta_i - theta*_i)^2."""
    penalty = torch.tensor(0.0, device=device)
    for n, p in model.named_parameters():
        if n in fisher and n in star_params:
            f = fisher[n].to(device)
            star = star_params[n].to(device)
            penalty += (f * (p - star) ** 2).sum()
    return penalty


# ---------------------------------------------------------------------------
#  Main engine
# ---------------------------------------------------------------------------

class ContinualLearningEngine:
    """Manages incremental model updates with EWC regularisation."""

    def __init__(
        self,
        model: nn.Module,
        device: str = "cpu",
        checkpoint_dir: str | Path = "checkpoints",
        max_replay: int = 5000,
    ):
        self.model = model
        self.device = device
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self.max_replay = max_replay

        self.state = ContinualState()
        # Keep a snapshot for rollback
        self._prev_state_dict: Optional[dict] = None

    # ------------------------------------------------------------------
    #  Incremental update
    # ------------------------------------------------------------------

    def update(
        self,
        features: torch.Tensor,
        labels: torch.Tensor,
        *,
        epochs: int = 5,
        lr: float = 1e-4,
        batch_size: int = 256,
        ewc_lambda: float = 5000.0,
        dataset_format: str = "unknown",
    ) -> UpdateRecord:
        """Fine-tune the model on new data with EWC regularisation."""

        update_id = str(uuid.uuid4())[:8]
        logger.info(
            "Continual update %s: %d samples, %d epochs, lambda=%.0f",
            update_id, len(features), epochs, ewc_lambda,
        )

        # Save snapshot for rollback
        self._prev_state_dict = copy.deepcopy(self.model.state_dict())

        # ── Evaluate BEFORE update ─────────────────────────────────
        acc_before, loss_before = self._evaluate(features, labels)

        # ── Prepare data (mix in replay buffer) ───────────────────
        train_feats = features
        train_labels = labels
        if self.state.replay_features is not None:
            train_feats = torch.cat([features, self.state.replay_features], dim=0)
            train_labels = torch.cat([labels, self.state.replay_labels], dim=0)

        dataset = TensorDataset(train_feats, train_labels)
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        # ── Train with EWC ────────────────────────────────────────
        self.model.train()
        optimiser = torch.optim.Adam(self.model.parameters(), lr=lr)

        has_fisher = bool(self.state.fisher_diag)
        for epoch in range(epochs):
            epoch_loss = 0.0
            for batch_x, batch_y in loader:
                batch_x = batch_x.to(self.device)
                batch_y = batch_y.to(self.device)

                logits = self.model(batch_x)
                ce_loss = F.cross_entropy(logits, batch_y)

                loss = ce_loss
                if has_fisher and ewc_lambda > 0:
                    ewc = _ewc_penalty(
                        self.model,
                        self.state.fisher_diag,
                        self.state.star_params,
                        self.device,
                    )
                    loss = ce_loss + 0.5 * ewc_lambda * ewc

                optimiser.zero_grad()
                loss.backward()
                optimiser.step()
                epoch_loss += loss.item()

            logger.info(
                "  epoch %d/%d  loss=%.4f", epoch + 1, epochs, epoch_loss / len(loader)
            )

        # ── Evaluate AFTER update ──────────────────────────────────
        acc_after, loss_after = self._evaluate(features, labels)

        # ── Update Fisher & star params ────────────────────────────
        new_fisher = _compute_fisher(self.model, features, self.device)
        if has_fisher:
            # Online EWC: running average of Fisher matrices
            for n in new_fisher:
                if n in self.state.fisher_diag:
                    self.state.fisher_diag[n] = (
                        0.5 * self.state.fisher_diag[n] + 0.5 * new_fisher[n]
                    )
                else:
                    self.state.fisher_diag[n] = new_fisher[n]
        else:
            self.state.fisher_diag = new_fisher

        self.state.star_params = {
            n: p.detach().cpu().clone()
            for n, p in self.model.named_parameters()
            if p.requires_grad
        }

        # ── Update replay buffer ──────────────────────────────────
        self._update_replay_buffer(features, labels)

        # ── Record history ────────────────────────────────────────
        self.state.version += 1
        self.state.total_samples_seen += len(features)
        record = UpdateRecord(
            update_id=update_id,
            timestamp=time.time(),
            n_samples=len(features),
            epochs=epochs,
            ewc_lambda=ewc_lambda,
            loss_before=round(loss_before, 4),
            loss_after=round(loss_after, 4),
            acc_before=round(acc_before, 4),
            acc_after=round(acc_after, 4),
            dataset_format=dataset_format,
            replay_size=len(self.state.replay_features) if self.state.replay_features is not None else 0,
        )
        self.state.history.append(record)

        # ── Save checkpoint ───────────────────────────────────────
        self._save_checkpoint()

        logger.info(
            "Update %s complete: acc %.4f → %.4f (version %d)",
            update_id, acc_before, acc_after, self.state.version,
        )
        return record

    # ------------------------------------------------------------------
    #  Rollback
    # ------------------------------------------------------------------

    def rollback(self) -> bool:
        """Revert to the model state before the last update."""
        if self._prev_state_dict is None:
            return False
        self.model.load_state_dict(self._prev_state_dict)
        self.model.to(self.device)
        if self.state.history:
            self.state.history.pop()
        self.state.version = max(0, self.state.version - 1)
        self._prev_state_dict = None
        logger.info("Rolled back to version %d", self.state.version)
        return True

    # ------------------------------------------------------------------
    #  Status
    # ------------------------------------------------------------------

    def get_status(self) -> dict:
        """Return a JSON-serialisable status summary."""
        return {
            "version": self.state.version,
            "total_samples_seen": self.state.total_samples_seen,
            "replay_buffer_size": (
                len(self.state.replay_features)
                if self.state.replay_features is not None
                else 0
            ),
            "max_replay": self.max_replay,
            "has_fisher": bool(self.state.fisher_diag),
            "can_rollback": self._prev_state_dict is not None,
            "n_updates": len(self.state.history),
            "history": [
                {
                    "update_id": r.update_id,
                    "timestamp": r.timestamp,
                    "n_samples": r.n_samples,
                    "epochs": r.epochs,
                    "ewc_lambda": r.ewc_lambda,
                    "loss_before": r.loss_before,
                    "loss_after": r.loss_after,
                    "acc_before": r.acc_before,
                    "acc_after": r.acc_after,
                    "dataset_format": r.dataset_format,
                    "replay_size": r.replay_size,
                }
                for r in self.state.history
            ],
        }

    # ------------------------------------------------------------------
    #  Drift detection
    # ------------------------------------------------------------------

    def measure_drift(self, features: torch.Tensor, labels: torch.Tensor) -> dict:
        """Measure how the current model performs on new data without updating."""
        acc, loss = self._evaluate(features, labels)
        return {
            "accuracy": round(acc, 4),
            "loss": round(loss, 4),
            "n_samples": len(features),
            "recommendation": (
                "update_recommended"
                if acc < 0.85
                else "monitor" if acc < 0.92 else "stable"
            ),
        }

    # ------------------------------------------------------------------
    #  Private helpers
    # ------------------------------------------------------------------

    def _evaluate(
        self, features: torch.Tensor, labels: torch.Tensor
    ) -> tuple[float, float]:
        """Compute accuracy and loss on a dataset."""
        self.model.eval()
        with torch.no_grad():
            feats = features.to(self.device)
            labs = labels.to(self.device)
            logits = self.model(feats)
            loss = F.cross_entropy(logits, labs).item()
            preds = logits.argmax(-1)
            acc = (preds == labs).float().mean().item()
        return acc, loss

    def _update_replay_buffer(
        self, features: torch.Tensor, labels: torch.Tensor
    ) -> None:
        """Reservoir sampling to maintain a bounded replay buffer."""
        new_feats = features.cpu()
        new_labels = labels.cpu()

        if self.state.replay_features is None:
            # First task — take up to max_replay samples
            if len(new_feats) <= self.max_replay:
                self.state.replay_features = new_feats
                self.state.replay_labels = new_labels
            else:
                idx = torch.randperm(len(new_feats))[: self.max_replay]
                self.state.replay_features = new_feats[idx]
                self.state.replay_labels = new_labels[idx]
        else:
            # Merge and subsample
            combined_feats = torch.cat(
                [self.state.replay_features, new_feats], dim=0
            )
            combined_labels = torch.cat(
                [self.state.replay_labels, new_labels], dim=0
            )
            if len(combined_feats) > self.max_replay:
                idx = torch.randperm(len(combined_feats))[: self.max_replay]
                self.state.replay_features = combined_feats[idx]
                self.state.replay_labels = combined_labels[idx]
            else:
                self.state.replay_features = combined_feats
                self.state.replay_labels = combined_labels

    def _save_checkpoint(self) -> None:
        """Persist the model and EWC state to disk."""
        ckpt = {
            "model_state_dict": self.model.state_dict(),
            "version": self.state.version,
            "total_samples_seen": self.state.total_samples_seen,
            "fisher_diag": self.state.fisher_diag,
            "star_params": self.state.star_params,
        }
        path = self.checkpoint_dir / f"continual_v{self.state.version}.pt"
        torch.save(ckpt, path)
        # Also save as latest
        latest = self.checkpoint_dir / "continual_latest.pt"
        torch.save(ckpt, latest)
        logger.info("Checkpoint saved: %s", path)

    def load_checkpoint(self, path: Optional[str | Path] = None) -> bool:
        """Restore model and EWC state from a checkpoint."""
        if path is None:
            path = self.checkpoint_dir / "continual_latest.pt"
        path = Path(path)
        if not path.exists():
            return False

        ckpt = torch.load(path, map_location="cpu", weights_only=False)
        self.model.load_state_dict(ckpt["model_state_dict"])
        self.model.to(self.device)
        self.state.version = ckpt.get("version", 0)
        self.state.total_samples_seen = ckpt.get("total_samples_seen", 0)
        self.state.fisher_diag = ckpt.get("fisher_diag", {})
        self.state.star_params = ckpt.get("star_params", {})
        logger.info("Checkpoint restored from %s (version %d)", path, self.state.version)
        return True
