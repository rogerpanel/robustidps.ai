"""Single integration seam between uav_defense models and the platform's
existing Detector.predict_proba contract (chapter 6 §6.7).

This adapter wraps a torch nn.Module so it behaves identically to the
NIDS detectors registered in the main backend dispatcher. The wrapper
is intentionally stateless beyond the wrapped model so it can be
hot-swapped via the same ApplyModelUpdate gRPC the airframe agent uses.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import torch

from plugins.uav.uav_defense.models import CTTGNN, MambaShield


@dataclass
class UAVDetectorAdapter:
    method: str
    model: torch.nn.Module

    @classmethod
    def from_checkpoint(cls, method: str, checkpoint: str | Path) -> "UAVDetectorAdapter":
        method_lower = method.lower()
        if method_lower in {"m1", "ct_tgnn", "ct-tgnn"}:
            model = CTTGNN()
        elif method_lower in {"m4", "mamba_shield", "mamba-shield", "mambashield"}:
            model = MambaShield()
        else:
            raise ValueError(f"Unknown UAV method: {method}")
        path = Path(checkpoint)
        if path.exists():
            model.load_state_dict(torch.load(path, map_location="cpu"))
        model.eval()
        return cls(method=method_lower, model=model)

    @torch.no_grad()
    def predict_proba(self, x: torch.Tensor, adj: torch.Tensor | None = None) -> torch.Tensor:
        if hasattr(self.model, "predict_proba"):
            try:
                return self.model.predict_proba(x, adj)
            except TypeError:
                return self.model.predict_proba(x)
        logits = self.model(x, adj) if adj is not None else self.model(x)
        return torch.softmax(logits, dim=-1)
