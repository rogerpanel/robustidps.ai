"""
Generate initial weight files for all CL-RL models.

Creates deterministic random weights so models are immediately usable
for demo inference without real training data.
"""

import torch
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))

from models.clrl_models import (
    CLRLUnifiedWrapper,
    CPOPolicyWrapper,
    ValueNetWrapper,
    CostValueNetWrapper,
    UnifiedFIMWrapper,
)

WEIGHTS_DIR = Path(__file__).parent / "weights"
WEIGHTS_DIR.mkdir(exist_ok=True)

MODELS = {
    "clrl_unified.pt": CLRLUnifiedWrapper,
    "cpo_policy.pt": CPOPolicyWrapper,
    "value_net.pt": ValueNetWrapper,
    "cost_value_net.pt": CostValueNetWrapper,
    "unified_fim.pt": UnifiedFIMWrapper,
}


def main():
    torch.manual_seed(42)
    for filename, cls in MODELS.items():
        path = WEIGHTS_DIR / filename
        m = cls(dropout=0.05)
        # Deterministic Xavier init
        for name, param in m.named_parameters():
            if "weight" in name and param.dim() >= 2:
                torch.nn.init.xavier_uniform_(param)
            elif "bias" in name:
                torch.nn.init.zeros_(param)

        torch.save(m.state_dict(), path)
        n_params = sum(p.numel() for p in m.parameters())
        print(f"  {filename}: {n_params:,} parameters -> {path}")

    print("Done. All CL-RL weight files created.")


if __name__ == "__main__":
    main()
