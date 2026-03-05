"""
RobustIDPS Model Implementations
=================================

Dissertation models (PyTorch nn.Module) plus lightweight surrogate
for demo inference.

Author: Roger Nick Anaedevha
"""

from .surrogate import SurrogateIDS
from .model_registry import list_models, load_model, MODEL_INFO

__all__ = [
    "SurrogateIDS",
    "list_models",
    "load_model",
    "MODEL_INFO",
]
