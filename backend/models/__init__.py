"""
RobustIDPS Model Implementations
=================================

Dissertation models (PyTorch nn.Module) plus lightweight surrogate
for demo inference.

Author: Roger Nick Anaedevha
"""

from .surrogate import SurrogateIDS

__all__ = [
    "SurrogateIDS",
]
