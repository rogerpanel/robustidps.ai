"""
RobustIDPS Model Implementations
=================================

Dissertation models (PyTorch nn.Module) plus lightweight surrogate
for demo inference, and CL-RL models for continual learning and
reinforcement learning-based autonomous response.

Author: Roger Nick Anaedevha
"""

from .surrogate import SurrogateIDS
from .model_registry import list_models, load_model, MODEL_INFO
from .clrl_models import (
    CLRLUnifiedWrapper,
    CPOPolicyWrapper,
    ValueNetWrapper,
    CostValueNetWrapper,
    UnifiedFIMWrapper,
)
from .policy_network import PolicyNetwork, ValueNetwork, CostValueNetwork
from .unified_fim import UnifiedFIM
from .nids_env import NIDSResponseEnv, ACTION_NAMES, ACTION_SEVERITY
from .adversarial import AdversarialEvaluator, ATTACK_CONFIGS
from .clrl_metrics import ContinualMetrics, RLMetrics, DriftDetector

__all__ = [
    "SurrogateIDS",
    "list_models",
    "load_model",
    "MODEL_INFO",
    # CL-RL Model Wrappers
    "CLRLUnifiedWrapper",
    "CPOPolicyWrapper",
    "ValueNetWrapper",
    "CostValueNetWrapper",
    "UnifiedFIMWrapper",
    # CL-RL Core Components
    "PolicyNetwork",
    "ValueNetwork",
    "CostValueNetwork",
    "UnifiedFIM",
    "NIDSResponseEnv",
    "ACTION_NAMES",
    "ACTION_SEVERITY",
    # Evaluation
    "AdversarialEvaluator",
    "ATTACK_CONFIGS",
    "ContinualMetrics",
    "RLMetrics",
    "DriftDetector",
]
