from plugins.uav.uav_defense.attacks.fgsm import fgsm
from plugins.uav.uav_defense.attacks.pgd import pgd
from plugins.uav.uav_defense.attacks.cw import cw
from plugins.uav.uav_defense.attacks.deepfool import deepfool
from plugins.uav.uav_defense.attacks.gaussian import gaussian_noise, feature_mask
from plugins.uav.uav_defense.attacks.hop_skip_jump import hop_skip_jump
from plugins.uav.uav_defense.attacks.boundary import boundary_attack
from plugins.uav.uav_defense.attacks.data_poisoning import feature_collision_poison
from plugins.uav.uav_defense.attacks.label_flip import random_label_flip, targeted_label_flip

__all__ = [
    "fgsm", "pgd", "cw", "deepfool", "gaussian_noise", "feature_mask",
    "hop_skip_jump", "boundary_attack",
    "feature_collision_poison", "random_label_flip", "targeted_label_flip",
]


ATTACK_CATALOG = [
    {"id": "fgsm",            "label": "FGSM",                 "kind": "white_box",  "desc": "Fast Gradient Sign — single-step, fast"},
    {"id": "pgd",             "label": "PGD",                  "kind": "white_box",  "desc": "Projected Gradient Descent — iterative, stronger"},
    {"id": "cw",              "label": "C&W (L2)",             "kind": "white_box",  "desc": "Carlini & Wagner — optimisation-based, smallest perturbation"},
    {"id": "deepfool",        "label": "DeepFool",             "kind": "white_box",  "desc": "Minimal perturbation to cross the closest decision boundary"},
    {"id": "hop_skip_jump",   "label": "HopSkipJump",          "kind": "black_box",  "desc": "Decision-based, query-efficient Monte-Carlo gradient estimate"},
    {"id": "boundary",        "label": "BoundaryAttack",       "kind": "black_box",  "desc": "Decision-based random walk along the decision boundary"},
    {"id": "gaussian",        "label": "Gaussian noise",       "kind": "baseline",   "desc": "Random Gaussian perturbation — non-adversarial baseline"},
    {"id": "feature_mask",    "label": "Feature masking",      "kind": "baseline",   "desc": "Random feature dropout — non-adversarial baseline"},
    {"id": "label_flip",      "label": "Label flipping",       "kind": "training",   "desc": "Training-time poison — flips a fraction of labels"},
]

