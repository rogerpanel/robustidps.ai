"""uav_defense — reference implementation of chapter 6 Phase A.

Package layout follows §6.7 of the dissertation:
  datasets/   TEXBAT, AU-AIR, calibrated synthetic generator
  models/     M1 CT-TGNN, M4 MambaShield, baselines (CAF-CNN, Seq2Seq Transformer)
  attacks/    FGSM, PGD, CW, HopSkipJump, BoundaryAttack, clean-label poisoning
  defenses/   randomized smoothing (Cohen + Clopper-Pearson), Gronwall Lipschitz
  ew_bench/   UAV-EW-Bench-2026 Mission-Completion-Rate vs J/S harness
"""
__version__ = "0.1.0-phaseA"
