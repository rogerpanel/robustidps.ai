# Manuscript changelog

## 2026-10-25: first full draft
- Results from AgentDojo v1.2 replay (filter 0.5.0), internal suites, deferral simulation.
- Found and fixed while writing: a power plateau in fixed-sequence Learn then Test (now a decile grid),
  pooled-session collisions in the replay harness, goal-level clustering for intervals.

## 2026-10-25: live-model protocol
- Added the live-model protocol (methodology) and a generated RQ5 section and table that fill in
  from results/live/live_results.json; until runs exist the text states that results are pending.

## 2026-10-26: burden-aware authoring
- RQ4 rewritten around review burden: balanced strategy, final-goal-call labels, and a held-out-goal split showing that edits do not transfer to unseen goals.

## 2026-10-26: live-run analysis
- Paired McNemar tests, attribution of lost tasks and stopped attacks to filter decisions, per-call check time,
  tokens per run, a utility-versus-attack-success figure; run manifests with file hashes, only verified runs used.
