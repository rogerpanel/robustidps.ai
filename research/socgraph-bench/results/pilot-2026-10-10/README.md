# Pilot run, 2026-10-10

The first run of the agent with a real model, on the 11 Windows tasks of the
benchmark (OTRF Security-Datasets), before the Linux tasks were added.

- Model: Claude Opus 5.5 (`claude-opus-5-5`), effort `high`, 4 tasks in parallel
- Agent: full configuration (no component turned off), soft budget 12, hard cap 30
- Result: 11/11 tasks completed, every verdict correct (3 benign, 8 malicious),
  mean quality 0.933, mean efficiency 0.659, mean reward 0.870, 7.27 tool
  calls per task, 56.7 s wall clock for the whole run

`per_task.csv` is transcribed from the run's console output (one log line per
task); `summary.json` from the summary it printed. The run folder itself
(`traces/20261010-231518-local-run/`) stays on the machine that ran it; add it
next to this file to make the record complete.

Note: after this run, the ground-truth rule for accounts was refined (core
accounts = the session owner, plus the trigger's account unless it is
SYSTEM/root). For these Windows tasks the core sets name the same operator
account, so scores are expected to be comparable, but the study runs on
SOCGraph-21 v1 are the reference results.
