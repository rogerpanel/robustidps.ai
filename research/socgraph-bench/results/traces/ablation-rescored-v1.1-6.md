| Configuration | Tasks | Quality | Efficiency | Reward | Verdict acc. | FP rate | FN rate | Calls/task | Sec/task | Δ Reward vs full |
|---|---|---|---|---|---|---|---|---|---|---|
| full | 21 | 0.823 | 0.636 | 0.765 | 0.952 | 0.000 | 0.067 | 8.10 | 21.8 |  |
| no cache | 21 | 0.871 | 0.605 | 0.802 | 1.000 | 0.000 | 0.000 | 8.38 | 24.0 | +0.037 |
| no validation | 21 | 0.821 | 0.592 | 0.759 | 0.952 | 0.000 | 0.000 | 8.10 | 23.5 | -0.006 |
| no grounding | 21 | 0.824 | 0.616 | 0.762 | 0.952 | 0.000 | 0.067 | 8.52 | 21.7 | -0.003 |
| no budget | 21 | 0.873 | 0.599 | 0.803 | 1.000 | 0.000 | 0.000 | 9.05 | 23.9 | +0.038 |
| no method | 21 | 0.800 | 0.442 | 0.713 | 0.905 | 0.000 | 0.133 | 11.38 | 25.1 | -0.053 |

Each row turns off one component of the full agent; Δ is the change in mean reward against the full configuration on the same tasks.
