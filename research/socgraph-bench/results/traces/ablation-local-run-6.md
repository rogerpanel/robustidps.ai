| Configuration | Tasks | Quality | Efficiency | Reward | Verdict acc. | FP rate | FN rate | Calls/task | Sec/task | Δ Reward vs full |
|---|---|---|---|---|---|---|---|---|---|---|
| full | 21 | 0.836 | 0.605 | 0.772 | 0.952 | 0.000 | 0.067 | 8.48 | 23.4 |  |
| no cache | 21 | 0.867 | 0.618 | 0.801 | 1.000 | 0.000 | 0.000 | 8.38 | 21.9 | +0.028 |
| no validation | 21 | 0.873 | 0.618 | 0.806 | 1.000 | 0.000 | 0.000 | 8.48 | 22.9 | +0.034 |
| no grounding | 21 | 0.874 | 0.602 | 0.805 | 1.000 | 0.000 | 0.000 | 8.67 | 23.5 | +0.033 |
| no budget | 21 | 0.876 | 0.613 | 0.808 | 1.000 | 0.000 | 0.000 | 8.71 | 24.5 | +0.036 |
| no method | 21 | 0.850 | 0.427 | 0.754 | 0.952 | 0.000 | 0.067 | 11.81 | 26.9 | -0.018 |

Each row turns off one component of the full agent; Δ is the change in mean reward against the full configuration on the same tasks.
