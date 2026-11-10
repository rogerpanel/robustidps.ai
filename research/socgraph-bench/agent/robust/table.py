"""Ablation table: one row per configuration, deltas against the full agent."""

from __future__ import annotations

import csv
import io
from typing import Any

COLUMNS = [
    ("mean_quality", "Quality", 3),
    ("mean_efficiency", "Efficiency", 3),
    ("mean_reward", "Reward", 3),
    ("verdict_accuracy", "Verdict acc.", 3),
    ("false_positive_rate", "FP rate", 3),
    ("false_negative_rate", "FN rate", 3),
    ("mean_tool_calls", "Calls/task", 2),
    ("mean_wall_seconds", "Sec/task", 1),
]


def ablation_table(summaries: list[dict[str, Any]]) -> tuple[str, str]:
    base = next((s for s in summaries if not s["config"]["ablations"]), summaries[0])
    b = base["metrics"]["overall"]
    head = ["Configuration", "Tasks"] + [c[1] for c in COLUMNS] + ["Δ Reward vs full"]
    md = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["configuration", "run_id", "tasks"] + [c[0] for c in COLUMNS] + ["delta_reward"])
    for s in summaries:
        m = s["metrics"]["overall"]
        delta = (m["mean_reward"] or 0) - (b["mean_reward"] or 0)
        cells = [_fmt(m.get(key), nd) for key, _, nd in COLUMNS]
        md.append(f"| {s['config']['label']} | {m['tasks']} | " + " | ".join(cells)
                  + f" | {'' if s is base else f'{delta:+.3f}'} |")
        w.writerow([s["config"]["label"], s["run_id"], m["tasks"]]
                   + [m.get(key) for key, _, _ in COLUMNS] + [round(delta, 4)])
    note = ("\nEach row turns off one component of the full agent; Δ is the change in mean "
            "reward against the full configuration on the same tasks.\n")
    return "\n".join(md) + "\n" + note, buf.getvalue()


def _fmt(v: Any, nd: int) -> str:
    return "–" if v is None else f"{v:.{nd}f}"
