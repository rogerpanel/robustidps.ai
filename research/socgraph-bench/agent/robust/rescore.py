"""Rescore finished practice runs against a (revised) task pack, offline.

Quality depends only on the submitted report and the ground truth, and
efficiency only on the number of tool calls, so a run can be rescored from its
traces without calling the model again, provided the task graphs are the same.

    python -m bluesec1_agent.robust.cli --rescore traces/2026*-local-run --pack pack.zip

Each run folder gets a sibling `<folder>-rescored-v<pack version>` holding a
summary.json in the same format as a live run, plus an ablation table across
all rescored runs.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

from .localdata.pack import PACK_VERSION, load_pack
from .localdata.runtime import score
from .localdata.scenarios import Task
from .metrics import compute
from .table import ablation_table


def rescore_run(folder: Path, tasks: dict[str, Task], version: str) -> dict[str, Any]:
    original = json.loads((folder / "summary.json").read_text())
    rows: list[dict[str, Any]] = []
    for path in sorted(folder.glob("*.json")):
        if path.name == "summary.json":
            continue
        trace = json.loads(path.read_text())
        tid = trace.get("task_id")
        if tid not in tasks:
            raise SystemExit(f"{path}: task {tid!r} is not in the pack")
        task = tasks[tid]
        result = trace.get("result") or {}
        calls = int(result.get("tool_calls") or 0)
        completion = result.get("completion_reason")
        sub = trace.get("submission")
        row: dict[str, Any] = {
            "task_id": tid,
            "platform": task.scenario.platform,
            "expected_verdict": task.scenario.verdict,
            "verdict": None,
            "completion": completion,
            "quality": 0.0,
            "efficiency": 0.0,
            "reward": 0.0,
            "calls": calls,
            "original_quality": result.get("quality_score"),
            "original_reward": result.get("total_reward"),
            "saved": trace.get("calls_saved_by_cache", 0),
            "refused_locally": sum(1 for st in trace.get("steps", [])
                                   if st.get("status") == "refused_locally"),
            "wall_seconds": trace.get("wall_seconds"),
            "usage": trace.get("usage") or {},
        }
        if completion == "terminated" and isinstance(sub, dict):
            quality, detail = score(task, sub)
            efficiency = min(1.0, (task.scenario.optimal_calls + 1) / max(calls, 1))
            row.update(verdict=sub.get("verdict"), quality=round(quality, 4),
                       efficiency=round(efficiency, 4),
                       reward=round(quality * (0.8 + 0.2 * efficiency), 4), detail=detail)
        rows.append(row)
    if not rows:
        raise SystemExit(f"{folder}: no task traces found")
    n = len(rows)
    summary = {
        "run_id": original.get("run_id", folder.name),
        "rescored_from": str(folder),
        "pack_version": version,
        "tasks": n,
        "completed": sum(r["completion"] in ("terminated", "truncated") for r in rows),
        "mean_quality": round(sum(r["quality"] for r in rows) / n, 4),
        "mean_efficiency": round(sum(r["efficiency"] for r in rows) / n, 4),
        "mean_reward": round(sum(r["reward"] for r in rows) / n, 4),
        "mean_tool_calls": round(sum(r["calls"] for r in rows) / n, 2),
        "config": original.get("config") or {"label": folder.name, "ablations": []},
        "metrics": compute(rows),
        "task_rows": rows,
    }
    out = folder.parent / f"{folder.name}-rescored-v{version}"
    out.mkdir(exist_ok=True)
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    return summary


def rescore(folders: list[Path], pack: Path) -> dict[str, Any]:
    with zipfile.ZipFile(pack) as zf:
        version = json.loads(zf.read("manifest.json")).get("version", "1.0")
    tasks = {t.scenario.id: t for t in load_pack(pack)}
    folders = [f for f in folders if (f / "summary.json").is_file() and "-rescored-" not in f.name]
    if not folders:
        raise SystemExit("no run folders (with a summary.json) to rescore")
    summaries = []
    for folder in folders:
        s = rescore_run(folder, tasks, version)
        summaries.append(s)
        m = s["metrics"]["overall"]
        print(f"{folder.name} [{s['config'].get('label')}]: quality {m['mean_quality']:.3f} "
              f"efficiency {m['mean_efficiency']:.3f} reward {m['mean_reward']:.3f}")
    md, csv_text = ablation_table(summaries)
    out = folders[0].parent / f"ablation-rescored-v{version}-{len(summaries)}"
    Path(f"{out}.md").write_text(md)
    Path(f"{out}.csv").write_text(csv_text)
    print(md)
    return {"ablation_table": f"{out}.md", "csv": f"{out}.csv", "runs": len(summaries),
            "pack_version": version, "pack_default_version": PACK_VERSION}
