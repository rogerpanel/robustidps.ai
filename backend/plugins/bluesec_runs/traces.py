"""Turn the JSON files a BlueSec agent run writes into one stored run.

A run directory (`traces/<YYYYMMDD-HHMMSS>-<run id>/`) holds one JSON file
per task plus `summary.json`. Files are recognised by shape, not by name,
so a partial upload (a few task files, or only the summary) still works.
Everything is copied field by field with size caps: uploaded JSON is
untrusted input and is stored and rendered, never executed.
"""
from __future__ import annotations

import datetime
import re
from typing import Any

MAX_TASKS = 500
MAX_STEPS = 300
MAX_TEXT = 4000
MAX_RESULT = 3000

RESULT_FIELDS = ("completion_reason", "quality_score", "efficiency_score", "total_reward",
                 "tool_calls", "steps_taken", "wall_time_seconds")
STEP_STATUSES = {"ok", "cached", "refused_locally", "error", "terminal"}


class TraceError(ValueError):
    """The documents do not contain a recognisable run."""


def build_run(documents: list[Any]) -> dict[str, Any]:
    summary: dict[str, Any] | None = None
    tasks: dict[str, dict[str, Any]] = {}
    ignored = 0
    for doc in documents:
        if not isinstance(doc, dict):
            ignored += 1
        elif isinstance(doc.get("task_results"), list) and "run_id" in doc:
            summary = doc
        elif isinstance(doc.get("task_id"), str) and ("result" in doc or "steps" in doc):
            task = _task(doc)
            tasks[task["task_id"]] = task
        else:
            ignored += 1

    if not tasks and summary:
        for r in summary["task_results"][:MAX_TASKS]:
            if isinstance(r, dict) and isinstance(r.get("task_id"), str):
                tasks[r["task_id"]] = {"task_id": r["task_id"][:255], "result": _result(r),
                                       "steps": [], "from_summary_only": True}
    if not tasks:
        raise TraceError("No task traces or summary.json found in the selected files.")
    if len(tasks) > MAX_TASKS:
        raise TraceError(f"Too many tasks ({len(tasks)}); the limit is {MAX_TASKS}.")

    ordered = sorted(tasks.values(), key=lambda t: t["task_id"])
    models = sorted({t.get("model") for t in ordered if t.get("model")})
    return {
        "pt_run_id": _s(summary.get("run_id"), 255) if summary else "",
        "agent_model": ", ".join(models)[:255],
        "tasks": ordered,
        "aggregates": aggregates(ordered),
        "ignored_files": ignored,
    }


def aggregates(tasks: list[dict[str, Any]]) -> dict[str, Any]:
    results = [t["result"] for t in tasks]
    n = len(results) or 1

    def mean(key: str) -> float:
        return round(sum(float(r.get(key) or 0) for r in results) / n, 4)

    return {
        "n_tasks": len(results),
        "n_completed": sum(r.get("completion_reason") in ("terminated", "truncated")
                           for r in results),
        "mean_quality": mean("quality_score"),
        "mean_efficiency": mean("efficiency_score"),
        "mean_reward": mean("total_reward"),
        "mean_tool_calls": round(sum(float(r.get("tool_calls") or 0) for r in results) / n, 2),
        "calls_saved_by_cache": sum(int(t.get("calls_saved_by_cache") or 0) for t in tasks),
    }


def started_at_from_folder(name: str) -> datetime.datetime | None:
    m = re.match(r"(\d{8}-\d{6})", name)
    if not m:
        return None
    try:
        return datetime.datetime.strptime(m.group(1), "%Y%m%d-%H%M%S")
    except ValueError:
        return None


# ---------------------------------------------------------------- helpers
def _task(doc: dict[str, Any]) -> dict[str, Any]:
    steps = doc.get("steps") if isinstance(doc.get("steps"), list) else []
    return {
        "task_id": _s(doc["task_id"], 255),
        "model": _s(doc.get("model"), 255),
        "alert": _json(doc.get("alert")),
        "tools": [_s(t.get("name"), 100) for t in doc.get("tools", []) if isinstance(t, dict)][:50],
        "steps": [s for s in (_step(x) for x in steps[:MAX_STEPS]) if s],
        "submission": _json(doc.get("submission")),
        "calls_spent": _int(doc.get("calls_spent")),
        "calls_saved_by_cache": _int(doc.get("calls_saved_by_cache")),
        "wall_seconds": _num(doc.get("wall_seconds")),
        "error": _s(doc.get("error"), 2000) or None,
        "result": _result(doc.get("result") if isinstance(doc.get("result"), dict) else {}),
    }


def _step(step: Any) -> dict[str, Any] | None:
    if not isinstance(step, dict):
        return None
    kind = step.get("type")
    if kind in ("thinking", "text"):
        return {"type": kind, "text": _s(step.get("text"), MAX_TEXT)}
    if kind != "tool_call":
        return None
    status = step.get("status") if step.get("status") in STEP_STATUSES else "unknown"
    out = {
        "type": "tool_call",
        "tool": _s(step.get("tool"), 100),
        "arguments": _json(step.get("arguments")),
        "status": status,
        "spent_so_far": _int(step.get("spent_so_far")),
        "result": _s(step.get("result"), MAX_RESULT),
    }
    if isinstance(step.get("reward"), int | float):
        out["reward"] = float(step["reward"])
    return out


def _result(r: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in RESULT_FIELDS:
        value = r.get(key)
        if key == "completion_reason":
            out[key] = value if value in ("terminated", "truncated", "error", "aborted") else "unknown"
        else:
            out[key] = _num(value)
    return out


def _json(value: Any, depth: int = 0) -> Any:
    """Copy plain JSON with depth and size caps."""
    if depth > 12:
        return None
    if isinstance(value, dict):
        return {str(k)[:200]: _json(v, depth + 1) for k, v in list(value.items())[:200]}
    if isinstance(value, list):
        return [_json(v, depth + 1) for v in value[:500]]
    if isinstance(value, str):
        return value[:MAX_TEXT]
    if isinstance(value, bool | int | float) or value is None:
        return value
    return str(value)[:200]


def _s(value: Any, limit: int) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _int(value: Any) -> int:
    return int(value) if isinstance(value, int | float) and not isinstance(value, bool) else 0


def _num(value: Any) -> float:
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else 0.0
