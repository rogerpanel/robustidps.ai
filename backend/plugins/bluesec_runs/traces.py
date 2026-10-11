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

    # Rows from summary.json fill in task metadata a trace may lack (summary-only uploads).
    if summary and isinstance(summary.get("task_rows"), list):
        for row in summary["task_rows"][:MAX_TASKS]:
            t = tasks.get(row.get("task_id")) if isinstance(row, dict) else None
            if t is not None:
                t.setdefault("task_meta", _meta(row))
                if not t.get("submission") and row.get("verdict") in ("malicious", "benign"):
                    t["submission"] = {"verdict": row["verdict"]}
                if not t.get("usage"):
                    t["usage"] = _usage(row.get("usage"))

    ordered = sorted(tasks.values(), key=lambda t: t["task_id"])
    models = sorted({t.get("model") for t in ordered if t.get("model")})
    config = _config(summary.get("config")) if summary else {}
    return {
        "pt_run_id": _s(summary.get("run_id"), 255) if summary else "",
        "agent_model": ", ".join(models)[:255],
        "label": config.get("label", ""),
        "config": config,
        "tasks": ordered,
        "aggregates": aggregates(ordered),
        "metrics": metrics(ordered),
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
        **({"task_meta": _meta(doc["task_meta"])} if isinstance(doc.get("task_meta"), dict) else {}),
        "usage": _usage(doc.get("usage")),
        "ablations": [_s(a, 40) for a in doc.get("ablations", []) if isinstance(a, str)][:10],
    }


def _meta(m: dict[str, Any]) -> dict[str, Any]:
    out = {k: _s(m.get(k), 120) for k in ("platform", "expected_verdict", "attack", "source")}
    return {k: v for k, v in out.items() if v}


def _usage(u: Any) -> dict[str, int]:
    u = u if isinstance(u, dict) else {}
    return {k: _int(u.get(k)) for k in ("input", "output", "cache_read", "cache_write",
                                        "llm_calls")}


CONFIG_STR = ("label", "provider", "model", "effort", "runtime")
CONFIG_INT = ("concurrency", "soft_budget", "max_tool_calls")


def _config(c: Any) -> dict[str, Any]:
    if not isinstance(c, dict):
        return {}
    out: dict[str, Any] = {k: _s(c.get(k), 120) for k in CONFIG_STR if isinstance(c.get(k), str)}
    out.update({k: _int(c.get(k)) for k in CONFIG_INT if c.get(k) is not None})
    out["ablations"] = [_s(a, 40) for a in c.get("ablations", []) if isinstance(a, str)][:10]
    return out


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 4) if values else None


def _group(tasks: list[dict[str, Any]]) -> dict[str, Any]:
    """Same definitions as the agent's own summary (bluesec/robust/metrics.py)."""
    rows = []
    for t in tasks:
        sub = t.get("submission") if isinstance(t.get("submission"), dict) else {}
        r = t["result"]
        rows.append({
            "expected": (t.get("task_meta") or {}).get("expected_verdict"),
            "verdict": sub.get("verdict") if r["completion_reason"] == "terminated" else None,
            "quality": r["quality_score"], "efficiency": r["efficiency_score"],
            "reward": r["total_reward"], "calls": r["tool_calls"],
            "wall": t.get("wall_seconds") or 0.0, "usage": t.get("usage") or {},
            "completed": r["completion_reason"] in ("terminated", "truncated"),
        })
    judged = [r for r in rows if r["expected"] in ("malicious", "benign")]
    benign = [r for r in judged if r["expected"] == "benign"]
    malicious = [r for r in judged if r["expected"] == "malicious"]
    return {
        "tasks": len(rows),
        "completed": sum(r["completed"] for r in rows),
        "mean_quality": _mean([r["quality"] for r in rows]),
        "mean_efficiency": _mean([r["efficiency"] for r in rows]),
        "mean_reward": _mean([r["reward"] for r in rows]),
        "mean_tool_calls": _mean([r["calls"] for r in rows]),
        "verdict_accuracy": _mean([float(r["verdict"] == r["expected"]) for r in judged]),
        "false_positive_rate": _mean([float(r["verdict"] == "malicious") for r in benign]),
        "false_negative_rate": _mean([float(r["verdict"] == "benign") for r in malicious]),
        "mean_wall_seconds": _mean([r["wall"] for r in rows if r["wall"]]),
        "tokens_input": sum(r["usage"].get("input", 0) for r in rows),
        "tokens_output": sum(r["usage"].get("output", 0) for r in rows),
        "llm_calls": sum(r["usage"].get("llm_calls", 0) for r in rows),
    }


def metrics(tasks: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {"overall": _group(tasks)}
    for key in ("platform", "expected_verdict"):
        values = sorted({(t.get("task_meta") or {}).get(key) for t in tasks} - {None, ""})
        out[f"by_{key}"] = {
            v: _group([t for t in tasks if (t.get("task_meta") or {}).get(key) == v])
            for v in values
        }
    return out


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
