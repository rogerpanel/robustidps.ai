"""Run-level metrics for comparing agent configurations (ablation studies).

Each task row carries the runtime's scores plus, on practice tasks, the
expected verdict and platform. From those: verdict accuracy, false-positive
rate (benign judged malicious), false-negative rate (malicious judged
benign), and the same figures per platform and per expected verdict.
"""

from __future__ import annotations

from typing import Any


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 4) if values else None


def group(rows: list[dict[str, Any]]) -> dict[str, Any]:
    judged = [r for r in rows if r.get("expected_verdict") in ("malicious", "benign")]
    benign = [r for r in judged if r["expected_verdict"] == "benign"]
    malicious = [r for r in judged if r["expected_verdict"] == "malicious"]
    return {
        "tasks": len(rows),
        "completed": sum(r["completion"] in ("terminated", "truncated") for r in rows),
        "mean_quality": _mean([r["quality"] for r in rows]),
        "mean_efficiency": _mean([r["efficiency"] for r in rows]),
        "mean_reward": _mean([r["reward"] for r in rows]),
        "mean_tool_calls": _mean([r["calls"] for r in rows]),
        "verdict_accuracy": _mean(
            [float(r.get("verdict") == r["expected_verdict"]) for r in judged]
        ),
        "false_positive_rate": _mean([float(r.get("verdict") == "malicious") for r in benign]),
        "false_negative_rate": _mean([float(r.get("verdict") == "benign") for r in malicious]),
        "mean_wall_seconds": _mean([r["wall_seconds"] for r in rows if r.get("wall_seconds")]),
        "calls_saved_by_cache": sum(r.get("saved", 0) for r in rows),
        "calls_refused_locally": sum(r.get("refused_locally", 0) for r in rows),
        "tokens_input": sum(r.get("usage", {}).get("input", 0) for r in rows),
        "tokens_output": sum(r.get("usage", {}).get("output", 0) for r in rows),
        "tokens_cache_read": sum(r.get("usage", {}).get("cache_read", 0) for r in rows),
        "llm_calls": sum(r.get("usage", {}).get("llm_calls", 0) for r in rows),
    }


def compute(rows: list[dict[str, Any]]) -> dict[str, Any]:
    out = {"overall": group(rows)}
    for key in ("platform", "expected_verdict"):
        values = sorted({r.get(key) for r in rows if r.get(key)})
        out[f"by_{key}"] = {v: group([r for r in rows if r.get(key) == v]) for v in values}
    return out
