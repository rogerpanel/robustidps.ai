"""Consume the task queue and keep a trace of every investigation."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from loguru import logger

from bluesec1_client import TaskResult

from .catalog import ToolCatalog
from .drivers import run_claude, run_openai
from .investigation import Investigation
from .settings import RobustSettings


class RobustAgent:
    def __init__(self, settings: RobustSettings, llm: Any) -> None:
        self.s = settings
        self.llm = llm

    async def run(self, client: Any) -> dict[str, Any]:
        run_id = client.run.run_id
        trace_dir = Path(self.s.trace_dir) / f"{time.strftime('%Y%m%d-%H%M%S')}-{run_id[:12]}"
        trace_dir.mkdir(parents=True, exist_ok=True)
        results: list[TaskResult] = []
        while (session := await client.start_task()) is not None:
            result = await self._one(session, trace_dir)
            results.append(result)
            logger.info(
                "Task {} {}: quality={:.3f} efficiency={:.3f} reward={:.3f} calls={}",
                result.task_id, result.completion_reason, result.quality_score,
                result.efficiency_score, result.total_reward, result.tool_calls,
            )
        summary = summarise(run_id, results)
        (trace_dir / "summary.json").write_text(json.dumps(summary, indent=2))
        logger.info("Traces written to {}", trace_dir)
        return summary

    async def _one(self, session: Any, trace_dir: Path) -> TaskResult:
        trace: dict[str, Any] = {
            "task_id": session.task_id,
            "model": self.s.model_label(),
            "alert": {k: v for k, v in session.task.observation.items() if k != "available_tools"},
        }
        inv: Investigation | None = None
        try:
            catalog = ToolCatalog.from_observation(session.task.observation)
            trace["tools"] = catalog.public()
            inv = Investigation(
                session, catalog,
                soft_budget=self.s.soft_budget,
                hard_budget=self.s.max_tool_calls,
                max_result_chars=self.s.max_result_chars,
            )
            if self.s.provider == "anthropic":
                result = await run_claude(inv, self.llm, model=self.s.anthropic_model,
                                          effort=self.s.anthropic_effort,
                                          max_turns=self.s.max_turns)
            else:
                result = await run_openai(inv, self.llm, model=self.s.llm_default_model or "",
                                          max_turns=self.s.max_turns,
                                          max_completion_tokens=self.s.llm_max_completion_tokens)
        except Exception as exc:
            logger.error("Task {} failed in the agent: {}", session.task_id, exc)
            trace["error"] = f"{type(exc).__name__}: {exc}"[:2000]
            result = TaskResult.model_validate(
                await session.abort_task(error_message=trace["error"])
            )
        if inv is not None:
            trace.update(steps=inv.steps, submission=inv.submission, calls_spent=inv.spent,
                         calls_saved_by_cache=inv.saved,
                         wall_seconds=round(time.monotonic() - inv.started, 1))
        trace["result"] = result.model_dump(mode="json")
        safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in session.task_id)
        (trace_dir / f"{safe}.json").write_text(
            json.dumps(trace, indent=2, ensure_ascii=False, default=str)
        )
        return result


def summarise(run_id: str, results: list[TaskResult]) -> dict[str, Any]:
    n = len(results) or 1
    return {
        "run_id": run_id,
        "tasks": len(results),
        "completed": sum(r.completion_reason in ("terminated", "truncated") for r in results),
        "mean_quality": round(sum(r.quality_score for r in results) / n, 4),
        "mean_efficiency": round(sum(r.efficiency_score for r in results) / n, 4),
        "mean_reward": round(sum(r.total_reward for r in results) / n, 4),
        "mean_tool_calls": round(sum(r.tool_calls for r in results) / n, 2),
        "task_results": [r.model_dump(mode="json") for r in results],
    }
