"""Consume the task queue, several tasks at a time, and trace every investigation.

Parallel mode: `concurrency` workers each lease a task and investigate it.
The runtime may cap how many tasks one participant or run holds at once; a
lease refused for that reason (TaskCapacityExceededError) teaches the pool the
real limit, and the worker waits for a slot instead of failing.

Deadline: with `deadline` set, no new task is leased after
`deadline - lease_stop_minutes`, and from `deadline - finish_minutes` running
investigations may only submit, so nothing is left unsubmitted at the cutoff.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from loguru import logger

from bluesec1_client import TaskCapacityExceededError, TaskResult

from .catalog import ToolCatalog
from .drivers import run_claude, run_openai
from .investigation import Investigation
from .settings import RobustSettings

CAPACITY_WAIT_SECONDS = 5.0
CAPACITY_MAX_IDLE_RETRIES = 24      # ~2 minutes refused with nothing of ours running


class _Pool:
    """Shared lease state for the workers of one run.

    A worker reserves a slot before leasing, so no more leases are attempted
    than the (learned) limit allows.
    """

    def __init__(self, target: int) -> None:
        self.limit = target
        self.active = 0          # reserved slots: leasing or investigating
        self.exhausted = False
        self.cond = asyncio.Condition()

    async def acquire(self) -> bool:
        """Reserve a slot. False once there is nothing left to lease."""
        async with self.cond:
            await self.cond.wait_for(lambda: self.exhausted or self.active < self.limit)
            if self.exhausted:
                return False
            self.active += 1
            return True

    async def release(self) -> None:
        async with self.cond:
            self.active -= 1
            self.cond.notify_all()

    async def learn_limit(self) -> None:
        """Called by a worker whose lease was refused: the others are the real limit."""
        async with self.cond:
            others = self.active - 1
            if 0 < others < self.limit:
                logger.info("Runtime holds {} task(s) at a time; using that limit.", others)
                self.limit = others

    async def done(self) -> None:
        async with self.cond:
            self.exhausted = True
            self.cond.notify_all()


_BUSY = object()   # lease refused for capacity while our other tasks run


class RobustAgent:
    def __init__(self, settings: RobustSettings, llm: Any) -> None:
        self.s = settings
        self.llm = llm

    async def run(self, client: Any) -> dict[str, Any]:
        run_id = client.run.run_id
        trace_dir = Path(self.s.trace_dir) / f"{time.strftime('%Y%m%d-%H%M%S')}-{run_id[:12]}"
        trace_dir.mkdir(parents=True, exist_ok=True)
        results: list[TaskResult] = []
        pool = _Pool(max(1, self.s.concurrency))
        running = {"now": 0, "peak": 0}
        lease_stop, finish_by = self._cutoffs()
        if lease_stop:
            logger.info("Deadline set: no new tasks after {}, submit-only from {}.",
                        time.strftime("%H:%M:%S", time.localtime(lease_stop)),
                        time.strftime("%H:%M:%S", time.localtime(finish_by)))

        async def worker(n: int) -> None:
            while await pool.acquire():
                try:
                    if lease_stop and time.time() >= lease_stop:
                        logger.warning("Lease cut-off reached; no new tasks are taken.")
                        await pool.done()
                        return
                    session = await self._lease(client, pool)
                    if session is _BUSY:
                        continue
                    if session is None:
                        await pool.done()
                        return
                    running["now"] += 1
                    running["peak"] = max(running["peak"], running["now"])
                    try:
                        result = await self._one(session, trace_dir, finish_by)
                    finally:
                        running["now"] -= 1
                    results.append(result)
                    logger.info(
                        "Task {} {}: quality={:.3f} efficiency={:.3f} reward={:.3f} calls={} "
                        "[{} done]",
                        result.task_id, result.completion_reason, result.quality_score,
                        result.efficiency_score, result.total_reward, result.tool_calls,
                        len(results),
                    )
                except TaskCapacityExceededError:
                    logger.error("The runtime keeps refusing new tasks although none of ours "
                                 "are running. Stopping; check for another open run.")
                    await pool.done()
                    return
                except Exception as exc:  # never let one task stop the other workers
                    logger.error("Worker {} task error: {}", n, exc)
                finally:
                    await pool.release()

        await asyncio.gather(*(worker(i + 1) for i in range(pool.limit)))
        summary = summarise(run_id, results)
        summary["peak_parallel_tasks"] = running["peak"]
        (trace_dir / "summary.json").write_text(json.dumps(summary, indent=2))
        logger.info("Traces written to {}", trace_dir)
        return summary

    async def _lease(self, client: Any, pool: _Pool) -> Any:
        idle_refusals = 0
        while True:
            try:
                return await client.start_task()
            except TaskCapacityExceededError:
                if pool.active > 1:
                    await pool.learn_limit()
                    return _BUSY
                # Refused while none of our other tasks run: a task held elsewhere
                # (an earlier run still releasing) or a server-wide limit. Wait it out.
                idle_refusals += 1
                if idle_refusals > CAPACITY_MAX_IDLE_RETRIES:
                    raise
                await asyncio.sleep(CAPACITY_WAIT_SECONDS)

    def _cutoffs(self) -> tuple[float | None, float | None]:
        if self.s.deadline is None:
            return None, None
        end = self.s.deadline.timestamp()
        return end - 60 * self.s.lease_stop_minutes, end - 60 * self.s.finish_minutes

    async def _one(self, session: Any, trace_dir: Path, finish_by: float | None) -> TaskResult:
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
                finish_by=finish_by,
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
