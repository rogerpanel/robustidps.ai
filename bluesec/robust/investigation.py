"""One task: executes tool calls for the LLM and keeps the trace.

Everything here exists to avoid spending runtime tool calls on mistakes the
agent can catch itself:

- unknown tool names and schema violations are answered locally;
- an identical call is answered from the cache;
- a submission citing ids never seen in the alert or a tool result gets one
  local warning before it is sent;
- past the hard budget, evidence calls are refused so the agent submits.

A locally rejected call is sent anyway the second time the agent makes it
unchanged, because the runtime, not this module, is the authority.
"""
from __future__ import annotations

import contextlib
import json
import time
from dataclasses import dataclass
from typing import Any

from bluesec1_client import TaskResult, ToolCallResult

from .catalog import FINISH_TOOL, ToolCatalog
from .prompt import budget_note, render

_ID_KEYS = ("entity_id", "relation_id", "ad_object_id")


@dataclass
class Outcome:
    text: str
    is_error: bool = False
    terminal: TaskResult | None = None


class Investigation:
    def __init__(
        self,
        session: Any,
        catalog: ToolCatalog,
        *,
        soft_budget: int,
        hard_budget: int,
        max_result_chars: int,
    ) -> None:
        self.session = session
        self.catalog = catalog
        self.soft_budget = soft_budget
        self.hard_budget = hard_budget
        self.max_result_chars = max_result_chars
        self.spent = 0
        self.saved = 0
        self.started = time.monotonic()
        observation = session.task.observation
        self.corpus = [render(observation)]
        self._cache: dict[str, str] = {}
        self._rejected: set[str] = set()
        self.steps: list[dict[str, Any]] = []
        self.submission: dict[str, Any] | None = None

    # ------------------------------------------------------------------ calls
    async def execute(self, name: str, arguments: Any) -> Outcome:
        if not isinstance(arguments, dict):
            return self._local(name, arguments, "Arguments must be a JSON object.")
        if name not in self.catalog:
            return self._local(
                name, arguments, f"Unknown tool {name!r}. Available: {self.catalog.names()}"
            )
        arguments = _normalise(arguments, self.catalog.specs[name].schema)
        key = _key(name, arguments)
        is_finish = name == FINISH_TOOL

        if not is_finish and key in self._cache:
            self.saved += 1
            self._record(name, arguments, "cached", self._cache[key])
            return Outcome("[Duplicate call: answered from cache, no call spent]\n"
                           + self._cache[key])
        if not is_finish and self.spent >= self.hard_budget:
            return self._local(name, arguments, budget_note(self.spent, self.soft_budget,
                                                            self.hard_budget), soft=True)
        if key not in self._rejected:
            problems = self.catalog.specs[name].validate(arguments)
            if problems:
                self._rejected.add(key)
                return self._local(name, arguments,
                                   "Arguments do not match the tool schema: " + "; ".join(problems))
            if is_finish:
                missing = self._ungrounded(arguments)
                if missing:
                    self._rejected.add(key)
                    return self._local(
                        name, arguments,
                        "These ids never appeared in the alert or in any tool result: "
                        f"{missing}. Use ids exactly as returned, or drop them. "
                        "(Resubmitting unchanged sends it as is.)",
                    )

        response: ToolCallResult = await self.session.call_tool(name, arguments)
        self.spent += 1
        feedback = {
            "status": response.info.get("tool_status", "unknown"),
            "result": response.info.get("tool_result", response.observation),
            "error": response.info.get("error"),
        }
        text = render(feedback)
        self.corpus.append(text)
        if is_finish:
            self.submission = arguments.get("submission")
        if response.task_result is not None:
            self._record(name, arguments, "terminal", text, reward=response.reward)
            return Outcome(text, terminal=TaskResult.model_validate(response.task_result))
        status = str(feedback["status"]).lower()
        failed = bool(feedback["error"]) or status in ("error", "failed", "failure", "invalid")
        if not failed:
            self._cache[key] = text
        self._record(name, arguments, "error" if failed else "ok", text, reward=response.reward)
        return Outcome(self._clip(text), is_error=failed)

    def note(self) -> str:
        return budget_note(self.spent, self.soft_budget, self.hard_budget)

    def log_model(self, kind: str, text: str) -> None:
        if text and text.strip():
            self.steps.append({"type": kind, "text": text.strip()[:4000]})

    # ---------------------------------------------------------------- helpers
    def _local(self, name: str, arguments: Any, message: str, soft: bool = False) -> Outcome:
        self._record(name, arguments, "refused_locally", message)
        return Outcome(message, is_error=not soft)

    def _record(self, name: str, arguments: Any, status: str, text: str,
                reward: float | None = None) -> None:
        step: dict[str, Any] = {
            "type": "tool_call",
            "tool": name,
            "arguments": arguments,
            "status": status,
            "spent_so_far": self.spent,
            "result": text[:3000],
        }
        if reward is not None:
            step["reward"] = reward
        self.steps.append(step)

    def _clip(self, text: str) -> str:
        if len(text) <= self.max_result_chars:
            return text
        return (text[: self.max_result_chars]
                + f"... [truncated {len(text) - self.max_result_chars} chars; narrow the query"
                  " or page further if the rest matters]")

    def _ungrounded(self, arguments: dict[str, Any]) -> list[str]:
        corpus = "\n".join(self.corpus)
        ids = set()
        for item in _walk(arguments.get("submission")):
            for k in _ID_KEYS:
                if isinstance(item.get(k), str):
                    ids.add(item[k])
        return sorted(i for i in ids if i and i not in corpus)


def _normalise(arguments: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    """Undo a common LLM slip: an object or list argument sent as a JSON string."""
    out = dict(arguments)
    props = schema.get("properties") or {}
    for k, v in out.items():
        expected = props.get(k) or {}
        structured = expected.get("type") in ("object", "array") or any(
            o.get("type") in ("object", "array")
            for o in expected.get("anyOf", []) + expected.get("oneOf", [])
            if isinstance(o, dict)
        ) or "properties" in expected
        if structured and isinstance(v, str) and v[:1] in "{[":
            with contextlib.suppress(json.JSONDecodeError):
                out[k] = json.loads(v)
    return out


def _key(name: str, arguments: dict[str, Any]) -> str:
    material = {k: v for k, v in arguments.items() if k != "reasoning"}
    return name + json.dumps(material, sort_keys=True, default=str)


def _walk(node: Any):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v)
