"""Agent Guard for AgentDojo: a drop-in replacement for ToolsExecutor.

    from agentdojo.agent_pipeline import AgentPipeline, InitQuery, SystemMessage, ToolsExecutionLoop
    from agent_guard_client import GuardClient
    from agentdojo_guard import GuardedToolsExecutor

    guard = GuardClient("https://robustidps.ai", token="<token or rids_live_ key>", policy_id="mcp-general")
    pipeline = AgentPipeline([
        SystemMessage(system_message), InitQuery(), llm,
        ToolsExecutionLoop([GuardedToolsExecutor(guard), llm]),
    ])

Every tool call the model makes is checked before it runs:
  allow    the call runs;
  modify   the call runs with the guard's corrected arguments;
  ask      not run (a tool error tells the model approval is needed), unless the
           GuardClient waits for a person (approval_wait) and the call is approved;
  deny     not run; the tool error carries the guard's reasons.
Any guard failure is a deny. Each AgentDojo query gets its own guard session
(executor prefix + digest of the query text), so budgets and repeated-denial
rules do not leak between tasks or between runs. The same user task is run once
per injection task with the same prompt, so benchmark harnesses should call
begin_session() at the start of every run (NewGuardSession does this as the
first pipeline element). Verified against agentdojo 0.1.35.

on_ask="approve" runs calls that need approval, as if a person approved every
request (for measuring a filter's refusals alone); `approved(tool, args,
session, verdict)` is then called so an in-process guard can record the
approval. A checker may take (tool, args) or (tool, args, session).
"""
from __future__ import annotations

import hashlib
import inspect
import time
import uuid
from collections.abc import Callable, Sequence
from typing import Any

from agentdojo.agent_pipeline import ToolsExecutor
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

try:  # the downloaded client file
    from agent_guard_client import GuardClient
except ImportError:  # running inside the robustidps.ai repository
    from plugins.agent_guard.client import GuardClient

Checker = Callable[[str, dict[str, Any]], dict[str, Any]]


class GuardedToolsExecutor(ToolsExecutor):
    """ToolsExecutor that asks Agent Guard before executing each tool call."""

    def __init__(self, guard: GuardClient | None = None, checker: Checker | None = None,
                 session_prefix: str | None = None, on_ask: str = "block",
                 approved: Callable[..., None] | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        if guard is None and checker is None:
            raise ValueError("pass a GuardClient or a checker(tool_name, args) -> verdict function")
        if on_ask not in ("block", "approve"):
            raise ValueError("on_ask must be 'block' or 'approve'")
        self.guard = guard
        self.checker = checker
        self.on_ask = on_ask
        self.approved = approved
        # A fresh prefix per executor: repeated benchmark runs do not share budgets or denials.
        self.session_prefix = session_prefix or f"agentdojo-{uuid.uuid4().hex[:8]}"
        self.current_session: str | None = None
        self.session_tags: dict[str, Any] = {}
        self.decisions: list[dict[str, Any]] = []   # every verdict, for analysis after a run
        self._checker_takes_session = checker is not None and len(inspect.signature(checker).parameters) >= 3

    def begin_session(self, **tags: Any) -> str:
        """Start a fresh guard session (call once per benchmark run); tags are stored with each decision."""
        self.current_session = f"{self.session_prefix}-{uuid.uuid4().hex[:12]}"
        self.session_tags = dict(tags)
        return self.current_session

    def _session(self, query: str) -> str:
        return self.current_session or f"{self.session_prefix}-{hashlib.sha256(query.encode()).hexdigest()[:12]}"

    def _check(self, query: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        try:
            session = self._session(query)
            if self.checker is not None:
                return self.checker(tool, args, session) if self._checker_takes_session else self.checker(tool, args)
            self.guard.session_id = session
            return self.guard.check(tool, args)
        except Exception as exc:  # noqa: BLE001 — fail closed
            return {"decision": "deny", "reasons": [f"guard failed ({type(exc).__name__}); failing closed"]}

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args

        last = messages[-1]
        results: list[ChatToolResultMessage] = []
        for tool_call in last["tool_calls"]:
            t0 = time.perf_counter()
            verdict = self._check(query, tool_call.function, dict(tool_call.args))
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)
            decision = verdict.get("decision")
            self.decisions.append({"tool": tool_call.function, "args": dict(tool_call.args),
                                   "decision": decision, "reasons": verdict.get("reasons", []),
                                   "rules": [f.get("rule_id") for f in verdict.get("findings", [])
                                             if f.get("verdict") == decision],
                                   "check_ms": elapsed_ms, "session": self._session(query), **self.session_tags})
            if decision == "ask" and self.on_ask == "approve":
                if self.approved is not None:
                    self.approved(tool_call.function, dict(tool_call.args), self._session(query), verdict)
                decision = "allow" if verdict.get("modified_args") is None else "modify"
            if decision not in ("allow", "modify"):
                reason = "; ".join(verdict.get("reasons") or [str(decision)])
                if decision == "ask":
                    reason = f"This call needs approval by a person. {reason}"
                results.append(ChatToolResultMessage(
                    role="tool", content=[text_content_block_from_string("")],
                    tool_call_id=tool_call.id, tool_call=tool_call,
                    error=f"Blocked by Agent Guard ({decision}): {reason}"))
                continue
            if decision == "modify" and verdict.get("modified_args") is not None:
                tool_call = tool_call.model_copy(update={"args": dict(verdict["modified_args"])})
            # Run this one call through the stock executor (argument coercion, errors, formatting).
            single = {**last, "tool_calls": [tool_call]}
            _, _, env, out, _ = super().query(query, runtime, env, [*messages[:-1], single], extra_args)
            results.extend(out[len(messages):])
        return query, runtime, env, [*messages, *results], extra_args


class NewGuardSession(BasePipelineElement):
    """First pipeline element: starts a fresh guard session for every run and tags it with AgentDojo's task ids."""

    def __init__(self, executor: GuardedToolsExecutor) -> None:
        self.executor = executor

    def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args={}):  # noqa: B006
        try:
            from agentdojo.logging import Logger
            ctx = dict(getattr(Logger.get(), "context", {}) or {})
        except Exception:  # noqa: BLE001
            ctx = {}
        self.executor.begin_session(suite=ctx.get("suite_name"), user_task=ctx.get("user_task_id"),
                                    injection_task=ctx.get("injection_task_id"))
        return query, runtime, env, messages, extra_args
