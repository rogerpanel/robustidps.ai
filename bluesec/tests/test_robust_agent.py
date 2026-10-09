"""Tests for the RobustIDPS agent (copied into the reference repo's tests/)."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace as NS
from typing import Any

from bluesec1_agent.robust.agent import RobustAgent
from bluesec1_agent.robust.catalog import ToolCatalog, prepare_schema
from bluesec1_agent.robust.drivers import FALLBACK_BETA, run_claude, run_openai
from bluesec1_agent.robust.investigation import Investigation
from bluesec1_agent.robust.mock import SCENARIOS, MockClient, MockSession
from bluesec1_agent.robust.settings import RobustSettings
from bluesec1_client import RemoteBenchmarkClient
from bluesec1_client.remote.models import (
    AbortTaskOutcome,
    CloseRunOutcome,
    LeasedTask,
    QueueExhausted,
    RemoteRun,
    ToolCallOutcome,
)

MALICIOUS = {
    "verdict": "malicious",
    "summary": "Unsigned download beaconing to a listed C2 address.",
    "ir_artifacts": [
        {"entity_id": "host-fin-02", "kind": "host_to_isolate"},
        {"entity_id": "conn-44", "kind": "network_block"},
        {"entity_id": "file-d1", "kind": "file_to_delete"},
        {"entity_id": "user-mk", "kind": "identity_to_rotate"},
    ],
}
BENIGN = {
    "verdict": "benign",
    "summary": "Signed vendor updater launched by its own service created its update task.",
    "legitimacy_evidence": [
        {"anchor": "entity", "entity_id": "proc-7a1",
         "property_fields": ["signer", "signature_status"]},
        {"anchor": "entity", "entity_id": "proc-5c0", "property_fields": ["service_name"]},
        {"anchor": "relation", "relation_id": "rel-2", "property_fields": []},
    ],
}


# --------------------------------------------------------------- fake Claude
def tu(i: int, name: str, args: dict[str, Any]) -> NS:
    return NS(type="tool_use", id=f"tu{i}", name=name, input=args)


def reply(*blocks: NS, stop: str = "tool_use") -> NS:
    return NS(content=list(blocks), stop_reason=stop, stop_details=None)


class FakeClaude:
    def __init__(self, replies: list[NS]) -> None:
        self.replies = list(replies)
        self.requests: list[dict[str, Any]] = []
        self.beta = NS(messages=NS(stream=self._stream))

    def _stream(self, **kw: Any) -> Any:
        self.requests.append({**kw, "messages": list(kw["messages"])})
        resp = self.replies.pop(0)

        class _S:
            async def __aenter__(self_inner):
                return self_inner

            async def __aexit__(self_inner, *a):
                return False

            async def get_final_message(self_inner):
                return resp

        return _S()


def mk_inv(session: MockSession, hard: int = 30) -> Investigation:
    return Investigation(session, ToolCatalog.from_observation(session.task.observation),
                         soft_budget=8, hard_budget=hard, max_result_chars=20_000)


def malicious_session() -> MockSession:
    return MockSession(next(s for s in SCENARIOS if s["task_id"] == "mock-malicious-c2"))


def test_catalog_inlines_refs_and_validates() -> None:
    cat = ToolCatalog.from_observation(malicious_session().task.observation)
    finish = cat.specs["finish_investigation"]
    assert "$defs" not in json.dumps(finish.schema) and "$ref" not in json.dumps(finish.schema)
    assert finish.validate(finish.from_llm({"submission": MALICIOUS})) == []
    assert finish.validate(finish.from_llm({"submission": {**MALICIOUS, "verdict": "maybe"}}))
    assert cat.specs["get_entity"].validate({"reasoning": "x"})  # entity_id missing
    # the model never sees a field called `reasoning`; the runtime always gets one
    assert '"reasoning"' not in json.dumps(cat.anthropic_tools())
    assert '"reasoning"' not in json.dumps(cat.openai_tools())
    assert '"reasoning"' in json.dumps(finish.schema)
    assert finish.from_llm({"submission": MALICIOUS})["submission"]["reasoning"]
    schema = prepare_schema({"$defs": {"A": {"type": "string", "title": "A"}},
                             "properties": {"a": {"$ref": "#/$defs/A"}}})
    assert schema == {"type": "object", "properties": {"a": {"type": "string"}}}


def test_claude_loop_saves_calls_and_submits() -> None:
    session = malicious_session()
    inv = mk_inv(session)
    claude = FakeClaude([
        reply(NS(type="thinking", thinking="H1 C2 beacon; H2 benign app."),
              tu(1, "get_entity", {"entity_id": "proc-c33", "purpose": "Inspect trigger."})),
        reply(tu(2, "get_relation", {"relation_id": "rel-11", "purpose": "Where to?"}),
              tu(3, "get_relation", {"relation_id": "rel-10", "purpose": "Which file?"})),
        reply(tu(4, "get_entity", {"entity_id": "proc-c33", "purpose": "again"}),  # cached
              tu(5, "get_entity", {"purpose": "no id"})),  # schema error
        reply(tu(6, "finish_investigation", {"submission": {
            **MALICIOUS, "ir_artifacts": [{"entity_id": "conn-99", "kind": "network_block"}]}})),
        reply(tu(7, "finish_investigation", {"submission": MALICIOUS})),
    ])
    result = asyncio.run(run_claude(inv, claude, model="claude-opus-5-5", effort="high",
                                    max_turns=10))
    assert result.completion_reason == "terminated"
    assert [c[0] for c in session.calls] == [
        "get_entity", "get_relation", "get_relation", "finish_investigation"]
    assert inv.spent == 4 and inv.saved == 1
    assert session.calls[0][1] == {"entity_id": "proc-c33", "reasoning": "Inspect trigger."}
    sent = session.calls[-1][1]["submission"]
    assert "summary" not in sent and sent["reasoning"] == MALICIOUS["summary"]
    statuses = [s["status"] for s in inv.steps if s["type"] == "tool_call"]
    assert statuses == ["ok", "ok", "ok", "cached", "refused_locally", "refused_locally",
                        "terminal"]
    req = claude.requests[0]
    assert req["thinking"] == {"type": "adaptive", "display": "summarized"}
    assert req["output_config"] == {"effort": "high"}
    assert req["betas"] == [FALLBACK_BETA] and req["fallbacks"] == "default"
    assert req["cache_control"] == {"type": "ephemeral"}
    # the parallel results come back together, followed by the budget note
    turn3 = claude.requests[2]["messages"][-1]["content"]
    assert [b["type"] for b in turn3] == ["tool_result", "tool_result", "text"]
    assert "tool calls used: 3" in turn3[-1]["text"]
    warn = claude.requests[4]["messages"][-1]["content"][0]
    assert warn["is_error"] and "conn-99" in warn["content"]
    assert result.quality_score == 1.0


def test_hard_budget_refuses_evidence_calls_but_allows_submission() -> None:
    session = malicious_session()
    inv = mk_inv(session, hard=1)
    claude = FakeClaude([
        reply(tu(1, "get_entity", {"entity_id": "proc-c33", "purpose": "trigger"})),
        reply(tu(2, "get_entity", {"entity_id": "conn-44", "purpose": "more"})),
        reply(tu(3, "finish_investigation", {"submission": {
            **MALICIOUS, "ir_artifacts": MALICIOUS["ir_artifacts"][:1]}})),
    ])
    asyncio.run(run_claude(inv, claude, model="m", effort="low", max_turns=5))
    assert [c[0] for c in session.calls] == ["get_entity", "finish_investigation"]
    assert "Budget exhausted" in claude.requests[2]["messages"][-1]["content"][0]["content"]


# --------------------------------------------------------------- fake OpenAI
def call(i: int, name: str, args: Any) -> NS:
    raw = args if isinstance(args, str) else json.dumps(args)
    return NS(id=f"c{i}", function=NS(name=name, arguments=raw))


class FakeOpenAI:
    def __init__(self, turns: list[list[NS]]) -> None:
        self.turns = list(turns)
        self.requests: list[list[dict[str, Any]]] = []
        self.chat = NS(completions=NS(create=self._create))

    async def _create(self, **kw: Any) -> NS:
        self.requests.append([dict(m) for m in kw["messages"]])
        calls = self.turns.pop(0)
        return NS(choices=[NS(message=NS(content="", refusal=None, tool_calls=calls))])


def test_openai_loop_handles_bad_json_and_string_submission() -> None:
    session = MockSession(next(s for s in SCENARIOS if s["task_id"] == "mock-benign-updater"))
    inv = mk_inv(session)
    oai = FakeOpenAI([
        [call(1, "get_entity", '{"entity_id": "proc-7a1", "purpose": '),  # truncated JSON
         call(2, "get_entity", {"entity_id": "proc-7a1", "purpose": "trigger"})],
        [call(3, "get_relation", {"relation_id": "rel-1", "purpose": "parent?"})],
        [call(4, "finish_investigation", {"submission": json.dumps(BENIGN)})],
    ])
    result = asyncio.run(run_openai(inv, oai, model="m", max_turns=6,
                                    max_completion_tokens=1000))
    assert result.completion_reason == "terminated" and result.quality_score > 0.9
    assert [c[0] for c in session.calls] == ["get_entity", "get_relation",
                                             "finish_investigation"]
    tool_msgs = [m for m in oai.requests[1] if m["role"] == "tool"]
    assert "not valid JSON" in tool_msgs[0]["content"]
    assert "tool calls used: 1" in tool_msgs[-1]["content"]


# --------------------------------------------------------------- whole run
def test_run_writes_traces_and_aborts_on_refusal(tmp_path: Path) -> None:
    settings = RobustSettings(ROBUST_TRACE_DIR=tmp_path, ANTHROPIC_API_KEY="k")
    claude = FakeClaude([
        reply(tu(1, "get_entity", {"entity_id": "proc-7a1", "purpose": "trigger"})),
        reply(tu(2, "get_relation", {"relation_id": "rel-1", "purpose": "parent?"})),
        reply(tu(3, "finish_investigation", {"submission": BENIGN})),
        reply(stop="refusal"),
    ])
    client = MockClient()
    summary = asyncio.run(RobustAgent(settings, claude).run(client))
    assert summary["tasks"] == 2 and summary["completed"] == 1
    reasons = [r["completion_reason"] for r in summary["task_results"]]
    assert reasons == ["terminated", "aborted"]
    run_dir = next(tmp_path.iterdir())
    traces = {p.name for p in run_dir.iterdir()}
    assert {"summary.json", "mock-benign-updater.json", "mock-malicious-c2.json"} <= traces
    aborted = json.loads((run_dir / "mock-malicious-c2.json").read_text())
    assert "refused" in aborted["error"]


class MockTransport:
    """Serves the mock scenarios through the organisers' real client classes."""

    def __init__(self) -> None:
        self.sessions = {s["task_id"]: MockSession(s) for s in SCENARIOS}
        self.queue = list(self.sessions)
        self.closed: list[Any] = []

    async def create_run(self, command: Any) -> Any:
        return RemoteRun(run_id="run-r", state="active")

    async def lease_task(self, command: Any) -> Any:
        if not self.queue:
            return QueueExhausted(run_id="run-r")
        return LeasedTask(run_id="run-r", task=self.sessions[self.queue.pop(0)].task)

    async def call_tool(self, command: Any) -> Any:
        result = await self.sessions[command.task_id].call_tool(command.tool_name,
                                                                 command.arguments)
        return ToolCallOutcome(run_id="run-r", call_id=command.call_id, result=result)

    async def abort_task(self, command: Any) -> Any:
        result = await self.sessions[command.task_id].abort_task()
        return AbortTaskOutcome(run_id="run-r", task_result=result)

    async def close_run(self, command: Any) -> Any:
        self.closed.append(command)
        return CloseRunOutcome(run_id="run-r", state="closed")

    async def aclose(self) -> None:
        return None


def test_agent_runs_through_the_real_remote_client(tmp_path: Path) -> None:
    settings = RobustSettings(ROBUST_TRACE_DIR=tmp_path, ANTHROPIC_API_KEY="k")
    claude = FakeClaude([
        reply(tu(1, "get_entity", {"entity_id": "proc-7a1", "purpose": "trigger"}),
              tu(2, "get_relation", {"relation_id": "rel-1", "purpose": "parent?"})),
        reply(tu(3, "finish_investigation", {"submission": BENIGN})),
        reply(tu(4, "get_entity", {"entity_id": "proc-c33", "purpose": "trigger"})),
        reply(tu(5, "get_relation", {"relation_id": "rel-11", "purpose": "where?"}),
              tu(6, "get_relation", {"relation_id": "rel-10", "purpose": "file?"})),
        reply(tu(7, "finish_investigation", {"submission": MALICIOUS})),
    ])
    transport = MockTransport()

    async def go() -> dict[str, Any]:
        async with RemoteBenchmarkClient(transport=transport) as client:
            return await RobustAgent(settings, claude).run(client)

    summary = asyncio.run(go())
    assert summary["completed"] == 2 and summary["mean_quality"] > 0.9
    assert summary["mean_tool_calls"] == 3.5
    assert transport.closed and transport.closed[0].reason == "client_requested"


# --------------------------------------------------------------- parallel mode
class ScriptedByTask:
    """Fake Claude for parallel runs: the script is chosen by the task's trigger id."""

    def __init__(self, scripts: dict[str, list[NS]]) -> None:
        self.scripts = scripts
        self.inflight = 0
        self.max_inflight = 0
        self.beta = NS(messages=NS(stream=self._stream))

    def _stream(self, **kw: Any) -> Any:
        first = kw["messages"][0]["content"]
        key = next(k for k in self.scripts if k in first)
        turn = sum(1 for m in kw["messages"] if m["role"] == "assistant")
        resp = self.scripts[key][turn]
        outer = self

        class _S:
            async def __aenter__(self_inner):
                outer.inflight += 1
                outer.max_inflight = max(outer.max_inflight, outer.inflight)
                await asyncio.sleep(0.01)
                return self_inner

            async def __aexit__(self_inner, *a):
                outer.inflight -= 1
                return False

            async def get_final_message(self_inner):
                return resp

        return _S()


SCRIPTS = {
    "proc-7a1": [
        reply(tu(1, "get_entity", {"entity_id": "proc-7a1", "purpose": "trigger"})),
        reply(tu(2, "get_relation", {"relation_id": "rel-1", "purpose": "parent"})),
        reply(tu(3, "finish_investigation", {"submission": BENIGN})),
    ],
    "proc-c33": [
        reply(tu(1, "get_entity", {"entity_id": "proc-c33", "purpose": "trigger"})),
        reply(tu(2, "get_relation", {"relation_id": "rel-11", "purpose": "where"}),
              tu(3, "get_relation", {"relation_id": "rel-10", "purpose": "file"})),
        reply(tu(4, "finish_investigation", {"submission": MALICIOUS})),
    ],
}


def test_parallel_run_learns_the_runtime_task_limit(tmp_path: Path) -> None:
    settings = RobustSettings(ROBUST_TRACE_DIR=tmp_path, ANTHROPIC_API_KEY="k",
                              ROBUST_CONCURRENCY=4)
    client = MockClient(repeat=4, max_active=2)      # 8 tasks, runtime allows 2 at once
    claude = ScriptedByTask(SCRIPTS)
    summary = asyncio.run(RobustAgent(settings, claude).run(client))
    assert summary["tasks"] == 8 and summary["completed"] == 8
    assert client.peak_active == 2 and summary["peak_parallel_tasks"] == 2
    assert client.refused_leases >= 1                 # the limit was discovered, not assumed
    assert claude.max_inflight == 2
    assert len(list(next(tmp_path.iterdir()).glob("mock-*.json"))) == 8


def test_parallel_run_without_a_runtime_limit(tmp_path: Path) -> None:
    settings = RobustSettings(ROBUST_TRACE_DIR=tmp_path, ANTHROPIC_API_KEY="k",
                              ROBUST_CONCURRENCY=3)
    client = MockClient(repeat=3)
    summary = asyncio.run(RobustAgent(settings, ScriptedByTask(SCRIPTS)).run(client))
    assert summary["completed"] == 6 and summary["peak_parallel_tasks"] == 3
    assert client.refused_leases == 0


def test_busy_runtime_is_waited_out_without_spending(monkeypatch) -> None:
    from bluesec1_agent.robust import investigation as inv_mod
    from bluesec1_client import OperationCapacityExceededError

    async def no_sleep(_: float) -> None:
        return None

    monkeypatch.setattr(inv_mod.asyncio, "sleep", no_sleep)
    session = malicious_session()
    real = session.call_tool
    refusals = {"left": 2}

    async def flaky(name: str, args: dict[str, Any]) -> Any:
        if refusals["left"]:
            refusals["left"] -= 1
            raise OperationCapacityExceededError(
                "busy", reason="SUBJECT_IN_FLIGHT_OPERATION_LIMIT_REACHED")
        return await real(name, args)

    session.call_tool = flaky
    inv = mk_inv(session)
    out = asyncio.run(inv.execute("get_entity", {"entity_id": "proc-c33", "purpose": "x"}))
    assert not out.is_error and inv.spent == 1 and len(session.calls) == 1


def test_deadline_stops_leasing_and_forces_submission(tmp_path: Path) -> None:
    import datetime
    import time

    session = malicious_session()
    inv = Investigation(session, ToolCatalog.from_observation(session.task.observation),
                        soft_budget=8, hard_budget=30, max_result_chars=20_000,
                        finish_by=time.time() - 1)
    out = asyncio.run(inv.execute("get_entity", {"entity_id": "proc-c33", "purpose": "x"}))
    assert "deadline" in out.text and session.calls == []
    done = asyncio.run(inv.execute("finish_investigation", {"submission": {
        **MALICIOUS, "ir_artifacts": MALICIOUS["ir_artifacts"][:1]}}))
    assert done.terminal is not None

    soon = datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=3)
    settings = RobustSettings(ROBUST_TRACE_DIR=tmp_path, ANTHROPIC_API_KEY="k",
                              ROBUST_CONCURRENCY=2, ROBUST_DEADLINE=soon)   # inside the 6-min stop
    client = MockClient()
    summary = asyncio.run(RobustAgent(settings, ScriptedByTask(SCRIPTS)).run(client))
    assert summary["tasks"] == 0 and len(client._queue) == 2


def test_cli_deadline_parsing() -> None:
    import argparse

    from bluesec1_agent.robust.cli import parse_deadline

    d = parse_deadline("14:58")
    assert (d.hour, d.minute) == (14, 58) and d.utcoffset().total_seconds() == 3 * 3600
    assert parse_deadline("2026-10-10T14:58:00+03:00").hour == 14
    try:
        parse_deadline("2026-10-10T14:58:00")
        raise AssertionError("naive ISO time must be rejected")
    except argparse.ArgumentTypeError:
        pass


def test_parallel_run_through_the_real_remote_client(tmp_path: Path) -> None:
    settings = RobustSettings(ROBUST_TRACE_DIR=tmp_path, ANTHROPIC_API_KEY="k",
                              ROBUST_CONCURRENCY=2)
    transport = MockTransport()

    async def go() -> dict[str, Any]:
        async with RemoteBenchmarkClient(transport=transport) as client:
            return await RobustAgent(settings, ScriptedByTask(SCRIPTS)).run(client)

    summary = asyncio.run(go())
    assert summary["completed"] == 2 and summary["peak_parallel_tasks"] == 2
    assert transport.closed[0].reason == "client_requested"
