"""A small in-memory stand-in for the competition runtime.

Use it to check that keys, model and loop work before spending a real run:
    python -m bluesec1_agent.robust.cli --mock

It mimics the shape of the real client (start_task / call_tool / abort_task,
`available_tools` as a JSON string, results in `info.tool_result`). Its
graphs and its score are toys, not the competition's.
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

from bluesec1_client import PublicTask, TaskResult, ToolCallResult

from .catalog import _reference_schemas

SCENARIOS: list[dict[str, Any]] = [
    {
        "task_id": "mock-benign-updater",
        "alert": {
            "title": "New scheduled task created by a process outside the Windows directory",
            "host": "host-ws-17",
            "trigger_entities": ["proc-7a1"],
        },
        "entities": {
            "host-ws-17": {"type": "host", "hostname": "WS-17", "os": "Windows 11"},
            "proc-7a1": {"type": "windows_process", "image": "C:\\Program Files\\ExampleSoft\\"
                         "Updater\\exupdate.exe", "signer": "ExampleSoft Ltd",
                         "signature_status": "valid", "user": "NT AUTHORITY\\SYSTEM"},
            "proc-5c0": {"type": "windows_process", "image": "C:\\Program Files\\ExampleSoft\\"
                         "Updater\\exupdatesvc.exe", "signer": "ExampleSoft Ltd",
                         "signature_status": "valid", "service_name": "ExampleSoftUpdate"},
            "task-91": {"type": "scheduled_task", "name": "\\ExampleSoft\\DailyUpdateCheck",
                        "action": "C:\\Program Files\\ExampleSoft\\Updater\\exupdate.exe /check",
                        "author": "ExampleSoft Ltd"},
        },
        "relations": {
            "rel-1": {"type": "win_process_create", "source": "proc-5c0", "target": "proc-7a1"},
            "rel-2": {"type": "created_scheduled_task", "source": "proc-7a1", "target": "task-91"},
            "rel-3": {"type": "runs_process", "source": "host-ws-17", "target": "proc-7a1"},
        },
        "answer": {"verdict": "benign", "ids": {"proc-7a1", "proc-5c0", "task-91", "rel-2"}},
        "optimal": 2,
    },
    {
        "task_id": "mock-malicious-c2",
        "alert": {
            "title": "Process connected to an address on the threat-intelligence blocklist",
            "host": "host-fin-02",
            "trigger_entities": ["proc-c33"],
        },
        "entities": {
            "host-fin-02": {"type": "host", "hostname": "FIN-02"},
            "user-mk": {"type": "windows_user", "name": "m.kuznetsova"},
            "proc-c33": {"type": "windows_process", "image": "C:\\Users\\m.kuznetsova\\"
                         "Downloads\\invoice_viewer.exe", "signature_status": "unsigned",
                         "user": "m.kuznetsova", "user_entity_id": "user-mk"},
            "file-d1": {"type": "windows_file", "path": "C:\\Users\\m.kuznetsova\\Downloads\\"
                        "invoice_viewer.exe", "zone_identifier": "internet"},
            "conn-44": {"type": "network_connection", "remote_ip": "203.0.113.50",
                        "remote_port": 443, "intel": "listed: command-and-control",
                        "pattern": "every 600 s"},
        },
        "relations": {
            "rel-10": {"type": "executed_file", "source": "proc-c33", "target": "file-d1"},
            "rel-11": {"type": "connected_to", "source": "proc-c33", "target": "conn-44"},
            "rel-12": {"type": "runs_process", "source": "host-fin-02", "target": "proc-c33"},
            "rel-13": {"type": "logged_on_to", "source": "user-mk", "target": "host-fin-02"},
        },
        "answer": {"verdict": "malicious",
                   "ids": {"host-fin-02", "conn-44", "file-d1", "user-mk"}},
        "optimal": 3,
    },
]


def mock_catalog() -> str:
    tools = []
    for name, (schema, doc) in _reference_schemas().items():
        tools.append({"name": name, "description": doc, "parameters": schema})
    return json.dumps(tools)


class MockSession:
    def __init__(self, scenario: dict[str, Any]) -> None:
        self.sc = scenario
        self.task = PublicTask(task_id=scenario["task_id"], observation={
            "alert_text": scenario["alert"], "available_tools": mock_catalog()})
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.result: TaskResult | None = None

    @property
    def task_id(self) -> str:
        return self.task.task_id

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        self.calls.append((tool_name, arguments))
        ents, rels = self.sc["entities"], self.sc["relations"]
        status, payload, error = "ok", None, None
        if tool_name == "get_entity":
            eid = arguments.get("entity_id")
            if eid in ents:
                payload = {"entity_id": eid, **ents[eid],
                           "outgoing": [r for r, v in rels.items() if v["source"] == eid],
                           "incoming": [r for r, v in rels.items() if v["target"] == eid]}
            else:
                status, error = "error", f"entity {eid!r} not found"
        elif tool_name == "get_relation":
            rid = arguments.get("relation_id")
            if rid in rels:
                payload = {"relation_id": rid, **rels[rid]}
            else:
                status, error = "error", f"relation {rid!r} not found"
        elif tool_name == "search":
            q = str(arguments.get("query", "")).lower()
            hits = [{"entity_id": k, **v} for k, v in ents.items() if q in json.dumps(v).lower()]
            hits += [{"relation_id": k, **v} for k, v in rels.items()
                     if q in json.dumps(v).lower() or q in k]
            payload = {"page": 1, "results": hits[:10]}
        elif tool_name == "finish_investigation":
            return self._finish(arguments)
        else:
            status, error = "error", f"tool {tool_name!r} not available in the mock"
        return ToolCallResult(task_id=self.task_id, tool_name=tool_name, reward=0.0,
                              info={"tool_status": status, "tool_result": payload,
                                    "error": error})

    def _finish(self, arguments: dict[str, Any]) -> ToolCallResult:
        sub = arguments.get("submission") or {}
        answer = self.sc["answer"]
        cited = {i.get("entity_id") or i.get("relation_id")
                 for i in sub.get("ir_artifacts", []) + sub.get("legitimacy_evidence", [])}
        cited.discard(None)
        hit = len(cited & answer["ids"])
        precision = hit / len(cited) if cited else 0.0
        recall = hit / len(answer["ids"])
        f1 = 2 * precision * recall / (precision + recall) if hit else 0.0
        quality = 0.5 * (sub.get("verdict") == answer["verdict"]) + 0.5 * f1
        calls = len(self.calls)
        efficiency = min(1.0, (self.sc["optimal"] + 1) / calls)
        self.result = TaskResult(task_id=self.task_id, completion_reason="terminated",
                                 total_reward=round(quality * (0.8 + 0.2 * efficiency), 4),
                                 steps_taken=calls, tool_calls=calls,
                                 quality_score=round(quality, 4),
                                 efficiency_score=round(efficiency, 4))
        return ToolCallResult(task_id=self.task_id, tool_name="finish_investigation",
                              terminated=True, info={"tool_status": "ok",
                                                     "tool_result": "Report accepted"},
                              task_result=self.result)

    async def abort_task(self, *, error_message: str | None = None) -> TaskResult:
        self.result = TaskResult(task_id=self.task_id, completion_reason="aborted",
                                 tool_calls=len(self.calls))
        return self.result


class MockClient:
    def __init__(self, scenarios: list[dict[str, Any]] | None = None) -> None:
        self.run = SimpleNamespace(run_id="mock-run")
        self.sessions = [MockSession(s) for s in (scenarios or SCENARIOS)]
        self._queue = list(self.sessions)

    async def start_task(self) -> MockSession | None:
        return self._queue.pop(0) if self._queue else None
