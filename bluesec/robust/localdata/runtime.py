"""A local stand-in for the competition runtime, serving practice tasks built
from public datasets. Same client shape as the real one (start_task /
call_tool / abort_task), same tool names and argument schemas, so the agent
runs on it unchanged and its traces upload to BlueSec Runs.

Scoring is ours, not the competition's, and is documented in `score()`.
"""

from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace
from typing import Any

from bluesec1_client import PublicTask, TaskResult, ToolCallResult

from ..mock import mock_catalog
from .scenarios import Task

PAGE_SIZE = 10
MAX_IDS_PER_TYPE = 40

# Artifact kinds that fit each entity type (full credit); any other kind on a
# correct entity earns half credit.
KINDS = {
    "host": {"host_to_isolate"},
    "windows_user": {"identity_to_rotate", "identity_observed"},
    "linux_user": {"identity_to_rotate", "identity_observed"},
    "windows_process": {"process_observed", "cleanup_to_verify", "other"},
    "linux_process": {"process_observed", "cleanup_to_verify", "other"},
    "windows_file": {
        "file_to_delete",
        "file_observed",
        "persistence_to_remove",
        "cleanup_to_verify",
    },
    "linux_file": {"file_to_delete", "file_observed", "persistence_to_remove", "cleanup_to_verify"},
    "registry_key": {"persistence_to_remove", "registry_observed", "cleanup_to_verify"},
    "network_connection": {"network_block", "artifact_observed"},
    "scheduled_task": {"persistence_to_remove"},
    "windows_service": {"persistence_to_remove"},
    "named_pipe": {"artifact_observed"},
}
# Bookkeeping fields that cannot prove legitimacy on their own.
NON_EVIDENCE = {"count", "last_seen", "timestamp", "process_guid", "hostname", "process_id"}


class LocalSession:
    def __init__(self, task: Task, task_id: str) -> None:
        self.t = task
        self.g = task.graph
        self.task = PublicTask(
            task_id=task_id,
            observation={"alert_text": task.alert, "available_tools": mock_catalog()},
        )
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.result: TaskResult | None = None
        self.started = time.monotonic()

    @property
    def task_id(self) -> str:
        return self.task.task_id

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        await asyncio.sleep(0)
        self.calls.append((tool_name, arguments))
        if tool_name == "finish_investigation":
            return self._finish(arguments)
        handler = {
            "get_entity": self._get_entity,
            "get_relation": self._get_relation,
            "search": self._search,
        }.get(tool_name)
        if handler is None:
            return self._reply(tool_name, None, f"{tool_name} is not available for this dataset")
        try:
            payload = handler(arguments)
        except LookupError as exc:
            return self._reply(tool_name, None, str(exc))
        return self._reply(tool_name, payload, None)

    async def abort_task(self, *, error_message: str | None = None) -> TaskResult:
        self.result = TaskResult(
            task_id=self.task_id, completion_reason="aborted", tool_calls=len(self.calls)
        )
        return self.result

    # ---------------------------------------------------------------- tools
    def _reply(self, tool: str, payload: Any, error: str | None) -> ToolCallResult:
        return ToolCallResult(
            task_id=self.task_id,
            tool_name=tool,
            info={
                "tool_status": "error" if error else "ok",
                "tool_result": payload,
                "error": error,
            },
        )

    def _get_entity(self, args: dict[str, Any]) -> dict[str, Any]:
        eid = args.get("entity_id")
        ent = self.g.entities.get(eid)
        if ent is None:
            raise LookupError(f"entity {eid!r} not found")
        return {
            "entity_id": eid,
            **ent,
            "outgoing": self._grouped(self.g.outgoing.get(eid, [])),
            "incoming": self._grouped(self.g.incoming.get(eid, [])),
        }

    def _grouped(self, rel_ids: list[str]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for rid in rel_ids:
            out.setdefault(self.g.relations[rid]["type"], []).append(rid)
        for rtype, ids in out.items():
            if len(ids) > MAX_IDS_PER_TYPE:
                out[rtype] = ids[:MAX_IDS_PER_TYPE] + [f"... {len(ids) - MAX_IDS_PER_TYPE} more"]
        return out

    def _get_relation(self, args: dict[str, Any]) -> dict[str, Any]:
        rid = args.get("relation_id")
        rel = self.g.relations.get(rid)
        if rel is None:
            raise LookupError(f"relation {rid!r} not found")
        return {"relation_id": rid, **rel}

    def _search(self, args: dict[str, Any]) -> dict[str, Any]:
        q = str(args.get("query", "")).lower()
        scope = args.get("scope") or {}
        window = args.get("time_window") or {}
        lo, hi = str(window.get("from", "")), str(window.get("to", ""))
        hits: list[tuple[str, dict[str, Any]]] = []
        if scope.get("kind") in (None, "entity"):
            for eid, e in self.g.entities.items():
                if scope.get("type") and e["type"] != scope["type"]:
                    continue
                ts = str(e.get("start_time", ""))
                if (lo or hi) and not (ts and (not lo or ts >= lo) and (not hi or ts <= hi + "~")):
                    continue
                if q in eid.lower() or q in json.dumps(e).lower():
                    hits.append((ts, _compact_entity(eid, e)))
        if scope.get("kind") in (None, "relation"):
            for rid, r in self.g.relations.items():
                if scope.get("type") and r["type"] != scope["type"]:
                    continue
                ts = str(r.get("timestamp", ""))
                if (lo or hi) and not (ts and (not lo or ts >= lo) and (not hi or ts <= hi + "~")):
                    continue
                if q in rid.lower() or q in json.dumps(r).lower():
                    hits.append(
                        (
                            ts,
                            {
                                "relation_id": rid,
                                **{k: v for k, v in r.items() if k != "call_trace"},
                            },
                        )
                    )
        hits.sort(key=lambda h: h[0], reverse=args.get("sort_order") == "descending")
        page = max(1, int(args.get("page_id") or 1))
        chunk = hits[(page - 1) * PAGE_SIZE : page * PAGE_SIZE]
        return {
            "page": page,
            "total": len(hits),
            "has_more": page * PAGE_SIZE < len(hits),
            "results": [h[1] for h in chunk],
        }

    # --------------------------------------------------------------- scoring
    def _finish(self, args: dict[str, Any]) -> ToolCallResult:
        quality, detail = score(self.t, args.get("submission") or {})
        calls = len(self.calls)
        efficiency = min(1.0, (self.t.scenario.optimal_calls + 1) / max(calls, 1))
        self.result = TaskResult(
            task_id=self.task_id,
            completion_reason="terminated",
            total_reward=round(quality * (0.8 + 0.2 * efficiency), 4),
            steps_taken=calls,
            tool_calls=calls,
            quality_score=round(quality, 4),
            efficiency_score=round(efficiency, 4),
            wall_time_seconds=round(time.monotonic() - self.started, 2),
        )
        return ToolCallResult(
            task_id=self.task_id,
            tool_name="finish_investigation",
            terminated=True,
            task_result=self.result,
            info={
                "tool_status": "ok",
                "tool_result": {"message": "Report accepted", "local_score_detail": detail},
            },
        )


def _compact_entity(eid: str, e: dict[str, Any]) -> dict[str, Any]:
    keep = (
        "type",
        "image",
        "command_line",
        "path",
        "destination_ip",
        "destination_port",
        "query_name",
        "name",
        "hostname",
        "user",
        "start_time",
        "value_data",
    )
    return {"entity_id": eid, **{k: e[k] for k in keep if k in e}}


def score(task: Task, sub: dict[str, Any]) -> tuple[float, dict[str, Any]]:
    """Quality in [0, 1]: half for the verdict, half for the artifacts or evidence.

    Malicious: recall over the core set (an entity named with a fitting kind
    counts 1, with another kind 0.5) combined with precision over the
    acceptable set, as F1. Benign: the share of core anchors cited with at
    least one decisive property field, each anchor counted once; citing ids
    outside the anchors lowers it. A wrong verdict scores 0 overall.
    """
    verdict = sub.get("verdict")
    expected = task.scenario.verdict
    if verdict != expected:
        return 0.0, {"verdict": verdict, "expected": expected}
    g = task.graph
    if expected == "malicious":
        cited: dict[str, float] = {}
        for a in sub.get("ir_artifacts") or []:
            eid, kind = a.get("entity_id"), a.get("kind")
            ent = g.entities.get(eid) or {}
            credit = 1.0 if kind in KINDS.get(ent.get("type", ""), set()) else 0.5
            cited[eid] = max(cited.get(eid, 0.0), credit)
        recall = sum(cited.get(i, 0.0) for i in task.core) / len(task.core)
        precision = (sum(1 for i in cited if i in task.acceptable) / len(cited)) if cited else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        return 0.5 + 0.5 * f1, {
            "recall": round(recall, 3),
            "precision": round(precision, 3),
            "missed_core": sorted(i for i in task.core if i not in cited),
        }
    hits, outside = set(), 0
    for ev in sub.get("legitimacy_evidence") or []:
        anchor = ev.get("entity_id") or ev.get("relation_id")
        fields = set(ev.get("property_fields") or [])
        valid = task.evidence_fields.get(anchor, set()) - NON_EVIDENCE
        if anchor in task.evidence_fields:
            if fields & valid or (ev.get("anchor") == "relation" and not fields):
                hits.add(anchor)
        else:
            outside += 1
    coverage = len(hits) / len(task.evidence_fields)
    penalty = outside / (len(hits) + outside) if hits or outside else 0.0
    part = max(0.0, coverage - 0.5 * penalty)
    return 0.5 + 0.5 * part, {"anchors_cited": sorted(hits), "outside_anchors": outside}


class LocalClient:
    """Serves the given tasks once each, like a runtime queue."""

    def __init__(self, tasks: list[Task], run_id: str = "local-run") -> None:
        self.run = SimpleNamespace(run_id=run_id)
        self.sessions = [LocalSession(t, t.scenario.id) for t in tasks]
        self._queue = list(self.sessions)

    async def start_task(self) -> LocalSession | None:
        await asyncio.sleep(0)
        return self._queue.pop(0) if self._queue else None
