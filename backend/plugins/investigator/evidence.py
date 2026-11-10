"""Evidence sources the investigator queries.

`EvidenceSource` is the seam between the agent and wherever evidence
lives. `MissionEvidence` serves a practice mission from memory; a
competition platform gets its own implementation of the same four
methods, so the agent, prompt and scorer are reused unchanged.
"""
from __future__ import annotations

import json
from typing import Protocol

from .missions import Mission

MAX_EVENTS = 50
DEFAULT_EVENTS = 20


class EvidenceSource(Protocol):
    def search_events(self, *, host: str | None = None, user: str | None = None,
                      event_type: str | None = None, source: str | None = None,
                      text: str | None = None, time_from: str | None = None,
                      time_to: str | None = None, limit: int = DEFAULT_EVENTS) -> dict: ...
    def get_process_tree(self, *, host: str, pid: int) -> dict: ...
    def get_host_info(self, *, host: str) -> dict: ...
    def lookup_indicator(self, *, value: str) -> dict: ...


def _eq(a: str | None, b: str | None) -> bool:
    return (a or "").lower() == (b or "").lower()


class MissionEvidence:
    def __init__(self, mission: Mission):
        # ISO-8601 timestamps in one zone sort lexicographically.
        self._events = sorted(mission.events, key=lambda e: e.get("ts", ""))
        self._hosts = mission.hosts
        self._intel = mission.intel

    def search_events(self, *, host=None, user=None, event_type=None, source=None,
                      text=None, time_from=None, time_to=None, limit=DEFAULT_EVENTS) -> dict:
        limit = max(1, min(int(limit or DEFAULT_EVENTS), MAX_EVENTS))
        needle = (text or "").lower()
        hits = []
        for e in self._events:
            if host and not _eq(e.get("host"), host): continue
            if user and not _eq(e.get("user"), user): continue
            if event_type and not _eq(e.get("event_type"), event_type): continue
            if source and not _eq(e.get("source"), source): continue
            if time_from and e.get("ts", "") < time_from: continue
            if time_to and e.get("ts", "") > time_to: continue
            if needle and needle not in json.dumps(e, ensure_ascii=False).lower(): continue
            hits.append(e)
        return {"total_matches": len(hits), "returned": min(len(hits), limit),
                "truncated": len(hits) > limit, "events": hits[:limit]}

    def get_process_tree(self, *, host: str, pid: int) -> dict:
        procs = {e["details"]["pid"]: e for e in self._events
                 if _eq(e.get("host"), host) and e.get("event_type") == "process_start"
                 and "pid" in e.get("details", {})}
        if pid not in procs:
            return {"error": f"no process {pid} recorded on {host}"}
        ancestors, cur, seen = [], procs[pid], {pid}
        while (ppid := cur["details"].get("ppid")) in procs and ppid not in seen:
            seen.add(ppid)
            cur = procs[ppid]
            ancestors.append(cur)
        children = [e for e in procs.values() if e["details"].get("ppid") == pid]
        return {"process": procs[pid], "ancestors": ancestors, "children": children}

    def get_host_info(self, *, host: str) -> dict:
        return self._hosts.get(host.lower()) or {"error": f"no asset record for {host}"}

    def lookup_indicator(self, *, value: str) -> dict:
        return self._intel.get(value.strip().lower()) or {
            "value": value, "verdict": "unknown", "note": "no threat-intel record"}
