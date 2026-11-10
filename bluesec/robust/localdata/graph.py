"""Build a BlueSec-style evidence graph from Sysmon (Windows and Linux) and
Windows Security events.

Input: event dicts, either JSON lines as published by OTRF Security-Datasets
(Mordor) or Sysmon XML `<Event>` lines as published by Splunk attack_data
(Sysmon for Linux). Output: entities and typed relations using the same type
names as the competition runtime: windows_process / linux_process,
windows_file / linux_file, registry_key, network_connection, ...;
win_process_create / linux_process_create, wrote_file, set_registry_value,
connected_to, ...

Events are untrusted input: they are read as data, fields are copied with
length caps, and nothing in them is executed.
"""

from __future__ import annotations

import hashlib
import json
import xml.etree.ElementTree as ET  # noqa: N817 - only after rejecting DTDs
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

SYSMON = "Microsoft-Windows-Sysmon/Operational"
SYSMON_LINUX = "Linux-Sysmon/Operational"
MAX_FIELD = 600

WINDOWS = {"process": "windows_process", "file": "windows_file", "user": "windows_user",
           "create": "win_process_create"}
LINUX = {"process": "linux_process", "file": "linux_file", "user": "linux_user",
         "create": "linux_process_create"}
PROCESS_TYPES = {WINDOWS["process"], LINUX["process"]}
CREATE_RELATIONS = {WINDOWS["create"], LINUX["create"]}


@dataclass
class Graph:
    entities: dict[str, dict[str, Any]] = field(default_factory=dict)
    relations: dict[str, dict[str, Any]] = field(default_factory=dict)
    outgoing: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    incoming: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    _rel_keys: dict[tuple, str] = field(default_factory=dict)

    # ---------------------------------------------------------------- build
    def entity(self, etype: str, key: str, **props: Any) -> str:
        eid = f"{_PREFIX.get(etype, 'ent')}-{_digest(etype + '|' + key)}"
        ent = self.entities.setdefault(eid, {"type": etype})
        for k, v in props.items():
            if v not in (None, "", "-") and k not in ent:
                ent[k] = _clip(v)
        return eid

    def update(self, eid: str, **props: Any) -> None:
        ent = self.entities[eid]
        for k, v in props.items():
            if v not in (None, "", "-"):
                ent[k] = _clip(v)

    def relate(
        self,
        rtype: str,
        source: str,
        target: str,
        ts: str | None,
        dedupe: tuple | None = None,
        **props: Any,
    ) -> str:
        key = (rtype, source, target) + (dedupe if dedupe is not None else (ts,))
        if key in self._rel_keys:
            rel = self.relations[self._rel_keys[key]]
            rel["count"] = rel.get("count", 1) + 1
            if ts and ts > rel.get("last_seen", ""):
                rel["last_seen"] = ts
            return self._rel_keys[key]
        rid = f"rel-{_digest('|'.join(map(str, key)))}"
        rel = {"type": rtype, "source": source, "target": target}
        if ts:
            rel["timestamp"] = ts
        rel.update({k: _clip(v) for k, v in props.items() if v not in (None, "", "-")})
        self.relations[rid] = rel
        self._rel_keys[key] = rid
        self.outgoing[source].append(rid)
        self.incoming[target].append(rid)
        return rid

    # --------------------------------------------------------------- queries
    def processes(self) -> Iterable[tuple[str, dict[str, Any]]]:
        return ((k, v) for k, v in self.entities.items() if v["type"] in PROCESS_TYPES)

    def children(self, eid: str) -> list[str]:
        return [
            self.relations[r]["target"]
            for r in self.outgoing.get(eid, [])
            if self.relations[r]["type"] in CREATE_RELATIONS
        ]

    def parent(self, eid: str) -> str | None:
        for r in self.incoming.get(eid, []):
            if self.relations[r]["type"] in CREATE_RELATIONS:
                return self.relations[r]["source"]
        return None


_PREFIX = {
    "windows_process": "proc",
    "linux_process": "proc",
    "windows_file": "file",
    "linux_file": "file",
    "linux_user": "user",
    "registry_key": "reg",
    "network_connection": "conn",
    "host": "host",
    "windows_user": "user",
    "named_pipe": "pipe",
    "scheduled_task": "task",
    "windows_service": "svc",
    "wmi_event_filter": "wmif",
    "wmi_event_consumer": "wmic",
    "wmi_binding": "wmib",
}


def _digest(s: str) -> str:
    return hashlib.sha1(s.lower().encode("utf-8", "replace")).hexdigest()[:10]


def _clip(v: Any) -> Any:
    if isinstance(v, str):
        return v[:MAX_FIELD]
    return v


def _ts(e: dict[str, Any]) -> str | None:
    utc = e.get("UtcTime")
    if isinstance(utc, str) and len(utc) >= 19:
        return utc.replace(" ", "T") + ("Z" if not utc.endswith("Z") else "")
    t = e.get("@timestamp") or e.get("TimeCreated")
    return t if isinstance(t, str) else None


def _sha256(hashes: Any) -> str | None:
    if isinstance(hashes, str):
        for part in hashes.split(","):
            if part.upper().startswith("SHA256="):
                return part.split("=", 1)[1]
    return None


def build_graph(events: Iterable[dict[str, Any]]) -> Graph:
    g = Graph()
    hosts: dict[str, str] = {}
    users: dict[str, str] = {}
    v = WINDOWS  # vocabulary of the event being processed

    def host_of(e: dict[str, Any]) -> str:
        name = str(e.get("Hostname") or e.get("Computer") or "unknown").lower()
        if name not in hosts:
            hosts[name] = g.entity("host", name, hostname=name)
        return hosts[name]

    def user_of(name: Any, host: str) -> str | None:
        if not isinstance(name, str) or not name.strip():
            return None
        key = name.lower()
        if key not in users:
            users[key] = g.entity(v["user"], key, name=name)
            g.relate("logged_on_to", users[key], host, None, dedupe=())
        return users[key]

    def proc(guid: Any, host: str, **props: Any) -> str | None:
        if not isinstance(guid, str) or not guid:
            return None
        pid = g.entity(v["process"], guid, process_guid=guid, **props)
        if "hostname" not in g.entities[pid]:
            g.update(pid, hostname=g.entities[host]["hostname"])
            g.relate("runs_process", host, pid, None, dedupe=())
        if "user_entity_id" not in g.entities[pid] and isinstance(props.get("user"), str):
            u = user_of(props["user"], host)
            if u:
                g.update(pid, user_entity_id=u)
        return pid

    def file_(path: Any, **props: Any) -> str | None:
        if not isinstance(path, str) or not path:
            return None
        return g.entity(v["file"], path, path=path, **props)

    for e in events:
        if not isinstance(e, dict):
            continue
        ch, eid_ = e.get("Channel"), str(e.get("EventID", ""))
        h = host_of(e)
        ts = _ts(e)
        v = LINUX if ch == SYSMON_LINUX else WINDOWS
        if ch in (SYSMON, SYSMON_LINUX):
            if eid_ == "1":
                child = proc(
                    e.get("ProcessGuid"),
                    h,
                    image=e.get("Image"),
                    command_line=e.get("CommandLine"),
                    user=e.get("User"),
                    integrity_level=e.get("IntegrityLevel"),
                    process_id=e.get("ProcessId"),
                    company=e.get("Company"),
                    product=e.get("Product"),
                    description=e.get("Description"),
                    original_file_name=e.get("OriginalFileName"),
                    current_directory=e.get("CurrentDirectory"),
                    sha256=_sha256(e.get("Hashes")),
                    start_time=ts,
                )
                if child is None:
                    continue
                g.update(
                    child, image=e.get("Image"), command_line=e.get("CommandLine"), start_time=ts
                )
                u = user_of(e.get("User"), h)
                if u:
                    g.update(child, user_entity_id=u)
                parent = proc(
                    e.get("ParentProcessGuid"),
                    h,
                    image=e.get("ParentImage"),
                    command_line=e.get("ParentCommandLine"),
                    user=e.get("ParentUser"),
                    process_id=e.get("ParentProcessId"),
                )
                if parent:
                    g.relate(v["create"], parent, child, ts)
                f = file_(e.get("Image"), sha256=_sha256(e.get("Hashes")))
                if f:
                    g.relate("executed_file", child, f, ts)
            elif eid_ == "3":
                p = proc(e.get("ProcessGuid"), h, image=e.get("Image"), user=e.get("User"))
                dst, port = e.get("DestinationIp"), e.get("DestinationPort")
                if not p or not dst:
                    continue
                initiated = str(e.get("Initiated", "")).lower() == "true"
                # Outbound: one entity per destination, so repeated beacons from new
                # ephemeral ports collapse. Inbound: one per client socket.
                local_port = "" if initiated else e.get("SourcePort")
                c = g.entity(
                    "network_connection",
                    f"{e.get('Protocol')}|{dst}|{port}|{e.get('SourceIp')}|{local_port}",
                    protocol=e.get("Protocol"),
                    source_ip=e.get("SourceIp"),
                    source_port=e.get("SourcePort"),
                    destination_ip=dst,
                    destination_port=port,
                    destination_hostname=e.get("DestinationHostname"),
                    initiated=initiated,
                )
                g.relate(
                    "connected_to" if initiated else "accepted_connection_from", p, c, ts, dedupe=()
                )
            elif eid_ == "5":
                p = proc(e.get("ProcessGuid"), h, image=e.get("Image"))
                if p:
                    g.update(p, end_time=ts)
            elif eid_ == "7":
                p = proc(e.get("ProcessGuid"), h, image=e.get("Image"))
                f = file_(
                    e.get("ImageLoaded"),
                    signed=e.get("Signed"),
                    signature=e.get("Signature"),
                    signature_status=e.get("SignatureStatus"),
                    company=e.get("Company"),
                    sha256=_sha256(e.get("Hashes")),
                )
                if p and f:
                    g.relate("loaded_image", p, f, ts, dedupe=())
            elif eid_ == "8":
                s = proc(e.get("SourceProcessGuid"), h, image=e.get("SourceImage"))
                t = proc(e.get("TargetProcessGuid"), h, image=e.get("TargetImage"))
                if s and t:
                    g.relate(
                        "injected_into",
                        s,
                        t,
                        ts,
                        start_function=e.get("StartFunction"),
                        start_module=e.get("StartModule"),
                    )
            elif eid_ == "10":
                s = proc(e.get("SourceProcessGUID"), h, image=e.get("SourceImage"))
                t = proc(e.get("TargetProcessGUID"), h, image=e.get("TargetImage"))
                if s and t:
                    access = e.get("GrantedAccess")
                    g.relate(
                        "accessed_process",
                        s,
                        t,
                        ts,
                        dedupe=(access,),
                        granted_access=access,
                        call_trace=e.get("CallTrace"),
                    )
            elif eid_ == "11":
                p = proc(e.get("ProcessGuid"), h, image=e.get("Image"))
                f = file_(e.get("TargetFilename"), created=e.get("CreationUtcTime"))
                if p and f:
                    g.relate("wrote_file", p, f, ts, dedupe=())
            elif eid_ in ("23", "26"):
                p = proc(e.get("ProcessGuid"), h, image=e.get("Image"))
                f = file_(e.get("TargetFilename"))
                if p and f:
                    g.relate("deleted_file", p, f, ts, dedupe=())
            elif eid_ in ("12", "13", "14"):
                p = proc(e.get("ProcessGuid"), h, image=e.get("Image"))
                key = e.get("TargetObject")
                if not p or not isinstance(key, str):
                    continue
                r = g.entity("registry_key", key, path=key)
                event_type = str(e.get("EventType", ""))
                if eid_ == "13":
                    g.update(r, value_data=e.get("Details"))
                    g.relate("set_registry_value", p, r, ts, dedupe=(), value_data=e.get("Details"))
                elif eid_ == "14":
                    g.relate("renamed_registry_key", p, r, ts, dedupe=(), new_name=e.get("NewName"))
                elif "Delete" in event_type:
                    g.relate("deleted_registry_key", p, r, ts, dedupe=())
                else:
                    g.relate("created_registry_key", p, r, ts, dedupe=())
            elif eid_ in ("17", "18"):
                p = proc(e.get("ProcessGuid"), h, image=e.get("Image"))
                name = e.get("PipeName")
                if p and isinstance(name, str):
                    pipe = g.entity("named_pipe", name, name=name)
                    g.relate(
                        "created_pipe" if eid_ == "17" else "connected_to_pipe",
                        p,
                        pipe,
                        ts,
                        dedupe=(),
                    )
            elif eid_ == "22":
                p = proc(e.get("ProcessGuid"), h, image=e.get("Image"))
                q = e.get("QueryName")
                if p and isinstance(q, str):
                    d = g.entity(
                        "network_connection",
                        "dns|" + q,
                        query_name=q,
                        query_results=e.get("QueryResults"),
                    )
                    g.relate("resolves_to", p, d, ts, dedupe=())
            elif eid_ in ("19", "20", "21"):
                kind = {"19": "wmi_event_filter", "20": "wmi_event_consumer", "21": "wmi_binding"}[
                    eid_
                ]
                name = e.get("Name") or e.get("Consumer") or e.get("Filter")
                if isinstance(name, str):
                    w = g.entity(
                        kind,
                        name,
                        name=name,
                        query=e.get("Query"),
                        destination=e.get("Destination"),
                        consumer=e.get("Consumer"),
                        filter=e.get("Filter"),
                    )
                    u = user_of(e.get("User"), h)
                    rel = {
                        "19": "created_wmi_filter",
                        "20": "created_wmi_consumer",
                        "21": "bound_wmi_filter_to_consumer",
                    }[eid_]
                    g.relate(rel, u or h, w, ts, dedupe=())
        elif ch == "Security":
            if eid_ == "4698":
                name = e.get("TaskName")
                if isinstance(name, str):
                    t = g.entity("scheduled_task", name, name=name, content=e.get("TaskContent"))
                    u = user_of(e.get("SubjectUserName"), h)
                    g.relate("created_scheduled_task", u or h, t, ts, dedupe=())
            elif eid_ == "4624":
                u = user_of(f"{e.get('TargetDomainName', '')}\\{e.get('TargetUserName', '')}", h)
                if u:
                    g.relate(
                        "logged_on_to",
                        u,
                        h,
                        ts,
                        dedupe=(e.get("LogonType"),),
                        logon_type=e.get("LogonType"),
                        source_ip=e.get("IpAddress"),
                    )
        elif ch == "System" and eid_ == "7045":
            name = e.get("ServiceName")
            if isinstance(name, str):
                s = g.entity(
                    "windows_service",
                    name,
                    name=name,
                    image_path=e.get("ImagePath"),
                    start_type=e.get("StartType"),
                    account=e.get("AccountName"),
                )
                g.relate("hosts", h, s, ts, dedupe=())
    return g


def load_events(path: str) -> list[dict[str, Any]]:
    """Read one dataset file: JSON lines or a JSON array (OTRF), or one Sysmon
    XML `<Event>` per line (Splunk attack_data, Sysmon for Linux)."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    stripped = text.lstrip()
    if stripped.startswith("<"):
        return [e for e in (_xml_event(line) for line in text.splitlines()) if e]
    if stripped.startswith("["):
        data = json.loads(stripped)
        return [e for e in data if isinstance(e, dict)]
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _xml_event(line: str) -> dict[str, Any] | None:
    """Flatten one Sysmon `<Event>` into the dict shape OTRF uses.

    Untrusted input: lines declaring a DTD or entities are skipped, so no
    entity expansion can happen.
    """
    line = line.strip()
    if not line.startswith("<Event") or "<!" in line:
        return None
    try:
        root = ET.fromstring(line)
    except ET.ParseError:
        return None
    out: dict[str, Any] = {}
    for el in root.iter():
        tag = el.tag.split("}")[-1]
        if tag == "EventID":
            out["EventID"] = (el.text or "").strip()
        elif tag == "Channel":
            out["Channel"] = (el.text or "").strip()
        elif tag == "Computer":
            out["Hostname"] = (el.text or "").strip()
        elif tag == "TimeCreated":
            out.setdefault("TimeCreated", el.attrib.get("SystemTime"))
        elif tag == "Data" and "Name" in el.attrib:
            out[el.attrib["Name"]] = (el.text or "").strip()
    return out if out.get("EventID") else None
