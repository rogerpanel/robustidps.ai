"""Tests for the local practice runtime built from public datasets."""

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from test_robust_agent import FakeClaude, reply, tu

from bluesec1_agent.robust.agent import RobustAgent
from bluesec1_agent.robust.localdata.graph import build_graph
from bluesec1_agent.robust.localdata.runtime import LocalClient, LocalSession, score
from bluesec1_agent.robust.localdata.scenarios import Scenario, build_task
from bluesec1_agent.robust.settings import RobustSettings

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def ev(eid: int, **kw: Any) -> dict[str, Any]:
    return {
        "Channel": SYSMON,
        "EventID": eid,
        "Hostname": "WS1",
        "UtcTime": kw.pop("t", "2026-01-01 10:00:00.000"),
        **kw,
    }


EVENTS = [
    ev(
        1,
        ProcessGuid="{shell}",
        ParentProcessGuid="{explorer}",
        Image="C:\\Windows\\System32\\cmd.exe",
        ParentImage="C:\\Windows\\explorer.exe",
        CommandLine="cmd.exe",
        User="WS1\\alice",
    ),
    ev(
        1,
        ProcessGuid="{tool}",
        ParentProcessGuid="{shell}",
        Image="C:\\Windows\\System32\\reg.exe",
        ParentImage="C:\\Windows\\System32\\cmd.exe",
        CommandLine="reg add HKCU\\Run /v x",
        User="WS1\\alice",
        t="2026-01-01 10:00:01.000",
    ),
    ev(
        13,
        ProcessGuid="{tool}",
        Image="C:\\Windows\\System32\\reg.exe",
        TargetObject="HKU\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x",
        Details="C:\\Users\\alice\\x.exe",
        EventType="SetValue",
    ),
    ev(
        11,
        ProcessGuid="{shell}",
        Image="C:\\Windows\\System32\\cmd.exe",
        TargetFilename="C:\\Users\\alice\\x.exe",
    ),
    ev(
        3,
        ProcessGuid="{tool}",
        Image="C:\\Windows\\System32\\reg.exe",
        Protocol="tcp",
        SourceIp="10.0.0.5",
        SourcePort="50000",
        DestinationIp="203.0.113.9",
        DestinationPort="443",
        Initiated="true",
    ),
    ev(
        3,
        ProcessGuid="{tool}",
        Image="C:\\Windows\\System32\\reg.exe",
        Protocol="tcp",
        SourceIp="10.0.0.5",
        SourcePort="50001",
        DestinationIp="203.0.113.9",
        DestinationPort="443",
        Initiated="true",
        t="2026-01-01 10:00:05.000",
    ),
    ev(
        10,
        SourceProcessGUID="{svc}",
        SourceImage="C:\\Windows\\System32\\svchost.exe",
        TargetProcessGUID="{lsass}",
        TargetImage="C:\\Windows\\System32\\lsass.exe",
        GrantedAccess="0x1000",
        CallTrace="C:\\Windows\\System32\\lsm.dll+1",
    ),
    {"Channel": "Security", "EventID": 4663, "Hostname": "WS1"},  # ignored noise
]


def test_graph_builder_maps_sysmon_to_runtime_vocabulary() -> None:
    g = build_graph(EVENTS)
    types = sorted({e["type"] for e in g.entities.values()})
    assert types == [
        "host",
        "network_connection",
        "registry_key",
        "windows_file",
        "windows_process",
        "windows_user",
    ]
    rels = sorted({r["type"] for r in g.relations.values()})
    for needed in (
        "win_process_create",
        "set_registry_value",
        "wrote_file",
        "connected_to",
        "accessed_process",
        "runs_process",
        "executed_file",
        "logged_on_to",
    ):
        assert needed in rels
    conn = [r for r in g.relations.values() if r["type"] == "connected_to"]
    assert len(conn) == 1 and conn[0]["count"] == 2  # repeated beacons collapse
    tool = next(k for k, v in g.entities.items() if v.get("image", "").endswith("reg.exe"))
    assert g.entities[tool]["user_entity_id"].startswith("user-")
    assert g.parent(tool) and g.entities[g.parent(tool)]["image"].endswith("cmd.exe")


SC_MAL = Scenario(
    id="t-mal",
    dataset="x/y",
    otrf_id="T",
    attack="T1547.001",
    verdict="malicious",
    title="Run key set",
    summary="reg.exe set a Run value",
    severity="high",
    trigger={"type": "windows_process", "image": "reg.exe"},
    core=({"type": "registry_key", "path_contains": "currentversion\\run\\x"},),
    optimal_calls=2,
)
SC_BEN = Scenario(
    id="t-ben",
    dataset="x/y",
    otrf_id="T",
    attack="-",
    verdict="benign",
    title="LSASS handle",
    summary="svchost opened lsass",
    severity="medium",
    trigger={"rel": "accessed_process", "source_image": "svchost.exe", "target_image": "lsass.exe"},
    core=("trigger_relation", "trigger_source"),
    optimal_calls=1,
)


def test_scoring_rewards_complete_and_precise_answers() -> None:
    g = build_graph(EVENTS)
    t = build_task(SC_MAL, g)
    kinds = {
        "host": "host_to_isolate",
        "windows_user": "identity_to_rotate",
        "registry_key": "persistence_to_remove",
        "windows_process": "process_observed",
    }
    full = [{"entity_id": i, "kind": kinds[g.entities[i]["type"]]} for i in t.core]
    assert score(t, {"verdict": "malicious", "ir_artifacts": full})[0] == 1.0
    q_partial, d = score(t, {"verdict": "malicious", "ir_artifacts": full[:2]})
    assert 0.5 < q_partial < 1.0 and d["missed_core"]
    noisy = full + [{"entity_id": "proc-not-related", "kind": "process_observed"}]
    assert score(t, {"verdict": "malicious", "ir_artifacts": noisy})[0] < 1.0
    assert score(t, {"verdict": "benign", "legitimacy_evidence": []})[0] == 0.0

    b = build_task(SC_BEN, g)
    rel = next(iter(i for i in b.core if i.startswith("rel-")))
    src = next(iter(i for i in b.core if i.startswith("proc-")))
    good = [
        {"anchor": "relation", "relation_id": rel, "property_fields": ["granted_access"]},
        {"anchor": "entity", "entity_id": src, "property_fields": ["image"]},
    ]
    assert score(b, {"verdict": "benign", "legitimacy_evidence": good})[0] == 1.0
    weak = [{"anchor": "entity", "entity_id": src, "property_fields": ["hostname"]}]
    assert score(b, {"verdict": "benign", "legitimacy_evidence": weak})[0] == 0.5


def test_local_session_tools() -> None:
    g = build_graph(EVENTS)
    s = LocalSession(build_task(SC_MAL, g), "t-mal")
    trig = s.task.observation["alert_text"]["trigger_entities"][0]
    r = asyncio.run(s.call_tool("get_entity", {"entity_id": trig, "reasoning": "x"}))
    out = r.info["tool_result"]
    assert "set_registry_value" in out["outgoing"] and out["image"].endswith("reg.exe")
    r = asyncio.run(
        s.call_tool(
            "search",
            {
                "query": "203.0.113.9",
                "reasoning": "x",
                "scope": {"kind": "entity", "type": "network_connection"},
            },
        )
    )
    assert r.info["tool_result"]["total"] == 1
    r = asyncio.run(s.call_tool("get_entity", {"entity_id": "nope", "reasoning": "x"}))
    assert r.info["tool_status"] == "error"


DATA = Path("datasets")


@pytest.mark.skipif(not DATA.is_dir(), reason="practice datasets not downloaded")
def test_agent_runs_on_real_public_datasets(tmp_path: Path) -> None:
    from bluesec1_agent.robust.localdata.fetch import load_tasks

    tasks = load_tasks(DATA, ["lsass-dump-comsvcs", "lsass-query-by-svchost"])
    mal, ben = tasks
    g = mal.graph
    kind = {
        "host": "host_to_isolate",
        "windows_user": "identity_to_rotate",
        "windows_file": "file_to_delete",
        "windows_process": "process_observed",
    }
    artifacts = [{"entity_id": i, "kind": kind[g.entities[i]["type"]]} for i in sorted(mal.core)]
    trig = mal.alert["trigger_entities"][0]
    rel = ben.alert["trigger_relations"][0]
    src = ben.alert["trigger_entities"][0]
    finish_mal = {
        "submission": {
            "verdict": "malicious",
            "summary": "LSASS dumped to disk.",
            "ir_artifacts": artifacts,
        }
    }
    claude = FakeClaude(
        [
            reply(tu(1, "get_entity", {"entity_id": trig, "purpose": "trigger"})),
            # ids not looked up yet: the agent warns once, the unchanged resubmission is sent
            reply(tu(2, "finish_investigation", finish_mal)),
            reply(tu(5, "finish_investigation", finish_mal)),
            reply(tu(3, "get_relation", {"relation_id": rel, "purpose": "access mask"})),
            reply(
                tu(
                    4,
                    "finish_investigation",
                    {
                        "submission": {
                            "verdict": "benign",
                            "summary": "Query-limited handle from svchost.",
                            "legitimacy_evidence": [
                                {
                                    "anchor": "relation",
                                    "relation_id": rel,
                                    "property_fields": ["granted_access"],
                                },
                                {
                                    "anchor": "entity",
                                    "entity_id": src,
                                    "property_fields": ["image"],
                                },
                            ],
                        }
                    },
                )
            ),
        ]
    )
    settings = RobustSettings(ROBUST_TRACE_DIR=tmp_path, ANTHROPIC_API_KEY="k")
    summary = asyncio.run(RobustAgent(settings, claude).run(LocalClient(tasks)))
    assert summary["completed"] == 2 and summary["mean_quality"] == 1.0
    trace = json.loads((next(tmp_path.iterdir()) / "lsass-dump-comsvcs.json").read_text())
    assert "local_score_detail" in json.dumps(trace["steps"][-1])


LINUX_XML = [
    '<Event><System><Provider Name="Linux-Sysmon"/><EventID>1</EventID>'
    "<Channel>Linux-Sysmon/Operational</Channel><Computer>lab-1</Computer></System>"
    '<EventData><Data Name="UtcTime">2026-01-01 10:00:00.000</Data>'
    '<Data Name="ProcessGuid">{child}</Data><Data Name="Image">/usr/bin/cat</Data>'
    '<Data Name="CommandLine">cat /etc/shadow</Data><Data Name="User">root</Data>'
    '<Data Name="ParentProcessGuid">{shell}</Data><Data Name="ParentImage">/bin/bash</Data>'
    '<Data Name="ParentCommandLine">-bash</Data><Data Name="ParentUser">ubuntu</Data>'
    "</EventData></Event>",
    '<!DOCTYPE x [<!ENTITY a "boom">]><Event><System><EventID>1</EventID></System></Event>',
    "not xml at all",
]


def test_sysmon_for_linux_xml_maps_to_linux_vocabulary(tmp_path: Path) -> None:
    from bluesec1_agent.robust.localdata.graph import load_events

    f = tmp_path / "sysmon_linux.log"
    f.write_text("\n".join(LINUX_XML))
    events = load_events(str(f))
    assert len(events) == 1                                 # DTD line and junk are refused
    g = build_graph(events)
    kinds = {e["type"] for e in g.entities.values()}
    assert {"linux_process", "linux_file", "linux_user", "host"} <= kinds
    rel = next(r for r in g.relations.values() if r["type"] == "linux_process_create")
    shell = g.entities[rel["source"]]
    assert shell["image"] == "/bin/bash" and g.entities[shell["user_entity_id"]]["name"] == "ubuntu"


@pytest.mark.skipif(not (DATA / "splunk").is_dir(), reason="Linux practice data not downloaded")
def test_linux_tasks_build_and_pair_with_benign_twins() -> None:
    from bluesec1_agent.robust.localdata.fetch import load_tasks

    tasks = {t.scenario.id: t for t in load_tasks(DATA) if t.scenario.platform == "linux"}
    assert len(tasks) == 10
    mal, ben = tasks["linux-service-stopped"], tasks["linux-dpkg-service-start"]
    assert mal.alert["title"] == ben.alert["title"]          # same alert, opposite verdicts
    assert mal.scenario.verdict == "malicious" and ben.scenario.verdict == "benign"
    users = {mal.graph.entities[i]["name"] for i in mal.core
             if mal.graph.entities.get(i, {}).get("type") == "linux_user"}
    assert users == {"ubuntu"}


def test_pack_round_trip_and_rejects_foreign_zip(tmp_path: Path) -> None:
    import zipfile

    from bluesec1_agent.robust.localdata.pack import build_pack, load_pack

    g = build_graph(EVENTS)
    tasks = [build_task(SC_MAL, g), build_task(SC_BEN, g)]
    out = tmp_path / "pack.zip"
    manifest = build_pack(tasks, out)
    assert [t["id"] for t in manifest["tasks"]] == ["t-mal", "t-ben"]
    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
        assert {"manifest.json", "README.md", "tasks/t-mal.json", "answers/t-mal.json"} <= names
        assert any(n.startswith("LICENSES/") for n in names)
        assert "verdict" not in json.loads(zf.read("tasks/t-mal.json"))   # answers kept apart
    loaded = {t.scenario.id: t for t in load_pack(out)}
    assert loaded["t-mal"].core == tasks[0].core and loaded["t-ben"].evidence_fields
    s = LocalSession(loaded["t-mal"], "t-mal")
    trig = s.task.observation["alert_text"]["trigger_entities"][0]
    r = asyncio.run(s.call_tool("get_entity", {"entity_id": trig, "reasoning": "x"}))
    assert r.info["tool_status"] == "ok" and r.info["tool_result"]["outgoing"]

    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr("manifest.json", json.dumps({"format": "something-else"}))
    with pytest.raises(ValueError):
        load_pack(bad)
