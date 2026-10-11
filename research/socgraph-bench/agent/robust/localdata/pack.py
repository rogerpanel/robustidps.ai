"""Build and load a self-contained practice pack (one zip, no downloads needed).

    python -m bluesec1_agent.robust.localdata.pack --out robustidps-bluesec-pack.zip
    python -m bluesec1_agent.robust.cli --pack robustidps-bluesec-pack.zip

Layout of the zip:
    manifest.json         pack metadata and the task index (no answers)
    tasks/<id>.json       alert + evidence graph: what the agent sees
    answers/<id>.json     ground truth used for scoring (verdict, core,
                          acceptable, legitimacy anchors)
    README.md             what the pack is, how it was built, how it is scored
    LICENSES/*            upstream licences (OTRF: MIT, Splunk attack_data: Apache-2.0)

A pack opened from elsewhere is untrusted: only JSON members are read, with
size caps, and nothing in it is executed.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import zipfile
from pathlib import Path
from typing import Any

from .fetch import load_tasks
from .graph import Graph
from .scenarios import BY_ID, OTRF_BASE, SOURCE_LABEL, SPLUNK_BASE, Scenario, Task

PACK_FORMAT = "robustidps-bluesec-pack/1"
MAX_MEMBER_BYTES = 64 * 1024 * 1024
LICENSE_DIR = Path(__file__).parent / "licenses"


def source_url(sc: Scenario) -> str:
    if sc.source == "splunk":
        return SPLUNK_BASE + sc.dataset + "/sysmon_linux.log"
    return OTRF_BASE + sc.dataset + ".zip"


def task_record(t: Task) -> dict[str, Any]:
    sc = t.scenario
    return {
        "id": sc.id,
        "platform": sc.platform,
        "alert": t.alert,
        "optimal_calls": sc.optimal_calls,
        "graph": {"entities": t.graph.entities, "relations": t.graph.relations},
    }


def answer_record(t: Task) -> dict[str, Any]:
    sc = t.scenario
    return {
        "id": sc.id,
        "verdict": sc.verdict,
        "attack": sc.attack,
        "core": sorted(t.core),
        "acceptable": sorted(t.acceptable),
        "evidence_fields": {k: sorted(v) for k, v in t.evidence_fields.items()},
    }


def build_pack(tasks: list[Task], out: Path) -> dict[str, Any]:
    manifest = {
        "format": PACK_FORMAT,
        "name": "RobustIDPS BlueSec practice pack",
        "created": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tasks": [
            {
                "id": t.scenario.id,
                "platform": t.scenario.platform,
                "verdict": t.scenario.verdict,
                "attack": t.scenario.attack,
                "title": t.scenario.title,
                "source": SOURCE_LABEL[t.scenario.source],
                "source_dataset": t.scenario.otrf_id,
                "source_url": source_url(t.scenario),
                "entities": len(t.graph.entities),
                "relations": len(t.graph.relations),
            }
            for t in tasks
        ],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
        for t in tasks:
            zf.writestr(f"tasks/{t.scenario.id}.json", json.dumps(task_record(t)))
            zf.writestr(f"answers/{t.scenario.id}.json", json.dumps(answer_record(t), indent=1))
        zf.writestr("README.md", _readme(manifest))
        for lic in sorted(LICENSE_DIR.glob("*.txt")):
            zf.writestr(f"LICENSES/{lic.name}", lic.read_text(encoding="utf-8"))
    return manifest


def load_pack(path: Path, ids: list[str] | None = None) -> list[Task]:
    with zipfile.ZipFile(path) as zf:
        manifest = _json(zf, "manifest.json")
        if manifest.get("format") != PACK_FORMAT:
            raise ValueError(f"not a {PACK_FORMAT} pack")
        tasks = []
        for entry in manifest.get("tasks", []):
            tid = str(entry.get("id", ""))
            if ids and tid not in ids:
                continue
            rec, ans = _json(zf, f"tasks/{tid}.json"), _json(zf, f"answers/{tid}.json")
            g = Graph()
            g.entities.update(rec["graph"]["entities"])
            for rid, rel in rec["graph"]["relations"].items():
                g.relations[rid] = rel
                g.outgoing[rel["source"]].append(rid)
                g.incoming[rel["target"]].append(rid)
            sc = BY_ID.get(tid) or Scenario(
                id=tid, dataset="", otrf_id=str(entry.get("source_dataset", "")),
                attack=str(ans.get("attack", "-")), verdict=ans["verdict"],
                title=rec["alert"].get("title", tid), summary=rec["alert"].get("summary", ""),
                severity=rec["alert"].get("severity", "medium"), trigger={},
                optimal_calls=int(rec.get("optimal_calls", 4)),
                source="splunk" if rec.get("platform") == "linux" else "otrf",
            )
            tasks.append(Task(
                scenario=sc, graph=g, alert=rec["alert"], core=set(ans["core"]),
                acceptable=set(ans["acceptable"]),
                evidence_fields={k: set(v) for k, v in ans.get("evidence_fields", {}).items()},
            ))
    if ids:
        missing = set(ids) - {t.scenario.id for t in tasks}
        if missing:
            raise ValueError(f"not in pack: {sorted(missing)}")
    return tasks


def _json(zf: zipfile.ZipFile, name: str) -> Any:
    info = zf.getinfo(name)
    if info.file_size > MAX_MEMBER_BYTES:
        raise ValueError(f"{name} is too large")
    return json.loads(zf.read(info).decode("utf-8"))


def _readme(manifest: dict[str, Any]) -> str:
    rows = "\n".join(
        f"| {t['id']} | {t['platform']} | {t['verdict']} | {t['attack']} | {t['title']} | "
        f"{t['entities']} / {t['relations']} |"
        for t in manifest["tasks"]
    )
    sources = "\n".join(sorted({f"- {t['source']} `{t['source_dataset']}`: {t['source_url']}"
                                for t in manifest["tasks"]}))
    return f"""# RobustIDPS BlueSec practice pack

Investigation tasks built from public attack telemetry, in the evidence-graph
form used by the BlueSec competition runtime (entities and typed relations).
Created {manifest['created']}.

| Task | Platform | Verdict | ATT&CK | Alert | Entities / relations |
|---|---|---|---|---|---|
{rows}

## Run it

    uv run --with anthropic --with jsonschema --env-file .env \\
        python -m bluesec1_agent.robust.cli --pack this-pack.zip --concurrency 4

Then import the run folder on robustidps.ai > BlueSec Runs.

## How it was built

- Windows: OTRF Security-Datasets (Open Threat Research Forge, MIT licence),
  Sysmon and Windows Security events recorded during ATT&CK technique
  simulations.
- Linux: Splunk attack_data (Splunk, Apache-2.0), Sysmon for Linux events
  recorded in Splunk Attack Range. The log forwarder's own checkpoint-file
  writes under /opt/splunkforwarder were removed as collector self-telemetry.
- Events were converted into entities (processes, files, registry keys,
  connections, users, hosts) and relations (process creation, file write,
  registry write, connect, process access, ...). Field values are copied
  from the source events, capped at 600 characters.
- Malicious tasks: the operator's recorded session is the root of the
  activity. Benign tasks: real background events from the same recordings
  that a naive rule would flag.

Sources:
{sources}

## Scoring (RobustIDPS, not the competition's)

Quality = half verdict, half artifacts. Malicious: F1 of recall over `core`
(full credit for a fitting response kind, half for another kind) and
precision against `acceptable`. Benign: share of `evidence_fields` anchors
cited with a decisive property field. Wrong verdict = 0.
Efficiency = min(1, (optimal_calls + 1) / tool calls).
Reward = quality x (0.8 + 0.2 x efficiency).

`answers/` holds the ground truth. Keep it away from the agent under test.
"""


def main() -> None:
    ap = argparse.ArgumentParser(description="Build the practice pack zip")
    ap.add_argument("--data-dir", default="datasets")
    ap.add_argument("--out", default="robustidps-bluesec-pack.zip")
    args = ap.parse_args()
    tasks = load_tasks(Path(args.data_dir))
    manifest = build_pack(tasks, Path(args.out))
    size = Path(args.out).stat().st_size
    print(f"{len(manifest['tasks'])} tasks -> {args.out} ({size / 1e6:.2f} MB)")


if __name__ == "__main__":
    sys.exit(main())

