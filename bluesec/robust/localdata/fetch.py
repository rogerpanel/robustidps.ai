"""Download the public datasets the practice scenarios use, and load tasks.

    python -m bluesec1_agent.robust.localdata.fetch            # into ./datasets/

Windows: OTRF Security-Datasets (MIT). Each zip is saved in memory and only its
.json members are extracted, by base name, into datasets/otrf/<name>/.
Linux: Splunk attack_data (Apache-2.0), one Sysmon-for-Linux log per scenario,
saved as datasets/splunk/<name>/sysmon_linux.log.
Nothing downloaded is executed.

Splunk's recordings include the log forwarder's own checkpoint-file churn
(thousands of writes under /opt/splunkforwarder per minute). That is collector
self-telemetry, not host activity, and is dropped when the graph is built;
the forwarder's processes and connections stay as benign background.
"""

from __future__ import annotations

import argparse
import io
import sys
import urllib.request
import zipfile
from pathlib import Path

from .graph import build_graph, load_events
from .scenarios import OTRF_BASE, SCENARIOS, SPLUNK_BASE, Scenario, ScenarioError, Task, build_task

MAX_ZIP_BYTES = 60 * 1024 * 1024
MAX_JSON_BYTES = 200 * 1024 * 1024
MAX_LOG_BYTES = 120 * 1024 * 1024


def dataset_dir(data_dir: Path, sc: Scenario) -> Path:
    return data_dir / sc.source / sc.dataset.split("/")[-1]


def _download(url: str, limit: int) -> bytes:
    with urllib.request.urlopen(url, timeout=300) as resp:  # noqa: S310 - fixed https hosts
        blob = resp.read(limit + 1)
    if len(blob) > limit:
        raise RuntimeError(f"{url} is larger than expected")
    return blob


def fetch(data_dir: Path, *, force: bool = False) -> list[str]:
    done = []
    seen: set[tuple[str, str]] = set()
    for sc in SCENARIOS:
        if (sc.source, sc.dataset) in seen:
            continue
        seen.add((sc.source, sc.dataset))
        dataset = sc.dataset
        target = dataset_dir(data_dir, sc)
        if target.is_dir() and _data_files(target) and not force:
            done.append(f"have  {sc.source}:{dataset}")
            continue
        target.mkdir(parents=True, exist_ok=True)
        if sc.source == "splunk":
            blob = _download(SPLUNK_BASE + dataset + "/sysmon_linux.log", MAX_LOG_BYTES)
            if not blob.lstrip().startswith(b"<"):
                raise RuntimeError(f"{dataset}: unexpected content (not Sysmon XML)")
            (target / "sysmon_linux.log").write_bytes(blob)
            done.append(f"fetch splunk:{dataset}")
            continue
        url = OTRF_BASE + dataset + ".zip"
        blob = _download(url, MAX_ZIP_BYTES)
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for info in zf.infolist():
                name = Path(info.filename).name
                if not name.lower().endswith(".json") or info.file_size > MAX_JSON_BYTES:
                    continue
                (target / name).write_bytes(zf.read(info))
        done.append(f"fetch otrf:{dataset}")
    return done


def _data_files(folder: Path) -> list[Path]:
    return sorted(list(folder.glob("*.json")) + list(folder.glob("*.log")))


def _collector_noise(e: dict) -> bool:
    return str(e.get("EventID")) in ("11", "23") and str(e.get("TargetFilename", "")).startswith(
        "/opt/splunkforwarder/"
    )


def load_tasks(data_dir: Path, ids: list[str] | None = None) -> list[Task]:
    graphs: dict[str, object] = {}
    tasks = []
    for sc in SCENARIOS:
        if ids and sc.id not in ids:
            continue
        files = _data_files(dataset_dir(data_dir, sc))
        if not files:
            raise FileNotFoundError(
                f"{sc.dataset} is not downloaded; run: python -m "
                "bluesec1_agent.robust.localdata.fetch"
            )
        key = f"{sc.source}:{sc.dataset}"
        if key not in graphs:
            events = []
            for f in files:
                events.extend(e for e in load_events(str(f)) if not _collector_noise(e))
            graphs[key] = build_graph(events)
        tasks.append(build_task(sc, graphs[key]))
    if ids:
        unknown = set(ids) - {t.scenario.id for t in tasks}
        if unknown:
            raise ScenarioError(f"unknown scenario ids: {sorted(unknown)}")
    return tasks


def main() -> None:
    ap = argparse.ArgumentParser(description="Download the practice datasets")
    ap.add_argument("--data-dir", default="datasets")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--list", action="store_true", help="list the scenarios")
    args = ap.parse_args()
    if args.list:
        for s in SCENARIOS:
            print(f"{s.id:26s} {s.platform:8s} {s.verdict:9s} {s.attack:10s} {s.title}")
        return
    for line in fetch(Path(args.data_dir), force=args.force):
        print(line)
    tasks = load_tasks(Path(args.data_dir))
    print(f"{len(tasks)} practice tasks ready in {args.data_dir}")


if __name__ == "__main__":
    sys.exit(main())
