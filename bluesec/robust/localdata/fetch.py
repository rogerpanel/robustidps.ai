"""Download the public datasets the practice scenarios use, and load tasks.

    python -m bluesec1_agent.robust.localdata.fetch            # into ./datasets/otrf

Files come from OTRF Security-Datasets on GitHub (MIT licence). Each zip is
saved, then only its .json members are extracted, by base name, into a folder
of their own; nothing in them is executed.
"""

from __future__ import annotations

import argparse
import io
import sys
import urllib.request
import zipfile
from pathlib import Path

from .graph import build_graph, load_events
from .scenarios import OTRF_BASE, SCENARIOS, ScenarioError, Task, build_task

MAX_ZIP_BYTES = 60 * 1024 * 1024
MAX_JSON_BYTES = 200 * 1024 * 1024


def dataset_dir(data_dir: Path, dataset: str) -> Path:
    return data_dir / dataset.split("/")[-1]


def fetch(data_dir: Path, *, force: bool = False) -> list[str]:
    done = []
    for dataset in sorted({s.dataset for s in SCENARIOS}):
        target = dataset_dir(data_dir, dataset)
        if target.is_dir() and any(target.glob("*.json")) and not force:
            done.append(f"have  {dataset}")
            continue
        url = OTRF_BASE + dataset + ".zip"
        with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 - fixed https host
            blob = resp.read(MAX_ZIP_BYTES + 1)
        if len(blob) > MAX_ZIP_BYTES:
            raise RuntimeError(f"{url} is larger than expected")
        target.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for info in zf.infolist():
                name = Path(info.filename).name
                if not name.lower().endswith(".json") or info.file_size > MAX_JSON_BYTES:
                    continue
                (target / name).write_bytes(zf.read(info))
        done.append(f"fetch {dataset}")
    return done


def load_tasks(data_dir: Path, ids: list[str] | None = None) -> list[Task]:
    graphs: dict[str, object] = {}
    tasks = []
    for sc in SCENARIOS:
        if ids and sc.id not in ids:
            continue
        files = sorted(dataset_dir(data_dir, sc.dataset).glob("*.json"))
        if not files:
            raise FileNotFoundError(
                f"{sc.dataset} is not downloaded; run: python -m "
                "bluesec1_agent.robust.localdata.fetch"
            )
        if sc.dataset not in graphs:
            events = []
            for f in files:
                events.extend(load_events(str(f)))
            graphs[sc.dataset] = build_graph(events)
        tasks.append(build_task(sc, graphs[sc.dataset]))
    if ids:
        unknown = set(ids) - {t.scenario.id for t in tasks}
        if unknown:
            raise ScenarioError(f"unknown scenario ids: {sorted(unknown)}")
    return tasks


def main() -> None:
    ap = argparse.ArgumentParser(description="Download the practice datasets")
    ap.add_argument("--data-dir", default="datasets/otrf")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--list", action="store_true", help="list the scenarios")
    args = ap.parse_args()
    if args.list:
        for s in SCENARIOS:
            print(f"{s.id:26s} {s.verdict:9s} {s.attack:10s} {s.otrf_id:20s} {s.title}")
        return
    for line in fetch(Path(args.data_dir), force=args.force):
        print(line)
    tasks = load_tasks(Path(args.data_dir))
    print(f"{len(tasks)} practice tasks ready in {args.data_dir}")


if __name__ == "__main__":
    sys.exit(main())
