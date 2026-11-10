#!/usr/bin/env python3
"""Build study run folders from the agent's console output.

Used when a run's trace folders are not at hand but its console output is:
every per-task line ("Task <id> terminated: quality=... calls=...") and the
printed ablation table are enough for the aggregate and per-task results.
Token counts, cache hits and local refusals are only in the traces.

    python scripts/console_to_runs.py \
        --log results/console/runs2-3-v1.1.log \
        --table results/console/run1-rescored-v1.1.txt:1 \
        --exclude "1:no validation" \
        --pack benchmark/socgraph-21-v1.1.zip --out results/study

--log: console output with "# repeat N" markers, "== ablation suite: <label>"
headers and per-task lines; each repeat must be followed by its printed table.
--table: a printed ablation table only (no per-task lines), with the repeat
number after the colon; those runs get aggregate metrics only.
Verdicts are inferred from quality: a terminated task with quality 0 had the
wrong verdict (the scorer gives 0 only then), otherwise the expected one.
"""

from __future__ import annotations

import argparse
import json
import re
import zipfile
from pathlib import Path
from typing import Any

ABLATION = {"full": [], "no cache": ["cache"], "no validation": ["validation"],
            "no grounding": ["grounding"], "no budget": ["budget"], "no method": ["method"]}
TASK = re.compile(r"Task (\S+) (\w+): quality=([\d.]+) efficiency=([\d.]+) reward=([\d.]+) calls=(\d+)")
ROW = re.compile(r"^\| (full|no [a-z]+) \| (\d+) \| ([\d.]+) \| ([\d.]+) \| ([\d.]+) \| ([\d.]+) \| "
                 r"([\d.]+) \| ([\d.]+) \| ([\d.]+) \| ([\d.]+) \|")


def _mean(xs: list[float]) -> float | None:
    return round(sum(xs) / len(xs), 4) if xs else None


def group(rows: list[dict[str, Any]]) -> dict[str, Any]:
    judged = [r for r in rows if r.get("expected_verdict") in ("malicious", "benign")]
    ben = [r for r in judged if r["expected_verdict"] == "benign"]
    mal = [r for r in judged if r["expected_verdict"] == "malicious"]
    return {
        "tasks": len(rows),
        "completed": sum(r["completion"] in ("terminated", "truncated") for r in rows),
        "mean_quality": _mean([r["quality"] for r in rows]),
        "mean_efficiency": _mean([r["efficiency"] for r in rows]),
        "mean_reward": _mean([r["reward"] for r in rows]),
        "mean_tool_calls": _mean([r["calls"] for r in rows]),
        "verdict_accuracy": _mean([float(r.get("verdict") == r["expected_verdict"]) for r in judged]),
        "false_positive_rate": _mean([float(r.get("verdict") == "malicious") for r in ben]),
        "false_negative_rate": _mean([float(r.get("verdict") == "benign") for r in mal]),
    }


def table_row(m: re.Match) -> dict[str, Any]:
    keys = ["mean_quality", "mean_efficiency", "mean_reward", "verdict_accuracy",
            "false_positive_rate", "false_negative_rate", "mean_tool_calls", "mean_wall_seconds"]
    out = {"tasks": int(m.group(2))}
    out.update({k: float(m.group(i + 3)) for i, k in enumerate(keys)})
    return out


def write_run(out: Path, rep: int, label: str, rows: list[dict[str, Any]],
              printed: dict[str, Any], source: str) -> None:
    folder = out / f"r{rep}-{label.replace(' ', '-')}"
    folder.mkdir(parents=True, exist_ok=True)
    metrics: dict[str, Any] = {"overall": printed}
    if rows:
        metrics["overall"] = {**group(rows), "mean_wall_seconds": printed.get("mean_wall_seconds")}
        for key in ("platform", "expected_verdict"):
            vals = sorted({r[key] for r in rows})
            metrics[f"by_{key}"] = {v: group([r for r in rows if r[key] == v]) for v in vals}
    summary = {
        "run_id": f"repeat-{rep}",
        "repeat": rep,
        "source": source,
        "pack_version": "1.1",
        "config": {"label": label, "ablations": ABLATION[label], "model": "claude-opus-5-5",
                   "effort": "high", "concurrency": 4, "soft_budget": 12, "max_tool_calls": 30},
        "metrics": metrics,
        "task_rows": rows,
    }
    (folder / "summary.json").write_text(json.dumps(summary, indent=2))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--log", type=Path, action="append", default=[])
    ap.add_argument("--table", action="append", default=[], help="PATH:REPEAT")
    ap.add_argument("--exclude", action="append", default=[], help="REPEAT:LABEL")
    ap.add_argument("--pack", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    with zipfile.ZipFile(args.pack) as zf:
        meta = {t["id"]: t for t in json.loads(zf.read("manifest.json"))["tasks"]}
    excluded = {(int(e.split(":", 1)[0]), e.split(":", 1)[1]) for e in args.exclude}
    written = 0

    for path in args.log:
        rep, label = 0, ""
        rows: dict[tuple[int, str], list[dict[str, Any]]] = {}
        printed: dict[tuple[int, str], dict[str, Any]] = {}
        for line in path.read_text().splitlines():
            if line.startswith("# repeat"):
                rep = int(line.split()[-1])
            elif m := re.match(r"== ablation suite: (.+)", line):
                label = m.group(1).strip()
            elif m := TASK.search(line):
                tid, completion = m.group(1), m.group(2)
                q, e, r, n = float(m.group(3)), float(m.group(4)), float(m.group(5)), int(m.group(6))
                exp = meta[tid]["verdict"]
                verdict = None
                if completion == "terminated":
                    verdict = exp if q > 0 else ("benign" if exp == "malicious" else "malicious")
                rows.setdefault((rep, label), []).append({
                    "task_id": tid, "platform": meta[tid]["platform"], "expected_verdict": exp,
                    "verdict": verdict, "completion": completion, "quality": q,
                    "efficiency": e, "reward": r, "calls": n})
            elif m := ROW.match(line):
                printed[(rep, m.group(1))] = table_row(m)
        for key, rs in rows.items():
            if key in excluded:
                continue
            if len(rs) != len(meta) or key not in printed:
                raise SystemExit(f"{path}: repeat {key[0]} {key[1]}: incomplete")
            p = printed[key]
            check = group(rs)
            for k in ("mean_quality", "mean_efficiency", "mean_reward"):
                if abs(check[k] - p[k]) > 0.0015:
                    raise SystemExit(f"{path}: {key}: {k} {check[k]} != printed {p[k]}")
            write_run(args.out, key[0], key[1], rs, p, f"console output ({path.name})")
            written += 1

    for spec in args.table:
        path, rep_s = spec.rsplit(":", 1)
        rep = int(rep_s)
        for line in Path(path).read_text().splitlines():
            if (m := ROW.match(line)) and (rep, m.group(1)) not in excluded:
                write_run(args.out, rep, m.group(1), [], table_row(m),
                          f"printed table only ({Path(path).name}); per-task rows in the traces")
                written += 1
    print(f"wrote {written} run folders under {args.out}")


if __name__ == "__main__":
    main()
