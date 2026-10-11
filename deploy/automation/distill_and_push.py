#!/usr/bin/env python3
"""
distill_and_push — weekly model refresh orchestrator.

What it does, in order:

  1. Runs `backend/distill_student.py` to produce a fresh INT8 ONNX
     student model from the latest SurrogateIDS weights.
  2. Verifies the output files exist + computes their SHA-256.
  3. Loads the configured fleet of edge agents and fans out a
     `push_model` (= gRPC `ApplyModelUpdate`) to every one in parallel.
  4. After every push completes, calls `gather_stats` so the operator
     can confirm each agent is now reporting `verdicts_*` counters
     against the new model.
  5. Writes a single-line JSON record to a log file at
     `/var/log/robustidps/distill_and_push.jsonl` per run, including
     SHA-256, fleet outcomes, and timing.

Designed to be run from cron (see crontab.example in the same directory)
or manually from a deploy host. Exits non-zero on any agent failure so
cron emails surface the failure.

Usage:
  python3 distill_and_push.py
  python3 distill_and_push.py --agents edge1.prod:50090,edge2.prod:50090
  python3 distill_and_push.py --skip-distill   # push the existing artefact
  python3 distill_and_push.py --dry-run        # don't actually push
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_AGENTS_ENV = "ROBUSTIDPS_FLEET_AGENTS"
DEFAULT_LOG_PATH = Path("/var/log/robustidps/distill_and_push.jsonl")

LOG = logging.getLogger("distill_and_push")


def parse_args() -> argparse.Namespace:
    """Parse CLI flags."""
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument(
        "--agents",
        default=os.environ.get(DEFAULT_AGENTS_ENV, ""),
        help="Comma-separated fleet endpoints. Accepts host:port, name=host:port, "
             f"or empty for ${DEFAULT_AGENTS_ENV}. At least one required unless --dry-run.",
    )
    p.add_argument(
        "--model-dir",
        type=Path,
        default=REPO_ROOT / "agent/agent-inference/weights",
        help="Where distill_student.py writes its output (and where we read SHA-256 from).",
    )
    p.add_argument(
        "--artefact-name",
        default="student_int8.onnx",
        help="Filename of the model artefact emitted by distill_student.py.",
    )
    p.add_argument(
        "--labels-name",
        default="labels.json",
        help="Sibling labels JSON emitted by distill_student.py.",
    )
    p.add_argument(
        "--epochs",
        type=int,
        default=50,
        help="Training epochs handed to distill_student.py.",
    )
    p.add_argument(
        "--n-train",
        type=int,
        default=20000,
        help="Synthetic train samples handed to distill_student.py.",
    )
    p.add_argument(
        "--skip-distill",
        action="store_true",
        help="Skip the distill step and just push the existing artefacts.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip the actual push — useful to validate the pipeline locally.",
    )
    p.add_argument(
        "--log-path",
        type=Path,
        default=DEFAULT_LOG_PATH,
        help="Per-run JSONL log destination.",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="DEBUG-level logging.",
    )
    return p.parse_args()


def setup_logging(verbose: bool) -> None:
    """Stream INFO/DEBUG to stderr with timestamps."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
        stream=sys.stderr,
    )


def run_distill(args: argparse.Namespace) -> None:
    """Invoke backend/distill_student.py as a subprocess."""
    script = REPO_ROOT / "backend/distill_student.py"
    if not script.exists():
        raise FileNotFoundError(f"distill_student.py missing at {script}")

    cmd = [
        sys.executable,
        str(script),
        "--n-train", str(args.n_train),
        "--epochs", str(args.epochs),
        "--output-dir", str(args.model_dir),
    ]
    LOG.info("running: %s", " ".join(cmd))
    t0 = time.monotonic()
    proc = subprocess.run(cmd, cwd=REPO_ROOT, check=False, capture_output=True, text=True)
    elapsed = time.monotonic() - t0
    LOG.info("distill_student.py exit=%d elapsed=%.1fs", proc.returncode, elapsed)
    if proc.stdout.strip():
        for line in proc.stdout.splitlines()[-10:]:
            LOG.info("distill stdout | %s", line)
    if proc.returncode != 0:
        for line in proc.stderr.splitlines()[-20:]:
            LOG.error("distill stderr | %s", line)
        raise RuntimeError(f"distill_student.py failed with exit {proc.returncode}")


def sha256_of(path: Path) -> str:
    """Streamed SHA-256 of a file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_artefacts(args: argparse.Namespace) -> tuple[Path, Path, str, int]:
    """Confirm the model + labels exist and compute the model's SHA-256."""
    model_path = args.model_dir / args.artefact_name
    labels_path = args.model_dir / args.labels_name
    for p in (model_path, labels_path):
        if not p.exists():
            raise FileNotFoundError(f"missing artefact: {p}")
    sha = sha256_of(model_path)
    size = model_path.stat().st_size
    LOG.info("artefact ready: %s (%d bytes, sha256=%s...)", model_path, size, sha[:16])
    return model_path, labels_path, sha, size


def parse_agents(raw: str) -> list[str]:
    """Split the --agents string the same way edge_fleet does."""
    out = [s.strip() for s in raw.split(",") if s.strip()]
    return out


async def push_to_fleet(args: argparse.Namespace, model: Path, labels: Path) -> dict[str, Any]:
    """Drive backend.edge_fleet.EdgeFleet.push_model() and gather stats."""
    # Late import: backend.edge_fleet pulls in grpcio + the generated stubs;
    # we don't want this module unimportable when grpc isn't installed.
    sys.path.insert(0, str(REPO_ROOT))
    try:
        from backend.edge_fleet import EdgeEndpoint, EdgeFleet  # type: ignore[import]
    except ImportError as e:
        raise RuntimeError(
            "couldn't import backend.edge_fleet — run "
            "`backend/edge_proto_gen.sh` first (or `pip install grpcio grpcio-tools`)"
        ) from e

    endpoints = [EdgeEndpoint.parse(s) for s in parse_agents(args.agents)]
    if not endpoints:
        raise ValueError("--agents must list at least one endpoint")

    fleet = EdgeFleet(endpoints)

    LOG.info("pushing model to %d agent(s): %s", len(endpoints), [e.address for e in endpoints])
    push_results = await fleet.push_model(model, labels, artifact_name=args.artefact_name)

    LOG.info("gathering post-push stats ...")
    stats = await fleet.gather_stats()

    return {
        "push_results": [asdict(r) for r in push_results],
        "per_agent_stats": stats.per_agent,
        "errors": stats.errors,
    }


def append_log(args: argparse.Namespace, record: dict[str, Any]) -> None:
    """Append a single JSON line to args.log_path."""
    try:
        args.log_path.parent.mkdir(parents=True, exist_ok=True)
        with args.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
    except PermissionError:
        LOG.warning("could not write to %s — printing to stderr instead", args.log_path)
        sys.stderr.write(json.dumps(record, default=str) + "\n")


def main() -> int:
    """Entry point."""
    args = parse_args()
    setup_logging(args.verbose)

    record: dict[str, Any] = {
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "skip_distill": args.skip_distill,
        "dry_run": args.dry_run,
        "agents": parse_agents(args.agents),
    }
    started_ns = time.monotonic_ns()

    try:
        if not args.skip_distill:
            run_distill(args)
        model, labels, sha, size = verify_artefacts(args)
        record["sha256"] = sha
        record["bytes"] = size
        record["model_path"] = str(model)
        record["labels_path"] = str(labels)

        if args.dry_run:
            LOG.info("dry-run: would push %s to %d agents", model.name, len(record["agents"]))
            record["dry_run_outcome"] = "skipped push"
            record["exit_code"] = 0
        elif not record["agents"]:
            raise ValueError("no --agents supplied and no dry-run flag set")
        else:
            result = asyncio.run(push_to_fleet(args, model, labels))
            record.update(result)
            any_failed = any(
                (not r.get("accepted")) or r.get("error")
                for r in record.get("push_results", [])
            ) or bool(record.get("errors"))
            record["exit_code"] = 1 if any_failed else 0
    except Exception as exc:  # noqa: BLE001
        LOG.exception("orchestrator failed: %s", exc)
        record["error"] = str(exc)
        record["exit_code"] = 2

    record["elapsed_secs"] = round((time.monotonic_ns() - started_ns) / 1e9, 3)
    append_log(args, record)

    # Pretty-print the JSON summary to stdout for cron mailers.
    print(json.dumps(record, indent=2, default=str))
    return int(record.get("exit_code", 0))


if __name__ == "__main__":
    sys.exit(main())
