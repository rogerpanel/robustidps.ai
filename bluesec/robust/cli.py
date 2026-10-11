"""Entry point.

    uv run --with anthropic --with jsonschema --env-file .env \
        python -m bluesec1_agent.robust.cli            # real competition run
    ... python -m bluesec1_agent.robust.cli --mock     # offline check, no run spent
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import sys
from typing import Any

import truststore

from bluesec1_client import (
    CompetitionClosedError,
    RemoteAuthenticationError,
    RemoteBenchmarkClient,
    RemoteRateLimitError,
    RemoteUnavailableError,
    RunCapacityExceededError,
)

from .agent import RobustAgent
from .settings import RobustSettings


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="RobustIDPS investigation agent for BlueSec1")
    p.add_argument("--mock", action="store_true",
                   help="run against the built-in offline mock instead of the competition")
    p.add_argument("--local", nargs="?", const="all", metavar="IDS",
                   help="run the practice tasks built from public datasets (all, or "
                        "comma-separated scenario ids); see localdata/fetch.py --list")
    p.add_argument("--pack", metavar="ZIP",
                   help="run the tasks in a practice pack zip (see localdata/pack.py); "
                        "combine with --local IDS to run a subset")
    p.add_argument("--data-dir", default="datasets",
                   help="where the public datasets were downloaded (default datasets)")
    p.add_argument("--arena", help="override SCENARIO_RUNTIME_ARENA (e.g. practice)")
    p.add_argument("--provider", choices=["anthropic", "openai"], help="override ROBUST_PROVIDER")
    p.add_argument("--model", help="override ANTHROPIC_MODEL / LLM_DEFAULT_MODEL")
    p.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"],
                   help="override ANTHROPIC_EFFORT")
    p.add_argument("--agent-name", help="override AGENT_NAME")
    p.add_argument("--mock-tasks", type=int, default=1, metavar="N",
                   help="with --mock: repeat the mock scenarios N times (2*N tasks)")
    p.add_argument("--mock-limit", type=int, metavar="N",
                   help="with --mock: imitate a runtime that holds at most N tasks at once")
    p.add_argument("--concurrency", type=int,
                   help="tasks investigated in parallel (override ROBUST_CONCURRENCY)")
    p.add_argument("--deadline", type=parse_deadline,
                   help="submission cutoff: HH:MM Moscow time today, or ISO 8601 with timezone")
    return p


MOSCOW = datetime.timezone(datetime.timedelta(hours=3), "MSK")   # no DST since 2014


def parse_deadline(value: str) -> datetime.datetime:
    try:
        if len(value) <= 5 and ":" in value:
            hh, mm = (int(x) for x in value.split(":"))
            today = datetime.datetime.now(MOSCOW).date()
            return datetime.datetime.combine(today, datetime.time(hh, mm), tzinfo=MOSCOW)
        parsed = datetime.datetime.fromisoformat(value)
    except ValueError:
        raise argparse.ArgumentTypeError("use HH:MM (Moscow time) or ISO 8601") from None
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("an ISO deadline needs a timezone, e.g. +03:00")
    return parsed


def make_llm(s: RobustSettings) -> Any:
    if s.provider == "anthropic":
        from anthropic import AsyncAnthropic

        # Parallel tasks share one rate limit: allow more SDK retries on 429/529.
        return AsyncAnthropic(api_key=s.anthropic_api_key.get_secret_value(),
                              timeout=s.llm_timeout_seconds * 5, max_retries=8)
    from openai import AsyncOpenAI

    return AsyncOpenAI(base_url=s.llm_base_url, api_key=s.llm_api_key.get_secret_value(),
                       timeout=s.llm_timeout_seconds, max_retries=6)


async def run(args: argparse.Namespace) -> dict[str, Any]:
    truststore.inject_into_ssl()
    s = RobustSettings()
    overrides: dict[str, Any] = {}
    if args.provider:
        overrides["provider"] = args.provider
    if args.effort:
        overrides["anthropic_effort"] = args.effort
    if args.agent_name:
        overrides["agent_name"] = args.agent_name
    if args.arena:
        overrides["scenario_runtime_arena"] = args.arena
    if args.concurrency:
        overrides["concurrency"] = args.concurrency
    if args.deadline:
        overrides["deadline"] = args.deadline
    if overrides:
        s = s.model_copy(update=overrides)
    if args.model:
        key = "anthropic_model" if s.provider == "anthropic" else "llm_default_model"
        s = s.model_copy(update={key: args.model})

    missing = s.missing(need_runtime=not (args.mock or args.local or args.pack))
    if missing:
        print("Missing configuration in .env: " + ", ".join(missing), file=sys.stderr)
        raise SystemExit(1)

    llm = make_llm(s)
    try:
        if args.pack:
            from pathlib import Path

            from .localdata.pack import load_pack
            from .localdata.runtime import LocalClient

            subset = None if args.local in (None, "all") else args.local.split(",")
            ids = [i.strip() for i in subset] if subset else None
            return await RobustAgent(s, llm).run(LocalClient(load_pack(Path(args.pack), ids)))
        if args.local:
            from pathlib import Path

            from .localdata.fetch import load_tasks
            from .localdata.runtime import LocalClient

            ids = None if args.local == "all" else [i.strip() for i in args.local.split(",")]
            tasks = load_tasks(Path(args.data_dir), ids)
            return await RobustAgent(s, llm).run(LocalClient(tasks))
        if args.mock:
            from .mock import MockClient

            mock = MockClient(repeat=max(1, args.mock_tasks), max_active=args.mock_limit)
            return await RobustAgent(s, llm).run(mock)
        async with RemoteBenchmarkClient(
            endpoint=s.scenario_runtime_endpoint,
            token=s.scenario_runtime_token.get_secret_value(),
            verify_tls=s.scenario_runtime_verify_tls,
            run_label=s.remote_run_label,
            agent_name=s.agent_name,
            model_name=s.model_label(),
            arena=s.scenario_runtime_arena,
            metadata={"agent": s.agent_name, "implementation": "robustidps-hypothesis-agent",
                      "model": s.model_label()},
        ) as client:
            return await RobustAgent(s, llm).run(client)
    finally:
        await llm.close()


def main() -> None:
    args = build_parser().parse_args()
    try:
        summary = asyncio.run(run(args))
    except RunCapacityExceededError as error:
        from bluesec1_agent.cli import _run_capacity_message

        print(_run_capacity_message(error), file=sys.stderr)
        raise SystemExit(1) from error
    except CompetitionClosedError as error:
        print("The selected arena is closed. Check SCENARIO_RUNTIME_ARENA or retry when it "
              "opens.", file=sys.stderr)
        raise SystemExit(1) from error
    except RemoteRateLimitError as error:
        print("Run starts are rate-limited. Wait before starting another run.", file=sys.stderr)
        raise SystemExit(1) from error
    except RemoteAuthenticationError as error:
        print("The runtime rejected your key. Check SCENARIO_RUNTIME_TOKEN.", file=sys.stderr)
        raise SystemExit(1) from error
    except RemoteUnavailableError as error:
        print("Cannot reach the runtime. Check SCENARIO_RUNTIME_ENDPOINT and network access.",
              file=sys.stderr)
        raise SystemExit(1) from error
    print(json.dumps({k: v for k, v in summary.items() if k != "task_results"}, indent=2))


if __name__ == "__main__":
    main()
