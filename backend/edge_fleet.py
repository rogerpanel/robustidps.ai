"""edge_fleet — control-plane gRPC client for a fleet of RobustIDPS edge agents.

This module is the Python counterpart of the Rust ``agent-edge`` gRPC server.
It speaks the ``robustidps.edge.v1.EdgeAgent`` service over ``grpc.aio`` to
one or more remote agents in parallel, and exposes a small CLI for operators
who want to push a new ONNX model, refresh an on-disk artefact, send a fresh
block list, or scrape stats from the whole fleet at once.

The intentional design choices:

* No per-agent state — channels are opened per call. gRPC's aio channels
  are cheap, reconnect transparently, and removing pooling makes failure
  recovery trivial.
* Concurrent fan-out with ``asyncio.gather(return_exceptions=True)``. One
  agent going dark must not poison the rest of the rollout.
* Chunked model uploads. Each chunk stays under ~3 MiB so we never bump
  into gRPC's default 4 MiB message ceiling.

Quick CLI example::

    python -m backend.edge_fleet \\
        --agents edge1=10.0.0.5:50090,edge2=10.0.0.6:50090 \\
        push-model agent/agent-inference/weights/student_int8.onnx \\
                   agent/agent-inference/weights/labels.json

The CLI always prints a JSON summary to stdout and exits non-zero if any
agent rejects the update or raises a transport error.
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
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import AsyncIterator, Iterable

LOGGER = logging.getLogger("edge_fleet")

# ---------------------------------------------------------------------------
# Generated gRPC stub import — with auto-regen fallback.
# ---------------------------------------------------------------------------

_PROTO_GEN_SCRIPT = Path(__file__).resolve().parent / "edge_proto_gen.sh"


def _try_regen_stubs() -> bool:
    """Attempt to (re)generate the proto stubs by invoking edge_proto_gen.sh.

    Returns True on success, False otherwise. Never raises.
    """
    if not _PROTO_GEN_SCRIPT.is_file():
        LOGGER.warning(
            "cannot auto-regen proto stubs: %s does not exist", _PROTO_GEN_SCRIPT
        )
        return False
    try:
        LOGGER.info("attempting to regenerate proto stubs via %s", _PROTO_GEN_SCRIPT)
        subprocess.run(
            ["bash", str(_PROTO_GEN_SCRIPT)],
            check=True,
            capture_output=True,
            text=True,
        )
        return True
    except subprocess.CalledProcessError as exc:
        LOGGER.error(
            "edge_proto_gen.sh failed (rc=%s):\nstdout: %s\nstderr: %s",
            exc.returncode,
            exc.stdout,
            exc.stderr,
        )
        return False
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("edge_proto_gen.sh invocation failed: %s", exc)
        return False


try:
    from .proto import edge_pb2, edge_pb2_grpc  # type: ignore  # noqa: F401
except ImportError:
    try:
        from backend.proto import edge_pb2, edge_pb2_grpc  # type: ignore  # noqa: F401
    except ImportError:
        # Stubs missing — try to build them once, then re-import.
        sys.stderr.write(
            "edge_fleet: gRPC stubs not found — attempting to generate them.\n"
            f"If this fails, run: bash {_PROTO_GEN_SCRIPT}\n"
        )
        if _try_regen_stubs():
            try:
                from .proto import edge_pb2, edge_pb2_grpc  # type: ignore  # noqa: F401
            except ImportError:
                from backend.proto import edge_pb2, edge_pb2_grpc  # type: ignore  # noqa: F401
        else:
            raise ImportError(
                "edge_fleet: could not import or generate proto stubs. "
                f"Run `bash {_PROTO_GEN_SCRIPT}` after `pip install grpcio-tools`."
            )

import grpc  # noqa: E402  (after the conditional import block)


__all__ = ["EdgeFleet", "EdgeEndpoint", "FleetPushResult", "FleetStats"]


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


DEFAULT_PORT = 50090


@dataclass(frozen=True)
class EdgeEndpoint:
    """Where an edge agent's gRPC server lives."""

    name: str
    address: str

    @classmethod
    def parse(cls, s: str) -> "EdgeEndpoint":
        """Parse a string in one of these forms::

            host:port
            host                 (port defaults to 50090)
            name=host:port
            name=host            (port defaults to 50090)
        """
        s = s.strip()
        if not s:
            raise ValueError("empty endpoint string")

        if "=" in s:
            name, _, hostport = s.partition("=")
            name = name.strip()
            hostport = hostport.strip()
            if not name or not hostport:
                raise ValueError(f"invalid endpoint: {s!r}")
        else:
            hostport = s
            # Name defaults to the host portion (everything before the colon).
            name = hostport.split(":", 1)[0]

        if ":" not in hostport:
            address = f"{hostport}:{DEFAULT_PORT}"
        else:
            host, _, port = hostport.partition(":")
            if not host or not port.isdigit():
                raise ValueError(f"invalid host:port in {s!r}")
            address = f"{host}:{port}"

        return cls(name=name, address=address)


@dataclass
class FleetPushResult:
    """One agent's outcome from a fleet operation."""

    endpoint: EdgeEndpoint
    accepted: bool
    message: str
    received_bytes: int = 0
    applied_artifact_path: str = ""
    reload_succeeded: bool = False
    computed_sha256: str = ""
    error: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        # Flatten the nested endpoint for cleaner JSON output.
        d["endpoint"] = {"name": self.endpoint.name, "address": self.endpoint.address}
        return d


@dataclass
class FleetStats:
    """Aggregated stats from a fleet of agents."""

    per_agent: dict[str, dict] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"per_agent": self.per_agent, "errors": self.errors}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_RETRYABLE_STATUSES = {
    grpc.StatusCode.UNAVAILABLE,
    grpc.StatusCode.DEADLINE_EXCEEDED,
}


def _sha256_file(path: Path, *, block_size: int = 64 * 1024) -> tuple[str, int]:
    """Return (hex_digest, total_bytes) for the given file."""
    h = hashlib.sha256()
    total = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(block_size)
            if not chunk:
                break
            h.update(chunk)
            total += len(chunk)
    return h.hexdigest(), total


def _agent_stats_to_dict(stats) -> dict:
    """Convert an edge_pb2.AgentStats message into a plain dict."""
    return {
        "agent_id": stats.agent_id,
        "hostname": stats.hostname,
        "interface": stats.interface,
        "mode": stats.mode,
        "packets_seen": stats.packets_seen,
        "packets_decoded": stats.packets_decoded,
        "packets_skipped": stats.packets_skipped,
        "flows_open": stats.flows_open,
        "flows_emitted": stats.flows_emitted,
        "verdicts_benign": stats.verdicts_benign,
        "verdicts_low": stats.verdicts_low,
        "verdicts_medium": stats.verdicts_medium,
        "verdicts_high": stats.verdicts_high,
        "verdicts_critical": stats.verdicts_critical,
        "uptime_seconds": stats.uptime_seconds,
        "active_block_count": stats.active_block_count,
    }


def _verdict_to_dict(v) -> dict:
    return {
        "predicted_label": v.predicted_label,
        "confidence": v.confidence,
        "severity": v.severity,
        "source_blocked": v.source_blocked,
        "reason": v.reason,
    }


# ---------------------------------------------------------------------------
# Fleet
# ---------------------------------------------------------------------------


class EdgeFleet:
    """Async client that talks to multiple RobustIDPS edge agents in parallel."""

    # Conservative defaults: 3 MiB stays under gRPC's 4 MiB message ceiling.
    def __init__(
        self,
        endpoints: Iterable[EdgeEndpoint],
        *,
        chunk_size: int = 3 * 1024 * 1024,
        request_timeout_secs: float = 30.0,
        max_retries: int = 2,
    ) -> None:
        self.endpoints: list[EdgeEndpoint] = list(endpoints)
        if not self.endpoints:
            raise ValueError("EdgeFleet requires at least one endpoint")
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        self.chunk_size = chunk_size
        self.request_timeout_secs = request_timeout_secs
        self.max_retries = max_retries

    # ------------------------------------------------------------------
    # Public RPC methods
    # ------------------------------------------------------------------

    async def push_blocks(self, blocks: list[str]) -> list[FleetPushResult]:
        """Send the same block-IP list to every agent via UpdateConfig."""
        coros = [self._push_blocks_one(ep, blocks) for ep in self.endpoints]
        return await self._gather(coros)

    async def push_model(
        self,
        model_path: Path,
        labels_path: Path | None = None,
        *,
        artifact_name: str = "student_int8.onnx",
        subpath: str = "",
    ) -> list[FleetPushResult]:
        """Stream a model artefact to every agent via ApplyModelUpdate."""
        model_path = Path(model_path)
        if not model_path.is_file():
            raise FileNotFoundError(f"model not found: {model_path}")

        labels_json = ""
        if labels_path is not None:
            labels_path = Path(labels_path)
            if not labels_path.is_file():
                raise FileNotFoundError(f"labels file not found: {labels_path}")
            labels_json = labels_path.read_text(encoding="utf-8")

        digest, total_bytes = _sha256_file(model_path)
        LOGGER.info(
            "computed sha256=%s total_bytes=%d for %s",
            digest,
            total_bytes,
            model_path,
        )

        coros = [
            self._push_model_one(
                ep,
                model_path=model_path,
                total_bytes=total_bytes,
                digest=digest,
                labels_json=labels_json,
                artifact_name=artifact_name,
                subpath=subpath,
            )
            for ep in self.endpoints
        ]
        return await self._gather(coros)

    async def refresh_model(
        self,
        model_path: Path,
        labels_path: Path,
    ) -> list[FleetPushResult]:
        """Trigger a from-disk reload on every agent via RefreshModel."""
        coros = [
            self._refresh_model_one(ep, str(model_path), str(labels_path))
            for ep in self.endpoints
        ]
        return await self._gather(coros)

    async def gather_stats(self) -> FleetStats:
        """Pull stats snapshots from every agent in parallel."""
        coros = [self._get_stats_one(ep) for ep in self.endpoints]
        raw = await asyncio.gather(*coros, return_exceptions=True)

        out = FleetStats()
        for ep, item in zip(self.endpoints, raw):
            if isinstance(item, Exception):
                out.errors[ep.name] = f"{type(item).__name__}: {item}"
            elif isinstance(item, tuple) and item[0] == "error":
                out.errors[ep.name] = item[1]
            else:
                out.per_agent[ep.name] = item
        return out

    async def classify_flow(
        self,
        endpoint_name: str,
        flow: dict,
    ) -> dict:
        """Forward a one-off flow record to a specific agent's ClassifyFlow RPC."""
        ep = next((e for e in self.endpoints if e.name == endpoint_name), None)
        if ep is None:
            raise KeyError(f"no endpoint named {endpoint_name!r}")

        record = self._flow_dict_to_proto(flow)

        async def _call() -> dict:
            async with grpc.aio.insecure_channel(ep.address) as channel:
                stub = edge_pb2_grpc.EdgeAgentStub(channel)
                verdict = await stub.ClassifyFlow(
                    record, timeout=self.request_timeout_secs
                )
                return _verdict_to_dict(verdict)

        return await self._with_retries(_call, ep)

    # ------------------------------------------------------------------
    # Per-endpoint workers
    # ------------------------------------------------------------------

    async def _push_blocks_one(
        self, ep: EdgeEndpoint, blocks: list[str]
    ) -> FleetPushResult:
        update = edge_pb2.ConfigUpdate(
            block_ips=blocks,
            bpf_filter="",
            min_severity="",
        )

        async def _call() -> FleetPushResult:
            async with grpc.aio.insecure_channel(ep.address) as channel:
                stub = edge_pb2_grpc.EdgeAgentStub(channel)
                ack = await stub.UpdateConfig(
                    update, timeout=self.request_timeout_secs
                )
                return FleetPushResult(
                    endpoint=ep,
                    accepted=ack.accepted,
                    message=ack.message,
                )

        try:
            return await self._with_retries(_call, ep)
        except Exception as exc:  # noqa: BLE001
            return FleetPushResult(
                endpoint=ep,
                accepted=False,
                message="",
                error=f"{type(exc).__name__}: {exc}",
            )

    async def _push_model_one(
        self,
        ep: EdgeEndpoint,
        *,
        model_path: Path,
        total_bytes: int,
        digest: str,
        labels_json: str,
        artifact_name: str,
        subpath: str,
    ) -> FleetPushResult:
        async def _call() -> FleetPushResult:
            async with grpc.aio.insecure_channel(ep.address) as channel:
                stub = edge_pb2_grpc.EdgeAgentStub(channel)
                gen = self._proto_chunks_generator(
                    model_path=model_path,
                    total_bytes=total_bytes,
                    digest=digest,
                    labels_json=labels_json,
                    artifact_name=artifact_name,
                    subpath=subpath,
                )
                # Explicit deadline on the entire streaming call.
                ack = await stub.ApplyModelUpdate(
                    gen, timeout=self.request_timeout_secs
                )
                return FleetPushResult(
                    endpoint=ep,
                    accepted=ack.accepted,
                    message=ack.message,
                    received_bytes=ack.received_bytes,
                    applied_artifact_path=ack.applied_artifact_path,
                    reload_succeeded=ack.reload_succeeded,
                    computed_sha256=ack.computed_sha256,
                )

        try:
            return await self._with_retries(_call, ep)
        except Exception as exc:  # noqa: BLE001
            return FleetPushResult(
                endpoint=ep,
                accepted=False,
                message="",
                error=f"{type(exc).__name__}: {exc}",
            )

    async def _refresh_model_one(
        self, ep: EdgeEndpoint, model_path: str, labels_path: str
    ) -> FleetPushResult:
        req = edge_pb2.RefreshModelRequest(
            model_path=model_path,
            labels_path=labels_path,
        )

        async def _call() -> FleetPushResult:
            async with grpc.aio.insecure_channel(ep.address) as channel:
                stub = edge_pb2_grpc.EdgeAgentStub(channel)
                ack = await stub.RefreshModel(req, timeout=self.request_timeout_secs)
                return FleetPushResult(
                    endpoint=ep,
                    accepted=ack.accepted,
                    message=ack.message,
                    received_bytes=ack.received_bytes,
                    applied_artifact_path=ack.applied_artifact_path,
                    reload_succeeded=ack.reload_succeeded,
                    computed_sha256=ack.computed_sha256,
                )

        try:
            return await self._with_retries(_call, ep)
        except Exception as exc:  # noqa: BLE001
            return FleetPushResult(
                endpoint=ep,
                accepted=False,
                message="",
                error=f"{type(exc).__name__}: {exc}",
            )

    async def _get_stats_one(self, ep: EdgeEndpoint):
        async def _call():
            async with grpc.aio.insecure_channel(ep.address) as channel:
                stub = edge_pb2_grpc.EdgeAgentStub(channel)
                stats = await stub.GetStats(
                    edge_pb2.StatsRequest(), timeout=self.request_timeout_secs
                )
                return _agent_stats_to_dict(stats)

        try:
            return await self._with_retries(_call, ep)
        except Exception as exc:  # noqa: BLE001
            return ("error", f"{type(exc).__name__}: {exc}")

    # ------------------------------------------------------------------
    # Streaming generator for ApplyModelUpdate
    # ------------------------------------------------------------------

    async def _proto_chunks_generator(
        self,
        *,
        model_path: Path,
        total_bytes: int,
        digest: str,
        labels_json: str,
        artifact_name: str,
        subpath: str,
    ) -> AsyncIterator:
        """Yield a header chunk followed by binary payload chunks.

        Final chunk handling — covers the exact-multiple edge case:
        * If the file size is NOT an exact multiple of chunk_size, the
          tail chunk is shorter than ``chunk_size`` and is sent with
          ``finalize=True``.
        * If the file size IS an exact multiple of chunk_size, the last
          *full-sized* chunk is sent with ``finalize=True`` (saves a
          round-trip vs. sending a trailing empty chunk).
        * If the file is empty (total_bytes == 0), no payload chunks are
          read; we still send a trailing empty ``finalize=True`` chunk so
          the agent always sees an explicit end-of-stream marker.
        """
        header_msg = edge_pb2.ModelChunk(
            header=edge_pb2.ModelHeader(
                artifact_name=artifact_name,
                total_bytes=total_bytes,
                sha256=digest,
                labels_json=labels_json,
                subpath=subpath,
            ),
            bytes=b"",
            finalize=False,
        )
        LOGGER.debug(
            "yielding header artifact=%s total=%d subpath=%r labels_bytes=%d",
            artifact_name,
            total_bytes,
            subpath,
            len(labels_json),
        )
        yield header_msg

        sent = 0
        # Use asyncio.to_thread for the blocking reads so we don't hold the
        # event loop during disk IO.
        with model_path.open("rb") as f:
            while True:
                chunk = await asyncio.to_thread(f.read, self.chunk_size)
                if not chunk:
                    break
                sent += len(chunk)
                is_short = len(chunk) < self.chunk_size
                # If this is a short (partial) chunk it's necessarily the
                # last one; mark it finalize. If it's a full chunk AND we've
                # now read every byte, also finalize.
                finalize = is_short or sent >= total_bytes
                # Only finalize here when there will be no more bytes left.
                if finalize and sent < total_bytes:
                    finalize = False
                yield edge_pb2.ModelChunk(bytes=chunk, finalize=finalize)
                if finalize:
                    LOGGER.debug(
                        "yielded final payload chunk sent=%d total=%d",
                        sent,
                        total_bytes,
                    )
                    return

        # We get here only when total_bytes was 0 OR we never finalized
        # inside the loop (e.g. the file size was an exact multiple of
        # chunk_size and the short-circuit above was inconclusive). Send a
        # trailing empty finalize=True chunk to close the stream cleanly.
        LOGGER.debug(
            "yielding trailing empty finalize=True chunk (sent=%d total=%d)",
            sent,
            total_bytes,
        )
        yield edge_pb2.ModelChunk(bytes=b"", finalize=True)

    # ------------------------------------------------------------------
    # Retry + fan-out helpers
    # ------------------------------------------------------------------

    async def _with_retries(self, fn, ep: EdgeEndpoint):
        """Run ``fn()`` with exponential-backoff retry on transient gRPC errors."""
        delays = [0.25, 0.5, 1.0]
        attempts = self.max_retries + 1
        last_exc: Exception | None = None
        for attempt in range(attempts):
            try:
                return await fn()
            except grpc.RpcError as exc:
                code = exc.code() if hasattr(exc, "code") else None
                if code not in _RETRYABLE_STATUSES or attempt == attempts - 1:
                    LOGGER.warning(
                        "agent %s (%s) RPC failed: code=%s detail=%s",
                        ep.name,
                        ep.address,
                        code,
                        exc.details() if hasattr(exc, "details") else exc,
                    )
                    raise
                delay = delays[min(attempt, len(delays) - 1)]
                LOGGER.info(
                    "agent %s (%s) transient %s, retrying in %.2fs (attempt %d/%d)",
                    ep.name,
                    ep.address,
                    code,
                    delay,
                    attempt + 1,
                    attempts,
                )
                await asyncio.sleep(delay)
                last_exc = exc
        # Unreachable, but keeps type-checkers happy.
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("retry loop exited unexpectedly")

    async def _gather(self, coros) -> list[FleetPushResult]:
        """Run coroutines concurrently; convert exceptions into FleetPushResult."""
        results = await asyncio.gather(*coros, return_exceptions=True)
        out: list[FleetPushResult] = []
        for ep, item in zip(self.endpoints, results):
            if isinstance(item, FleetPushResult):
                out.append(item)
            elif isinstance(item, Exception):
                out.append(
                    FleetPushResult(
                        endpoint=ep,
                        accepted=False,
                        message="",
                        error=f"{type(item).__name__}: {item}",
                    )
                )
            else:
                # Should not happen — workers always return FleetPushResult.
                out.append(
                    FleetPushResult(
                        endpoint=ep,
                        accepted=False,
                        message="",
                        error=f"unexpected worker return type: {type(item).__name__}",
                    )
                )
        return out

    # ------------------------------------------------------------------
    # Helpers for ClassifyFlow
    # ------------------------------------------------------------------

    @staticmethod
    def _flow_dict_to_proto(flow: dict):
        """Best-effort dict -> FlowRecord conversion."""
        return edge_pb2.FlowRecord(
            src_ip=str(flow.get("src_ip", "")),
            dst_ip=str(flow.get("dst_ip", "")),
            src_port=int(flow.get("src_port", 0)),
            dst_port=int(flow.get("dst_port", 0)),
            protocol=int(flow.get("protocol", 0)),
            first_ts_us=int(flow.get("first_ts_us", 0)),
            last_ts_us=int(flow.get("last_ts_us", 0)),
            fwd_packets=int(flow.get("fwd_packets", 0)),
            bwd_packets=int(flow.get("bwd_packets", 0)),
            fwd_bytes=int(flow.get("fwd_bytes", 0)),
            bwd_bytes=int(flow.get("bwd_bytes", 0)),
            features=[float(x) for x in flow.get("features", [])],
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_agents(s: str) -> list[EdgeEndpoint]:
    parts = [p for p in (x.strip() for x in s.split(",")) if p]
    if not parts:
        raise argparse.ArgumentTypeError("--agents requires at least one endpoint")
    return [EdgeEndpoint.parse(p) for p in parts]


def _parse_blocks(s: str) -> list[str]:
    return [p for p in (x.strip() for x in s.split(",")) if p]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="edge_fleet",
        description=(
            "Control-plane gRPC client for a fleet of RobustIDPS edge agents."
        ),
    )
    parser.add_argument(
        "--agents",
        required=True,
        type=_parse_agents,
        help=(
            "comma-separated list of agent endpoints "
            "(host:port or name=host:port; default port 50090)"
        ),
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=3 * 1024 * 1024,
        help="model upload chunk size in bytes (default 3 MiB)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="per-request gRPC deadline in seconds (default 30s)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="max retries on UNAVAILABLE / DEADLINE_EXCEEDED (default 2)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")

    subs = parser.add_subparsers(dest="cmd", required=True)

    p_push_model = subs.add_parser(
        "push-model", help="stream an ONNX model to every agent"
    )
    p_push_model.add_argument("model", type=Path)
    p_push_model.add_argument("labels", type=Path, nargs="?", default=None)
    p_push_model.add_argument(
        "--artifact-name",
        default="student_int8.onnx",
        help="logical filename the agent should persist as (default student_int8.onnx)",
    )
    p_push_model.add_argument(
        "--subpath",
        default="",
        help="subdirectory under the agent's model dir (default root)",
    )

    p_push_blocks = subs.add_parser(
        "push-blocks", help="send a block-IP list to every agent"
    )
    p_push_blocks.add_argument(
        "blocks",
        type=_parse_blocks,
        help="comma-separated IPs / CIDRs (empty string clears the list)",
    )

    p_refresh = subs.add_parser(
        "refresh-model", help="ask every agent to reload a model already on disk"
    )
    p_refresh.add_argument("model_path", type=Path)
    p_refresh.add_argument("labels_path", type=Path)

    subs.add_parser("gather-stats", help="pull stats from every agent")

    return parser


def _results_to_summary(cmd: str, results: list[FleetPushResult]) -> dict:
    return {
        "command": cmd,
        "agent_count": len(results),
        "results": [r.to_dict() for r in results],
        "all_accepted": all(r.accepted and r.error is None for r in results),
    }


def _exit_code_for_results(results: list[FleetPushResult]) -> int:
    for r in results:
        if r.error is not None or not r.accepted:
            return 1
    return 0


async def _run_cli(args: argparse.Namespace) -> int:
    fleet = EdgeFleet(
        args.agents,
        chunk_size=args.chunk_size,
        request_timeout_secs=args.timeout,
        max_retries=args.retries,
    )

    if args.cmd == "push-model":
        results = await fleet.push_model(
            args.model,
            args.labels,
            artifact_name=args.artifact_name,
            subpath=args.subpath,
        )
        sys.stdout.write(json.dumps(_results_to_summary("push-model", results), indent=2))
        sys.stdout.write("\n")
        return _exit_code_for_results(results)

    if args.cmd == "push-blocks":
        results = await fleet.push_blocks(args.blocks)
        sys.stdout.write(json.dumps(_results_to_summary("push-blocks", results), indent=2))
        sys.stdout.write("\n")
        return _exit_code_for_results(results)

    if args.cmd == "refresh-model":
        results = await fleet.refresh_model(args.model_path, args.labels_path)
        sys.stdout.write(
            json.dumps(_results_to_summary("refresh-model", results), indent=2)
        )
        sys.stdout.write("\n")
        return _exit_code_for_results(results)

    if args.cmd == "gather-stats":
        stats = await fleet.gather_stats()
        summary = {
            "command": "gather-stats",
            "agent_count": len(fleet.endpoints),
            "stats": stats.to_dict(),
            "all_ok": not stats.errors,
        }
        sys.stdout.write(json.dumps(summary, indent=2))
        sys.stdout.write("\n")
        return 0 if not stats.errors else 1

    raise RuntimeError(f"unhandled subcommand: {args.cmd}")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        return asyncio.run(_run_cli(args))
    except KeyboardInterrupt:
        LOGGER.warning("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
