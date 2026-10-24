"""Agent run service for the RobustIDPS web app (BlueSec Runs, "Run agent").

Starts the same command-line agent used for the SOCGraph experiments,

    python -m bluesec1_agent.robust.cli --pack <pack> [--ablate X | --ablation-suite] ...

in a subprocess, one run at a time, and reports progress parsed from its log.
Trace folders are written under RUNNER_WORK_DIR/traces, which the backend
mounts read-only and imports into BlueSec Runs when a run finishes.

API keys are passed only to the subprocess environment: they are never
written to disk, logged or returned, and every log line is scrubbed of them.
This is an internal service with no published port; the backend calls it
with a shared token (RUNNER_TOKEN) when one is configured.
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import datetime
import hmac
import json
import os
import re
import signal
import sys
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, SecretStr, model_validator

PACKS_DIR = Path(os.getenv("RUNNER_PACKS_DIR", "/packs"))
WORK_DIR = Path(os.getenv("RUNNER_WORK_DIR", "/runs"))
TOKEN = os.getenv("RUNNER_TOKEN", "")
PACKS = {
    "v1.1": "socgraph-21-v1.1.zip",
    "blind": "socgraph-21-v1.1-blind.zip",
    "mimicry": "socgraph-21-v1.1-mimicry.zip",
}
ABLATIONS = ("cache", "validation", "grounding", "budget", "method")
AGENT_CMD = [sys.executable, "-m", "bluesec1_agent.robust.cli"]
# Variables passed through to the agent process; everything else is dropped.
PASS_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR",
            "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY")
MAX_JOBS_KEPT = 30
LOG_LINES = 400

TASK_LINE = re.compile(r"Task (\S+) (terminated|aborted|truncated)\b.*\[(\d+) done\]")
FOLDER_LINE = re.compile(r"Traces written to (?:.*/)?([A-Za-z0-9_.-]+)\s*$")
SUITE_LINE = re.compile(r"^== ablation suite: (.+?)\s*$")
ERROR_LINE = re.compile(r"\|\s*ERROR\s*\|.*? - (.*)$")
TASK_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
LABEL_SAFE = re.compile(r"[^A-Za-z0-9 ,._+()-]")

app = FastAPI(title="RobustIDPS agent runner", docs_url=None, redoc_url=None)


def require_token(x_runner_token: str = Header("")) -> None:
    if TOKEN and not hmac.compare_digest(x_runner_token.encode(), TOKEN.encode()):
        raise HTTPException(401, "bad runner token")


class RunRequest(BaseModel):
    pack: Literal["v1.1", "blind", "mimicry"] = "v1.1"
    suite: bool = False
    ablate: list[Literal["cache", "validation", "grounding", "budget", "method"]] = Field(
        default_factory=list, max_length=5)
    provider: Literal["anthropic", "openai"] = "anthropic"
    model: str = Field("", max_length=120)
    effort: Literal["low", "medium", "high", "xhigh", "max"] = "high"
    base_url: str = Field("", max_length=300)
    api_key: SecretStr = Field(..., min_length=1, max_length=500)
    label: str = Field("", max_length=120)
    concurrency: int = Field(4, ge=1, le=4)
    tasks: list[str] = Field(default_factory=list, max_length=21)

    @model_validator(mode="after")
    def check(self) -> RunRequest:
        if self.suite and self.ablate:
            raise ValueError("choose either the ablation suite or components to turn off")
        if self.provider == "openai":
            if not re.match(r"^https?://[^\s]+$", self.base_url):
                raise ValueError("an OpenAI-compatible provider needs a base URL (http or https)")
            if not self.model.strip():
                raise ValueError("an OpenAI-compatible provider needs a model name")
        if self.model and not re.match(r"^[A-Za-z0-9._:/@+-]+$", self.model):
            raise ValueError("model name contains unsupported characters")
        bad = [t for t in self.tasks if not TASK_ID.match(t)]
        if bad:
            raise ValueError(f"invalid task ids: {bad[:3]}")
        self.label = LABEL_SAFE.sub("", self.label).strip()
        return self


@dataclass
class Job:
    id: str
    params: dict[str, Any]
    total_tasks: int
    status: str = "running"     # running | done | failed | cancelled
    started: str = field(default_factory=lambda: _now())
    finished: str | None = None
    done_tasks: int = 0
    current: str = ""
    folders: list[str] = field(default_factory=list)
    log: collections.deque = field(default_factory=lambda: collections.deque(maxlen=LOG_LINES))
    errors: collections.deque = field(default_factory=lambda: collections.deque(maxlen=10))
    returncode: int | None = None
    proc: asyncio.subprocess.Process | None = None
    cancelled: bool = False

    def view(self, tail: int = 80) -> dict[str, Any]:
        return {
            "id": self.id, "status": self.status, "params": self.params,
            "started": self.started, "finished": self.finished,
            "done_tasks": self.done_tasks, "total_tasks": self.total_tasks,
            "current": self.current, "folders": list(self.folders),
            "returncode": self.returncode, "errors": list(self.errors),
            "log": list(self.log)[-tail:] if tail else [],
        }


JOBS: collections.OrderedDict[str, Job] = collections.OrderedDict()


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def pack_tasks(name: str) -> list[str] | None:
    path = PACKS_DIR / PACKS[name]
    if not path.is_file():
        return None
    with zipfile.ZipFile(path) as zf:
        return [str(t["id"]) for t in json.loads(zf.read("manifest.json")).get("tasks", [])]


def busy() -> bool:
    return any(j.status == "running" for j in JOBS.values())


def build_command(req: RunRequest) -> list[str]:
    cmd = [*AGENT_CMD, "--pack", str(PACKS_DIR / PACKS[req.pack]),
           "--concurrency", str(req.concurrency), "--provider", req.provider]
    if req.model:
        cmd += ["--model", req.model]
    if req.provider == "anthropic":
        cmd += ["--effort", req.effort]
    if req.tasks:
        cmd += ["--local", ",".join(req.tasks)]
    if req.suite:
        cmd.append("--ablation-suite")
    else:
        if req.ablate:
            cmd += ["--ablate", ",".join(req.ablate)]
        if req.label:
            cmd += ["--label", req.label]
    return cmd


def build_env(req: RunRequest) -> dict[str, str]:
    """A minimal environment: nothing of the runner's own configuration leaks in."""
    env = {k: v for k, v in os.environ.items() if k in PASS_ENV}
    env.update(PYTHONUNBUFFERED="1", ROBUST_TRACE_DIR=str(WORK_DIR / "traces"))
    key = req.api_key.get_secret_value()
    if req.provider == "anthropic":
        env["ANTHROPIC_API_KEY"] = key
    else:
        env.update(LLM_BASE_URL=req.base_url, LLM_API_KEY=key, LLM_DEFAULT_MODEL=req.model)
    return env


def scrub(line: str, secret: str) -> str:
    """Remove the API key from a log line. Very short strings (placeholder keys for
    local model servers) are not secrets and would mangle the log, so they are kept."""
    line = line.rstrip("\n")
    if len(secret) >= 8 and secret in line:
        line = line.replace(secret, "***")
    return line[:2000]


async def execute(job: Job, cmd: list[str], env: dict[str, str], secret: str) -> None:
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    try:
        job.proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=str(WORK_DIR), env=env, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT, start_new_session=True)
        assert job.proc.stdout is not None
        async for raw in job.proc.stdout:
            line = scrub(raw.decode("utf-8", "replace"), secret)
            job.log.append(line)
            if TASK_LINE.search(line):
                job.done_tasks += 1
            elif m := ERROR_LINE.search(line):
                job.errors.append(m.group(1)[:500])
            elif m := SUITE_LINE.match(line):
                job.current = m.group(1)
            elif m := FOLDER_LINE.search(line):
                job.folders.append(m.group(1))
        job.returncode = await job.proc.wait()
        if job.cancelled:
            job.status = "cancelled"
        else:
            job.status = "done" if job.returncode == 0 else "failed"
    except Exception as exc:  # noqa: BLE001 - report any launch failure to the caller
        job.log.append(f"runner error: {type(exc).__name__}: {scrub(str(exc), secret)}")
        job.status = "failed"
    finally:
        job.finished = _now()
        job.proc = None


@app.get("/health")
def health(_: None = Depends(require_token)) -> dict[str, Any]:
    tasks = {name: pack_tasks(name) for name in PACKS}
    packs = {name: (len(t) if t is not None else None) for name, t in tasks.items()}
    return {"ok": True, "busy": busy(), "packs": packs, "tasks": tasks.get("v1.1") or [],
            "ablations": list(ABLATIONS)}


@app.post("/runs")
async def start(req: RunRequest, _: None = Depends(require_token)) -> dict[str, Any]:
    if busy():
        raise HTTPException(409, "a run is already in progress; wait for it or cancel it")
    tasks = pack_tasks(req.pack)
    if tasks is None:
        raise HTTPException(404, f"pack {req.pack!r} is not available on this server")
    unknown = sorted(set(req.tasks) - set(tasks))
    if unknown:
        raise HTTPException(400, f"not in pack {req.pack}: {unknown[:5]}")
    n = len(req.tasks or tasks) * (1 + len(ABLATIONS) if req.suite else 1)
    params = req.model_dump(exclude={"api_key"})
    job = Job(id=uuid.uuid4().hex[:12], params=params, total_tasks=n)
    JOBS[job.id] = job
    while len(JOBS) > MAX_JOBS_KEPT:
        oldest = next(iter(JOBS))
        if JOBS[oldest].status == "running":
            break
        JOBS.pop(oldest)
    asyncio.get_running_loop().create_task(
        execute(job, build_command(req), build_env(req), req.api_key.get_secret_value()))
    return job.view()


@app.get("/runs")
def list_runs(_: None = Depends(require_token)) -> dict[str, Any]:
    return {"runs": [j.view(tail=0) for j in reversed(JOBS.values())]}


@app.get("/runs/{job_id}")
def get_run(job_id: str, _: None = Depends(require_token)) -> dict[str, Any]:
    job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown run")
    return job.view()


@app.post("/runs/{job_id}/cancel")
async def cancel(job_id: str, _: None = Depends(require_token)) -> dict[str, Any]:
    job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown run")
    if job.status == "running" and job.proc is not None:
        job.cancelled = True
        with contextlib.suppress(ProcessLookupError):
            os.killpg(job.proc.pid, signal.SIGTERM)
        for _i in range(50):
            if job.proc is None:
                break
            await asyncio.sleep(0.1)
        if job.proc is not None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(job.proc.pid, signal.SIGKILL)
    return job.view()
