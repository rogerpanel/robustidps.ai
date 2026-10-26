"""Tests for the agent run service, with a fake agent in place of the real CLI.

    python -m pytest bluesec/runner/test_server.py
"""

import json
import sys
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

import server

FAKE_AGENT = r'''
import os, sys, time
args = sys.argv[1:]
print("args", " ".join(args), flush=True)
print("key echo:", os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("LLM_API_KEY"), flush=True)
print("token leaked:", "RUNNER_TOKEN" in os.environ, flush=True)
print("2026-10-12 | ERROR    | agent:_one:216 - Task t0 failed in the agent: AuthenticationError: 401", flush=True)
configs = ["full", "no cache"] if "--ablation-suite" in args else [None]
for i, cfg in enumerate(configs):
    if cfg:
        print(f"== ablation suite: {cfg}", flush=True)
    for n, t in enumerate(["t1", "t2"], 1):
        print(f"2026-10-12 | INFO | Task {t} terminated: quality=1.000 efficiency=1.000 "
              f"reward=1.000 calls=3 [{n} done]", flush=True)
        if "--slow" in os.environ.get("FAKE_MODE", ""):
            time.sleep(5)
    print(f"2026-10-12 | INFO | Traces written to {os.environ['ROBUST_TRACE_DIR']}/2026101{i}-run", flush=True)
sys.exit(int(os.environ.get("FAKE_EXIT", "0")))
'''


@pytest.fixture
def client(tmp_path, monkeypatch):
    packs = tmp_path / "packs"
    packs.mkdir()
    with zipfile.ZipFile(packs / server.PACKS["v1.1"], "w") as zf:
        zf.writestr("manifest.json", json.dumps({"tasks": [{"id": "t1"}, {"id": "t2"}]}))
    agent = tmp_path / "fake_agent.py"
    agent.write_text(FAKE_AGENT)
    monkeypatch.setattr(server, "PACKS_DIR", packs)
    monkeypatch.setattr(server, "WORK_DIR", tmp_path / "runs")
    monkeypatch.setattr(server, "AGENT_CMD", [sys.executable, str(agent)])
    monkeypatch.setattr(server, "TOKEN", "s3cret")
    monkeypatch.setattr(server, "PASS_ENV", (*server.PASS_ENV, "FAKE_EXIT", "FAKE_MODE"))
    monkeypatch.setenv("RUNNER_TOKEN", "s3cret")
    server.JOBS.clear()
    with TestClient(server.app) as c:
        c.headers["X-Runner-Token"] = "s3cret"
        yield c


def wait(c, job_id, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = c.get(f"/runs/{job_id}").json()
        if job["status"] != "running":
            return job
        time.sleep(0.1)
    raise AssertionError("run did not finish")


def test_token_required(client):
    assert client.get("/health", headers={"X-Runner-Token": "wrong"}).status_code == 401
    health = client.get("/health").json()
    assert health["packs"] == {"v1.1": 2, "blind": None, "mimicry": None} and not health["busy"]
    assert health["tasks"] == ["t1", "t2"]


def test_single_run_progress_folders_and_secret_scrubbing(client):
    r = client.post("/runs", json={"api_key": "sk-test-SECRET", "ablate": ["cache"], "label": "no cache <x>"})
    assert r.status_code == 200, r.text
    job = wait(client, r.json()["id"])
    assert job["status"] == "done" and job["returncode"] == 0
    assert job["done_tasks"] == 2 and job["total_tasks"] == 2
    assert job["folders"] == ["20261010-run"]
    log = "\n".join(job["log"])
    assert "sk-test-SECRET" not in log and "key echo: ***" in log
    assert "token leaked: False" in log
    assert "--ablate cache" in log and "--label no cache x" in log and "--effort high" in log
    assert "api_key" not in job["params"]
    assert job["errors"] == ["Task t0 failed in the agent: AuthenticationError: 401"]


def test_suite_counts_all_configurations(client):
    job = wait(client, client.post("/runs", json={"api_key": "k", "suite": True}).json()["id"])
    assert job["total_tasks"] == 2 * 6 and job["done_tasks"] == 4
    assert job["current"] == "no cache" and len(job["folders"]) == 2
    assert "--ablation-suite" in "\n".join(job["log"]) and "--label" not in "\n".join(job["log"])
    assert "key echo: k" in "\n".join(job["log"])   # placeholder keys are not scrubbed


def test_validation_and_unavailable_pack(client):
    assert client.post("/runs", json={"api_key": "k", "suite": True, "ablate": ["cache"]}).status_code == 422
    assert client.post("/runs", json={"api_key": "k", "provider": "openai"}).status_code == 422
    assert client.post("/runs", json={"api_key": "k", "provider": "openai", "model": "m",
                                      "base_url": "ftp://x"}).status_code == 422
    assert client.post("/runs", json={"api_key": "k", "pack": "mimicry"}).status_code == 404
    assert client.post("/runs", json={"api_key": "k", "tasks": ["t9"]}).status_code == 400
    assert client.post("/runs", json={"api_key": "k", "tasks": ["../x"]}).status_code == 422


def test_openai_provider_environment(client):
    job = wait(client, client.post("/runs", json={
        "api_key": "local-key", "provider": "openai", "model": "qwen2.5-7b",
        "base_url": "http://gpu:8000/v1", "tasks": ["t1"]}).json()["id"])
    log = "\n".join(job["log"])
    assert "--provider openai" in log and "--model qwen2.5-7b" in log and "--local t1" in log
    assert "--effort" not in log and "key echo: ***" in log


def test_failed_run_and_one_at_a_time_and_cancel(client, monkeypatch):
    monkeypatch.setenv("FAKE_EXIT", "3")
    job = wait(client, client.post("/runs", json={"api_key": "k"}).json()["id"])
    assert job["status"] == "failed" and job["returncode"] == 3
    monkeypatch.setenv("FAKE_EXIT", "0")
    monkeypatch.setenv("FAKE_MODE", "--slow")
    first = client.post("/runs", json={"api_key": "k"}).json()
    assert client.post("/runs", json={"api_key": "k"}).status_code == 409
    time.sleep(0.5)
    cancelled = client.post(f"/runs/{first['id']}/cancel").json()
    assert cancelled["status"] == "cancelled"
    assert client.get("/runs").json()["runs"][0]["id"] == first["id"]
