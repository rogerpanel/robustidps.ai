"""BlueSec Runs: trace parsing, per-user storage, and the admin-only server import."""
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from database import get_db
from plugins.bluesec_runs import api
from plugins.bluesec_runs.traces import TraceError, build_run

pytestmark = pytest.mark.p1


def _task(task_id, quality, efficiency, calls, verdict="benign"):
    return {
        "task_id": task_id, "model": "claude-opus-5-5",
        "alert": {"alert_text": {"trigger_entities": ["proc-1"]}},
        "tools": [{"name": "get_entity", "description": "x"}],
        "steps": [
            {"type": "thinking", "text": "two hypotheses"},
            {"type": "tool_call", "tool": "get_entity",
             "arguments": {"entity_id": "proc-1", "reasoning": "Inspect the trigger"},
             "status": "ok", "spent_so_far": 1, "result": "{}"},
            {"type": "tool_call", "tool": "get_entity", "arguments": {"entity_id": "proc-1"},
             "status": "cached", "spent_so_far": 1, "result": "{}"},
            {"type": "tool_call", "tool": "rm -rf", "status": "<script>", "arguments": {}},
            {"type": "unknown"},
        ],
        "submission": {"verdict": verdict, "reasoning": "summary"},
        "calls_spent": calls, "calls_saved_by_cache": 1, "wall_seconds": 12.5,
        "result": {"task_id": task_id, "completion_reason": "terminated",
                   "quality_score": quality, "efficiency_score": efficiency,
                   "total_reward": quality * efficiency, "tool_calls": calls},
    }


SUMMARY = {"run_id": "run-abc", "tasks": 2, "task_results": [
    {"task_id": "t1", "completion_reason": "terminated", "quality_score": 1.0,
     "efficiency_score": 0.5, "tool_calls": 4},
    {"task_id": "t2", "completion_reason": "aborted", "quality_score": 0.0,
     "efficiency_score": 0.0, "tool_calls": 0},
]}


def test_build_run_aggregates_and_sanitises():
    built = build_run([_task("t2", 0.5, 0.5, 6), _task("t1", 1.0, 1.0, 4), SUMMARY, 7, {"x": 1}])
    assert [t["task_id"] for t in built["tasks"]] == ["t1", "t2"]
    agg = built["aggregates"]
    assert agg["n_tasks"] == 2 and agg["n_completed"] == 2
    assert agg["mean_quality"] == 0.75 and agg["mean_tool_calls"] == 5.0
    assert agg["calls_saved_by_cache"] == 2
    assert built["pt_run_id"] == "run-abc" and built["ignored_files"] == 2
    steps = built["tasks"][0]["steps"]
    assert [s["type"] for s in steps] == ["thinking", "tool_call", "tool_call", "tool_call"]
    assert steps[-1]["status"] == "unknown"  # unrecognised status is not passed through


def test_build_run_from_summary_only_and_rejects_noise():
    built = build_run([SUMMARY])
    assert built["aggregates"]["n_completed"] == 1
    assert all(t["from_summary_only"] for t in built["tasks"])
    with pytest.raises(TraceError):
        build_run([{"hello": "world"}])


@pytest.fixture
def mini(db_session, tmp_path, monkeypatch):
    folder = tmp_path / "20261009-101500-run-abc"
    folder.mkdir()
    (folder / "t1.json").write_text(json.dumps(_task("t1", 1.0, 1.0, 4)))
    (folder / "summary.json").write_text(json.dumps(SUMMARY))
    monkeypatch.setattr(api, "TRACES_DIR", tmp_path)
    app = FastAPI()
    app.state.limiter = api.limiter
    app.include_router(api.router)
    app.dependency_overrides[get_db] = lambda: db_session
    return TestClient(app)


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_upload_list_get_update_delete(mini, admin_token, analyst_token):
    body = {"documents": [_task("t1", 1.0, 1.0, 4), SUMMARY], "folder": "20261009-101500-x"}
    r = mini.post("/api/bluesec-runs", json=body, headers=_auth(analyst_token))
    assert r.status_code == 200, r.text
    run = r.json()
    assert run["name"] == "20261009-101500-x" and run["started_at"].startswith("2026-10-09T10:15")
    rid = run["id"]

    full = mini.get(f"/api/bluesec-runs/{rid}", headers=_auth(analyst_token)).json()
    assert full["tasks"][0]["submission"]["verdict"] == "benign"

    r = mini.patch(f"/api/bluesec-runs/{rid}", json={"name": "Practice 1", "notes": "baseline"},
                   headers=_auth(analyst_token))
    assert r.json()["name"] == "Practice 1"

    # another user cannot see, read or delete it
    assert mini.get("/api/bluesec-runs", headers=_auth(admin_token)).json()["runs"] == []
    assert mini.get(f"/api/bluesec-runs/{rid}", headers=_auth(admin_token)).status_code == 404
    assert mini.delete(f"/api/bluesec-runs/{rid}", headers=_auth(admin_token)).status_code == 404

    assert mini.delete(f"/api/bluesec-runs/{rid}", headers=_auth(analyst_token)).status_code == 200
    assert mini.get("/api/bluesec-runs", headers=_auth(analyst_token)).json()["runs"] == []


def test_upload_requires_auth_and_valid_documents(mini, analyst_token):
    assert mini.get("/api/bluesec-runs").status_code == 401
    r = mini.post("/api/bluesec-runs", json={"documents": [{"a": 1}]}, headers=_auth(analyst_token))
    assert r.status_code == 400


def test_server_import_is_admin_only_and_confined(mini, admin_token, analyst_token):
    assert mini.get("/api/bluesec-runs/server", headers=_auth(analyst_token)).status_code == 403
    listing = mini.get("/api/bluesec-runs/server", headers=_auth(admin_token)).json()
    assert listing["enabled"] and listing["folders"][0]["name"] == "20261009-101500-run-abc"

    r = mini.post("/api/bluesec-runs/server/import", json={"folder": "20261009-101500-run-abc"},
                  headers=_auth(admin_token))
    assert r.status_code == 200 and r.json()["source"] == "server:20261009-101500-run-abc"
    listing = mini.get("/api/bluesec-runs/server", headers=_auth(admin_token)).json()
    assert listing["folders"][0]["imported"] is True

    for bad in ("../", "../../etc", "/etc"):
        r = mini.post("/api/bluesec-runs/server/import", json={"folder": bad},
                      headers=_auth(admin_token))
        assert r.status_code == 404
