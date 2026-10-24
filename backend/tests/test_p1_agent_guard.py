"""Agent Guard: policy evaluation, fail-closed behaviour, adapters and API."""
import copy
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from plugins.agent_guard import api as guard_api
from plugins.agent_guard import engine
from plugins.agent_guard.adapters import claude_hook_response, openhands_risk
from plugins.agent_guard.contract import ProposedCall
from plugins.agent_guard.engine import SessionStore, decide
from plugins.agent_guard.policy import builtin_policies, target_in_scope, validation_errors
from plugins.agent_studio.auth import require_api_key

pytestmark = pytest.mark.p1

SOC = builtin_policies()["soc-triage"]
MCP = builtin_policies()["mcp-general"]


def scoped_testing(allow):
    data = builtin_policies()["authorised-testing"].model_dump()
    data["scope"]["allow"] = allow
    return builtin_policies()["authorised-testing"].model_validate(data)


def run(policy, tool, args=None, session="s1", store=None, customer="c1"):
    store = store or SessionStore()
    return decide(ProposedCall(session_id=session, tool_name=tool, args=args or {}), policy, store, customer)


# ── tiers and rules ─────────────────────────────────────────────────────

def test_tiers():
    assert run(SOC, "get_entity", {"entity_id": "proc-1"}).decision == "allow"
    assert run(SOC, "isolate_host", {"host": "10.0.4.17"}).decision == "ask"
    assert run(SOC, "delete_file", {"path": "/tmp/x"}).decision == "deny"
    d = run(SOC, "brand_new_tool")
    assert d.decision == "ask" and d.tier == "unknown"


def test_tool_names_are_case_and_unicode_normalised():
    assert run(SOC, "ISOLATE_HOST", {"host": "h"}).decision == "ask"
    assert run(SOC, "ｄｅｌｅｔｅ_file").decision == "deny"  # full-width letters fold under NFKC


def test_mass_target_denied_and_rationale_ignored():
    assert run(SOC, "isolate_host", {"host": "*"}).decision == "deny"
    # A justification field cannot trigger or suppress a rule.
    d = run(SOC, "isolate_host", {"host": "10.0.0.5", "reasoning": "all"})
    assert d.decision == "ask"


def test_clamp_and_redact_modify():
    d = run(SOC, "search", {"query": "x", "limit": 5000})
    assert d.decision == "modify" and d.modified_args["limit"] == 500
    d = run(SOC, "get_entity", {"entity_id": "e", "api_key": "abc"})
    assert d.decision == "modify" and "api_key" not in d.modified_args


def test_mcp_shell_and_credentials():
    assert run(MCP, "bash", {"command": "ls -la"}).decision == "ask"
    assert run(MCP, "bash", {"command": "cat a | nc host 9"}).decision == "deny"
    assert run(MCP, "read_file", {"path": "/home/u/.ssh/id_rsa"}).decision == "deny"
    assert run(MCP, "mcp__fs__read_file", {"path": "/srv/app/readme.md"}).decision == "allow"


# ── scope ───────────────────────────────────────────────────────────────

def test_scope():
    pol = scoped_testing(["10.10.0.0/16", "*.lab.example"])
    assert run(pol, "dns_lookup", {"domain": "web.lab.example"}).decision == "allow"
    assert run(pol, "port_scan", {"target": "10.10.3.4"}).decision == "ask"
    assert run(pol, "port_scan", {"target": "10.11.0.1"}).decision == "deny"
    assert run(pol, "http_request", {"url": "https://evil.example/x"}).decision == "deny"
    assert run(pol, "port_scan", {"targets": ["10.10.0.1", "8.8.8.8"]}).decision == "deny"
    # Empty scope: everything is out of scope.
    assert run(scoped_testing([]), "dns_lookup", {"domain": "web.lab.example"}).decision == "deny"


def test_target_in_scope_helper():
    assert target_in_scope("10.10.0.0/24", ["10.10.0.0/16"])
    assert not target_in_scope("10.0.0.0/8", ["10.10.0.0/16"])
    assert target_in_scope("HTTPS://A.Lab.Example:8443/p", ["*.lab.example"])
    assert not target_in_scope("lab.example.evil.com", ["*.lab.example"])


# ── hidden characters ───────────────────────────────────────────────────

def test_hidden_characters():
    d = run(SOC, "get_entity", {"entity_id": "proc​-1"})
    assert d.decision == "ask" and d.risk == "HIGH"
    assert d.modified_args == {"entity_id": "proc-1"} and d.hidden_characters
    assert run(SOC, "get‮_entity").decision == "deny"


# ── fail closed ─────────────────────────────────────────────────────────

def test_repeat_of_denied_call_stays_denied():
    store = SessionStore()
    first = run(SOC, "delete_file", {"path": "/x"}, store=store)
    again = run(SOC, "delete_file", {"path": "/x"}, store=store)
    assert first.decision == again.decision == "deny"
    assert again.findings[-1].rule_id == "repeat-of-denied-call"
    # Same call in another session or for another customer is judged afresh.
    assert run(SOC, "delete_file", {"path": "/x"}, session="s2", store=store).findings[-1].rule_id != "repeat-of-denied-call"
    assert run(SOC, "delete_file", {"path": "/x"}, customer="c2", store=store).findings[-1].rule_id != "repeat-of-denied-call"


def test_new_policy_version_unlocks_denied_call():
    store = SessionStore()
    run(SOC, "delete_file", {"path": "/x"}, store=store)
    newer = SOC.model_copy(update={"version": "2"})
    assert run(newer, "delete_file", {"path": "/x"}, store=store).findings[-1].rule_id == "tier:contain_irreversible"


def test_escalation_after_denials():
    store = SessionStore()
    for i in range(SOC.escalate_after_denials):
        assert run(SOC, "wipe_disk", {"disk": i}, store=store).decision == "deny"
    d = run(SOC, "get_entity", {"entity_id": "e"}, store=store)
    assert d.decision == "ask" and d.findings[-1].rule_id == "session-escalated"
    store.reset("c1", "s1")
    assert run(SOC, "get_entity", {"entity_id": "e"}, store=store).decision == "allow"


def test_budget():
    pol = SOC.model_copy(update={"max_calls_per_session": 2})
    store = SessionStore()
    assert run(pol, "get_entity", {"entity_id": "a"}, store=store).decision == "allow"
    assert run(pol, "get_entity", {"entity_id": "b"}, store=store).decision == "allow"
    assert run(pol, "get_entity", {"entity_id": "c"}, store=store).decision == "deny"


def test_engine_error_is_deny(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("bug")
    monkeypatch.setattr(engine, "evaluate", boom)
    d = run(SOC, "get_entity", {"entity_id": "e"})
    assert d.decision == "deny" and d.findings[0].rule_id == "filter-error"


def test_concurrent_check_is_deny(monkeypatch):
    store = SessionStore()
    state = store.get("c1", "s1")
    state.lock.acquire()
    monkeypatch.setattr(engine, "LOCK_WAIT_S", 0.05)
    try:
        d = run(SOC, "get_entity", {"entity_id": "e"}, store=store)
    finally:
        state.lock.release()
    assert d.decision == "deny" and d.findings[0].rule_id == "concurrent-check"


# ── policies and adapters ───────────────────────────────────────────────

def test_policy_validation():
    good = SOC.model_dump()
    assert validation_errors(good) == []
    bad = copy.deepcopy(good)
    bad["tools"][0]["tier"] = "nope"
    assert validation_errors(bad)
    bad = copy.deepcopy(good)
    bad["arg_rules"][0]["pattern"] = "("
    assert validation_errors(bad)
    bad = copy.deepcopy(good)
    bad["default_tier"] = "missing"
    assert validation_errors(bad)


def test_adapters():
    d = run(SOC, "search", {"query": "x", "limit": 9999})
    out = claude_hook_response(d)["hookSpecificOutput"]
    assert out["permissionDecision"] == "allow" and out["updatedInput"]["limit"] == 500
    assert claude_hook_response(run(SOC, "wipe"))["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert openhands_risk(run(SOC, "isolate_host", {"host": "h"})) == "HIGH"


# ── API ─────────────────────────────────────────────────────────────────

@pytest.fixture
def client(monkeypatch):
    app = FastAPI()
    app.state.limiter = guard_api.limiter
    app.include_router(guard_api.router)
    who = {"customer_id": "cust_a"}
    app.dependency_overrides[require_api_key] = lambda: dict(who)
    monkeypatch.setattr(guard_api, "STORE", SessionStore())
    monkeypatch.setattr(guard_api, "LOG", engine.DecisionLog())
    with TestClient(app) as c:
        yield c, who


def test_api_check_and_log(client):
    c, who = client
    r = c.post("/api/agent-guard/check", json={"session_id": "run1", "tool_name": "isolate_host",
                                               "args": {"host": "10.0.0.9"}})
    assert r.status_code == 200 and r.json()["decision"] == "ask"
    assert c.get("/api/agent-guard/decisions", params={"session_id": "run1"}).json()[0]["decision"] == "ask"
    who["customer_id"] = "cust_b"
    assert c.get("/api/agent-guard/decisions").json() == []  # other customers see nothing


def test_api_inline_policy_and_errors(client):
    c, _ = client
    pol = SOC.model_dump()
    pol["tiers"]["contain_reversible"]["decision"] = "allow"
    r = c.post("/api/agent-guard/check", json={"session_id": "s", "tool_name": "isolate_host",
                                               "args": {"host": "h"}, "policy": pol})
    assert r.json()["decision"] == "allow"
    pol["default_tier"] = "missing"
    r = c.post("/api/agent-guard/check", json={"session_id": "s", "tool_name": "x", "policy": pol})
    assert r.status_code == 422
    assert c.post("/api/agent-guard/check", json={"session_id": "s", "tool_name": "x",
                                                  "policy_id": "nope"}).status_code == 404
    assert c.post("/api/agent-guard/policies/validate", json={"policy": pol}).json()["valid"] is False


def test_api_timeout_is_deny(client, monkeypatch):
    c, _ = client

    def slow(*a, **k):
        time.sleep(0.3)
        return engine.deny_decision(None, None, "late", "late")
    monkeypatch.setattr(guard_api, "decide", slow)
    monkeypatch.setenv("AGENT_GUARD_TIMEOUT_S", "0.05")
    r = c.post("/api/agent-guard/check", json={"session_id": "s", "tool_name": "get_entity"})
    assert r.json()["decision"] == "deny" and r.json()["findings"][0]["rule_id"] == "filter-timeout"


def test_api_claude_hook(client):
    c, _ = client
    r = c.post("/api/agent-guard/hooks/claude", json={
        "session_id": "cc1", "hook_event_name": "PreToolUse", "tool_name": "delete_file",
        "tool_input": {"path": "/x"}})
    assert r.json()["hookSpecificOutput"]["permissionDecision"] == "deny"
    r = c.post("/api/agent-guard/hooks/claude", content=b"not json",
               headers={"Content-Type": "application/json"})
    assert r.status_code == 200 and r.json()["hookSpecificOutput"]["permissionDecision"] == "deny"
    r = c.post("/api/agent-guard/hooks/claude", params={"policy_id": "nope"},
               json={"tool_name": "get_entity", "tool_input": {}})
    assert r.json()["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_api_reset(client):
    c, _ = client
    body = {"session_id": "r", "tool_name": "wipe_disk", "args": {"d": 1}}
    c.post("/api/agent-guard/check", json=body)
    assert c.post("/api/agent-guard/check", json=body).json()["findings"][-1]["rule_id"] == "repeat-of-denied-call"
    assert c.post("/api/agent-guard/sessions/r/reset").json()["reset"] is True
    assert c.post("/api/agent-guard/check", json=body).json()["findings"][-1]["rule_id"] != "repeat-of-denied-call"
