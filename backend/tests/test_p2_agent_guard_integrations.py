"""AgentDojo and Inspect connectors (run only where those packages are installed)."""
import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "plugins" / "agent_guard" / "integrations"))

VERDICTS = {
    "read_file": {"decision": "allow", "reasons": ["read"]},
    "search": {"decision": "modify", "reasons": ["capped"], "modified_args": {"query": "x", "limit": 500}},
    "bash": {"decision": "ask", "reasons": ["shell"], "approval_id": "a1"},
    "delete_file": {"decision": "deny", "reasons": ["irreversible"]},
}


def checker(tool, args):
    if tool == "explode":
        raise RuntimeError("guard down")
    return VERDICTS[tool]


def test_agentdojo_executor():
    pytest.importorskip("agentdojo")
    from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
    from agentdojo_guard import GuardedToolsExecutor

    runtime, ran = FunctionsRuntime([]), []

    @runtime.register_function
    def read_file(path: str) -> str:
        """Read a file.

        :param path: path
        """
        ran.append(("read_file", path))
        return "contents"

    @runtime.register_function
    def search(query: str, limit: int) -> str:
        """Search.

        :param query: query
        :param limit: limit
        """
        ran.append(("search", limit))
        return f"{limit} results"

    calls = [FunctionCall(function=f, args=a, id=f"c{i}") for i, (f, a) in enumerate([
        ("read_file", {"path": "/a"}), ("search", {"query": "x", "limit": 9999}),
        ("bash", {"command": "ls"}), ("delete_file", {"path": "/a"}), ("explode", {})])]
    msgs = [{"role": "user", "content": [{"type": "text", "content": "q"}]},
            {"role": "assistant", "content": None, "tool_calls": calls}]
    ex = GuardedToolsExecutor(checker=checker)
    _, _, _, out, _ = ex.query("q", runtime, messages=msgs)
    results = {m["tool_call_id"]: m for m in out[2:]}
    assert [m["tool_call_id"] for m in out[2:]] == ["c0", "c1", "c2", "c3", "c4"]   # order and pairing kept
    assert results["c0"]["error"] is None and results["c1"]["content"][0]["content"] == "500 results"
    assert "approval" in results["c2"]["error"] and "(deny)" in results["c3"]["error"]
    assert "failing closed" in results["c4"]["error"]
    assert ran == [("read_file", "/a"), ("search", 500)]
    assert [d["decision"] for d in ex.decisions] == ["allow", "modify", "ask", "deny", "deny"]


def test_inspect_approver():
    pytest.importorskip("inspect_ai")
    from inspect_ai.tool import ToolCall
    from inspect_guard import agent_guard

    def approve(fn, tool, args):
        call = ToolCall(id="t1", function=tool, arguments=args)
        return asyncio.run(fn("", call, None, []))

    a = agent_guard(checker=checker)
    assert approve(a, "read_file", {"path": "/a"}).decision == "approve"
    m = approve(a, "search", {"query": "x", "limit": 9999})
    assert m.decision == "modify" and m.modified.arguments["limit"] == 500 and m.modified.id == "t1"
    assert approve(a, "bash", {"command": "ls"}).decision == "escalate"
    assert approve(a, "delete_file", {"path": "/a"}).decision == "reject"
    assert approve(a, "explode", {}).decision == "reject"
    strict = agent_guard(checker=checker, ask_as="reject", deny_as="terminate")
    assert approve(strict, "bash", {}).decision == "reject"
    assert approve(strict, "delete_file", {}).decision == "terminate"


# ── Claude Agent SDK hook (no SDK needed: the hook is a plain async function) ──

def _hook_call(hook, tool, args, session="s1"):
    return asyncio.run(hook({"hook_event_name": "PreToolUse", "session_id": session, "tool_name": tool,
                             "tool_input": args, "tool_use_id": "t1"}, "t1", {"signal": None}))


def test_claude_sdk_hook_mapping():
    from claude_sdk_guard import agent_guard_hook
    hook = agent_guard_hook(checker=checker)
    assert _hook_call(hook, "read_file", {"path": "a"}) == {}                      # Claude's own rules decide
    out = _hook_call(hook, "search", {"query": "x", "limit": 9999})["hookSpecificOutput"]
    assert out["permissionDecision"] == "allow" and out["updatedInput"] == {"query": "x", "limit": 500}
    out = _hook_call(hook, "bash", {"command": "ls"})["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny" and "a1" in out["permissionDecisionReason"]
    assert _hook_call(hook, "delete_file", {})["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert _hook_call(hook, "explode", {})["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert asyncio.run(hook({"hook_event_name": "PostToolUse"}, None, {})) == {}
    bad = asyncio.run(hook({"hook_event_name": "PreToolUse", "tool_name": "x", "tool_input": "no"}, None, {}))
    assert bad["hookSpecificOutput"]["permissionDecision"] == "deny"
    ask = agent_guard_hook(checker=checker, ask_as="ask")
    assert _hook_call(ask, "bash", {"command": "ls"})["hookSpecificOutput"]["permissionDecision"] == "ask"
    grant = agent_guard_hook(checker=checker, grant_on_allow=True)
    assert _hook_call(grant, "read_file", {"path": "a"})["hookSpecificOutput"]["permissionDecision"] == "allow"
    import time as _t
    slow = agent_guard_hook(checker=lambda t, a: _t.sleep(2) or {"decision": "allow"}, deadline_s=0.3)
    assert _hook_call(slow, "read_file", {})["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert [d["decision"] for d in hook.decisions] == ["allow", "modify", "ask", "deny"]


def test_claude_sdk_options_accept_the_hook():
    sdk = pytest.importorskip("claude_agent_sdk")
    from claude_sdk_guard import agent_guard_hook
    hook = agent_guard_hook(checker=checker)
    opts = sdk.ClaudeAgentOptions(hooks={"PreToolUse": [sdk.HookMatcher(matcher=None, hooks=[hook], timeout=90)]})
    assert opts.hooks["PreToolUse"][0].hooks[0] is hook


def test_openhands_parses_the_served_hooks_json():
    hooks = pytest.importorskip("openhands.sdk.hooks")
    import json as _json
    from plugins.agent_guard.api import openhands_hooks
    text = openhands_hooks(policy="mcp-general", approval_wait=60, python="python3",
                           client_path="/opt/guard/agent_guard_client.py").body.decode()
    cfg = hooks.HookConfig.from_dict(_json.loads(text))
    (h,) = cfg.get_hooks_for_event(hooks.HookEventType.PRE_TOOL_USE, "terminal")
    assert h.command.endswith("hook --format openhands --policy mcp-general --approval-wait 60") and h.timeout == 90
