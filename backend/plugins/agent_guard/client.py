#!/usr/bin/env python3
"""Agent Guard client: copy this single file into any agent project (stdlib only).

As a library:

    from agent_guard_client import GuardClient, GuardDenied
    guard = GuardClient("https://robustidps.ai", token="<platform token or rids_live_ key>",
                        session_id="run-42", policy_id="soc-triage", approval_wait=300)
    verdict = guard.check("isolate_host", {"host": "10.0.4.17"})
    # allow | modify (use verdict["modified_args"]) | ask (a person approves on the
    # Safety Filter page; with approval_wait the client waits and re-checks) | deny

    @guard.tool                      # wraps a Python tool function
    def isolate_host(host: str): ...  # raises GuardDenied unless allowed

As a Claude-style PreToolUse command hook (Claude Code; Hermes shell hooks
take the same JSON):

    AGENT_GUARD_URL=https://robustidps.ai AGENT_GUARD_TOKEN=... \\
    python agent_guard_client.py hook --policy soc-triage

As an MCP gateway between an agent and a local (stdio) MCP server:

    python agent_guard_client.py mcp-proxy --policy mcp-general --toolset my-server \\
        -- npx -y @modelcontextprotocol/server-filesystem /srv/app

  - tools/list is verified against the version of the toolset pinned in the
    Tool Registry; tools that changed, are new or carry hidden characters are
    withheld from the agent (and calls to them refused);
  - every tools/call is checked first: deny and unapproved ask return a tool
    error to the agent, modify forwards the corrected arguments;
  - hidden characters are stripped from tool results.

Every failure (network, timeout, bad response) is a deny: the agent never runs
a tool the guard did not approve.
"""
from __future__ import annotations

import argparse
import functools
import json
import os
import re
import subprocess
import sys
import threading
import time
import unicodedata
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable

_HIDDEN = re.compile(
    "[­͏؜ᅟᅠ឴឵᠋-᠏​-‏"
    "‪-‮⁠-⁤⁦-⁯ㅤ︀-️﻿ﾠ"
    "\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)


def strip_hidden(value: Any) -> tuple[Any, int]:
    """NFKC and remove invisible characters in every string of a JSON-like value."""
    if isinstance(value, str):
        norm = unicodedata.normalize("NFKC", value)
        return _HIDDEN.sub("", norm), len(_HIDDEN.findall(norm))
    if isinstance(value, list):
        out, n = [], 0
        for v in value:
            cv, k = strip_hidden(v)
            out.append(cv)
            n += k
        return out, n
    if isinstance(value, dict):
        out_d, n = {}, 0
        for k, v in value.items():
            cv, c = strip_hidden(v)
            out_d[k] = cv
            n += c
        return out_d, n
    return value, 0


class GuardDenied(RuntimeError):
    def __init__(self, verdict: dict[str, Any]):
        super().__init__("; ".join(verdict.get("reasons") or ["denied"]))
        self.verdict = verdict


class GuardClient:
    def __init__(self, base_url: str, token: str = "", session_id: str = "default",
                 policy_id: str = "soc-triage", timeout: float = 5.0, approval_wait: float = 0.0,
                 poll_interval: float = 3.0, agent_id: str = "", framework: str = "python"):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.session_id = session_id
        self.policy_id = policy_id
        self.timeout = timeout
        self.approval_wait = approval_wait      # seconds to wait for a person on "ask"; 0 = do not wait
        self.poll_interval = poll_interval
        self.agent_id = agent_id
        self.framework = framework
        self._approvals: dict[str, str] = {}    # call -> approval id, so a retry reuses its approval

    def _req(self, method: str, path: str, body: dict | None = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f"{self.base_url}{path}", data=data, method=method,
            headers={"Content-Type": "application/json",
                     **({"Authorization": f"Bearer {self.token}"} if self.token else {})})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode())

    def _post(self, path: str, body: dict) -> Any:
        return self._req("POST", path, body)

    def _check_once(self, tool_name: str, args: dict[str, Any], approval_id: str | None = None) -> dict[str, Any]:
        verdict = self._post("/api/agent-guard/check", {
            "session_id": self.session_id, "policy_id": self.policy_id, "tool_name": tool_name, "args": args,
            "agent_id": self.agent_id, "framework": self.framework,
            **({"approval_id": approval_id} if approval_id else {})})
        if verdict.get("decision") not in ("allow", "modify", "ask", "deny"):
            raise ValueError("unexpected response")
        return verdict

    def check(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """The guard's verdict; with approval_wait, an 'ask' waits for a person and is re-checked."""
        key = json.dumps([tool_name, args], sort_keys=True, default=str)
        try:
            aid = self._approvals.get(key)
            if aid:  # retry of a call that was sent for approval earlier
                status = self._approval_status(aid)
                if status == "approved":
                    self._approvals.pop(key, None)
                    return self._check_once(tool_name, args, aid)
                if status == "pending":
                    verdict = {"decision": "ask", "approval_id": aid,
                               "reasons": [f"Approval {aid} is still pending."]}
                else:
                    self._approvals.pop(key, None)
                    verdict = self._check_once(tool_name, args)
            else:
                verdict = self._check_once(tool_name, args)
            aid = verdict.get("approval_id")
            if verdict["decision"] != "ask" or not aid:
                return verdict
            self._approvals[key] = aid
            if self.approval_wait <= 0:
                return verdict
            deadline = time.monotonic() + self.approval_wait
            while time.monotonic() < deadline:
                status = self._approval_status(aid)
                if status == "approved":
                    self._approvals.pop(key, None)
                    return self._check_once(tool_name, args, aid)
                if status in ("denied", "expired", "used"):
                    self._approvals.pop(key, None)
                    return {**verdict, "decision": "deny", "reasons": [f"Approval {status}."]}
                time.sleep(self.poll_interval)
            return {**verdict, "decision": "deny", "reasons": ["No approval within the waiting time."]}
        except Exception as exc:  # noqa: BLE001 — fail closed
            return {"decision": "deny", "reasons": [f"guard unreachable or invalid ({exc}); failing closed"]}

    def _approval_status(self, approval_id: str) -> str:
        return str(self._req("GET", f"/api/agent-guard/approvals/{urllib.parse.quote(approval_id)}").get("status"))

    def tool(self, fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(**kwargs):
            verdict = self.check(fn.__name__, kwargs)
            if verdict["decision"] not in ("allow", "modify"):
                raise GuardDenied(verdict)
            args = verdict.get("modified_args") if verdict.get("modified_args") is not None else kwargs
            return fn(**args)
        return wrapper

    def verify_tools(self, toolset: str, tools: list) -> dict:
        return self._post(f"/api/agent-guard/toolsets/{urllib.parse.quote(toolset)}/verify", {"tools": tools})


# ── command hook ──────────────────────────────────────────────────────

def _hook(policy: str) -> int:
    def deny(reason: str) -> int:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                 "permissionDecisionReason": f"Agent Guard: {reason}"}}))
        return 0
    try:
        payload = json.load(sys.stdin)
        client = GuardClient(os.environ.get("AGENT_GUARD_URL", "http://localhost:8000"),
                             os.environ.get("AGENT_GUARD_TOKEN", ""), policy_id=policy)
        answer = client._post(f"/api/agent-guard/hooks/claude?policy_id={urllib.parse.quote(policy)}", payload)
        if answer.get("hookSpecificOutput", {}).get("permissionDecision") not in ("allow", "ask", "deny"):
            return deny("invalid guard response; failing closed")
        print(json.dumps(answer))
        return 0
    except Exception as exc:  # noqa: BLE001
        return deny(f"guard unreachable ({type(exc).__name__}); failing closed")


# ── MCP stdio gateway ─────────────────────────────────────────────────

class McpGateway:
    """Relays newline-delimited JSON-RPC between the agent (our stdio) and an MCP server process."""

    def __init__(self, guard: GuardClient, command: list[str], toolset: str | None,
                 out=None, inp=None, log=None):
        self.guard = guard
        self.toolset = toolset
        self.out = out or sys.stdout
        self.inp = inp or sys.stdin
        self.log = log or sys.stderr
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                     bufsize=1, encoding="utf-8")
        self.write_lock = threading.Lock()
        self.list_ids: set = set()
        self.call_ids: set = set()
        self.allowed: set[str] | None = None    # None until a tools/list was verified (no toolset: no gate)
        self.verified = threading.Event()
        self.internal_ids: set = set()

    def _say(self, msg: str) -> None:
        print(f"[agent-guard] {msg}", file=self.log, flush=True)

    def _to_agent(self, msg: dict) -> None:
        with self.write_lock:
            self.out.write(json.dumps(msg) + "\n")
            self.out.flush()

    def _to_server(self, msg: dict) -> None:
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def _blocked(self, req_id: Any, reason: str) -> None:
        self._to_agent({"jsonrpc": "2.0", "id": req_id, "result": {
            "content": [{"type": "text", "text": f"Blocked by Agent Guard: {reason}"}], "isError": True}})

    def handle_agent(self, msg: dict) -> None:
        method = msg.get("method")
        if method == "tools/list" and "id" in msg:
            self.list_ids.add(msg["id"])
        if method != "tools/call" or "id" not in msg:
            self._to_server(msg)
            return
        params = msg.get("params") or {}
        name, args = str(params.get("name", "")), params.get("arguments") or {}
        if self.toolset and self.allowed is None:
            # No verified tool list yet: wait for the agent's tools/list, or ask the server ourselves.
            if not self.list_ids:
                iid = f"agent-guard-list-{uuid.uuid4().hex[:8]}"
                self.internal_ids.add(iid)
                self._to_server({"jsonrpc": "2.0", "id": iid, "method": "tools/list", "params": {}})
            self.verified.wait(timeout=15)
        if self.toolset and (self.allowed is None or name not in self.allowed):
            self._say(f"refused call to withheld tool {name!r}")
            self._blocked(msg["id"], f"tool {name!r} is not in the pinned, verified tool list")
            return
        verdict = self.guard.check(name, args if isinstance(args, dict) else {})
        decision = verdict.get("decision")
        if decision not in ("allow", "modify"):
            reason = "; ".join(verdict.get("reasons") or [str(decision)])
            if decision == "ask" and verdict.get("approval_id"):
                reason += (f" Approval {verdict['approval_id']} is waiting on the Safety Filter page; "
                           "retry the same call once it is approved.")
            self._say(f"{decision} {name}: {reason}")
            self._blocked(msg["id"], reason)
            return
        if verdict.get("modified_args") is not None:
            msg = {**msg, "params": {**params, "arguments": verdict["modified_args"]}}
        self.call_ids.add(msg["id"])
        self._to_server(msg)

    def handle_server(self, msg: dict) -> None:
        rid = msg.get("id")
        internal = rid in self.internal_ids
        if (rid in self.list_ids or internal) and "result" in msg:
            self.list_ids.discard(rid)
            self.internal_ids.discard(rid)
            tools = (msg.get("result") or {}).get("tools") or []
            if self.toolset:
                try:
                    report = self.guard.verify_tools(self.toolset, tools)
                    self.allowed = set(report.get("allowed") or [])
                    for t in report.get("tools", []):
                        if t.get("status") != "ok":
                            self._say(f"withheld {t.get('name')!r}: {t.get('status')}")
                    if report.get("reason"):
                        self._say(report["reason"])
                except Exception as exc:  # noqa: BLE001 — cannot verify: expose nothing
                    self.allowed = set()
                    self._say(f"tool verification failed ({exc}); withholding all tools")
                tools = [t for t in tools if t.get("name") in self.allowed]
            self.verified.set()
            if internal:
                return
            msg = {**msg, "result": {**msg["result"], "tools": tools}}
        elif rid in self.call_ids and "result" in msg:
            self.call_ids.discard(rid)
            cleaned, n = strip_hidden(msg["result"])
            if n:
                self._say(f"removed {n} hidden character(s) from a tool result")
            msg = {**msg, "result": cleaned}
        self._to_agent(msg)

    def _pump_server(self) -> None:
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self.handle_server(json.loads(line))
            except json.JSONDecodeError:
                self._say("dropped a non-JSON line from the server")

    def run(self) -> int:
        t = threading.Thread(target=self._pump_server, daemon=True)
        t.start()
        for line in self.inp:
            line = line.strip()
            if not line:
                continue
            try:
                self.handle_agent(json.loads(line))
            except json.JSONDecodeError:
                self._say("dropped a non-JSON line from the agent")
        self.proc.stdin.close()
        self.proc.wait(timeout=10)
        t.join(timeout=5)
        return self.proc.returncode or 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Agent Guard client")
    sub = ap.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hook", help="Claude-style PreToolUse command hook (stdin JSON -> stdout JSON)")
    h.add_argument("--policy", default=os.environ.get("AGENT_GUARD_POLICY", "soc-triage"))
    m = sub.add_parser("mcp-proxy", help="guard a stdio MCP server: mcp-proxy [options] -- command args...")
    m.add_argument("--policy", default=os.environ.get("AGENT_GUARD_POLICY", "mcp-general"))
    m.add_argument("--toolset", help="Tool Registry name whose pinned version tools/list must match")
    m.add_argument("--session", default=f"mcp-{uuid.uuid4().hex[:8]}")
    m.add_argument("--approval-wait", type=float, default=float(os.environ.get("AGENT_GUARD_APPROVAL_WAIT", "0")),
                   help="seconds to wait for a person to approve an 'ask' (default 0: refuse)")
    m.add_argument("command", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    if args.cmd == "hook":
        return _hook(args.policy)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        ap.error("mcp-proxy needs the MCP server command after --")
    guard = GuardClient(os.environ.get("AGENT_GUARD_URL", "http://localhost:8000"),
                        os.environ.get("AGENT_GUARD_TOKEN", ""), session_id=args.session,
                        policy_id=args.policy, approval_wait=args.approval_wait,
                        agent_id=f"mcp:{args.toolset or 'unpinned'}", framework="mcp")
    if not args.toolset:
        print("[agent-guard] no --toolset: tool definitions are not verified against a pinned version",
              file=sys.stderr)
    return McpGateway(guard, command, args.toolset).run()


if __name__ == "__main__":
    sys.exit(main())
