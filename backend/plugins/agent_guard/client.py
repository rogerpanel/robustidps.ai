#!/usr/bin/env python3
"""Agent Guard client: copy this single file into any agent project (stdlib only).

As a library:

    from client import GuardClient, GuardDenied
    guard = GuardClient("https://robustidps.ai", token="<platform token or rids_live_ key>",
                        session_id="run-42", policy_id="soc-triage")
    verdict = guard.check("isolate_host", {"host": "10.0.4.17"})
    # verdict["decision"]: allow | modify (use verdict["modified_args"]) | ask | deny

    @guard.tool                      # wraps a Python tool function
    def isolate_host(host: str): ...  # raises GuardDenied on deny / unapproved ask

As a Claude-style PreToolUse command hook (Claude Code; Hermes shell hooks
take the same JSON):

    AGENT_GUARD_URL=https://robustidps.ai AGENT_GUARD_TOKEN=... \
    python client.py hook --policy soc-triage

Every failure (network, timeout, bad response) is a deny: the agent never runs
a tool the guard did not approve.
"""
from __future__ import annotations

import argparse
import functools
import json
import os
import sys
import urllib.request
from typing import Any, Callable


class GuardDenied(RuntimeError):
    def __init__(self, verdict: dict[str, Any]):
        super().__init__("; ".join(verdict.get("reasons") or ["denied"]))
        self.verdict = verdict


class GuardClient:
    def __init__(self, base_url: str, token: str = "", session_id: str = "default",
                 policy_id: str = "soc-triage", timeout: float = 5.0,
                 approve: Callable[[str, dict, dict], bool] | None = None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.session_id = session_id
        self.policy_id = policy_id
        self.timeout = timeout
        # Called for "ask" verdicts; return True only if a human approved. Default: not approved.
        self.approve = approve or (lambda tool, args, verdict: False)

    def _post(self, path: str, body: dict) -> dict:
        req = urllib.request.Request(
            f"{self.base_url}{path}", data=json.dumps(body).encode(), method="POST",
            headers={"Content-Type": "application/json",
                     **({"Authorization": f"Bearer {self.token}"} if self.token else {})})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode())

    def check(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        try:
            verdict = self._post("/api/agent-guard/check", {
                "session_id": self.session_id, "policy_id": self.policy_id,
                "tool_name": tool_name, "args": args})
            if verdict.get("decision") not in ("allow", "modify", "ask", "deny"):
                raise ValueError("unexpected response")
            return verdict
        except Exception as exc:  # noqa: BLE001 — fail closed
            return {"decision": "deny", "reasons": [f"guard unreachable or invalid ({exc}); failing closed"]}

    def tool(self, fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(**kwargs):
            verdict = self.check(fn.__name__, kwargs)
            decision = verdict["decision"]
            if decision == "ask" and not self.approve(fn.__name__, kwargs, verdict):
                raise GuardDenied(verdict)
            if decision == "deny":
                raise GuardDenied(verdict)
            args = verdict.get("modified_args") if verdict.get("modified_args") is not None else kwargs
            return fn(**args)
        return wrapper


def _hook(policy: str) -> int:
    def deny(reason: str) -> int:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                 "permissionDecisionReason": f"Agent Guard: {reason}"}}))
        return 0
    try:
        payload = json.load(sys.stdin)
        client = GuardClient(os.environ.get("AGENT_GUARD_URL", "http://localhost:8000"),
                             os.environ.get("AGENT_GUARD_TOKEN", ""), policy_id=policy)
        answer = client._post(f"/api/agent-guard/hooks/claude?policy_id={policy}", payload)
        if answer.get("hookSpecificOutput", {}).get("permissionDecision") not in ("allow", "ask", "deny"):
            return deny("invalid guard response; failing closed")
        print(json.dumps(answer))
        return 0
    except Exception as exc:  # noqa: BLE001
        return deny(f"guard unreachable ({type(exc).__name__}); failing closed")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Agent Guard client")
    sub = ap.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hook", help="Claude-style PreToolUse command hook (stdin JSON -> stdout JSON)")
    h.add_argument("--policy", default=os.environ.get("AGENT_GUARD_POLICY", "soc-triage"))
    args = ap.parse_args()
    sys.exit(_hook(args.policy))
