"""MambaGuard verdict client — the one piece of plumbing every Aegis
wrapper shares. Submits an envelope to the RobustIDPS.ai backend scanner
and turns the response into a `Verdict` the wrapper can act on.

A typical envelope:
    {
        "input_kind": "system_prompt",
        "text": "<the thing being checked>",
        "context": {"agent_id": "...", "tool_name": "..."},
    }

The client is synchronous and timeout-bounded so it can be dropped into
any framework's hook callback without async-context surprise.
"""
from __future__ import annotations

import enum
import os
from dataclasses import dataclass, field
from typing import Any

import httpx


class VerdictDecision(str, enum.Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass
class Verdict:
    decision: VerdictDecision
    n_findings: int = 0
    severity_breakdown: dict[str, int] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.decision is VerdictDecision.BLOCK


class MambaGuardClient:
    DEFAULT_TIMEOUT_S = 2.0

    def __init__(
        self,
        api_base: str | None = None,
        api_key: str | None = None,
        block_on_severities: tuple[str, ...] = ("critical", "high"),
        warn_on_severities: tuple[str, ...] = ("medium",),
        timeout_s: float | None = None,
    ):
        self.api_base = (api_base or os.getenv("ROBUSTIDPS_API_BASE", "http://localhost:8000")).rstrip("/")
        self.api_key = api_key or os.getenv("ROBUSTIDPS_API_KEY")
        self.block_on = set(block_on_severities)
        self.warn_on = set(warn_on_severities)
        self.timeout_s = timeout_s or self.DEFAULT_TIMEOUT_S

    def check(self, text: str, input_kind: str = "system_prompt",
              context: dict[str, Any] | None = None) -> Verdict:
        if not text or not text.strip():
            return Verdict(decision=VerdictDecision.ALLOW)
        url = f"{self.api_base}/api/agent-studio/scanner/run"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = {"text": text[:50_000], "input_kind": input_kind}
        try:
            with httpx.Client(timeout=self.timeout_s) as client:
                resp = client.post(url, json=body, headers=headers)
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            # Network-fault tolerance: allow by default, surface the error
            return Verdict(decision=VerdictDecision.ALLOW, raw={"error": str(e), "context": context or {}})
        severity = data.get("severity_breakdown", {}) or {}
        if any(severity.get(s, 0) > 0 for s in self.block_on):
            decision = VerdictDecision.BLOCK
        elif any(severity.get(s, 0) > 0 for s in self.warn_on):
            decision = VerdictDecision.WARN
        else:
            decision = VerdictDecision.ALLOW
        return Verdict(
            decision=decision,
            n_findings=data.get("n_findings", 0),
            severity_breakdown=severity,
            findings=[r for r in data.get("results", []) if r.get("triggered")],
            raw=data,
        )
