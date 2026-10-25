"""The decision contract: what an agent sends before a tool call, and what it gets back.

The semantics follow the pre-execution hooks that agent harnesses converge on
(Claude-style PreToolUse, Hermes pre_tool_call, OpenHands security analyzers),
so one filter serves every harness through thin adapters (adapters.py).
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

FILTER_VERSION = "0.2.0"

Verdict = Literal["allow", "modify", "ask", "deny"]
Risk = Literal["LOW", "MEDIUM", "HIGH", "UNKNOWN"]

# Worst verdict wins when layers disagree.
SEVERITY: dict[str, int] = {"allow": 0, "modify": 1, "ask": 2, "deny": 3}
RISK_OF: dict[str, str] = {"allow": "LOW", "modify": "MEDIUM", "ask": "HIGH", "deny": "HIGH"}


class ProposedCall(BaseModel):
    """One tool call the agent wants to make, sent before it runs."""
    session_id: str = Field(..., min_length=1, max_length=128,
                            description="Groups calls of one agent run; state (budgets, denials) is per session")
    tool_name: str = Field(..., min_length=1, max_length=256)
    args: dict[str, Any] = Field(default_factory=dict)
    agent_id: str = Field("", max_length=128, description="Shown in the runtime monitor; defaults to the session")
    framework: str = Field("", max_length=64, description="e.g. claude, hermes, openhands, langgraph, custom")


class Finding(BaseModel):
    rule_id: str
    verdict: Verdict
    reason: str


class Decision(BaseModel):
    decision: Verdict
    risk: Risk
    reasons: list[str]
    findings: list[Finding] = Field(default_factory=list)
    modified_args: dict[str, Any] | None = None
    tool_name: str = ""
    canonical_tool: str = ""
    tier: str = ""
    hidden_characters: list[str] = Field(default_factory=list)
    session_calls: int = 0
    policy_id: str = ""
    policy_version: str = ""
    filter_version: str = FILTER_VERSION
    latency_ms: float = 0.0
    call_key: str = Field("", description="Digest of the canonical call; approvals and sticky denials bind to it")
    approval_id: str | None = Field(None, description="Set on 'ask': poll /approvals/{id}, then repeat the call with it")
    prediction: dict[str, Any] | None = Field(None, description="Predicted effect on the environment (L2), if evaluated")
    deferral: dict[str, Any] | None = Field(None, description="Calibrated-deferral assessment of an 'ask'")
