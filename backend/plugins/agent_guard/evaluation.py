"""Evaluate a policy on a labelled suite of calls, with a verifiable result.

Each case runs in its own session, so cases do not affect each other. Labels
are exact verdicts; for detection metrics, ask and deny count as "stop"
(positive) and allow and modify as "permit". Cases sharing a `group` differ
only in names an attacker controls (files, processes, accounts, hosts) or in
the agent's stated rationale, and must receive the same verdict.

The filter is deterministic, so a result is fully identified by the suite,
the policy and the filter version: result_digest covers all three digests and
every verdict. Anyone can re-run the same suite and policy and compare.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from plugins.agent_guard.contract import FILTER_VERSION, ProposedCall
from plugins.agent_guard.engine import SessionStore, decide
from plugins.agent_guard.evidence import digest
from plugins.agent_guard.policy import Policy

SUITE_DIR = Path(__file__).parent / "suites"
MAX_CASES = 500
STOP = {"ask", "deny"}


class Case(BaseModel):
    id: str = Field(..., min_length=1, max_length=64)
    tool: str = Field(..., min_length=1, max_length=256)
    args: dict[str, Any] = Field(default_factory=dict)
    expect: Literal["allow", "modify", "ask", "deny"]
    group: str | None = Field(None, max_length=64)


class Suite(BaseModel):
    id: str = Field(..., min_length=1, max_length=64)
    version: str = "1"
    policy_id: str = ""
    description: str = ""
    scope_allow: list[str] | None = None
    cases: list[Case] = Field(..., min_length=1, max_length=MAX_CASES)


_BUILTIN: dict[str, Suite] = {}


def builtin_suites() -> dict[str, Suite]:
    if not _BUILTIN:
        for path in sorted(SUITE_DIR.glob("*.json")):
            suite = Suite.model_validate(json.loads(path.read_text(encoding="utf-8")))
            _BUILTIN[suite.id] = suite
    return _BUILTIN


def apply_suite_scope(policy: Policy, suite: Suite) -> Policy:
    """A suite may fix the scope for its run (the authorised-testing pack ships with an empty one)."""
    if suite.scope_allow is None or policy.scope is None:
        return policy
    return policy.model_copy(update={"scope": policy.scope.model_copy(update={"allow": list(suite.scope_allow)})})


def run(suite: Suite, policy: Policy) -> dict:
    policy = apply_suite_scope(policy, suite)
    store = SessionStore()
    rows = []
    for case in suite.cases:
        d = decide(ProposedCall(session_id=f"eval:{case.id}", tool_name=case.tool, args=case.args), policy,
                   store, "evaluation")
        rows.append({"id": case.id, "tool": case.tool, "group": case.group, "expect": case.expect,
                     "got": d.decision, "correct": d.decision == case.expect,
                     "rules": [f.rule_id for f in d.findings if f.verdict == d.decision],
                     "latency_ms": d.latency_ms})

    tp = sum(r["expect"] in STOP and r["got"] in STOP for r in rows)
    fn = sum(r["expect"] in STOP and r["got"] not in STOP for r in rows)
    fp = sum(r["expect"] not in STOP and r["got"] in STOP for r in rows)
    tn = sum(r["expect"] not in STOP and r["got"] not in STOP for r in rows)
    groups: dict[str, set[str]] = {}
    for r in rows:
        if r["group"]:
            groups.setdefault(r["group"], set()).add(r["got"])
    violations = sorted(g for g, verdicts in groups.items() if len(verdicts) > 1)

    suite_digest = digest(suite.model_dump())
    policy_digest = digest(policy.model_dump())
    verdicts = [[r["id"], r["got"]] for r in rows]
    summary = {
        "suite": f"{suite.id} v{suite.version}", "policy": f"{policy.id} v{policy.version}",
        "cases": len(rows), "exact_accuracy": round(sum(r["correct"] for r in rows) / len(rows), 4),
        "stop_recall": round(tp / (tp + fn), 4) if tp + fn else None,
        "false_stop_rate": round(fp / (fp + tn), 4) if fp + tn else None,
        "confusion": {"tp": tp, "fn": fn, "fp": fp, "tn": tn},
        "groups": len(groups), "invariance_violations": violations,
        "mean_latency_ms": round(sum(r["latency_ms"] for r in rows) / len(rows), 3),
    }
    return {
        "summary": summary, "rows": rows, "filter_version": FILTER_VERSION,
        "suite_digest": suite_digest, "policy_digest": policy_digest,
        "result_digest": digest({"suite": suite_digest, "policy": policy_digest,
                                 "filter": FILTER_VERSION, "verdicts": verdicts}),
    }
