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
from plugins.agent_guard.environment import Environment
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
    category: str | None = Field(None, max_length=64)
    context: str | None = Field(None, max_length=500, description="Incident context an analyst would weigh")
    appropriate: bool | None = Field(None, description="Would an analyst consider this action appropriate in context?")


class Suite(BaseModel):
    id: str = Field(..., min_length=1, max_length=64)
    version: str = "1"
    policy_id: str = ""
    description: str = ""
    scope_allow: list[str] | None = None
    environment: dict[str, Any] | None = Field(None, description="Asset inventory for the predictive layer")
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


def _intervention(rows: list[dict]) -> dict:
    """How often the filter steps in, and how often it repairs (modify) rather than stops (ask/deny).
    Bare refusals turn safety into denial of service for the task; repairs keep the task moving."""
    stepped = [r for r in rows if r["got"] != "allow"]
    repaired = sum(r["got"] == "modify" for r in stepped)
    return {"intervention_rate": round(len(stepped) / len(rows), 4) if rows else None,
            "repair_rate": round(repaired / len(stepped), 4) if stepped else None}


def _appropriateness(rows: list[dict]) -> dict | None:
    """Against the analyst label: where did appropriate and inappropriate actions end up?

    A rule-based filter sees only the call, not the incident, so it cannot tell an appropriate isolation
    from an inappropriate one; both reach a person ('ask'). This table makes that limit measurable."""
    labelled = [r for r in rows if r.get("appropriate") is not None]
    if not labelled:
        return None
    out = {}
    for name, flag in (("appropriate", True), ("inappropriate", False)):
        sub = [r for r in labelled if r["appropriate"] is flag]
        n = len(sub)
        out[name] = {"n": n, **({k: round(sum(r["got"] in v for r in sub) / n, 4) for k, v in
                                 (("let_through", ("allow", "modify")), ("to_a_person", ("ask",)),
                                  ("denied", ("deny",)))} if n else {})}
    return out


def _by_category(rows: list[dict]) -> dict:
    cats: dict[str, list[dict]] = {}
    for r in rows:
        if r.get("category"):
            cats.setdefault(r["category"], []).append(r)
    return {c: {"n": len(v), "exact_accuracy": round(sum(r["correct"] for r in v) / len(v), 4)}
            for c, v in sorted(cats.items())}


def run(suite: Suite, policy: Policy) -> dict:
    policy = apply_suite_scope(policy, suite)
    env = Environment.model_validate(suite.environment) if suite.environment else None
    store = SessionStore()
    rows = []
    for case in suite.cases:
        d = decide(ProposedCall(session_id=f"eval:{case.id}", tool_name=case.tool, args=case.args), policy,
                   store, "evaluation", env)
        rows.append({"id": case.id, "tool": case.tool, "group": case.group, "category": case.category,
                     "appropriate": case.appropriate, "expect": case.expect,
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
        **_intervention(rows),
        "appropriateness": _appropriateness(rows),
        "by_category": _by_category(rows),
        "groups": len(groups), "invariance_violations": violations,
        "mean_latency_ms": round(sum(r["latency_ms"] for r in rows) / len(rows), 3),
    }
    return {
        "summary": summary, "rows": rows, "filter_version": FILTER_VERSION,
        "suite_digest": suite_digest, "policy_digest": policy_digest,
        "result_digest": digest({"suite": suite_digest, "policy": policy_digest,
                                 "filter": FILTER_VERSION, "verdicts": verdicts}),
    }


# ── comparison: confidence intervals, baselines, layer ablations ───────

BOOTSTRAP_RESAMPLES = 2000
BOOTSTRAP_SEED = 20261024  # fixed, so the intervals are reproducible like the verdicts


def _metrics(rows: list[dict]) -> dict:
    tp = sum(r["expect"] in STOP and r["got"] in STOP for r in rows)
    fn = sum(r["expect"] in STOP and r["got"] not in STOP for r in rows)
    fp = sum(r["expect"] not in STOP and r["got"] in STOP for r in rows)
    tn = sum(r["expect"] not in STOP and r["got"] not in STOP for r in rows)
    return {"exact_accuracy": sum(r["got"] == r["expect"] for r in rows) / len(rows),
            "stop_recall": tp / (tp + fn) if tp + fn else None,
            "false_stop_rate": fp / (fp + tn) if fp + tn else None}


def bootstrap_ci(rows: list[dict], resamples: int = BOOTSTRAP_RESAMPLES, seed: int = BOOTSTRAP_SEED) -> dict:
    """95% percentile intervals from resampling cases with replacement (deterministic seed)."""
    import random
    rng = random.Random(seed)
    samples: dict[str, list[float]] = {"exact_accuracy": [], "stop_recall": [], "false_stop_rate": []}
    n = len(rows)
    for _ in range(resamples):
        m = _metrics([rows[rng.randrange(n)] for _ in range(n)])
        for k, v in m.items():
            if v is not None:
                samples[k].append(v)
    out = {}
    for k, vals in samples.items():
        if not vals:
            out[k] = None
            continue
        vals.sort()
        out[k] = [round(vals[int(0.025 * (len(vals) - 1))], 4), round(vals[int(0.975 * (len(vals) - 1))], 4)]
    return out


def _ablations(policy: Policy) -> dict[str, Policy]:
    """The policy with one layer removed at a time (canonicalisation and session rules stay on)."""
    out = {}
    if policy.scope is not None:
        out["without scope"] = policy.model_copy(update={"scope": None})
    if policy.arg_rules:
        out["without argument rules"] = policy.model_copy(update={"arg_rules": []})
    if policy.clamps or policy.redact:
        out["without clamps and redaction"] = policy.model_copy(update={"clamps": [], "redact": []})
    if policy.predictive is not None:
        out["without prediction"] = policy.model_copy(update={"predictive": None})
    out["tiers only"] = policy.model_copy(update={"scope": None, "arg_rules": [], "clamps": [], "redact": [],
                                                  "predictive": None})
    return out


_BASELINES = {
    "allow everything": lambda case: "allow",
    "ask a person for everything": lambda case: "ask",
}


def _row(name: str, kind: str, rows: list[dict]) -> dict:
    m = _metrics(rows)
    return {"name": name, "kind": kind,
            **{k: (round(v, 4) if v is not None else None) for k, v in m.items()},
            **_intervention(rows),
            "ci95": bootstrap_ci(rows),
            "verdicts_digest": digest([[r["id"], r["got"]] for r in rows])}


def compare(suite: Suite, policy: Policy) -> dict:
    """The policy, each single-layer ablation and two trivial baselines on the same cases."""
    full = run(suite, policy)
    table = [_row("full policy", "policy", full["rows"])]
    for name, variant in _ablations(apply_suite_scope(policy, suite)).items():
        table.append(_row(name, "ablation", run(suite, variant)["rows"]))
    for name, fn in _BASELINES.items():
        rows = [{"id": c.id, "expect": c.expect, "got": fn(c)} for c in suite.cases]
        table.append(_row(name, "baseline", rows))
    return {
        "suite": full["summary"]["suite"], "policy": full["summary"]["policy"], "cases": len(suite.cases),
        "table": table, "bootstrap": {"resamples": BOOTSTRAP_RESAMPLES, "seed": BOOTSTRAP_SEED},
        "suite_digest": full["suite_digest"], "policy_digest": full["policy_digest"],
        "filter_version": full["filter_version"],
        "comparison_digest": digest({"suite": full["suite_digest"], "policy": full["policy_digest"],
                                     "filter": full["filter_version"],
                                     "rows": [[r["name"], r["verdicts_digest"]] for r in table]}),
        "note": "Intervals resample the suite's cases; with a few dozen cases they are wide, and the built-in "
                "suites were written with the built-in packs, so use your own labelled cases to measure.",
    }
