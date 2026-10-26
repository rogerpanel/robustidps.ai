"""Internal evaluations: built-in labelled suites, layer ablations, before/after comparisons with earlier policy
versions (frozen from git history), the predictive layer, policy authoring and the calibrated-deferral guarantee.

The built-in suites were written alongside the policy packs: they are regression tests and case studies, not an
independent benchmark (that is agentdojo_eval.py).

    PYTHONPATH=backend python research/agent-guard-bench/harness/internal_eval.py
"""
from __future__ import annotations

import os as _os
# Isolation: the harness never uses a database. Pin an in-memory one before any backend import, so that the
# backend's config (which loads the repository's .env) can never point it at a production database.
_os.environ["DATABASE_URL"] = "sqlite://"  # AGBENCH_ISOLATE

import json
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FROZEN = ROOT / "data" / "frozen_policies"
OUT = ROOT / "results" / "internal_results.json"


def main() -> int:
    from plugins.agent_guard import authoring
    from plugins.agent_guard.contract import FILTER_VERSION
    from plugins.agent_guard.deferral import calibrate
    from plugins.agent_guard.evaluation import builtin_suites, compare, run
    from plugins.agent_guard.policy import builtin_policies, parse_policy

    started = time.time()
    P, S = builtin_policies(), builtin_suites()
    frozen = {p.stem: parse_policy(json.loads(p.read_text())) for p in sorted(FROZEN.glob("*.json"))}
    res: dict = {"meta": {"filter_version": FILTER_VERSION,
                          "policies": {k: v.version for k, v in P.items()},
                          "suites": {k: {"version": v.version, "cases": len(v.cases)} for k, v in S.items()}}}

    # 1. Every built-in suite on its pack, with single-layer ablations and the two trivial baselines.
    res["suites"] = {}
    for sid, suite in S.items():
        if sid.startswith("org-coding"):
            continue
        c = compare(suite, P[suite.policy_id])
        full = run(suite, P[suite.policy_id])["summary"]
        res["suites"][sid] = {"policy": c["policy"], "cases": c["cases"], "sessions": full["sessions"],
                              "invariance_groups": full["groups"], "invariance_violations": full["invariance_violations"],
                              "table": [{k: r[k] for k in ("name", "kind", "exact_accuracy", "stop_recall",
                                                           "false_stop_rate", "intervention_rate", "reason_accuracy",
                                                           "ci95")} for r in c["table"]],
                              "comparison_digest": c["comparison_digest"]}

    # 2. Before/after with earlier versions of the same packs (current engine).
    def summary(suite_id, policy):
        r = run(S[suite_id], policy)["summary"]
        return {k: r[k] for k in ("policy", "exact_accuracy", "stop_recall", "false_stop_rate", "reason_accuracy",
                                  "confusion")}
    res["before_after"] = {
        "session-flow-soc": {"before": summary("session-flow-soc", frozen["soc-triage-v3"]),
                             "after": summary("session-flow-soc", P["soc-triage"])},
        "typed-actions-soc": {"before": summary("typed-actions-soc", frozen["soc-triage-v4"]),
                              "after": summary("typed-actions-soc", P["soc-triage"])},
        "typed-actions-testing": {"before": summary("typed-actions-testing", frozen["authorised-testing-v2"]),
                                  "after": summary("typed-actions-testing", P["authorised-testing"])},
    }

    # 3. Predictive layer: where appropriate and inappropriate response actions end up, with and without it.
    soc = P["soc-triage"]
    without = soc.model_copy(update={"predictive": None})
    res["predictive"] = {name: run(S["soc-response-actions"], pol)["summary"]["appropriateness"]
                         for name, pol in (("with prediction", soc), ("without prediction", without))}

    # 4. Policy authoring on the organisation example, both strategies, checked on the held-out suite.
    res["authoring_example"] = {}
    for strategy in ("narrow", "general"):
        sg = authoring.suggest(S["org-coding-preferences"], P["mcp-general"], S["org-coding-holdout"], strategy)
        cb = sg["combined"]
        res["authoring_example"][strategy] = {
            "train_before": sg["exact_accuracy"], "holdout_before": sg["holdout"]["exact_accuracy"],
            "train_after": cb["exact_accuracy"], "holdout_after": cb["holdout"]["exact_accuracy"],
            "edits": [e["description"] for e in cb["edits"]], "failures": sg["failures"]}

    # 5. Calibrated deferral (Learn then Test): failure rate of the guarantee and how often a threshold is found,
    #    by history size. Scores ~ U(0, 6); P(denied | score) = 0.01 below 2, 0.05 in [2, 3), 0.5 above.
    def p_denied(x):
        return 0.01 if x < 2 else 0.05 if x < 3 else 0.5

    def true_rate(t):
        if t < 2:
            return 0.01
        if t < 3:
            return (0.02 + 0.05 * (t - 2)) / t
        return (0.07 + 0.5 * (t - 3)) / t

    alpha, delta, runs = 0.05, 0.1, 1000
    res["deferral_simulation"] = {"alpha": alpha, "delta": delta, "runs": runs, "seed": 20261025,
                                  "optimal_auto_share": round(1.43 / 0.45 / 6, 4), "by_grid": {}}
    for grid_name in ("every score", "deciles"):
        rng = random.Random(20261025)
        table = {}
        for n in (100, 200, 400, 800, 1600):
            ready = violations = 0
            shares = []
            for _ in range(runs):
                s = [rng.uniform(0, 6) for _ in range(n)]
                d = [rng.random() < p_denied(x) for x in s]
                cal = calibrate(s, d, alpha, 50, delta, grid=n if grid_name == "every score" else 10)
                if cal["ready"]:
                    ready += 1
                    violations += true_rate(cal["threshold"]) > alpha
                    shares.append(cal["auto_share"])
            table[str(n)] = {"ready": ready / runs, "violations": violations / runs,
                             "mean_auto_share_when_ready": (sum(shares) / len(shares)) if shares else None}
        res["deferral_simulation"]["by_grid"][grid_name] = table
    res["meta"]["seconds"] = round(time.time() - started, 1)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1, default=str))
    print(json.dumps({k: res[k] for k in ("before_after", "predictive", "authoring_example", "deferral_simulation")},
                     indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
