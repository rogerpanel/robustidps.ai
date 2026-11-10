"""Paired analysis of live-model runs (results/live/<run>/summary.json and decisions.jsonl).

For every run that contains the no-filter condition and a filter condition, on the same tasks and attacks:

  paired tests   exact McNemar tests for utility (per user task) and attack success (per task x attack pair):
                 only discordant pairs count, so model variance on tasks both conditions solve or fail cancels;
  attribution    of legitimate tasks solved without the filter but not with it, how many had a call the filter
                 sent to a person or refused (and which rules), the rest being model variance; of attacks that
                 succeeded without the filter but not with it, how many met a filter decision on the way;
  overhead       the filter's per-call check time (in process, or the round trip to a deployed service) and the
                 tokens per agent run in each condition.

Runs are single samples per task: the paired tests are the right comparison, and discordant counts are reported
so a reader can see how much rests on few tasks.

    python research/agent-guard-bench/harness/live_analysis.py
"""
from __future__ import annotations

import json
import math
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIVE = ROOT / "results" / "live"


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value from the discordant counts b and c."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def _decisions(path: Path) -> dict:
    """{condition: {(suite, user_task, injection_task or None): [decisions]}}"""
    out: dict = defaultdict(lambda: defaultdict(list))
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        d = json.loads(line)
        inj = d.get("injection_task")
        out[d["condition"]][(d.get("suite"), d.get("user_task"), None if inj in (None, "None") else inj)].append(d)
    return out


def _runs_per_condition(plan: dict) -> int:
    return sum(len(p["user_tasks"]) + len(p["user_tasks"]) * len(p["injection_tasks"]) + len(p["injection_tasks"])
               for p in plan.values())


def analyse_run(summary: dict, decisions: dict) -> dict:
    res = summary["results"]
    out = {"provider": summary["meta"]["provider"], "model": summary["meta"]["model"],
           "guard": summary["meta"]["guard"], "comparisons": {}, "overhead": {}}
    runs = _runs_per_condition(summary["plan"])
    for cond, usage in (summary.get("usage") or {}).items():
        tokens = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
        out["overhead"].setdefault(cond, {})["tokens_per_run"] = round(tokens / runs) if runs else None
        out["overhead"][cond]["requests_per_run"] = round(usage.get("requests", 0) / runs, 2) if runs else None
    for cond, per in decisions.items():
        ms = sorted(d.get("check_ms") for ds in per.values() for d in ds if d.get("check_ms") is not None)
        if ms:
            out["overhead"].setdefault(cond, {}).update(
                {"checks": len(ms), "check_ms_median": statistics.median(ms),
                 "check_ms_p95": ms[int(0.95 * (len(ms) - 1))]})
    if "none" not in res:
        return out
    base = res["none"]
    for cond in [c for c in res if c != "none"]:
        cur = res[cond]
        b_u = c_u = 0
        lost, lost_blocked, lost_rules = [], 0, Counter()
        b_a = c_a = 0
        stopped, stopped_at_filter = [], 0
        both_tasks = both_pairs = 0
        for suite in base:
            if suite not in cur:
                continue
            for task, ok0 in base[suite]["utility"].items():
                if task not in cur[suite]["utility"]:
                    continue
                both_tasks += 1
                ok1 = cur[suite]["utility"][task]
                if ok0 and not ok1:
                    b_u += 1
                    lost.append(f"{suite}/{task}")
                    ds = decisions.get(cond, {}).get((suite, task, None), [])
                    hits = [d for d in ds if d["decision"] in ("ask", "deny")]
                    if hits:
                        lost_blocked += 1
                        lost_rules.update(r for d in hits for r in (d.get("rules") or [d["decision"]]))
                elif ok1 and not ok0:
                    c_u += 1
            for pair, s0 in base[suite]["attack_success"].items():
                if pair not in cur[suite]["attack_success"]:
                    continue
                both_pairs += 1
                s1 = cur[suite]["attack_success"][pair]
                if s0 and not s1:
                    b_a += 1
                    stopped.append(f"{suite}/{pair}")
                    task, inj = pair.split("|", 1)
                    ds = decisions.get(cond, {}).get((suite, task, inj), [])
                    if any(d["decision"] in ("ask", "deny") for d in ds):
                        stopped_at_filter += 1
                elif s1 and not s0:
                    c_a += 1
        out["comparisons"][cond] = {
            "tasks": both_tasks, "pairs": both_pairs,
            "utility_lost": b_u, "utility_gained": c_u, "utility_p": round(mcnemar_exact(b_u, c_u), 4),
            "utility_lost_with_filter_decision": lost_blocked, "utility_lost_rules": dict(lost_rules.most_common(10)),
            "attacks_stopped": b_a, "attacks_newly_succeeding": c_a, "attack_p": round(mcnemar_exact(b_a, c_a), 4),
            "attacks_stopped_at_filter_decision": stopped_at_filter,
            "examples": {"utility_lost": lost[:10], "attacks_stopped": stopped[:10]}}
    return out


def main(include_test_runs: bool = False) -> dict:
    analyses = []
    for summ in sorted(LIVE.glob("*/summary.json")):
        s = json.loads(summ.read_text())
        if not include_test_runs and (s["meta"].get("smoke") or s["meta"]["provider"] == "groundtruth"):
            continue
        a = analyse_run(s, _decisions(summ.parent / "decisions.jsonl"))
        a["run"] = summ.parent.name
        analyses.append(a)
    LIVE.mkdir(parents=True, exist_ok=True)
    (LIVE / "live_analysis.json").write_text(json.dumps({"runs": analyses}, indent=1))
    for a in analyses:
        for cond, c in a["comparisons"].items():
            print(f"{a['model']:28} none vs {cond:13} utility -{c['utility_lost']}/+{c['utility_gained']} "
                  f"(p={c['utility_p']}), attacks stopped {c['attacks_stopped']}/new {c['attacks_newly_succeeding']} "
                  f"(p={c['attack_p']}); lost tasks with a filter decision {c['utility_lost_with_filter_decision']}")
    return {"runs": analyses}


if __name__ == "__main__":
    main("--include-test-runs" in sys.argv)
