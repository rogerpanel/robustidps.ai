"""Unit tests for the live-run analysis (pytest research/agent-guard-bench/harness/test_live_analysis.py)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from live_analysis import analyse_run, mcnemar_exact  # noqa: E402


def test_mcnemar_exact():
    assert mcnemar_exact(0, 0) == 1.0
    assert abs(mcnemar_exact(10, 0) - 2 / 1024) < 1e-12
    assert abs(mcnemar_exact(8, 2) - 2 * 56 / 1024) < 1e-12
    assert mcnemar_exact(5, 5) == 1.0


def test_paired_comparison_and_attribution():
    summary = {
        "meta": {"provider": "anthropic", "model": "m", "guard": "local"},
        "plan": {"banking": {"user_tasks": ["user_task_0", "user_task_1"], "injection_tasks": ["injection_task_0"]}},
        "usage": {"none": {"input_tokens": 500, "output_tokens": 100, "requests": 10},
                  "guard": {"input_tokens": 400, "output_tokens": 80, "requests": 8}},
        "results": {
            "none": {"banking": {"utility": {"user_task_0": True, "user_task_1": True},
                                 "attack_success": {"user_task_0|injection_task_0": True,
                                                    "user_task_1|injection_task_0": True}}},
            "guard": {"banking": {"utility": {"user_task_0": False, "user_task_1": True},
                                  "attack_success": {"user_task_0|injection_task_0": False,
                                                     "user_task_1|injection_task_0": False}}}}}
    decisions = {"guard": {("banking", "user_task_0", None): [{"decision": "ask", "rules": ["tier:change"], "check_ms": 0.4}],
                           ("banking", "user_task_0", "injection_task_0"): [{"decision": "deny", "rules": ["x"], "check_ms": 0.5}]}}
    a = analyse_run(summary, decisions)
    c = a["comparisons"]["guard"]
    assert (c["utility_lost"], c["utility_gained"], c["utility_lost_with_filter_decision"]) == (1, 0, 1)
    assert c["utility_lost_rules"] == {"tier:change": 1}
    assert (c["attacks_stopped"], c["attacks_stopped_at_filter_decision"]) == (2, 1)
    assert a["overhead"]["none"]["tokens_per_run"] == 120          # 600 tokens / 5 runs (2 + 2 + 1)
    assert a["overhead"]["guard"]["check_ms_median"] == 0.45
