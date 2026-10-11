"""Score a finished investigation against a mission's expected answer.

This approximates the competition's stated criteria — quality (trace,
verdict, report artifacts) and efficiency (number of tool calls). The
weights are our own; the official formula is not published. Use the
score to compare agent versions on the same missions, not as a
prediction of the leaderboard.
"""
from __future__ import annotations

WEIGHTS = {
    "verdict": 0.35,
    "attack_techniques": 0.12,
    "affected_hosts": 0.10,
    "affected_accounts": 0.10,
    "indicators": 0.08,
    "key_events": 0.15,
    "grounding": 0.10,
}
# Efficiency scales the final score rather than adding to quality, so a
# fast wrong answer never outscores a slow right one.
EFFICIENCY_SHARE = 0.2


def _norm(items) -> set[str]:
    return {str(x).strip().lower() for x in (items or []) if str(x).strip()}


def _technique_match(a: str, b: str) -> bool:
    """T1059 and T1059.001 count as the same technique family."""
    return a == b or a.startswith(b + ".") or b.startswith(a + ".")


def _f1(predicted: set[str], expected: set[str], match=lambda a, b: a == b) -> float:
    if not expected and not predicted:
        return 1.0
    if not expected or not predicted:
        return 0.0  # missed everything, or reported findings where there were none
    tp_p = sum(any(match(p, e) for e in expected) for p in predicted)
    tp_e = sum(any(match(p, e) for p in predicted) for e in expected)
    precision, recall = tp_p / len(predicted), tp_e / len(expected)
    return 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)


def _retrieved_ids(trace: dict) -> set[str]:
    """Every event id the agent actually saw in a tool result."""
    ids: set[str] = set()

    def walk(node):
        if isinstance(node, dict):
            if "id" in node and "ts" in node:
                ids.add(str(node["id"]))
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    for step in trace.get("steps", []):
        if step.get("type") == "tool_call":
            walk(step.get("result"))
    return ids


def score(trace: dict, answer: dict | None, optimal_tool_calls: int | None) -> dict | None:
    if not answer:
        return None
    v = trace.get("verdict")
    calls = trace.get("tool_calls", 0)
    if optimal_tool_calls:
        efficiency = min(1.0, optimal_tool_calls / max(calls, 1))
    else:
        efficiency = None

    if v is None:
        return {"quality": 0.0, "efficiency": efficiency, "score": 0.0,
                "breakdown": {k: 0.0 for k in WEIGHTS}, "tool_calls": calls,
                "optimal_tool_calls": optimal_tool_calls, "note": "no verdict submitted"}

    cited = _norm([t.get("event_id") for t in v.get("timeline", [])]
                  + [i for h in v.get("hypotheses", []) for i in h.get("evidence_event_ids", [])])
    retrieved = _norm(_retrieved_ids(trace))
    key_events = _norm(answer.get("key_events"))
    timeline_ids = _norm([t.get("event_id") for t in v.get("timeline", [])])

    breakdown = {
        "verdict": 1.0 if v.get("verdict") == answer.get("verdict") else 0.0,
        "attack_techniques": _f1(_norm(v.get("attack_techniques")), _norm(answer.get("attack_techniques")),
                                 _technique_match),
        "affected_hosts": _f1(_norm(v.get("affected_hosts")), _norm(answer.get("affected_hosts"))),
        "affected_accounts": _f1(_norm(v.get("affected_accounts")), _norm(answer.get("affected_accounts"))),
        "indicators": _f1(_norm(v.get("indicators")), _norm(answer.get("indicators"))),
        "key_events": (len(key_events & timeline_ids) / len(key_events)) if key_events else 1.0,
        # Citing an event id the agent never retrieved means it was invented.
        "grounding": (len(cited & retrieved) / len(cited)) if cited else 0.0,
    }
    quality = sum(WEIGHTS[k] * breakdown[k] for k in WEIGHTS)
    eff = efficiency if efficiency is not None else 1.0
    final = 100 * quality * ((1 - EFFICIENCY_SHARE) + EFFICIENCY_SHARE * eff)
    return {"quality": round(quality, 3), "efficiency": None if efficiency is None else round(efficiency, 3),
            "score": round(final, 1), "breakdown": {k: round(x, 3) for k, x in breakdown.items()},
            "tool_calls": calls, "optimal_tool_calls": optimal_tool_calls,
            "invented_event_ids": sorted(cited - retrieved)}
