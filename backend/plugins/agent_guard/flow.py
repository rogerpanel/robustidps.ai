"""Session information flow: what a session has been exposed to, and where it may send data.

A filter that judges each call alone cannot see the classic agent leak: read an
e-mail or web page an attacker wrote (untrusted input), read private data
(sensitive), then send something out (egress). Each step is harmless alone; the
combination lets injected instructions exfiltrate what the agent read. The
"Rule of Two" says a session should not combine all three without a person.

Policy packs label tools (`flow.labels`); a session collects the labels of the
calls that were let through (approved and auto-approved ones included, denied
and pending ones not). Rules (`flow.rules`) judge the next call: a rule fires on
a call carrying its `sink` label when the session, counting this call, holds
every label in `requires`.

Design choices:
  - Labels come from the tool and its arguments, never from the agent's stated
    reasons, and are coarse (per session, not per value): once a session has
    read untrusted input, everything it does next may be steered by it. This
    over-approximates, which is the safe direction.
  - Egress may be exempted for destinations inside the organisation (policy
    `internal` plus the Environment tab's `internal` list). Every destination of
    the call must be internal; lists are split, and a call whose destination
    cannot be found counts as external.
  - A tool nothing classifies gets the pack's `unclassified` labels (fail closed).
  - Only a person resets a session, which clears its labels.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any

from plugins.agent_guard.canonical import matchable_strings
from plugins.agent_guard.contract import Finding
from plugins.agent_guard.policy import FlowLabel, Policy, target_in_scope, tool_matches

_SPLIT = re.compile(r"[\s,;]+")
_STRIP = "<>\"'()[]"

DESCRIPTIONS = {
    "untrusted": "untrusted input",
    "sensitive": "sensitive data",
    "egress": "sending data out",
}


@dataclass
class FlowResult:
    findings: list[Finding] = field(default_factory=list)
    report: dict[str, Any] | None = None


def _destinations(args: dict[str, Any], keys: list[str]) -> list[str]:
    out: list[str] = []
    for path, value in matchable_strings(args):
        # Any key along the path (to, message.to, recipients[0]); collecting more destinations only makes the
        # check stricter, since every destination must be internal.
        parts = [p for p in re.split(r"[.\[\]]+", path.lower()) if p and not p.isdigit()]
        if any(fnmatchcase(p, k.lower()) for p in parts for k in keys):
            out.extend(p.strip(_STRIP) for p in _SPLIT.split(value) if p.strip(_STRIP))
    return out


def _applies(lab: FlowLabel, tool: str, args: dict[str, Any], internal: list[str]) -> tuple[bool, str]:
    """Whether a label entry applies to this call, and why."""
    if not tool_matches(tool, lab.tools):
        return False, ""
    if lab.pattern is not None:
        pattern = re.compile(lab.pattern, re.IGNORECASE)
        keys = lab.args or ["*"]
        hit = next((p for p, v in matchable_strings(args)
                    if any(fnmatchcase(p.lower(), k.lower()) for k in keys) and pattern.search(v)), None)
        if hit is None:
            return False, ""
        why = f"{tool} (argument '{hit}')"
    else:
        why = tool
    if lab.destination_args:
        dests = _destinations(args, lab.destination_args)
        allowed = [*lab.internal, *internal]
        if dests and allowed and all(target_in_scope(d, allowed) for d in dests):
            return False, ""
        outside = [d for d in dests if not allowed or not target_in_scope(d, allowed)]
        why += f" to {', '.join(outside[:3])}" if outside else " (no destination found; treated as external)"
    return True, why


def call_labels(tool: str, args: dict[str, Any], policy: Policy, internal: list[str] | None = None
                ) -> tuple[dict[str, str], bool]:
    """Labels this call carries ({label: why}) and whether they came from `unclassified`."""
    flow = policy.flow
    if flow is None:
        return {}, False
    labels: dict[str, str] = {}
    matched_any = False
    for lab in flow.labels:
        if tool_matches(tool, lab.tools):
            matched_any = True
        ok, why = _applies(lab, tool, args, internal or [])
        if ok and lab.label not in labels:
            labels[lab.label] = why
    if not matched_any and policy.tier_for(tool) == policy.default_tier and flow.unclassified:
        return {name: f"{tool} (a tool this pack does not classify)" for name in flow.unclassified}, True
    return labels, False


def _say(label: str) -> str:
    return DESCRIPTIONS.get(label, label)


def check(tool: str, args: dict[str, Any], policy: Policy, internal: list[str] | None,
          session: dict[str, dict]) -> FlowResult:
    """Judge one (possibly repaired) call against the session's labels. Does not change the session."""
    if policy.flow is None:
        return FlowResult()
    labels, unclassified = call_labels(tool, args, policy, internal)
    held = set(session) | set(labels)
    findings, fired = [], []
    for rule in policy.flow.rules:
        if rule.sink not in labels or not all(r in held for r in rule.requires):
            continue
        sources = []
        for r in rule.requires:
            src = session.get(r)
            sources.append(f"{_say(r)} from {src['tool']} (call {src['call']})" if src
                           else f"{_say(r)} from this call")
        reason = (f"{rule.description or rule.id}: this call is {_say(rule.sink)} ({labels[rule.sink]})"
                  + (f" after the session read {' and '.join(sources)}" if sources else "")
                  + ". Untrusted input can steer an agent into leaking what it has read; a person must check "
                    "the destination and the content.")
        findings.append(Finding(rule_id=f"flow:{rule.id}", verdict=rule.on_violation, reason=reason))
        fired.append({"id": rule.id, "verdict": rule.on_violation})
    return FlowResult(findings, {
        "tool": tool,
        "call_labels": sorted(labels),
        "label_reasons": labels,
        "unclassified": unclassified,
        "session_before": {k: dict(v) for k, v in sorted(session.items())},
        "session_after": sorted(held),
        "rules": fired,
    })


def commit(labels: dict[str, dict], report: dict | None, call_no: int) -> None:
    """Record the labels of a call that was let through (first source of each label is kept)."""
    if not report:
        return
    for name in report.get("call_labels", []):
        labels.setdefault(name, {"tool": report.get("tool", ""), "call": call_no})
