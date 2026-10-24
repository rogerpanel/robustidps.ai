"""L1 evaluation of a proposed call against a policy pack, with session state.

Fail-closed by construction:
  - any exception while deciding is a deny (decide());
  - a call identical to one already denied in the session is denied again;
    only a reset of the session (a human decision) or a new policy version
    unlocks it, and repeats count towards escalation;
  - after `escalate_after_denials` denied attempts, calls that would be
    allowed need approval instead;
  - a second check for the same session that cannot start within
    LOCK_WAIT_S is denied rather than run concurrently.
The API adds a timeout around decide(); a timeout is a deny as well.

Session state lives in this process (bounded, expiring). Run one backend
worker for the guard, or move SessionStore to Redis before scaling out.
"""
from __future__ import annotations

import re
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any

from plugins.agent_guard.canonical import (
    call_key, canonical_tool, clean_value, matchable_strings, stable_json,
)
from plugins.agent_guard.contract import (
    Decision, Finding, ProposedCall, RISK_OF, SEVERITY,
)
from plugins.agent_guard.policy import Policy, project_target, target_in_scope, tool_matches

LOCK_WAIT_S = 1.0
MAX_SESSIONS = 5000
SESSION_TTL_S = 24 * 3600
LOG_SIZE = 500


@dataclass
class SessionState:
    calls: int = 0
    denied_attempts: int = 0
    denied_keys: set[str] = field(default_factory=set)
    budget_used: dict[str, float] = field(default_factory=dict)
    last_seen: float = field(default_factory=time.time)
    lock: threading.Lock = field(default_factory=threading.Lock)


class SessionStore:
    """Per (customer, session) state; least recently used sessions expire first."""

    def __init__(self, max_sessions: int = MAX_SESSIONS, ttl_s: float = SESSION_TTL_S):
        self._data: OrderedDict[tuple[str, str], SessionState] = OrderedDict()
        self._max = max_sessions
        self._ttl = ttl_s
        self._mutex = threading.Lock()

    def get(self, customer_id: str, session_id: str) -> SessionState:
        key = (customer_id, session_id)
        now = time.time()
        with self._mutex:
            while self._data:
                oldest_key, oldest = next(iter(self._data.items()))
                if len(self._data) < self._max and now - oldest.last_seen < self._ttl:
                    break
                del self._data[oldest_key]
            state = self._data.pop(key, None) or SessionState()
            state.last_seen = now
            self._data[key] = state
            return state

    def reset(self, customer_id: str, session_id: str) -> bool:
        with self._mutex:
            return self._data.pop((customer_id, session_id), None) is not None


class DecisionLog:
    """Recent decisions per customer, for the test page and audits."""

    def __init__(self, size: int = LOG_SIZE):
        self._logs: dict[str, deque] = {}
        self._size = size
        self._mutex = threading.Lock()

    def add(self, customer_id: str, entry: dict) -> None:
        with self._mutex:
            self._logs.setdefault(customer_id, deque(maxlen=self._size)).append(entry)

    def list(self, customer_id: str, session_id: str | None = None, limit: int = 100) -> list[dict]:
        with self._mutex:
            items = list(self._logs.get(customer_id, ()))
        if session_id:
            items = [e for e in items if e.get("session_id") == session_id]
        return items[-limit:][::-1]


@dataclass
class Canonical:
    tool: str
    args: dict[str, Any]
    hidden: list[str]
    hidden_in_tool: bool
    key: str


def canonicalize(call: ProposedCall, policy: Policy) -> Canonical:
    """L0 form of a call; `key` identifies the same call under the same policy version."""
    tool, hidden_in_tool = canonical_tool(call.tool_name)
    hidden: list[str] = []
    args: dict[str, Any] = clean_value(call.args, "", hidden)
    if hidden_in_tool:
        hidden.insert(0, f"tool_name: {', '.join(sorted(set(hidden_in_tool)))}")
    return Canonical(tool, args, hidden, bool(hidden_in_tool),
                     call_key(policy.id, policy.version, tool, stable_json(args)))


def evaluate(call: ProposedCall, policy: Policy, state: SessionState) -> Decision:
    """Judge one call. Mutates the session state (counts, denials)."""
    started = time.perf_counter()
    findings: list[Finding] = []

    c = canonicalize(call, policy)
    tool, args, hidden, key = c.tool, c.args, c.hidden, c.key
    if c.hidden_in_tool:
        findings.append(Finding(rule_id="hidden-characters-tool", verdict="deny",
                                reason="The tool name contains hidden characters; what a reviewer sees is not what runs."))
    elif hidden:
        findings.append(Finding(rule_id="hidden-characters-args", verdict="ask",
                                reason="Arguments contained hidden characters; they were removed and the cleaned call needs approval."))

    state.calls += 1
    tier = policy.tier_for(tool)

    def finish(verdict: str, modified: dict | None = None) -> Decision:
        if verdict == "deny":
            state.denied_keys.add(key)
            state.denied_attempts += 1
        decisive = [f.reason for f in findings if f.verdict == verdict]
        return Decision(
            decision=verdict, risk="HIGH" if hidden else RISK_OF[verdict],
            reasons=decisive or [f"Allowed: tier '{tier}'."],
            findings=findings, modified_args=modified if verdict in ("modify", "ask") else None,
            tool_name=call.tool_name, canonical_tool=tool, tier=tier,
            hidden_characters=hidden, session_calls=state.calls,
            policy_id=policy.id, policy_version=policy.version,
            latency_ms=round((time.perf_counter() - started) * 1000, 3), call_key=key,
        )

    if key in state.denied_keys:
        findings.append(Finding(rule_id="repeat-of-denied-call", verdict="deny",
                                reason="This exact call was already denied in this session; repeating it does not change the verdict."))
        return finish("deny")

    if policy.max_calls_per_session and state.calls > policy.max_calls_per_session:
        findings.append(Finding(rule_id="session-budget", verdict="deny",
                                reason=f"Session budget of {policy.max_calls_per_session} calls is spent."))

    t = policy.tiers[tier]
    findings.append(Finding(rule_id=f"tier:{tier}", verdict=t.decision,
                            reason=f"Tier '{tier}': {t.description or t.decision}."))

    modified = dict(args)
    changed = bool(hidden)

    if policy.scope and policy.scope.target_args:
        sc = policy.scope
        for arg_key in sc.target_args:
            value = args.get(arg_key)
            items = value if isinstance(value, list) else [value]
            targets = [str(v) for v in items
                       if isinstance(v, (str, int, float)) and not isinstance(v, bool) and str(v).strip()]
            outside = [t for t in targets if not target_in_scope(t, sc.allow)]
            if not outside:
                continue
            if sc.on_violation != "project":
                for t in outside:
                    findings.append(Finding(rule_id="out-of-scope", verdict=sc.on_violation,
                                            reason=f"Target '{t}' in '{arg_key}' is outside the agreed scope."))
                continue
            # Minimal repair: keep the in-scope part of the call, deny only if nothing in scope remains.
            if isinstance(value, list):
                kept = [v for v in value if str(v) not in outside]
                if kept:
                    modified[arg_key] = kept
                    changed = True
                    findings.append(Finding(rule_id="scope-projected", verdict="modify",
                                            reason=f"Dropped out-of-scope target(s) {', '.join(outside)} from '{arg_key}'."))
                else:
                    findings.append(Finding(rule_id="out-of-scope", verdict="deny",
                                            reason=f"No target in '{arg_key}' is inside the agreed scope."))
            else:
                narrowed = project_target(outside[0], sc.allow)
                if narrowed:
                    modified[arg_key] = narrowed
                    changed = True
                    findings.append(Finding(rule_id="scope-projected", verdict="modify",
                                            reason=f"Narrowed '{arg_key}' from {outside[0]} to the in-scope range {narrowed}."))
                else:
                    findings.append(Finding(rule_id="out-of-scope", verdict="deny",
                                            reason=f"Target '{outside[0]}' in '{arg_key}' is outside the agreed scope."))

    strings = matchable_strings(args)
    for rule in policy.arg_rules:
        if not tool_matches(tool, rule.tools):
            continue
        pattern = re.compile(rule.pattern, re.IGNORECASE)
        for path, value in strings:
            if any(fnmatchcase(path.lower(), a.lower()) for a in rule.args) and pattern.search(value):
                findings.append(Finding(rule_id=rule.id, verdict=rule.decision,
                                        reason=f"{rule.description or rule.id} (argument '{path}')."))
                break

    for red in policy.redact:
        if not tool_matches(tool, red.tools):
            continue
        for k in [k for k in modified if any(fnmatchcase(k.lower(), a.lower()) for a in red.args)]:
            del modified[k]
            changed = True
            findings.append(Finding(rule_id=red.id, verdict="modify",
                                    reason=f"Removed secret-bearing argument '{k}'."))
    for clamp in policy.clamps:
        value = modified.get(clamp.arg)
        if tool_matches(tool, clamp.tools) and isinstance(value, (int, float)) and not isinstance(value, bool) \
                and value > clamp.max:
            modified[clamp.arg] = int(clamp.max) if isinstance(value, int) else clamp.max
            changed = True
            findings.append(Finding(rule_id=clamp.id, verdict="modify",
                                    reason=f"Capped '{clamp.arg}' from {value} to {modified[clamp.arg]}."))

    # Session budgets: clip to what is left, or stop once exhausted. Charged only if the call is let through.
    charges: list[tuple[str, float]] = []
    for budget in policy.budgets:
        if not tool_matches(tool, budget.tools):
            continue
        left = budget.max_total - budget.reserve - state.budget_used.get(budget.id, 0.0)
        if budget.arg is None:
            amount = 1.0
            if left < 1:
                findings.append(Finding(rule_id=budget.id, verdict=budget.when_exhausted,
                                        reason=f"{budget.description or budget.id}: {int(budget.max_total - budget.reserve)} "
                                               "calls used in this session."))
                continue
        else:
            raw = modified.get(budget.arg)
            if not isinstance(raw, (int, float)) or isinstance(raw, bool) or raw < 0:
                findings.append(Finding(rule_id=budget.id, verdict="deny",
                                        reason=f"'{budget.arg}' must be a non-negative number for budget '{budget.id}'."))
                continue
            amount = float(raw)
            if left <= 0:
                findings.append(Finding(rule_id=budget.id, verdict=budget.when_exhausted,
                                        reason=f"{budget.description or budget.id}: nothing left in this session."))
                continue
            if amount > left:
                new = int(left) if isinstance(raw, int) else round(left, 6)
                if new <= 0:
                    findings.append(Finding(rule_id=budget.id, verdict=budget.when_exhausted,
                                            reason=f"{budget.description or budget.id}: nothing left in this session."))
                    continue
                modified[budget.arg] = new
                changed = True
                amount = float(new)
                findings.append(Finding(rule_id=budget.id, verdict="modify",
                                        reason=f"Clipped '{budget.arg}' from {raw} to the {new} left in budget '{budget.id}'."))
        charges.append((budget.id, amount))

    verdict = max((f.verdict for f in findings), key=SEVERITY.__getitem__)
    if verdict == "allow" and changed:
        verdict = "modify"
    if verdict in ("allow", "modify") and state.denied_attempts >= policy.escalate_after_denials:
        findings.append(Finding(rule_id="session-escalated", verdict="ask",
                                reason=f"{state.denied_attempts} denied attempts in this session; further calls need approval."))
        verdict = "ask"
    if verdict in ("allow", "modify"):
        for budget_id, amount in charges:
            state.budget_used[budget_id] = state.budget_used.get(budget_id, 0.0) + amount
    return finish(verdict, modified if changed else None)


def decide(call: ProposedCall, policy: Policy, store: SessionStore, customer_id: str) -> Decision:
    """evaluate() with the fail-closed guarantees described in the module docstring."""
    started = time.perf_counter()
    try:
        state = store.get(customer_id, call.session_id)
        if not state.lock.acquire(timeout=LOCK_WAIT_S):
            return deny_decision(call, policy, "Another check for this session is still running.",
                                 "concurrent-check", started)
        try:
            return evaluate(call, policy, state)
        finally:
            state.lock.release()
    except Exception as exc:  # noqa: BLE001 — any failure must be a deny
        return deny_decision(call, policy, f"The filter failed ({type(exc).__name__}); failing closed.",
                             "filter-error", started)


def deny_decision(call: ProposedCall | None, policy: Policy | None, reason: str, rule_id: str,
                  started: float | None = None) -> Decision:
    return Decision(
        decision="deny", risk="UNKNOWN", reasons=[reason],
        findings=[Finding(rule_id=rule_id, verdict="deny", reason=reason)],
        tool_name=call.tool_name if call else "",
        policy_id=policy.id if policy else "", policy_version=policy.version if policy else "",
        latency_ms=round((time.perf_counter() - started) * 1000, 3) if started else 0.0,
    )
