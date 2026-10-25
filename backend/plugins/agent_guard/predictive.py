"""L2: predict what a call would do to the environment, and whether a safe state remains afterwards.

The safe set is defined by the defender's inventory (environment.py): every
redundancy group keeps at least `min_available` members, and the dependents
taken down per call and per session stay under the policy's limits. A call
is admitted only if the predicted state after it is still in that set,
counting what the session has already taken down. That is the receding-
horizon idea of a predictive safety filter applied to a discrete action
space; the horizon here is the session.

Targets are resolved against the inventory only. A target the inventory does
not know has an unknown effect and is routed to a person (or allowed, if the
policy says so). Service effects matched by process name are weaker evidence
than hosts, accounts, IPs and domains, because a process can be named by
whoever started it: give such effects `on_violation: "ask"` so a look-alike
name can at most cause a review, not a refusal.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from plugins.agent_guard.contract import Finding
from plugins.agent_guard.environment import Environment
from plugins.agent_guard.policy import Effect, Policy, tool_matches

TARGET_KEYS: dict[str, tuple[str, ...]] = {
    "host": ("host", "hosts", "hostname", "target", "targets", "device", "endpoint", "vm"),
    "account": ("account", "accounts", "user", "users", "username", "principal"),
    "ip": ("ip", "ips", "address", "indicator"),
    "domain": ("domain", "domains", "fqdn", "indicator"),
}
PROCESS_KEYS = ("process", "process_name", "image")
PATH_KEYS = ("path", "file", "file_path")


@dataclass
class Prediction:
    findings: list[Finding] = field(default_factory=list)
    report: dict[str, Any] | None = None
    affected_ids: set[str] = field(default_factory=set)
    blast_radius: int = 0


def _values(args: dict[str, Any], keys: tuple[str, ...]) -> list[str]:
    out = []
    for k in keys:
        v = args.get(k)
        for item in (v if isinstance(v, list) else [v]):
            if isinstance(item, (str, int, float)) and not isinstance(item, bool) and str(item).strip():
                out.append(str(item).strip())
    return out


def _norm_path(p: str) -> str:
    return p.replace("/", "\\").strip().lower()


def predict(tool: str, args: dict[str, Any], policy: Policy, env: Environment | None,
            session_unavailable: set[str], session_blast: int) -> Prediction:
    pred = Prediction()
    cfg = policy.predictive
    if cfg is None or env is None or not env.assets:
        return pred
    effect: Effect | None = next((e for e in cfg.effects if tool_matches(tool, e.tools)), None)
    if effect is None:
        return pred

    affected: list[dict[str, Any]] = []
    unknown: list[str] = []
    kind = effect.makes_unavailable
    if kind == "service":
        processes = [p.lower() for p in _values(args, PROCESS_KEYS)]
        paths = [_norm_path(p) for p in _values(args, PATH_KEYS)]
        for host in _values(args, TARGET_KEYS["host"]):
            asset = env.find("host", host)
            if asset is None:
                unknown.append(host)
                continue
            for s in asset.services:
                if (s.process and s.process.lower() in processes) or (s.path and _norm_path(s.path) in paths):
                    affected.append({"id": f"{asset.name.lower()}/{s.name.lower()}",
                                     "name": f"{asset.name} / {s.name}", "role": f"service on {asset.role or asset.name}",
                                     "group": s.group, "dependents": s.dependents})
    else:
        for value in _values(args, TARGET_KEYS[kind]):
            asset = env.find(kind, value)
            if asset is None:
                unknown.append(value)
                continue
            affected.append({"id": asset.name.lower(), "name": asset.name, "role": asset.role,
                             "group": asset.group, "dependents": asset.dependents})

    seen: dict[str, dict[str, Any]] = {a["id"]: a for a in affected}
    pred.affected_ids = set(seen)
    pred.blast_radius = sum(a["dependents"] for a in seen.values())
    down = env.unavailable_ids() | session_unavailable | pred.affected_ids

    groups = []
    for g in sorted({a["group"] for a in seen.values() if a["group"]}):
        members = env.members(g)
        remaining = sum(1 for m in members if m not in down)
        need = env.groups[g].min_available
        groups.append({"group": g, "members": len(members), "remaining_after": remaining, "min_available": need})
        if remaining < need:
            pred.findings.append(Finding(
                rule_id="predicted-group-loss", verdict=effect.on_violation,
                reason=f"Predicted: after this call {remaining} of {len(members)} members of '{g}' remain available "
                       f"(at least {need} must stay up)."))
    if cfg.max_blast_radius is not None and pred.blast_radius > cfg.max_blast_radius:
        pred.findings.append(Finding(
            rule_id="predicted-blast-radius", verdict=effect.on_violation,
            reason=f"Predicted: this call takes down {pred.blast_radius} dependents (limit {cfg.max_blast_radius})."))
    total = session_blast + pred.blast_radius
    if cfg.max_session_blast_radius is not None and total > cfg.max_session_blast_radius:
        pred.findings.append(Finding(
            rule_id="predicted-session-blast-radius", verdict=effect.on_violation,
            reason=f"Predicted: this session would take down {total} dependents (limit {cfg.max_session_blast_radius})."))
    if unknown and cfg.unknown_target == "ask":
        pred.findings.append(Finding(
            rule_id="predicted-unknown-target", verdict="ask",
            reason=f"Effect unknown: {', '.join(unknown[:5])} not in the asset inventory."))

    pred.report = {
        "effect": kind, "affected": list(seen.values()), "unknown": unknown,
        "blast_radius": pred.blast_radius, "session_blast_radius": total, "groups": groups,
        "safe": not any(f.verdict in ("ask", "deny") and f.rule_id != "predicted-unknown-target"
                        for f in pred.findings),
    }
    return pred
