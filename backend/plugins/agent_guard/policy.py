"""Policy packs: the declarative part of the filter.

A pack names action tiers (each with a verdict), maps tool names to tiers with
glob patterns, and adds scope (rules of engagement), argument rules, numeric
clamps, secret redaction and a per-session budget. Built-in packs live in
policies/*.json; users can submit their own for validation and testing.

Policies never key on attacker-controllable names (file, process, account or
host names inside telemetry): they classify the action and its targets, so
renaming an artefact cannot change a verdict.
"""
from __future__ import annotations

import ipaddress
import json
import re
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

POLICY_DIR = Path(__file__).parent / "policies"
MAX_RULES = 300
MAX_PATTERN = 400

TierVerdict = Literal["allow", "ask", "deny"]
HINTS = frozenset({"read", "change", "destroy", "exec", "unclear"})


def check_regex(v: str) -> str:
    if len(v) > MAX_PATTERN:
        raise ValueError(f"pattern longer than {MAX_PATTERN} characters")
    try:
        re.compile(v)
    except re.error as exc:  # not a ValueError, so pydantic would not report it
        raise ValueError(f"invalid regular expression: {exc}") from None
    return v


def check_networks(v: list[str]) -> list[str]:
    for entry in v:
        if "/" in entry:
            ipaddress.ip_network(entry, strict=False)
    return v


class Tier(BaseModel):
    decision: TierVerdict
    description: str = ""
    reversible: bool | None = None


class ToolRule(BaseModel):
    match: list[str] = Field(..., min_length=1, description="Globs on the lower-cased tool name")
    tier: str


class ArgRule(BaseModel):
    id: str
    description: str = ""
    tools: list[str] = Field(default_factory=lambda: ["*"])
    args: list[str] = Field(default_factory=lambda: ["*"], description="Globs on argument key paths")
    pattern: str
    decision: Literal["ask", "deny"]

    @field_validator("pattern")
    @classmethod
    def _regex(cls, v: str) -> str:
        return check_regex(v)


class Clamp(BaseModel):
    id: str
    tools: list[str] = Field(default_factory=lambda: ["*"])
    arg: str
    max: float


class Redact(BaseModel):
    id: str
    tools: list[str] = Field(default_factory=lambda: ["*"])
    args: list[str] = Field(..., min_length=1, description="Argument keys (globs) removed before the call runs")


class Scope(BaseModel):
    target_args: list[str] = Field(default_factory=list, description="Argument keys that hold targets")
    allow: list[str] = Field(default_factory=list, description="CIDRs, IPs, host globs (*.lab.example)")
    on_violation: Literal["ask", "deny", "project"] = Field(
        "deny", description="project: repair the call to its in-scope part (drop out-of-scope list entries, "
                            "narrow a range to the one allowed network inside it); deny when nothing in scope remains")

    @field_validator("allow")
    @classmethod
    def _entries(cls, v: list[str]) -> list[str]:
        return check_networks(v)


class Budget(BaseModel):
    """Running total per session over matching tools: a count of calls (arg empty) or the sum of a numeric argument."""
    id: str
    description: str = ""
    tools: list[str] = Field(..., min_length=1)
    arg: str | None = None
    max_total: float = Field(..., gt=0)
    reserve: float = Field(0, ge=0, description="Kept back, e.g. for a safe abort; usable total is max_total - reserve")
    when_exhausted: Literal["ask", "deny"] = "deny"


class Effect(BaseModel):
    """What a matching tool does to its target, for the predictive layer."""
    tools: list[str] = Field(..., min_length=1)
    makes_unavailable: Literal["host", "account", "ip", "domain", "service"]
    on_violation: Literal["ask", "deny"] = "deny"


class Predictive(BaseModel):
    """L2: predict the effect of a call on the defender's environment model before it runs.

    A call is unsafe if, after it, a redundancy group would have fewer available members than it must keep,
    or if it (or the session so far) would take down more dependents than allowed. Targets missing from the
    inventory have an unknown effect."""
    effects: list[Effect] = Field(..., min_length=1)
    max_blast_radius: int | None = Field(None, ge=0, description="Dependents one call may take down")
    max_session_blast_radius: int | None = Field(None, ge=0, description="Dependents a session may take down")
    unknown_target: Literal["ask", "allow"] = "ask"


class RateLimit(BaseModel):
    """A numeric argument (rate, concurrency) with a ceiling. `default` is inserted when the argument is
    absent; set it only for tools that accept the argument."""
    args: list[str] = Field(..., min_length=1, description="Argument keys; the first present one is checked")
    max: float = Field(..., gt=0)
    default: float | None = Field(None, gt=0)
    on_exceed: Literal["clip", "ask", "deny"] = "clip"


class NetworkAction(BaseModel):
    """Typed reading of a network tool's arguments: targets (IPs, CIDRs, ranges, hosts, URLs, lists),
    ports and rates are parsed into values and checked as values; what cannot be parsed is denied."""
    id: str = Field(..., pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    description: str = ""
    tools: list[str] = Field(..., min_length=1)
    target_args: list[str] = Field(..., min_length=1, description="Argument keys (globs) holding targets")
    port_args: list[str] = Field(default_factory=list)
    max_targets: int | None = Field(None, ge=1, description="Addresses (a hostname counts as one) per call")
    max_ports: int | None = Field(None, ge=1)
    max_probes: int | None = Field(None, ge=1, description="Targets x ports per call")
    on_exceed: Literal["ask", "deny"] = "deny"
    rates: list[RateLimit] = Field(default_factory=list)
    schemes: list[str] = Field(default_factory=lambda: ["http", "https"], description="Allowed URL schemes")
    forbidden: list[str] = Field(default_factory=list, description="Networks never allowed, whatever the scope")
    forbidden_hosts: list[str] = Field(default_factory=list, description="Host globs never allowed")
    wildcard_hosts: bool = Field(False, description="Allow *.example.com (never * or *.tld)")
    require_targets: bool = Field(True, description="A matching call without any target is stopped")
    unparseable: Literal["ask", "deny"] = Field("deny", description="Verdict for targets, ports or rates that cannot "
                                                                     "be read, and for a missing target")
    split_spaces: bool = Field(True, description="Spaces separate list entries (commas and semicolons always do)")

    @field_validator("forbidden")
    @classmethod
    def _networks(cls, v: list[str]) -> list[str]:
        for entry in v:
            ipaddress.ip_network(entry, strict=False)
        return v


LABEL_PATTERN = r"^[a-z][a-z0-9_-]{0,31}$"


class FlowLabel(BaseModel):
    """Gives matching calls a data label, e.g. untrusted (reads content an outsider can influence), sensitive
    (reads private data) or egress (sends data outside the organisation)."""
    label: str = Field(..., pattern=LABEL_PATTERN)
    description: str = ""
    tools: list[str] = Field(..., min_length=1)
    args: list[str] = Field(default_factory=list, description="With pattern: argument key globs to test (default all)")
    pattern: str | None = Field(None, description="Label only calls with an argument value matching this regex")
    destination_args: list[str] = Field(default_factory=list,
                                        description="Argument keys holding destinations (recipients, URLs)")
    internal: list[str] = Field(default_factory=list,
                                description="Destinations inside the organisation (CIDRs, host or address globs "
                                            "such as *.corp.example or *@corp.example); if every destination of a "
                                            "call is internal, the label is not applied. Adds to the Environment "
                                            "tab's internal list")

    @field_validator("pattern")
    @classmethod
    def _regex(cls, v: str | None) -> str | None:
        return None if v is None else check_regex(v)

    @field_validator("internal")
    @classmethod
    def _entries(cls, v: list[str]) -> list[str]:
        return check_networks(v)


class FlowRule(BaseModel):
    """Fires on a call carrying `sink` when the session, counting this call, holds every label in `requires`."""
    id: str = Field(..., pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    description: str = ""
    sink: str = Field(..., pattern=LABEL_PATTERN)
    requires: list[str] = Field(default_factory=list)
    on_violation: Literal["ask", "deny"] = "ask"


class Flow(BaseModel):
    """Session information flow. Labels accumulate over the calls of a session that are let through
    (approved ones included); rules judge the next call against them. The default rule is the Rule of Two:
    a session that has read untrusted input and sensitive data may not send data out without a person."""
    labels: list[FlowLabel] = Field(..., min_length=1)
    rules: list[FlowRule] = Field(..., min_length=1)
    unclassified: list[str] = Field(default_factory=list,
                                    description="Labels assumed for a tool that neither the tier map nor any label "
                                                "classifies (fail closed: it could read or send anything)")

    @model_validator(mode="after")
    def _known_labels(self) -> "Flow":
        known = {lab.label for lab in self.labels} | set(self.unclassified)
        for name in self.unclassified:
            if not re.match(LABEL_PATTERN, name):
                raise ValueError(f"unclassified: invalid label '{name}'")
        if len({r.id for r in self.rules}) != len(self.rules):
            raise ValueError("flow rule ids must be unique")
        for r in self.rules:
            for name in [r.sink, *r.requires]:
                if name not in known:
                    raise ValueError(f"flow rule '{r.id}' uses label '{name}', which no label entry assigns")
        return self


class Policy(BaseModel):
    id: str = Field(..., pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    version: str = Field(..., min_length=1, max_length=32)
    name: str = ""
    description: str = ""
    default_tier: str = "unknown"
    tiers: dict[str, Tier]
    tools: list[ToolRule] = Field(default_factory=list)
    arg_rules: list[ArgRule] = Field(default_factory=list)
    clamps: list[Clamp] = Field(default_factory=list)
    redact: list[Redact] = Field(default_factory=list)
    scope: Scope | None = None
    budgets: list[Budget] = Field(default_factory=list)
    predictive: Predictive | None = None
    flow: Flow | None = None
    actions: list[NetworkAction] = Field(default_factory=list)
    max_calls_per_session: int | None = Field(None, ge=1, le=100_000)
    escalate_after_denials: int = Field(3, ge=1, le=100,
                                        description="After this many denied attempts in a session, allow becomes ask")
    hint_tiers: dict[str, str] = Field(default_factory=dict,
                                       description="Tool-registry effect hints (read, change, destroy, exec, unclear) "
                                                   "to tiers, used to suggest rules for unclassified tools")

    @model_validator(mode="after")
    def _consistent(self) -> "Policy":
        if self.default_tier not in self.tiers:
            raise ValueError(f"default_tier '{self.default_tier}' is not defined in tiers")
        for rule in self.tools:
            if rule.tier not in self.tiers:
                raise ValueError(f"tool rule {rule.match} uses undefined tier '{rule.tier}'")
        for hint, tier in self.hint_tiers.items():
            if hint not in HINTS:
                raise ValueError(f"hint_tiers: unknown hint '{hint}' (use {', '.join(sorted(HINTS))})")
            if tier not in self.tiers:
                raise ValueError(f"hint_tiers: '{hint}' uses undefined tier '{tier}'")
        if len({b.id for b in self.budgets}) != len(self.budgets):
            raise ValueError("budget ids must be unique")
        for b in self.budgets:
            if b.reserve >= b.max_total:
                raise ValueError(f"budget '{b.id}': reserve must be below max_total")
        n = len(self.tools) + len(self.arg_rules) + len(self.clamps) + len(self.redact) + len(self.budgets)
        if self.flow:
            n += len(self.flow.labels) + len(self.flow.rules)
        n += len(self.actions)
        if len({a.id for a in self.actions}) != len(self.actions):
            raise ValueError("action ids must be unique")
        if n > MAX_RULES:
            raise ValueError(f"too many rules ({n} > {MAX_RULES})")
        return self

    # ── matching helpers ───────────────────────────────────────────────

    def tier_for(self, tool: str) -> str:
        """First matching tool rule wins; otherwise the default tier."""
        for rule in self.tools:
            if any(fnmatchcase(tool, p.lower()) for p in rule.match):
                return rule.tier
        return self.default_tier


def tool_matches(tool: str, patterns: list[str]) -> bool:
    return any(fnmatchcase(tool, p.lower()) for p in patterns)


def target_in_scope(value: str, allow: list[str]) -> bool:
    """IP or CIDR inside an allowed network, or host (bare or from a URL) matching a glob."""
    raw = value.strip()
    host = urlparse(raw).hostname if "://" in raw else raw
    host = (host or "").strip("[]").lower()
    if not host:
        return False
    try:
        net = ipaddress.ip_network(host, strict=False)
    except ValueError:
        net = None
    for entry in allow:
        entry = entry.strip().lower()
        if net is not None:
            if "/" in entry or _is_ip(entry):
                allowed = ipaddress.ip_network(entry, strict=False)
                if net.version == allowed.version and net.subnet_of(allowed):
                    return True
        elif fnmatchcase(host, entry):
            return True
    return False


def project_target(value: str, allow: list[str]) -> str | None:
    """Narrow an out-of-scope range to the single allowed network it contains, else None."""
    try:
        requested = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None
    inside = []
    for entry in allow:
        entry = entry.strip()
        if "/" not in entry and not _is_ip(entry):
            continue
        net = ipaddress.ip_network(entry, strict=False)
        if net.version == requested.version and net.subnet_of(requested):
            inside.append(net)
    return str(inside[0]) if len(inside) == 1 else None


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def parse_policy(data: dict) -> Policy:
    return Policy.model_validate(data)


def validation_errors(data: object) -> list[str]:
    if not isinstance(data, dict):
        return ["policy must be a JSON object"]
    try:
        parse_policy(data)
        return []
    except ValidationError as exc:
        return [f"{'.'.join(str(p) for p in e['loc']) or 'policy'}: {e['msg']}" for e in exc.errors()]


_BUILTIN: dict[str, Policy] = {}


def builtin_policies() -> dict[str, Policy]:
    if not _BUILTIN:
        for path in sorted(POLICY_DIR.glob("*.json")):
            policy = parse_policy(json.loads(path.read_text(encoding="utf-8")))
            _BUILTIN[policy.id] = policy
    return _BUILTIN
