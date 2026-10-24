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
        if len(v) > MAX_PATTERN:
            raise ValueError(f"pattern longer than {MAX_PATTERN} characters")
        try:
            re.compile(v)
        except re.error as exc:  # not a ValueError, so pydantic would not report it
            raise ValueError(f"invalid regular expression: {exc}") from None
        return v


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
    on_violation: Literal["ask", "deny"] = "deny"

    @field_validator("allow")
    @classmethod
    def _entries(cls, v: list[str]) -> list[str]:
        for entry in v:
            if "/" in entry:
                ipaddress.ip_network(entry, strict=False)
        return v


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
        n = len(self.tools) + len(self.arg_rules) + len(self.clamps) + len(self.redact)
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
