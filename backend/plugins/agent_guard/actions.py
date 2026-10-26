"""Typed actions: network tool arguments are parsed into values, then checked as values.

String rules see "10.0.0.0/1" and "0.0.0.0/0" as different text, cannot count
the ports in "1-65535", and miss an instance-metadata address written as
0xa9.0xfe.0xa9.0xfe or [::ffff:169.254.169.254]. Here the arguments a pack
names (`actions[].target_args`, `port_args`, `rates`) are parsed first:

  targets  IPv4/IPv6 addresses and CIDRs, ranges (10.0.0.1-10.0.0.50 and
           10.0.0.1-50), trailing wildcard octets (10.0.0.*), hostnames
           (IDNA, trailing dot removed, optional leading *. when allowed),
           host:port, [v6]:port, URLs (scheme, real host after any user
           info, port), and lists of any of these (JSON lists, or separated
           by commas, semicolons or spaces). IPv4-mapped IPv6 is judged as
           the IPv4 address it reaches.
  ports    80, 1-1024, 22,80,443, nmap-style T:/U: prefixes, - or all.
  rates    numbers, or numeric strings such as "100" or "100/s".

Then: forbidden networks and hosts (metadata, loopback, link-local) are
denied whatever the scope; the scope is checked on networks, not text, and a
list or range reaching outside it is repaired to its exact in-scope part; the
number of addresses, ports and probes is bounded; rates are clipped.

Fail closed: a value that cannot be parsed, a numeric IP literal in a
non-canonical form (hex, octal, integer or shortened: forms some resolvers
accept and filters miss), an unsupported URL scheme, a backslash or percent
sign in a URL host, or a matching call with no target at all is denied.
"""
from __future__ import annotations

import ipaddress
import math
import re
import socket
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import urlsplit

from plugins.agent_guard.contract import Finding
from plugins.agent_guard.policy import NetworkAction, Policy, tool_matches

MAX_TOKENS = 1000
_SPLIT = re.compile(r"[\s,;]+")
_SPLIT_NO_SPACE = re.compile(r"\s*[,;]\s*")
_NUMERICISH = re.compile(r"^(0x[0-9a-f]*|[0-9]+)(\.(0x[0-9a-f]*|[0-9]+)){0,3}\.?$", re.I)
_WILDCARD_OCTETS = re.compile(r"^(\d{1,3}\.){1,3}\*(\.\*)*$")
_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
_RATE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(?:/s|/sec|ps)?\s*$", re.I)
_MAPPED = ipaddress.ip_network("::ffff:0:0/96")

Net = ipaddress.IPv4Network | ipaddress.IPv6Network


class Unparseable(ValueError):
    pass


class NonCanonical(ValueError):
    def __init__(self, token: str, reaches: str | None):
        super().__init__(token)
        self.token, self.reaches = token, reaches


@dataclass
class Target:
    token: str                      # what the agent wrote (one list entry)
    net: Net | None = None          # for addresses, CIDRs and range pieces
    host: str | None = None         # normalised hostname
    wildcard: bool = False          # *.example.com, or * (host == "*")
    scheme: str | None = None       # for URLs
    url: bool = False

    def label(self) -> str:
        if self.net is not None:
            return str(self.net.network_address) if self.net.num_addresses == 1 else str(self.net)
        return self.host or self.token


# ── parsing ──────────────────────────────────────────────────────────

def _unmap(net: Net) -> Net:
    if net.version == 6 and net.prefixlen >= 96 and net.subnet_of(_MAPPED):
        mapped = net.network_address.ipv4_mapped
        if mapped is not None:
            return ipaddress.ip_network(f"{mapped}/{net.prefixlen - 96}", strict=False)
    return net


def _ip(text: str) -> Net | None:
    try:
        return _unmap(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return None


def _noncanonical(text: str) -> NonCanonical:
    try:
        reaches = socket.inet_ntoa(socket.inet_aton(text.rstrip(".")))
    except OSError:
        reaches = None
    return NonCanonical(text, reaches)


def _hostname(text: str, token: str) -> Target:
    h = text.strip().lower()
    if h.endswith("."):
        h = h[:-1]
    if h == "*":
        return Target(token, host="*", wildcard=True)
    wildcard = h.startswith("*.")
    base = h[2:] if wildcard else h
    if not base or "*" in base:
        raise Unparseable(token)
    try:
        ascii_name = base.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise Unparseable(token) from None
    labels = ascii_name.split(".")
    if len(ascii_name) > 253 or not all(_LABEL.match(lab) for lab in labels):
        raise Unparseable(token)
    return Target(token, host=("*." if wildcard else "") + ascii_name, wildcard=wildcard)


def _host_part(text: str, token: str) -> list[Target]:
    """An address, CIDR or hostname (no port, no scheme)."""
    net = _ip(text)
    if net is not None:
        return [Target(token, net=net)]
    if _NUMERICISH.match(text):
        raise _noncanonical(text)
    return [_hostname(text, token)]


def parse_token(token: str) -> list[Target]:
    tok = token.strip()
    if not tok:
        return []
    if "://" in tok:
        parts = urlsplit(tok)
        if "\\" in parts.netloc or "%" in parts.netloc or any(c.isspace() for c in parts.netloc):
            raise Unparseable(token)
        try:
            _ = parts.port
        except ValueError:
            raise Unparseable(token) from None
        host = parts.hostname
        if not host:  # e.g. file:///etc/passwd: judged by its scheme first, then refused for having no host
            return [Target(token, scheme=parts.scheme.lower(), url=True)]
        out = _host_part(host, token)
        for t in out:
            t.scheme, t.url = parts.scheme.lower(), True
        return out
    if tok.startswith("["):
        m = re.match(r"^\[([0-9a-fA-F:.]+)\](?::(\d{1,5}))?$", tok)
        if not m or (m.group(2) and int(m.group(2)) > 65535):
            raise Unparseable(token)
        net = _ip(m.group(1))
        if net is None:
            raise Unparseable(token)
        return [Target(token, net=net)]
    net = _ip(tok)
    if net is not None:
        return [Target(token, net=net)]
    if tok.count("-") == 1:
        left, right = tok.split("-")
        start = _ip(left)
        if start is not None and start.num_addresses == 1:
            a = start.network_address
            if right.isdigit() and a.version == 4:
                if int(right) > 255:
                    raise Unparseable(token)
                b = ipaddress.ip_address(".".join(str(a).split(".")[:3] + [right]))
            else:
                end = _ip(right)
                if end is None or end.num_addresses != 1 or end.version != a.version:
                    raise Unparseable(token)
                b = end.network_address
            if int(b) < int(a):
                raise Unparseable(token)
            return [Target(token, net=n) for n in ipaddress.summarize_address_range(a, b)]
    if _WILDCARD_OCTETS.match(tok):
        parts = tok.split(".")
        if len(parts) != 4:
            raise Unparseable(token)
        fixed = [p for p in parts if p != "*"]
        if any(int(p) > 255 for p in fixed) or parts[:len(fixed)] != fixed:
            raise Unparseable(token)
        prefix = ".".join(fixed + ["0"] * (4 - len(fixed)))
        return [Target(token, net=ipaddress.ip_network(f"{prefix}/{8 * len(fixed)}"))]
    if _NUMERICISH.match(tok):
        raise _noncanonical(tok)
    if tok.count(":") == 1:
        host, port = tok.rsplit(":", 1)
        if not port.isdigit() or int(port) > 65535 or not host:
            raise Unparseable(token)
        return _host_part(host, token)
    return [_hostname(tok, token)]


def split_tokens(text: str, spaces: bool = True) -> list[str]:
    return [t for t in (_SPLIT if spaces else _SPLIT_NO_SPACE).split(text.strip()) if t]


def parse_targets(value: Any, spaces: bool = True) -> list[Target]:
    if value is None:
        return []
    if isinstance(value, bool) or isinstance(value, dict):
        raise Unparseable(str(value))
    if isinstance(value, list):
        out: list[Target] = []
        for v in value:
            out.extend(parse_targets(v, spaces))
        return out
    tokens = split_tokens(str(value), spaces)
    if len(tokens) > MAX_TOKENS:
        raise Unparseable(f"{len(tokens)} entries")
    out = []
    for t in tokens:
        out.extend(parse_token(t))
    return out


def parse_ports(value: Any) -> int:
    """Number of distinct ports in a port specification."""
    if value is None:
        return 0
    if isinstance(value, bool) or isinstance(value, dict):
        raise Unparseable(str(value))
    if isinstance(value, list):
        spans = [s for v in value for s in _port_spans(v)]
    else:
        spans = _port_spans(value)
    spans.sort()
    total, cur_a, cur_b = 0, None, None
    for a, b in spans:
        if cur_b is None or a > cur_b + 1:
            if cur_b is not None:
                total += cur_b - cur_a + 1
            cur_a, cur_b = a, b
        else:
            cur_b = max(cur_b, b)
    if cur_b is not None:
        total += cur_b - cur_a + 1
    return total


def _port_spans(value: Any) -> list[tuple[int, int]]:
    if isinstance(value, bool):
        raise Unparseable(str(value))
    if isinstance(value, int):
        if not 0 <= value <= 65535:
            raise Unparseable(str(value))
        return [(value, value)]
    out = []
    for raw in str(value).split(","):
        tok = re.sub(r"^[TUSY]:", "", raw.strip(), flags=re.I)
        if tok in ("-", "*", "all"):
            out.append((0, 65535))
            continue
        m = re.fullmatch(r"(\d{0,5})-(\d{0,5})|(\d{1,5})", tok)
        if not m:
            raise Unparseable(raw)
        if m.group(3):
            a = b = int(m.group(3))
        else:
            a = int(m.group(1)) if m.group(1) else 0
            b = int(m.group(2)) if m.group(2) else 65535
        if a > b or b > 65535:
            raise Unparseable(raw)
        out.append((a, b))
    return out


def parse_rate(value: Any) -> float:
    if isinstance(value, bool):
        raise Unparseable(str(value))
    if isinstance(value, (int, float)):
        if math.isnan(value) or math.isinf(value):
            raise Unparseable(str(value))
        return float(value)
    m = _RATE.match(str(value))
    if not m:
        raise Unparseable(str(value))
    return float(m.group(1))


# ── checking ─────────────────────────────────────────────────────────

@dataclass
class ActionResult:
    findings: list[Finding] = field(default_factory=list)
    changed: bool = False
    handled: set[str] = field(default_factory=set)
    reports: list[dict] = field(default_factory=list)


def _keys(args: dict[str, Any], globs: list[str]) -> list[str]:
    return [k for k in args if any(fnmatchcase(k.lower(), g.lower()) for g in globs)]


def _in_scope(t: Target, nets: list[Net], globs: list[str]) -> bool:
    if t.net is not None:
        return any(t.net.version == n.version and t.net.subnet_of(n) for n in nets)
    return bool(t.host) and t.host != "*" and any(fnmatchcase(t.host, g) for g in globs)


def _count(targets: list[Target]) -> float:
    return sum(t.net.num_addresses if t.net is not None else (math.inf if t.host == "*" else 1) for t in targets)


def _fmt(n: float) -> str:
    return "unbounded" if n == math.inf else f"{int(n):,}"


def check(tool: str, modified: dict[str, Any], policy: Policy) -> ActionResult:
    """Apply every typed action matching the tool. Repairs are written into `modified`."""
    res = ActionResult()
    for action in policy.actions:
        if tool_matches(tool, action.tools):
            _check_one(action, tool, modified, policy, res)
    return res


def _check_one(a: NetworkAction, tool: str, modified: dict[str, Any], policy: Policy, res: ActionResult) -> None:
    def find(check: str, verdict: str, reason: str) -> None:
        res.findings.append(Finding(rule_id=f"{a.id}:{check}", verdict=verdict, reason=reason))

    keys = _keys(modified, a.target_args)
    res.handled.update(k for k in modified if any(fnmatchcase(k.lower(), g.lower()) for g in a.target_args))
    report: dict[str, Any] = {"id": a.id, "targets": [], "n_targets": 0, "ports": None, "probes": None,
                              "rates": {}, "projected": False, "dropped": []}
    res.reports.append(report)

    parsed: dict[str, list[Target]] = {}
    for k in keys:
        try:
            parsed[k] = parse_targets(modified[k], a.split_spaces)
        except NonCanonical as nc:
            where = f" (would reach {nc.reaches})" if nc.reaches else ""
            find("non-canonical-ip", "deny",
                 f"'{nc.token}' in '{k}' is a numeric IP address in a non-canonical form{where}; write it as a "
                 "plain dotted address.")
            return
        except Unparseable as up:
            find("unparseable", a.unparseable, f"Could not read '{up}' in '{k}' as a target; the call is "
                                               f"{'denied' if a.unparseable == 'deny' else 'sent to a person'} "
                                               "rather than guessed.")
            return
    if not any(parsed.values()):
        if a.require_targets:
            find("no-target", a.unparseable, f"No target found in {', '.join(a.target_args[:6])}; a network "
                                             "action must name what it touches.")
        return

    forbidden = [ipaddress.ip_network(f, strict=False) for f in a.forbidden]
    for k, targets in parsed.items():
        for t in targets:
            if t.url and t.scheme not in [s.lower() for s in a.schemes]:
                find("scheme", "deny", f"URL scheme '{t.scheme}' in '{k}' is not allowed "
                                       f"(allowed: {', '.join(a.schemes)}).")
                return
            if t.url and t.net is None and not t.host:
                find("unparseable", "deny", f"URL '{t.token}' in '{k}' has no host.")
                return
            if t.net is not None and any(t.net.version == f.version and t.net.overlaps(f) for f in forbidden):
                find("forbidden", "deny", f"'{t.token}' in '{k}' reaches {t.label()}, a forbidden network "
                                          "(metadata, loopback, link-local or similar).")
                return
            if t.host and t.host != "*":
                base = t.host[2:] if t.wildcard else t.host
                hit = any(fnmatchcase(base, g.lower()) for g in a.forbidden_hosts) or (
                    t.wildcard and any(g.lower().endswith("." + base) for g in a.forbidden_hosts))
                if hit:
                    find("forbidden", "deny", f"'{t.token}' in '{k}' is (or covers) a forbidden host.")
                    return
            if t.wildcard:
                base = (t.host or "")[2:]
                if t.host == "*" or base.count(".") < 1:
                    find("too-many-targets", "deny", f"'{t.token}' in '{k}' covers everything or a whole top-level "
                                                     "domain.")
                    return
                if not a.wildcard_hosts:
                    find("unparseable", "deny", f"Wildcard host '{t.token}' in '{k}' is not allowed here.")
                    return

    # Scope on values: keep the in-scope part (exact intersection for networks), drop the rest.
    sc = policy.scope
    if sc is not None:
        nets = [ipaddress.ip_network(e.strip(), strict=False) for e in sc.allow if "/" in e or _ip(e.strip())]
        nets = [_unmap(n) for n in nets]
        globs = [e.strip().lower() for e in sc.allow if not ("/" in e or _ip(e.strip()))]
        for k, targets in list(parsed.items()):
            kept: list[Target] = []
            outside: list[str] = []
            for t in targets:
                if _in_scope(t, nets, globs):
                    kept.append(t)
                    continue
                inside = [n for n in nets if t.net is not None and n.version == t.net.version and n.subnet_of(t.net)]
                if inside and sc.on_violation == "project":
                    kept.extend(Target(t.token, net=n) for n in inside)
                outside.append(t.label())
            if not outside:
                continue
            if sc.on_violation != "project":
                for o in outside:
                    find("out-of-scope", sc.on_violation, f"Target '{o}' in '{k}' is outside the agreed scope.")
                continue
            original = modified[k]
            single = not isinstance(original, list) and len(split_tokens(str(original), a.split_spaces)) == 1
            if not kept or (single and len({t.label() for t in kept}) > 1):
                find("out-of-scope", "deny",
                     f"No target in '{k}' is inside the agreed scope." if not kept else
                     f"'{original}' in '{k}' overlaps the scope in several places; a single value cannot be "
                     "repaired without guessing.")
                return
            labels = [t.token if t.url else t.label() for t in kept]
            labels = list(dict.fromkeys(labels))
            if isinstance(original, list):
                modified[k] = labels
            elif single:
                modified[k] = labels[0]
            else:
                modified[k] = ("," if "," in str(original) else " ").join(labels)
            parsed[k] = kept
            res.changed = True
            report["projected"] = True
            report["dropped"].extend(outside)
            find("scope-projected", "modify", f"Kept the in-scope part of '{k}': {', '.join(labels[:5])}"
                                              f"{' …' if len(labels) > 5 else ''} (outside: {', '.join(outside[:5])}).")

    targets = [t for ts in parsed.values() for t in ts]
    n = _count(targets)
    report["targets"] = [t.token if t.url else t.label() for t in targets][:20]
    report["n_targets"] = None if n == math.inf else int(n)
    if a.max_targets is not None and n > a.max_targets:
        find("too-many-targets", a.on_exceed, f"{_fmt(n)} addresses in one call; the limit is {a.max_targets:,}.")

    ports = 0
    for k in _keys(modified, a.port_args):
        try:
            ports += parse_ports(modified[k])
        except Unparseable as up:
            find("unparseable", a.unparseable, f"Could not read '{up}' in '{k}' as ports.")
            return
    if a.port_args:
        report["ports"] = ports or None
    if a.max_ports is not None and ports > a.max_ports:
        find("too-many-ports", a.on_exceed, f"{ports:,} ports in one call; the limit is {a.max_ports:,}.")
    probes = n * max(ports, 1)
    report["probes"] = None if probes == math.inf else int(probes)
    if a.max_probes is not None and probes > a.max_probes:
        find("too-many-probes", a.on_exceed, f"{_fmt(probes)} target-port probes in one call; the limit is "
                                             f"{a.max_probes:,}.")

    for rl in a.rates:
        present = next((k for k in rl.args if k in modified), None)
        if present is None:
            if rl.default is not None:
                modified[rl.args[0]] = int(rl.default) if float(rl.default).is_integer() else rl.default
                res.changed = True
                report["rates"][rl.args[0]] = modified[rl.args[0]]
                find(f"rate:{rl.args[0]}", "modify", f"Added '{rl.args[0]}' = {modified[rl.args[0]]} (no limit was set).")
            continue
        try:
            value = parse_rate(modified[present])
        except Unparseable:
            find(f"rate:{present}", a.unparseable, f"Could not read '{modified[present]}' in '{present}' as a number.")
            return
        report["rates"][present] = value
        if 0 < value <= rl.max:
            continue
        why = "0 or less often means unlimited" if value <= 0 else f"{value:g} is above the limit of {rl.max:g}"
        if rl.on_exceed == "clip":
            modified[present] = int(rl.max) if float(rl.max).is_integer() else rl.max
            res.changed = True
            report["rates"][present] = modified[present]
            find(f"rate:{present}", "modify", f"Set '{present}' to {modified[present]} ({why}).")
        else:
            find(f"rate:{present}", rl.on_exceed, f"'{present}': {why}.")
