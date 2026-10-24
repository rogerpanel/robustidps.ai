"""Tool registry: register, fingerprint, diff and pin the tools an agent can call.

Shared by the MCP/Agent Scanner (the same text is scanned on registration),
the Safety Filter (tier coverage and generated policies) and the MCP gateway
in client.py (tools/list is verified against the pinned version, so a tool
whose description or schema changed after approval, a "rug pull", or one
carrying hidden characters is withheld from the agent).

Accepted inputs: an MCP tools/list result ({"tools": [...]}, or the whole
JSON-RPC response), a list of tools, OpenAI-style function tools, or an agent
spec with a "tools" array.
"""
from __future__ import annotations

import json
import re
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from plugins.agent_guard.canonical import clean_text, clean_value
from plugins.agent_guard.db_models import GuardToolset
from plugins.agent_guard.evidence import append, digest
from plugins.agent_guard.policy import Policy

MAX_TOOLS = 500
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$")

# Coarse effect classes from tool names and descriptions; policies map them to tiers (Policy.hint_tiers).
_EXEC = re.compile(r"\b(exec(ute)?|shell|bash|command|terminal|script|eval|run[_ ]code|powershell)\b", re.I)
_DESTROY = re.compile(r"\b(delete|remove|drop|wipe|purge|destroy|truncate|shred|reimage|format)\b", re.I)
_CHANGE = re.compile(r"\b(write|create|update|edit|modify|set|send|post|upload|move|rename|isolate|block|"
                     r"disable|enable|kill|terminate|quarantine|revoke|reset|assign|deploy|install|transfer)\b", re.I)
_READ = re.compile(r"\b(get|list|read|search|query|fetch|lookup|describe|show|view|find|inspect|count)\b", re.I)


class RegistryError(ValueError):
    pass


def extract_tools(data: Any) -> list[dict]:
    """Normalise the accepted formats to [{name, description, input_schema}]."""
    if isinstance(data, dict):
        if isinstance(data.get("result"), dict):
            data = data["result"]
        data = data.get("tools", data.get("functions"))
    if not isinstance(data, list):
        raise RegistryError("No tool list found: expected {\"tools\": [...]} or a JSON array of tools.")
    tools = []
    for item in data[:MAX_TOOLS + 1]:
        if not isinstance(item, dict):
            continue
        fn = item.get("function") if isinstance(item.get("function"), dict) else item
        name = fn.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        schema = fn.get("inputSchema", fn.get("input_schema", fn.get("parameters", {})))
        tools.append({"name": name, "description": str(fn.get("description") or ""),
                      "input_schema": schema if isinstance(schema, dict) else {}})
    if not tools:
        raise RegistryError("The tool list is empty.")
    if len(tools) > MAX_TOOLS:
        raise RegistryError(f"More than {MAX_TOOLS} tools.")
    return tools


def fingerprint_tools(tools: list[dict]) -> list[dict]:
    out = []
    for t in tools:
        hidden: list[str] = []
        name, h1 = clean_text(t["name"])
        desc, h2 = clean_text(t["description"])
        schema = clean_value(t["input_schema"], "input_schema", hidden)
        if h1:
            hidden.insert(0, f"name: {', '.join(sorted(set(h1)))}")
        if h2:
            hidden.insert(0, f"description: {', '.join(sorted(set(h2)))}")
        out.append({"name": name.strip(), "description": desc, "input_schema": schema,
                    "fingerprint": digest({"name": name.strip(), "description": desc, "input_schema": schema}),
                    "hidden": hidden})
    return out


def effect_hint(tool: dict) -> str:
    text = f"{tool['name'].replace('_', ' ')} {tool['description']}"
    head = tool["name"].replace("_", " ").replace("-", " ")
    if _EXEC.search(head) or _EXEC.search(text):
        return "exec"
    if _DESTROY.search(head):
        return "destroy"
    if _CHANGE.search(head):
        return "change"
    if _READ.search(head):
        return "read"
    if _DESTROY.search(text):
        return "destroy"
    if _CHANGE.search(text):
        return "change"
    if _READ.search(text):
        return "read"
    return "unclear"


def coverage(tools: list[dict], policy: Policy) -> dict:
    """How the policy classifies each tool, with a suggested tier where it falls to the default."""
    rows, unclassified = [], 0
    for t in tools:
        name = t["name"].strip().lower()
        tier = policy.tier_for(name)
        explicit = tier != policy.default_tier or any(name == p.lower() for r in policy.tools for p in r.match)
        hint = effect_hint(t)
        suggested = policy.hint_tiers.get(hint) if not explicit else None
        if not explicit:
            unclassified += 1
        rows.append({"name": t["name"], "tier": tier, "decision": policy.tiers[tier].decision,
                     "explicit": explicit, "effect_hint": hint, "suggested_tier": suggested,
                     "hidden": t.get("hidden", [])})
    return {"policy_id": policy.id, "policy_version": policy.version, "tools": rows,
            "unclassified": unclassified, "total": len(rows)}


def generated_policy(tools: list[dict], policy: Policy, toolset_name: str) -> dict:
    """A copy of the pack with explicit rules for these tools, from the suggestions (to review and edit)."""
    cov = coverage(tools, policy)
    data = policy.model_dump()
    rules = [{"match": [r["name"].strip().lower()], "tier": r["suggested_tier"]}
             for r in cov["tools"] if r["suggested_tier"]]
    data["tools"] = rules + data["tools"]
    data["id"] = re.sub(r"[^a-z0-9._-]", "-", f"{policy.id}.{toolset_name}".lower())[:64]
    data["version"] = "1"
    data["name"] = f"{policy.name or policy.id} + {toolset_name}"
    data["description"] = (f"{policy.description} Generated rules for {len(rules)} tools of '{toolset_name}' "
                           "from their names and descriptions; review before use.").strip()
    return data


def _row(r: GuardToolset, with_tools: bool = True) -> dict:
    out = {"id": r.id, "name": r.name, "version": r.version, "pinned": bool(r.pinned), "digest": r.digest,
           "created_at": r.created_at.isoformat() + "Z", "n_tools": len(r.tools or []),
           "n_hidden": sum(1 for t in r.tools or [] if t.get("hidden")), "scan": r.scan, "diff": r.diff}
    if with_tools:
        out["tools"] = r.tools
    return out


def register(db: Session, customer_id: str, name: str, raw: str) -> dict:
    if not NAME_RE.match(name or ""):
        raise RegistryError("Name: letters, digits, space, dot, dash or underscore; up to 128 characters.")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RegistryError(f"Not valid JSON: {exc.msg} (line {exc.lineno})") from None
    tools = fingerprint_tools(extract_tools(data))
    names = [t["name"] for t in tools]
    if len(set(names)) != len(names):
        raise RegistryError("Duplicate tool names.")

    from plugins.agent_studio.scanner import run_scan
    report = run_scan(raw, "tool_list")
    scan = {"n_findings": report.n_findings, "severity_breakdown": report.severity_breakdown,
            "triggered": [{"code": r.code, "title": r.title, "severity": r.severity}
                          for r in report.results if r.triggered]}

    prev = db.execute(select(GuardToolset).where(GuardToolset.customer_id == customer_id,
                                                 GuardToolset.name == name)
                      .order_by(GuardToolset.version.desc()).limit(1)).scalar_one_or_none()
    set_digest = digest(sorted(t["fingerprint"] for t in tools))
    if prev is not None and prev.digest == set_digest:
        return {**_row(prev), "unchanged": True}
    diff = None
    if prev is not None:
        before = {t["name"]: t["fingerprint"] for t in prev.tools}
        after = {t["name"]: t["fingerprint"] for t in tools}
        diff = {"against_version": prev.version,
                "added": sorted(set(after) - set(before)), "removed": sorted(set(before) - set(after)),
                "changed": sorted(n for n in set(after) & set(before) if after[n] != before[n])}
    row = GuardToolset(id=uuid.uuid4().hex, customer_id=customer_id, name=name,
                       version=(prev.version + 1) if prev else 1, digest=set_digest, tools=tools,
                       scan=scan, diff=diff, pinned=0)
    db.add(row)
    db.commit()
    append(db, customer_id, "toolset_register",
           {"toolset": name, "version": row.version, "digest": set_digest, "n_tools": len(tools),
            "scan_findings": scan["n_findings"], "diff": diff},
           f"Registered {name} v{row.version} ({len(tools)} tools, {scan['n_findings']} scanner findings)")
    return {**_row(row), "unchanged": False}


def listing(db: Session, customer_id: str) -> list[dict]:
    rows = db.execute(select(GuardToolset).where(GuardToolset.customer_id == customer_id)
                      .order_by(GuardToolset.name, GuardToolset.version.desc())).scalars().all()
    return [_row(r, with_tools=False) for r in rows]


def get(db: Session, customer_id: str, name: str, version: int | None = None) -> GuardToolset | None:
    q = select(GuardToolset).where(GuardToolset.customer_id == customer_id, GuardToolset.name == name)
    q = q.where(GuardToolset.version == version) if version else q.order_by(GuardToolset.version.desc())
    return db.execute(q.limit(1)).scalar_one_or_none()


def pinned(db: Session, customer_id: str, name: str) -> GuardToolset | None:
    return db.execute(select(GuardToolset).where(GuardToolset.customer_id == customer_id,
                                                 GuardToolset.name == name, GuardToolset.pinned == 1)
                      ).scalar_one_or_none()


def pin(db: Session, customer_id: str, name: str, version: int, actor: str) -> dict:
    row = get(db, customer_id, name, version)
    if row is None:
        raise RegistryError(f"{name} v{version} is not registered.")
    blocked = [t["name"] for t in row.tools if t.get("hidden")]
    if blocked:
        raise RegistryError(f"Cannot pin: hidden characters in {', '.join(blocked[:5])}. Fix the tool definitions first.")
    for other in db.execute(select(GuardToolset).where(GuardToolset.customer_id == customer_id,
                                                       GuardToolset.name == name)).scalars():
        other.pinned = 1 if other.id == row.id else 0
    db.commit()
    append(db, customer_id, "toolset_pin", {"toolset": name, "version": version, "digest": row.digest, "by": actor},
           f"Pinned {name} v{version}")
    return _row(row)


def verify(db: Session, customer_id: str, name: str, raw_tools: Any) -> dict:
    """Check a live tools/list against the pinned version; only 'ok' tools should reach the agent."""
    tools = fingerprint_tools(extract_tools(raw_tools))
    ref = pinned(db, customer_id, name)
    if ref is None:
        return {"toolset": name, "pinned_version": None, "allowed": [],
                "tools": [{"name": t["name"], "status": "not-pinned"} for t in tools],
                "reason": f"No pinned version of '{name}'. Register and pin it first."}
    pins = {t["name"]: t["fingerprint"] for t in ref.tools}
    rows = []
    for t in tools:
        if t["hidden"]:
            status = "hidden-characters"
        elif t["name"] not in pins:
            status = "new"
        elif pins[t["name"]] != t["fingerprint"]:
            status = "changed"
        else:
            status = "ok"
        rows.append({"name": t["name"], "status": status})
    missing = sorted(set(pins) - {t["name"] for t in tools})
    return {"toolset": name, "pinned_version": ref.version, "tools": rows, "missing": missing,
            "allowed": [r["name"] for r in rows if r["status"] == "ok"]}
