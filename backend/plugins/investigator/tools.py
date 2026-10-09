"""Tools exposed to the investigator, and their dispatch.

Every evidence tool takes a required `rationale`: the hypothesis the query
tests and what result would confirm or rule it out. That makes each call
hypothesis-driven (fewer wasted queries, which is what efficiency scoring
counts) and turns the tool inputs themselves into the investigation trace.

`submit_verdict` ends the investigation. It is `strict` so its arguments
always match the schema; forced tool_choice is unavailable on current
models, so the prompt steers the model to call it.
"""
from __future__ import annotations

import json

from .evidence import EvidenceSource

RATIONALE = {"type": "string", "description":
             "The hypothesis this query tests and what result would confirm or rule it out."}

EVIDENCE_TOOLS = [
    {
        "name": "search_events",
        "description": (
            "Search the evidence store (EDR, Windows security, network, DNS, proxy, auth, "
            "email logs). Combine filters to keep results small; results are sorted by time "
            "and capped at `limit` (max 50). Prefer one well-filtered query over several broad ones."),
        "input_schema": {
            "type": "object",
            "properties": {
                "rationale": RATIONALE,
                "host": {"type": "string", "description": "Exact host name."},
                "user": {"type": "string", "description": "Exact account name."},
                "event_type": {"type": "string", "description":
                               "e.g. logon, logon_failed, process_start, network_connection, "
                               "dns_query, file_write, email_received, account_change."},
                "source": {"type": "string", "description": "Log source, e.g. edr, windows_security, proxy, dns."},
                "text": {"type": "string", "description": "Case-insensitive substring matched anywhere in the event."},
                "time_from": {"type": "string", "description": "ISO-8601 lower bound, inclusive."},
                "time_to": {"type": "string", "description": "ISO-8601 upper bound, inclusive."},
                "limit": {"type": "integer", "description": "Max events to return (1-50, default 20)."},
            },
            "required": ["rationale"],
        },
    },
    {
        "name": "get_process_tree",
        "description": "Return a process's ancestor chain and direct children on one host.",
        "input_schema": {
            "type": "object",
            "properties": {"rationale": RATIONALE, "host": {"type": "string"},
                           "pid": {"type": "integer"}},
            "required": ["rationale", "host", "pid"],
        },
    },
    {
        "name": "get_host_info",
        "description": "Asset inventory record for a host: role, owner, criticality, and any notes.",
        "input_schema": {
            "type": "object",
            "properties": {"rationale": RATIONALE, "host": {"type": "string"}},
            "required": ["rationale", "host"],
        },
    },
    {
        "name": "lookup_indicator",
        "description": "Threat-intelligence verdict for an IP address, domain, or file hash.",
        "input_schema": {
            "type": "object",
            "properties": {"rationale": RATIONALE, "value": {"type": "string"}},
            "required": ["rationale", "value"],
        },
    },
]

_STR_LIST = {"type": "array", "items": {"type": "string"}}

SUBMIT_VERDICT = {
    "name": "submit_verdict",
    "description": "Submit the final investigation result. Call exactly once, when the evidence is sufficient.",
    "strict": True,
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "benign_true_positive"],
                        "description": "true_positive = malicious; false_positive = the alert was wrong; "
                                       "benign_true_positive = real activity that is authorised or expected."},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
            "confidence": {"type": "number", "description": "0.0 to 1.0."},
            "summary": {"type": "string", "description": "Two to four sentences: what happened and why you concluded this."},
            "root_cause": {"type": "string"},
            "attack_techniques": {**_STR_LIST, "description": "MITRE ATT&CK IDs observed, e.g. T1059.001. Empty if none."},
            "affected_hosts": {**_STR_LIST, "description": "Hosts compromised or misused. Empty if none."},
            "affected_accounts": {**_STR_LIST, "description": "Accounts compromised or misused. Empty if none."},
            "indicators": {**_STR_LIST, "description": "IOCs: IPs, domains, hashes. Empty if none."},
            "timeline": {
                "type": "array",
                "description": "Key events in time order, each tied to an evidence event id.",
                "items": {"type": "object", "additionalProperties": False,
                          "properties": {"ts": {"type": "string"}, "event_id": {"type": "string"},
                                         "description": {"type": "string"}},
                          "required": ["ts", "event_id", "description"]},
            },
            "hypotheses": {
                "type": "array",
                "description": "Every hypothesis considered and how the evidence resolved it.",
                "items": {"type": "object", "additionalProperties": False,
                          "properties": {"hypothesis": {"type": "string"},
                                         "status": {"type": "string", "enum": ["confirmed", "refuted", "inconclusive"]},
                                         "evidence_event_ids": _STR_LIST},
                          "required": ["hypothesis", "status", "evidence_event_ids"]},
            },
            "recommended_actions": _STR_LIST,
        },
        "required": ["verdict", "severity", "confidence", "summary", "root_cause", "attack_techniques",
                     "affected_hosts", "affected_accounts", "indicators", "timeline", "hypotheses",
                     "recommended_actions"],
    },
}

TOOLS = EVIDENCE_TOOLS + [SUBMIT_VERDICT]
EVIDENCE_NAMES = {t["name"] for t in EVIDENCE_TOOLS}


def openai_tools() -> list[dict]:
    """The same tools in OpenAI function-calling format (OpenAI, DeepSeek, Gemini)."""
    return [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                              "parameters": t["input_schema"]}} for t in TOOLS]


def run_evidence_tool(name: str, args: dict, source: EvidenceSource) -> tuple[dict, bool]:
    """Execute one evidence tool. Returns (result, is_error)."""
    if name not in EVIDENCE_NAMES:
        return {"error": f"unknown tool {name!r}"}, True
    schema = next(t for t in EVIDENCE_TOOLS if t["name"] == name)["input_schema"]
    missing = [k for k in schema["required"] if args.get(k) in (None, "")]
    if missing:
        return {"error": f"missing required argument(s): {', '.join(missing)}"}, True
    kwargs = {k: v for k, v in args.items() if k != "rationale" and k in schema["properties"]}
    try:
        result = getattr(source, name)(**kwargs)
    except (TypeError, ValueError) as exc:
        return {"error": f"bad arguments: {exc}"}, True
    return result, "error" in result


def validate_verdict(v: dict) -> list[str]:
    """Problems with a submitted verdict. Strict mode guarantees this on
    Claude; OpenAI-compatible providers get no such guarantee."""
    spec = SUBMIT_VERDICT["input_schema"]
    problems = [f"missing {k}" for k in spec["required"] if k not in v]
    for k in ("verdict", "severity"):
        if k in v and v[k] not in spec["properties"][k]["enum"]:
            problems.append(f"{k} must be one of {spec['properties'][k]['enum']}")
    if "confidence" in v and not isinstance(v["confidence"], (int, float)):
        problems.append("confidence must be a number")
    return problems


def to_text(result: dict) -> str:
    return json.dumps(result, ensure_ascii=False, sort_keys=True)
