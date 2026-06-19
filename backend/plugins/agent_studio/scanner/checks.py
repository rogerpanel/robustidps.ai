"""Free MCP / agent scanner — the venture plan's top-of-funnel wedge.

Twelve quick adversarial / governance checks executed against either a
pasted MCP server descriptor (tools, resources, prompts), a tool-list
JSON dump, or an agent's published system prompt. Designed to run in
under 500 ms server-side with zero LLM calls — the goal is conversion
to a discovery call, not a full security report.

The check catalogue mirrors:
  - OWASP Agentic Top 10 (Dec 2025): ASI01–ASI10
  - MITRE ATLAS v5.4 tactics (data-exfil, evasion, prompt-injection)
  - MCP-specific framing risks (oversized tool descriptors, ambiguous
    side-effects, unauthenticated resource URIs)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]


@dataclass(frozen=True)
class ScannerCheck:
    code: str
    title: str
    severity: Severity
    owasp_agentic: str | None
    detect: Callable[[str], bool]
    remediation: str


@dataclass
class ScanCheckResult:
    code: str
    title: str
    severity: Severity
    owasp_agentic: str | None
    triggered: bool
    remediation: str


@dataclass
class ScanReport:
    input_kind: str
    input_size_chars: int
    n_checks_run: int
    n_findings: int
    severity_breakdown: dict[str, int] = field(default_factory=dict)
    results: list[ScanCheckResult] = field(default_factory=list)


# ── 12 checks ──────────────────────────────────────────────────────────

def _contains(*needles: str):
    def _f(text: str) -> bool:
        low = text.lower()
        return any(n in low for n in needles)
    return _f


def _matches(pattern: str):
    rx = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    def _f(text: str) -> bool:
        return rx.search(text) is not None
    return _f


SCANNER_CHECKS: list[ScannerCheck] = [
    # ── MCP framing checks ────────────────────────────────────────────
    ScannerCheck(
        "MCP-S01", "Tool descriptor exposes API keys or secrets", "critical", "ASI04",
        _matches(r"(sk-[A-Za-z0-9]{16,}|api[_-]?key\s*[:=]\s*['\"][^'\"]{12,})"),
        "Strip credentials from tool descriptors; never inline keys in MCP manifests.",
    ),
    ScannerCheck(
        "MCP-S02", "Side-effect language hidden in tool description", "high", "ASI05",
        _contains("delete", "drop table", "rm -rf", "format disk", "wipe", "factory reset"),
        "Tool descriptions must explicitly enumerate side-effects; high-risk verbs require user confirmation.",
    ),
    ScannerCheck(
        "MCP-S03", "Unauthenticated resource URI exposed", "high", "ASI02",
        _matches(r"(?<!https://)file://|ftp://[^\s'\"]+|^[a-z]:[\\/]"),
        "Resources MUST be addressed over authenticated, TLS-protected URIs; never raw filesystem.",
    ),
    ScannerCheck(
        "MCP-S04", "Tool description allows prompt-injection echo", "high", "ASI01",
        _matches(r"\{\{\s*[a-z_]+\s*\}\}|<\?\s*include|\$\{[^}]+\}"),
        "Tool descriptions must be static strings; no templating tokens that can hijack the agent loop.",
    ),
    ScannerCheck(
        "MCP-S05", "Goal-hijack phrase detected in system prompt", "high", "ASI01",
        _contains("ignore previous", "disregard above", "new instructions:", "system override",
                  "you are now", "forget everything"),
        "Strip user-controlled goal-hijack prefixes; constrain agent to declared mission.",
    ),
    ScannerCheck(
        "MCP-S06", "Excessive tool privilege (write + network + exec)", "medium", "ASI06",
        _matches(r"shell|exec|subprocess|os\.system|eval\(|write_file.*http"),
        "Apply least-privilege: split write, network, and exec into separate tools with explicit consent.",
    ),
    ScannerCheck(
        "MCP-S07", "Resource shows no rate-limit or quota", "medium", "ASI03",
        lambda text: ("rate_limit" not in text.lower() and "quota" not in text.lower()
                      and len(text) > 200),
        "Declare per-tool rate limits and per-session quotas; uncapped tools enable resource-exhaustion attacks.",
    ),
    ScannerCheck(
        "MCP-S08", "Tool routes to LLM with no MambaGuard / output filter", "medium", "ASI07",
        lambda text: ("llm" in text.lower() or "openai" in text.lower() or "anthropic" in text.lower())
                     and "mambaguard" not in text.lower() and "guard" not in text.lower(),
        "Wrap downstream LLM calls with MambaGuard or equivalent runtime monitor.",
    ),
    ScannerCheck(
        "MCP-S09", "Agent memory persisted without TTL", "low", "ASI08",
        lambda text: ("memory" in text.lower() or "recall" in text.lower())
                     and "ttl" not in text.lower() and "expire" not in text.lower(),
        "Set a TTL on agent memory; uncapped recall enables drift, leakage, and prompt-injection persistence.",
    ),
    ScannerCheck(
        "MCP-S10", "Multi-agent chain without trust boundary", "medium", "ASI09",
        lambda text: ("delegate" in text.lower() or "subagent" in text.lower() or "a2a" in text.lower())
                     and "boundary" not in text.lower() and "scope" not in text.lower(),
        "Declare explicit trust boundaries between agents; chained agents must re-authenticate at each hop.",
    ),
    ScannerCheck(
        "MCP-S11", "Rogue-agent identity assertion (claims to be MCP server)", "high", "ASI10",
        _matches(r"(claude|gpt|gemini|deepseek)[- ]?(mcp|server|host)"),
        "Identity attestation must come from the MCP framing layer, never from inside tool output.",
    ),
    ScannerCheck(
        "MCP-S12", "No mention of authentication / authorization at all", "info", None,
        lambda text: not any(k in text.lower() for k in ("auth", "token", "oauth", "permission", "scope", "role")),
        "Document the authentication model for every tool / resource exposed via MCP.",
    ),
    # ── OWASP LLM Top 10 (v2025) ──────────────────────────────────────
    ScannerCheck(
        "LLM-01", "Prompt-injection vector in tool description (LLM01)", "high", "LLM01",
        _matches(r"(translate|repeat|echo|output)\s+(verbatim|exactly|literally)|"
                 r"(do\s+not\s+filter|skip\s+(safety|moderation))"),
        "LLM01: any tool description that asks the LLM to echo / translate verbatim is a prompt-injection vector.",
    ),
    ScannerCheck(
        "LLM-02", "Insecure output handling: raw HTML / SQL / shell echoed back (LLM02)", "high", "LLM02",
        _matches(r"<script|<iframe|sql\s+query|raw\s+command|render\s+as\s+html"),
        "LLM02: never return raw HTML / SQL / shell to downstream callers without sanitisation.",
    ),
    ScannerCheck(
        "LLM-03", "Training-data poisoning indicator (LLM03)", "medium", "LLM03",
        _contains("user_submitted_training", "fine_tune_on_input", "rlhf_from_chat"),
        "LLM03: never fine-tune on user-submitted input without curation + provenance attestation.",
    ),
    ScannerCheck(
        "LLM-04", "Model DoS: no max_tokens / no timeout (LLM04)", "medium", "LLM04",
        lambda text: ("max_tokens" not in text.lower() and "timeout" not in text.lower()
                      and ("llm" in text.lower() or "anthropic" in text.lower() or "openai" in text.lower())),
        "LLM04: declare max_tokens and a timeout on every LLM call; uncapped calls enable cost-DoS.",
    ),
    ScannerCheck(
        "LLM-05", "Supply-chain risk: pinned model version absent (LLM05)", "medium", "LLM05",
        lambda text: any(k in text.lower() for k in ("model:", "model_name:", "model_id:"))
                     and not _matches(r"[\w.-]+@[a-f0-9]{6,}|version\s*[:=]\s*['\"]?[\d.]+")(text),
        "LLM05: pin model identifiers to a commit-sha or semver to detect upstream tampering.",
    ),
    ScannerCheck(
        "LLM-06", "Sensitive information disclosure: PII pattern in prompt (LLM06)", "high", "LLM06",
        _matches(r"\b\d{3}-\d{2}-\d{4}\b|\b\d{16}\b|\b[\w.-]+@[\w-]+\.\w+\b.*password"),
        "LLM06: strip PII / PHI / payment data from prompts before the model call; log redacted only.",
    ),
    ScannerCheck(
        "LLM-07", "Insecure plugin design: plugin grants too many scopes (LLM07)", "medium", "LLM07",
        lambda text: _contains("scope:", "scopes:", "permissions:")(text)
                     and len([s for s in text.lower().split() if s.startswith("write") or s.startswith("admin")]) >= 3,
        "LLM07: split admin / write scopes across multiple plugins; consent per scope.",
    ),
    ScannerCheck(
        "LLM-08", "Excessive agency: agent acts without user confirmation (LLM08)", "high", "LLM08",
        lambda text: _contains("auto_execute", "no_confirm", "autonomous_mode", "fire_and_forget")(text)
                     and not _contains("dry_run", "user_approval", "confirm_before")(text),
        "LLM08: require explicit user confirmation for any tool with side-effects; default to dry-run.",
    ),
    ScannerCheck(
        "LLM-09", "Overreliance: no confidence / no source attribution (LLM09)", "low", "LLM09",
        lambda text: ("answer" in text.lower() or "response" in text.lower())
                     and not _contains("confidence", "source", "citation", "evidence")(text)
                     and len(text) > 300,
        "LLM09: return confidence + source attribution; never let the agent answer in the absence of evidence.",
    ),
    ScannerCheck(
        "LLM-10", "Model-theft enabler: full system prompt exposed in error (LLM10)", "medium", "LLM10",
        _matches(r"system_prompt.*expose|debug.*prompt.*true|verbose.*errors.*true"),
        "LLM10: never expose the system prompt in error messages; verbose mode off in production.",
    ),
    # ── Cross-cutting hygiene ─────────────────────────────────────────
    ScannerCheck(
        "HYG-01", "No incident-response contact declared", "info", None,
        lambda text: not any(k in text.lower() for k in ("contact", "incident", "security@", "responsible_disclosure")),
        "Declare a security contact + responsible-disclosure policy URL.",
    ),
    ScannerCheck(
        "HYG-02", "No audit-log / telemetry endpoint declared", "low", None,
        lambda text: not any(k in text.lower() for k in ("audit_log", "telemetry", "trace", "log_endpoint")),
        "Wire telemetry into the AegisAgents Kit so runtime issues surface for analysis.",
    ),
]


def run_scan(text: str, input_kind: str = "mcp_manifest") -> ScanReport:
    """Run all 12 checks against the input and return a structured report."""
    results = []
    breakdown: dict[str, int] = {}
    for chk in SCANNER_CHECKS:
        triggered = bool(chk.detect(text))
        if triggered:
            breakdown[chk.severity] = breakdown.get(chk.severity, 0) + 1
        results.append(ScanCheckResult(
            code=chk.code, title=chk.title, severity=chk.severity,
            owasp_agentic=chk.owasp_agentic, triggered=triggered,
            remediation=chk.remediation,
        ))
    return ScanReport(
        input_kind=input_kind,
        input_size_chars=len(text),
        n_checks_run=len(SCANNER_CHECKS),
        n_findings=sum(1 for r in results if r.triggered),
        severity_breakdown=breakdown,
        results=results,
    )
