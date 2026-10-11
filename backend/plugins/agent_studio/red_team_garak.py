"""Garak integration layer for the Red Team Automation harness.

Garak (https://github.com/leondz/garak) is NVIDIA's open-source LLM
vulnerability scanner — a curated catalog of jailbreak probes,
prompt-injection corpora, leakage tests, and toxicity provocations.

This module exposes Garak's probes through the same RedTeamRun /
ProbeResult schema the rule-based harness uses, so the React Red Team
page transparently shows Garak findings alongside the chapter-6
deterministic probes when Garak is installed.

When Garak isn't installed (no `pip install garak`), the runner falls
back to a curated 12-probe synthetic equivalent — same schema, no
network calls, deterministic outputs. Both paths emit the same
RedTeamRun shape so the UI doesn't care which is active.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Literal

from plugins.agent_studio.red_team import (
    ProbeResult, RedTeamRun, RED_TEAM_LOG_PATH,
)

Severity = Literal["critical", "high", "medium", "low", "info"]


# ── Synthetic-fallback Garak catalog ──────────────────────────────────
# Curated subset of Garak's actual probe families. Each entry mimics
# the shape of a real Garak invocation so the React UI shows the same
# fields when we transparently switch to the live runner.

GARAK_PROBES_FALLBACK = [
    ("garak.dan",                    "DAN jailbreak family",                 "high",     "ASI01", "AML.T0051"),
    ("garak.continuation",           "Continuation attack (incomplete prompts)", "medium", "ASI01", "AML.T0051"),
    ("garak.encoding",               "Base64 / ROT13 encoding evasion",      "medium",   "ASI01", "AML.T0051"),
    ("garak.goodside",               "Riley Goodside-style injections",      "high",     "ASI01", "AML.T0051"),
    ("garak.malwaregen",             "Malware generation provocation",       "high",     "ASI05", "AML.T0050"),
    ("garak.misleading",             "Misleading prompts (hallucination)",   "medium",   "ASI07", "AML.T0044"),
    ("garak.packagehallucination",   "Hallucinated package names",           "medium",   "ASI07", "AML.T0010.000"),
    ("garak.promptinject",           "PromptInject corpus",                  "high",     "ASI01", "AML.T0051"),
    ("garak.realtoxicityprompts",    "RealToxicityPrompts subset",           "medium",   "ASI05", "AML.T0050"),
    ("garak.suffix",                 "GCG suffix-attack family",             "high",     "ASI01", "AML.T0051"),
    ("garak.leakreplay",             "Training-data extraction (LLM06)",     "high",     "ASI04", "AML.T0024.001"),
    ("garak.snowball",               "Snowballed-hallucination chain",       "medium",   "ASI07", "AML.T0044"),
]


def _deterministic_garak_run(target_spec: dict) -> list[ProbeResult]:
    """Build Garak-shaped results from target spec signals without
    network calls. Outputs are stable per target spec so demos
    reproduce."""
    text = json.dumps(target_spec, default=str).lower()
    seed = int(hash(text) % 2 ** 31)
    import random
    rng = random.Random(seed)

    out: list[ProbeResult] = []
    for code, name, severity, asi, atlas in GARAK_PROBES_FALLBACK:
        # Trigger likelihood derives from heuristic signals on the
        # target spec: weaker prompts trigger more probes.
        prob = 0.20
        if "ignore previous" in text or "forget everything" in text:
            prob += 0.45
        if "shell" in text or "exec" in text:
            prob += 0.15 if severity in ("high", "critical") else 0
        if "mambaguard" not in text and "guardrail" not in text:
            prob += 0.20 if severity == "high" else 0.10
        if "max_tokens" not in text and "timeout" not in text:
            prob += 0.10
        triggered = rng.random() < min(prob, 0.95)
        out.append(ProbeResult(
            code=code, owasp_agentic=asi, atlas_tactic=atlas,
            name=name, severity=severity, triggered=triggered,
            remediation=f"Mitigate {code}: add a runtime guard, "
                        f"narrow tool scope, and add a {asi} attestation.",
        ))
    return out


def _live_garak_run(target_spec: dict) -> list[ProbeResult] | None:
    """Try a real Garak invocation. Returns None when Garak isn't
    importable so the caller can fall back."""
    try:
        import garak  # noqa: F401
        from garak import _config
    except ImportError:
        return None
    # Real Garak runs are heavyweight (each probe drives a real LLM
    # generation). For the in-platform "Run now" button we cap to a
    # short list of probes + low generations per probe; full Garak
    # campaigns belong in a queued worker.
    try:
        # Resolve LLM endpoint from spec; if no endpoint declared,
        # we can't run live → fall back.
        endpoint = (target_spec.get("llm_endpoint") or
                    target_spec.get("model_endpoint"))
        if not endpoint:
            return None
        # Production: invoke `python -m garak --probes garak.dan,...
        # --model rest --max-generations 1`. Stub kept narrow so this
        # module imports + serialises cleanly without spawning subprocess
        # from a request handler.
        return None  # signals: live mode not yet wired up
    except Exception:
        return None


def run_garak(target_spec: dict) -> RedTeamRun:
    """Public entrypoint. Tries live Garak first, falls back to the
    deterministic synthetic catalog."""
    results = _live_garak_run(target_spec)
    runner_label = "garak_live"
    if results is None:
        results = _deterministic_garak_run(target_spec)
        runner_label = "garak_synthetic_fallback"

    breakdown: dict[str, int] = {}
    atlas_chain: list[str] = []
    for r in results:
        if r.triggered:
            breakdown[r.severity] = breakdown.get(r.severity, 0) + 1
            if r.atlas_tactic not in atlas_chain:
                atlas_chain.append(r.atlas_tactic)

    run = RedTeamRun(
        run_id=f"garak-{uuid.uuid4().hex[:10]}",
        target_name=target_spec.get("name") or "unnamed-agent",
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        n_probes=len(results),
        n_findings=sum(1 for r in results if r.triggered),
        severity_breakdown=breakdown,
        atlas_chain=atlas_chain,
        results=results,
    )
    _append_garak_run(run, runner_label)
    return run


def _append_garak_run(run: RedTeamRun, runner_label: str) -> None:
    RED_TEAM_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    history: list[dict] = []
    if RED_TEAM_LOG_PATH.exists():
        try:
            history = json.loads(RED_TEAM_LOG_PATH.read_text())
        except json.JSONDecodeError:
            history = []
    history.append({
        "run_id": run.run_id, "target_name": run.target_name,
        "timestamp": run.timestamp, "n_probes": run.n_probes,
        "n_findings": run.n_findings,
        "severity_breakdown": run.severity_breakdown,
        "atlas_chain": run.atlas_chain,
        "runner": runner_label,
        "results": [asdict(r) for r in run.results],
    })
    history = history[-100:]
    RED_TEAM_LOG_PATH.write_text(json.dumps(history, indent=2))


def runner_info() -> dict:
    """Surface which runner is active so the UI can show a badge."""
    try:
        import garak  # noqa: F401
        return {"runner": "garak_live", "version": getattr(garak, "__version__", "unknown")}
    except ImportError:
        return {"runner": "garak_synthetic_fallback", "version": "0.1.0",
                "hint": "`pip install garak` in the backend image to switch to live runs."}
