"""The investigation loop.

`investigate()` drives an LLM through evidence queries to a verdict and
records every step in a trace dict. The trace is mutated in place, so a
caller can poll it while the run is in progress.

Two provider paths share one tool dispatcher:
  anthropic                  Anthropic SDK (beta Messages: refusal fallbacks)
  openai, deepseek, google   OpenAI SDK against each provider's
                             OpenAI-compatible endpoint
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass

from .evidence import EvidenceSource
from .tools import TOOLS, openai_tools, run_evidence_tool, to_text, validate_verdict

SYSTEM_PROMPT = """You are a senior SOC analyst investigating a security alert. You work autonomously: request evidence, test hypotheses, reconstruct what happened, and deliver a verdict.

Method
1. Read the alert. Before any query, form two to four competing hypotheses, always including a benign or false-positive explanation.
2. Each evidence query must target the hypothesis that would most change your conclusion, stated in its `rationale`. Filter tightly (host, user, time window, event type) so one query answers one question. Do not browse.
3. After each result, update which hypotheses remain plausible. Follow the strongest lead and drop refuted ones.
4. Check the context that most often changes a verdict: the asset record (role, owner, notes such as authorised testing or maintenance) and threat-intelligence verdicts for external indicators.
5. Stop as soon as the evidence settles the verdict and its scope: which hosts and accounts are affected and how it began. Efficiency is scored by the number of evidence queries, so unused budget is a good outcome.
6. Call submit_verdict exactly once. Every timeline entry and hypothesis must cite event ids you actually retrieved. Never invent hosts, accounts, indicators or event ids. Cite MITRE ATT&CK IDs only for behaviour the evidence shows.

Verdicts
- true_positive: malicious activity occurred.
- false_positive: the alert fired but nothing malicious or unexpected happened, for example a misconfiguration or a detection-logic error.
- benign_true_positive: the detected activity really happened but is authorised or expected.

Your evidence-query budget is stated in the first message. If you are told it is exhausted, submit your verdict immediately with what you have."""

NUDGE = ("You have not submitted a verdict. Call submit_verdict now with your best "
         "assessment of the evidence gathered so far.")

DEFAULT_MODELS = {
    "anthropic": "claude-opus-5-5",
    "openai": "gpt-4o",
    "google": "gemini-2.0-flash",
    "deepseek": "deepseek-chat",
}
OPENAI_COMPATIBLE_URLS = {
    "openai": None,
    "google": "https://generativelanguage.googleapis.com/v1beta/openai/",
    "deepseek": "https://api.deepseek.com",
}
KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY",
           "google": "GOOGLE_API_KEY", "deepseek": "DEEPSEEK_API_KEY"}

# Server-side refusal fallback: an investigation of attack evidence can trip
# a safety classifier; "default" lets the API re-run a declined turn on an
# appropriate fallback model instead of ending the investigation.
FALLBACK_BETA = "server-side-fallback-2026-07-01"


@dataclass
class RunConfig:
    provider: str = "anthropic"
    model: str | None = None
    effort: str = "high"          # anthropic only: low | medium | high | xhigh | max
    max_tool_calls: int = 15      # evidence queries; submit_verdict does not count
    api_key: str | None = None

    def resolved_model(self) -> str:
        return self.model or DEFAULT_MODELS[self.provider]


def new_trace(cfg: RunConfig, mission_id: str | None = None) -> dict:
    return {"status": "running", "mission_id": mission_id, "provider": cfg.provider,
            "model": cfg.resolved_model(), "max_tool_calls": cfg.max_tool_calls,
            "steps": [], "tool_calls": 0, "verdict": None, "stop_reason": None,
            "error": None, "usage": {"input_tokens": 0, "output_tokens": 0,
                                     "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0},
            "started_at": time.time(), "duration_s": None}


def _opening(brief: dict, cfg: RunConfig) -> str:
    return ("Investigate this incident.\n\n" + json.dumps(brief, indent=2, ensure_ascii=False)
            + f"\n\nEvidence-query budget: {cfg.max_tool_calls} calls.")


def _handle(name: str, args: dict, source: EvidenceSource, cfg: RunConfig, trace: dict) -> tuple[str, bool]:
    """Run one tool call and record it. Returns (tool result text, is_error)."""
    steps = trace["steps"]
    if name == "submit_verdict":
        problems = validate_verdict(args)
        if problems:
            steps.append({"type": "note", "text": f"Verdict rejected: {'; '.join(problems)}"})
            return to_text({"error": "verdict invalid", "problems": problems}), True
        trace["verdict"] = args
        steps.append({"type": "verdict", "verdict": args})
        return "Verdict recorded.", False
    if trace["tool_calls"] >= cfg.max_tool_calls:
        steps.append({"type": "note", "text": f"Refused {name}: evidence-query budget exhausted."})
        return to_text({"error": "Evidence-query budget exhausted. Call submit_verdict now."}), True
    trace["tool_calls"] += 1
    result, is_error = run_evidence_tool(name, args, source)
    steps.append({"type": "tool_call", "n": trace["tool_calls"], "tool": name,
                  "rationale": args.get("rationale", ""),
                  "input": {k: v for k, v in args.items() if k != "rationale"},
                  "result": result, "is_error": is_error})
    return to_text(result), is_error


def _add_usage(trace: dict, **counts: int | None) -> None:
    for k, v in counts.items():
        trace["usage"][k] += v or 0


def _run_anthropic(brief: dict, source: EvidenceSource, cfg: RunConfig, trace: dict, client=None) -> None:
    if client is None:
        import anthropic
        client = anthropic.Anthropic(api_key=cfg.api_key) if cfg.api_key else anthropic.Anthropic()
    messages: list[dict] = [{"role": "user", "content": _opening(brief, cfg)}]
    nudged = False
    for _ in range(cfg.max_tool_calls + 6):
        resp = client.beta.messages.create(
            model=cfg.resolved_model(), max_tokens=16000,
            system=SYSTEM_PROMPT, tools=TOOLS, messages=messages,
            thinking={"type": "adaptive", "display": "summarized"},
            output_config={"effort": cfg.effort},
            cache_control={"type": "ephemeral"},
            betas=[FALLBACK_BETA], fallbacks="default",
        )
        u = resp.usage
        _add_usage(trace, input_tokens=u.input_tokens, output_tokens=u.output_tokens,
                   cache_read_input_tokens=getattr(u, "cache_read_input_tokens", 0),
                   cache_creation_input_tokens=getattr(u, "cache_creation_input_tokens", 0))
        # Append the full content unchanged: thinking blocks are only valid
        # when the history is replayed exactly as the model produced it.
        messages.append({"role": "assistant", "content": resp.content})
        for block in resp.content:
            text = getattr(block, "thinking", None) if block.type == "thinking" else \
                   getattr(block, "text", None) if block.type == "text" else None
            if text and text.strip():
                trace["steps"].append({"type": "reasoning", "text": text.strip()})

        if resp.stop_reason == "refusal":
            cat = getattr(getattr(resp, "stop_details", None), "category", None)
            trace["steps"].append({"type": "note", "text": f"Model declined (category: {cat})."})
            trace["stop_reason"] = "refusal"
            return
        if resp.stop_reason == "max_tokens":
            trace["stop_reason"] = "max_tokens"
            return

        tool_uses = [b for b in resp.content if b.type == "tool_use"]
        if not tool_uses:
            if nudged:
                trace["stop_reason"] = "no_verdict"
                return
            nudged = True
            trace["steps"].append({"type": "note", "text": "No verdict yet; asked the model to submit."})
            messages.append({"role": "user", "content": NUDGE})
            continue

        results = []
        for tu in tool_uses:
            content, is_error = _handle(tu.name, tu.input, source, cfg, trace)
            result = {"type": "tool_result", "tool_use_id": tu.id, "content": content}
            if is_error:
                result["is_error"] = True
            results.append(result)
        # All results go back in one user message so parallel calls stay paired.
        messages.append({"role": "user", "content": results})
        if trace["verdict"] is not None:
            trace["stop_reason"] = "verdict_submitted"
            return
    trace["stop_reason"] = "turn_limit"


def _run_openai_compatible(brief: dict, source: EvidenceSource, cfg: RunConfig, trace: dict, client=None) -> None:
    if client is None:
        import openai
        key = cfg.api_key or os.environ.get(KEY_ENV[cfg.provider])
        base_url = OPENAI_COMPATIBLE_URLS[cfg.provider]
        client = openai.OpenAI(api_key=key, base_url=base_url) if base_url else openai.OpenAI(api_key=key)
    messages: list = [{"role": "system", "content": SYSTEM_PROMPT},
                      {"role": "user", "content": _opening(brief, cfg)}]
    tools = openai_tools()
    nudged = False
    for _ in range(cfg.max_tool_calls + 6):
        resp = client.chat.completions.create(model=cfg.resolved_model(), messages=messages,
                                              tools=tools, tool_choice="auto", max_tokens=8000)
        if resp.usage:
            _add_usage(trace, input_tokens=resp.usage.prompt_tokens, output_tokens=resp.usage.completion_tokens)
        msg = resp.choices[0].message
        messages.append(msg)
        if msg.content and msg.content.strip():
            trace["steps"].append({"type": "reasoning", "text": msg.content.strip()})
        if not msg.tool_calls:
            if nudged:
                trace["stop_reason"] = "no_verdict"
                return
            nudged = True
            trace["steps"].append({"type": "note", "text": "No verdict yet; asked the model to submit."})
            messages.append({"role": "user", "content": NUDGE})
            continue
        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
                content, _ = _handle(tc.function.name, args, source, cfg, trace)
            except json.JSONDecodeError:
                content = to_text({"error": "arguments were not valid JSON; resend the call"})
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": content})
        if trace["verdict"] is not None:
            trace["stop_reason"] = "verdict_submitted"
            return
    trace["stop_reason"] = "turn_limit"


def investigate(brief: dict, source: EvidenceSource, cfg: RunConfig,
                trace: dict | None = None, client=None) -> dict:
    """Run one investigation to completion. Pass `trace` to observe it live
    and `client` to inject a pre-built (or test) SDK client."""
    if cfg.provider not in DEFAULT_MODELS:
        raise ValueError(f"unknown provider {cfg.provider!r}; use one of {sorted(DEFAULT_MODELS)}")
    trace = trace if trace is not None else new_trace(cfg)
    try:
        if cfg.provider == "anthropic":
            _run_anthropic(brief, source, cfg, trace, client)
        else:
            _run_openai_compatible(brief, source, cfg, trace, client)
        trace["status"] = "done"
    except Exception as exc:  # surfaced to the caller via the trace, not raised mid-poll
        trace["status"] = "error"
        trace["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        trace["duration_s"] = round(time.time() - trace["started_at"], 1)
    return trace
