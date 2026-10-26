"""LLM dispatch for Agent Studio test sessions.

Light wrapper over the four providers the SOC Copilot already wires up
(Anthropic / OpenAI / Google Gemini / DeepSeek). Picks the first one
that has a key configured, falls back gracefully to the synthetic
responder when no provider is available.

Why a dedicated module instead of reusing copilot._openai_compatible_call?
- Sessions don't need the SOC Copilot's tool-loop or 4096-token system
  prompt — they're a single-turn dispatch with the template's prompt.
- Sessions must work offline (air-gapped deploys, CI), so the fallback
  must be deterministic — which the SOC Copilot path is not.
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger("agent_studio.llm")

DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-4-6",
    "openai":    "gpt-4o-mini",
    "google":    "gemini-2.5-flash",
    "deepseek":  "deepseek-chat",
}

OPENAI_COMPATIBLE_BASE = {
    "openai":   None,
    "google":   "https://generativelanguage.googleapis.com/v1beta/openai/",
    "deepseek": "https://api.deepseek.com",
}

MAX_TOKENS = 800       # plenty for a test-turn reply, keeps cost low
TIMEOUT_S = 30.0


def _provider_priority() -> list[str]:
    """Honour AGENT_STUDIO_LLM_PROVIDER if set; else first-available."""
    forced = os.getenv("AGENT_STUDIO_LLM_PROVIDER", "").lower().strip()
    if forced in DEFAULT_MODELS:
        return [forced]
    return ["anthropic", "openai", "google", "deepseek"]


def _provider_key(provider: str) -> str | None:
    env_var = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai":    "OPENAI_API_KEY",
        "google":    "GOOGLE_API_KEY",
        "deepseek":  "DEEPSEEK_API_KEY",
    }[provider]
    return os.getenv(env_var)


def active_provider() -> tuple[str, str] | None:
    """Return (provider, model) for the first provider with a key set, or None."""
    for p in _provider_priority():
        key = _provider_key(p)
        if key:
            return (p, DEFAULT_MODELS[p])
    return None


def dispatch(system_prompt: str, user_input: str,
             history: list[dict] | None = None,
             model: str | None = None) -> tuple[str, dict] | None:
    """Single-turn LLM call. Returns (reply_text, meta) or None when no
    provider is available. `meta` carries {provider, model, n_in, n_out}
    for the session record.
    """
    active = active_provider()
    if active is None:
        return None
    provider, default_model = active
    use_model = model or default_model

    messages: list[dict] = [{"role": "system", "content": system_prompt[:6000]}]
    for h in (history or [])[-6:]:        # cap context for cost
        if h.get("role") in ("user", "agent"):
            messages.append({
                "role": "user" if h["role"] == "user" else "assistant",
                "content": str(h.get("text", ""))[:4000],
            })
    messages.append({"role": "user", "content": user_input[:8000]})

    try:
        if provider == "anthropic":
            return _dispatch_anthropic(messages, use_model)
        return _dispatch_openai_compatible(messages, use_model,
                                           base_url=OPENAI_COMPATIBLE_BASE[provider],
                                           provider_name=provider)
    except Exception as e:
        logger.warning("LLM dispatch failed (provider=%s): %s", provider, e)
        return None


def _dispatch_anthropic(messages: list[dict], model: str) -> tuple[str, dict]:
    import anthropic
    sys_msg = next((m["content"] for m in messages if m["role"] == "system"), "")
    convo = [m for m in messages if m["role"] != "system"]
    client = anthropic.Anthropic(
        api_key=_provider_key("anthropic"),
        timeout=TIMEOUT_S,
    )
    resp = client.messages.create(
        model=model,
        max_tokens=MAX_TOKENS,
        system=sys_msg,
        messages=convo,
    )
    text = "".join(b.text for b in resp.content if hasattr(b, "text")) or ""
    return (text.strip(), {
        "provider": "anthropic", "model": model,
        "n_in": int(resp.usage.input_tokens), "n_out": int(resp.usage.output_tokens),
    })


def _dispatch_openai_compatible(messages: list[dict], model: str,
                                base_url: str | None,
                                provider_name: str) -> tuple[str, dict]:
    import openai
    api_key = _provider_key(provider_name)
    client = openai.OpenAI(api_key=api_key, base_url=base_url, timeout=TIMEOUT_S)
    resp = client.chat.completions.create(
        model=model, messages=messages, max_tokens=MAX_TOKENS,
    )
    text = resp.choices[0].message.content or ""
    n_in = getattr(resp.usage, "prompt_tokens", 0) if resp.usage else 0
    n_out = getattr(resp.usage, "completion_tokens", 0) if resp.usage else 0
    return (text.strip(), {
        "provider": provider_name, "model": model,
        "n_in": int(n_in), "n_out": int(n_out),
    })


def info() -> dict:
    """Diagnostic — surface which provider sessions will use."""
    active = active_provider()
    if active is None:
        return {
            "provider": "synthetic_fallback",
            "reason": "no LLM provider key set",
            "available": [],
            "configured_priority": _provider_priority(),
        }
    return {
        "provider": active[0], "model": active[1],
        "configured_priority": _provider_priority(),
        "available": [p for p in DEFAULT_MODELS if _provider_key(p)],
    }
