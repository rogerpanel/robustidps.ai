"""LLM loops: Claude (native tool use), any OpenAI-compatible provider (Chat
Completions), and OpenAI's Responses API (tool use with reasoning).

Both loops hand every tool call to `Investigation.execute` and stop at the
first terminal result from the runtime.
"""
from __future__ import annotations

import json
from typing import Any

from bluesec1_client import TaskResult

from .investigation import Investigation
from .prompt import NUDGE, SYSTEM_PROMPT, initial_message

FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AgentStop(RuntimeError):
    """The model cannot continue this task; the caller aborts it."""


async def run_claude(inv: Investigation, client: Any, *, model: str, effort: str,
                     max_turns: int, max_tokens: int = 32000,
                     system: str = SYSTEM_PROMPT) -> TaskResult:
    observation = inv.session.task.observation
    tools = inv.catalog.anthropic_tools()
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": initial_message(observation, inv.catalog.names())}
    ]
    nudges = 0
    for _ in range(max_turns):
        async with client.beta.messages.stream(
            model=model,
            max_tokens=max_tokens,
            system=system,
            tools=tools,
            messages=messages,
            thinking={"type": "adaptive", "display": "summarized"},
            output_config={"effort": effort},
            cache_control={"type": "ephemeral"},
            betas=[FALLBACK_BETA],
            fallbacks="default",
        ) as stream:
            resp = await stream.get_final_message()
        usage = getattr(resp, "usage", None)
        inv.add_usage(
            input=getattr(usage, "input_tokens", 0) or 0,
            output=getattr(usage, "output_tokens", 0) or 0,
            cache_read=getattr(usage, "cache_read_input_tokens", 0) or 0,
            cache_write=getattr(usage, "cache_creation_input_tokens", 0) or 0,
        )
        # Append the content unchanged: thinking blocks must be passed back as-is.
        messages.append({"role": "assistant", "content": resp.content})
        for block in resp.content:
            if block.type == "thinking":
                inv.log_model("thinking", getattr(block, "thinking", ""))
            elif block.type == "text":
                inv.log_model("text", block.text)

        if resp.stop_reason == "refusal":
            details = getattr(resp, "stop_details", None)
            raise AgentStop(f"model refused: {getattr(details, 'category', None) or 'unspecified'}")

        tool_uses = [b for b in resp.content if b.type == "tool_use"]
        if not tool_uses:
            nudges += 1
            if nudges > 2:
                raise AgentStop("model stopped calling tools without submitting")
            messages.append({"role": "user", "content": NUDGE})
            continue

        results: list[dict[str, Any]] = []
        for i, tu in enumerate(tool_uses):
            out = await inv.execute(tu.name, tu.input)
            if out.terminal is not None:
                return out.terminal
            results.append({"type": "tool_result", "tool_use_id": tu.id,
                            "content": out.text, "is_error": out.is_error})
            if tu.name == "finish_investigation" and i < len(tool_uses) - 1:
                # a rejected submission batched with other calls: skip the rest
                for later in tool_uses[i + 1:]:
                    results.append({"type": "tool_result", "tool_use_id": later.id,
                                    "content": "Not executed: fix the submission first.",
                                    "is_error": True})
                break
        note = inv.note()
        if note:
            results.append({"type": "text", "text": note})
        messages.append({"role": "user", "content": results})
    raise AgentStop(f"no submission after {max_turns} model turns")


async def run_openai(inv: Investigation, client: Any, *, model: str, max_turns: int,
                     max_completion_tokens: int, system: str = SYSTEM_PROMPT,
                     reasoning_effort: str | None = None) -> TaskResult:
    observation = inv.session.task.observation
    tools = inv.catalog.openai_tools()
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": initial_message(observation, inv.catalog.names())},
    ]
    nudges = 0
    for _ in range(max_turns):
        resp = await client.chat.completions.create(
            model=model,
            messages=messages,
            tools=tools,
            tool_choice="auto",
            max_completion_tokens=max_completion_tokens,
            **({"reasoning_effort": reasoning_effort} if reasoning_effort else {}),
        )
        if not resp.choices:
            raise AgentStop("provider returned no choices")
        usage = getattr(resp, "usage", None)
        inv.add_usage(input=getattr(usage, "prompt_tokens", 0) or 0,
                      output=getattr(usage, "completion_tokens", 0) or 0)
        msg = resp.choices[0].message
        if getattr(msg, "refusal", None):
            raise AgentStop(f"model refused: {msg.refusal}")
        inv.log_model("text", msg.content or "")
        calls = list(msg.tool_calls or [])
        messages.append({
            "role": "assistant",
            "content": msg.content or "",
            **({"tool_calls": [
                {"id": c.id, "type": "function",
                 "function": {"name": c.function.name, "arguments": c.function.arguments}}
                for c in calls
            ]} if calls else {}),
        })
        if not calls:
            nudges += 1
            if nudges > 2:
                raise AgentStop("model stopped calling tools without submitting")
            messages.append({"role": "user", "content": NUDGE})
            continue

        skip = False
        for c in calls:
            if skip:
                text = "Not executed: fix the submission first."
            else:
                try:
                    args = json.loads(c.function.arguments or "{}")
                except json.JSONDecodeError as exc:
                    text = f"Arguments are not valid JSON ({exc.msg}); no call was spent."
                else:
                    out = await inv.execute(c.function.name, args)
                    if out.terminal is not None:
                        return out.terminal
                    text = out.text
                    skip = c.function.name == "finish_investigation"
            messages.append({"role": "tool", "tool_call_id": c.id, "content": text})
        note = inv.note()
        if note:
            messages[-1]["content"] += "\n" + note
    raise AgentStop(f"no submission after {max_turns} model turns")


def responses_tools(chat_tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Chat Completions tool definitions in the Responses API's flat form."""
    return [{"type": "function", "name": t["function"]["name"],
             "description": t["function"].get("description") or "",
             "parameters": t["function"]["parameters"], "strict": False}
            for t in chat_tools]


async def run_openai_responses(inv: Investigation, client: Any, *, model: str, max_turns: int,
                               max_output_tokens: int, effort: str | None = None,
                               system: str = SYSTEM_PROMPT) -> TaskResult:
    """The same loop over OpenAI's Responses API, which allows tool calls together with
    reasoning on newer models. Turns are chained with previous_response_id, so each
    request carries only the new tool outputs."""
    observation = inv.session.task.observation
    tools = responses_tools(inv.catalog.openai_tools())
    pending: list[dict[str, Any]] = [
        {"role": "user", "content": initial_message(observation, inv.catalog.names())}]
    previous: str | None = None
    nudges = 0
    for _ in range(max_turns):
        kw: dict[str, Any] = {"model": model, "instructions": system, "input": pending,
                              "tools": tools, "max_output_tokens": max_output_tokens}
        if previous:
            kw["previous_response_id"] = previous
        if effort:
            kw["reasoning"] = {"effort": effort, "summary": "auto"}
        resp = await client.responses.create(**kw)
        previous = resp.id
        usage = getattr(resp, "usage", None)
        cached = getattr(getattr(usage, "input_tokens_details", None), "cached_tokens", 0) or 0
        inv.add_usage(input=max(0, (getattr(usage, "input_tokens", 0) or 0) - cached),
                      output=getattr(usage, "output_tokens", 0) or 0, cache_read=cached)
        calls = []
        for item in getattr(resp, "output", None) or []:
            kind = getattr(item, "type", "")
            if kind == "reasoning":
                summary = " ".join(getattr(s, "text", "") for s in getattr(item, "summary", None) or [])
                inv.log_model("thinking", summary)
            elif kind == "message":
                for part in getattr(item, "content", None) or []:
                    if getattr(part, "type", "") == "refusal":
                        raise AgentStop(f"model refused: {part.refusal}")
                    if getattr(part, "type", "") == "output_text":
                        inv.log_model("text", part.text)
            elif kind == "function_call":
                calls.append(item)
        if not calls:
            nudges += 1
            if nudges > 2:
                raise AgentStop("model stopped calling tools without submitting")
            pending = [{"role": "user", "content": NUDGE}]
            continue

        pending = []
        skip = False
        for c in calls:
            if skip:
                text = "Not executed: fix the submission first."
            else:
                try:
                    args = json.loads(c.arguments or "{}")
                except json.JSONDecodeError as exc:
                    text = f"Arguments are not valid JSON ({exc.msg}); no call was spent."
                else:
                    out = await inv.execute(c.name, args)
                    if out.terminal is not None:
                        return out.terminal
                    text = out.text
                    skip = c.name == "finish_investigation"
            pending.append({"type": "function_call_output", "call_id": c.call_id, "output": text})
        note = inv.note()
        if note:
            pending[-1]["output"] += "\n" + note
    raise AgentStop(f"no submission after {max_turns} model turns")
