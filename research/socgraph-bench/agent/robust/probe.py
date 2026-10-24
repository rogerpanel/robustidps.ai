"""Send only the first model request, in three variants, and report refusals.

    uv run --with anthropic --with jsonschema --env-file .env \
        python -m bluesec1_agent.robust.probe

A: the agent's real first request (prompt + tools) for a mock task
B: the same without tools
C: the same tools with a one-line system prompt
Costs a few cents. Use it when runs abort with "model refused".
"""
from __future__ import annotations

import asyncio

from anthropic import AsyncAnthropic

from .catalog import ToolCatalog
from .drivers import FALLBACK_BETA
from .mock import SCENARIOS, MockSession
from .prompt import SYSTEM_PROMPT, initial_message
from .settings import RobustSettings


async def main() -> None:
    s = RobustSettings()
    if not s.anthropic_api_key:
        raise SystemExit("ANTHROPIC_API_KEY is not set in .env")
    client = AsyncAnthropic(api_key=s.anthropic_api_key.get_secret_value())
    session = MockSession(SCENARIOS[0])
    catalog = ToolCatalog.from_observation(session.task.observation)
    user = [{"role": "user",
             "content": initial_message(session.task.observation, catalog.names())}]
    variants = {
        "A agent request": {"system": SYSTEM_PROMPT, "tools": catalog.anthropic_tools()},
        "B without tools": {"system": SYSTEM_PROMPT},
        "C short prompt ": {"system": "You are a SOC analyst. Investigate the alert with the "
                                      "tools.", "tools": catalog.anthropic_tools()},
    }
    try:
        for label, extra in variants.items():
            async with client.beta.messages.stream(
                model=s.anthropic_model, max_tokens=4000, messages=user,
                thinking={"type": "adaptive", "display": "summarized"},
                output_config={"effort": "low"},
                betas=[FALLBACK_BETA], fallbacks="default", **extra,
            ) as stream:
                r = await stream.get_final_message()
            details = getattr(r, "stop_details", None)
            category = getattr(details, "category", None) or "-"
            first = next((b.type + (":" + b.name if b.type == "tool_use" else "")
                          for b in r.content if b.type in ("tool_use", "text")), "-")
            print(f"{label}  stop={r.stop_reason:10s} category={category:22s} first={first}  "
                  f"model={r.model}")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
