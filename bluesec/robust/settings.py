"""Settings for the RobustIDPS agent. Reads the same .env as the reference agent."""
from __future__ import annotations

import datetime
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

_ENV_FILE = Path(__file__).resolve().parents[3] / ".env"

# Components that --ablate can turn off, to measure what each contributes.
ABLATIONS = {
    "cache": "repeated calls are sent to the runtime again",
    "validation": "no local schema validation before sending",
    "grounding": "no warning for submitted ids never seen in evidence",
    "budget": "no call-count notes and no hard cap on tool calls",
    "method": "minimal system prompt instead of the investigation method",
}


class RobustSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_ENV_FILE, env_file_encoding="utf-8", extra="ignore", populate_by_name=True
    )

    # Competition runtime (same variables as the reference agent).
    scenario_runtime_endpoint: str = Field("bluesec.team:443", alias="SCENARIO_RUNTIME_ENDPOINT")
    scenario_runtime_token: SecretStr | None = Field(None, alias="SCENARIO_RUNTIME_TOKEN")
    scenario_runtime_verify_tls: bool = Field(True, alias="SCENARIO_RUNTIME_VERIFY_TLS")
    scenario_runtime_arena: str | None = Field(None, alias="SCENARIO_RUNTIME_ARENA")
    remote_run_label: str = Field("robustidps-agent", alias="REMOTE_RUN_LABEL")
    agent_name: str = Field("robustidps-agent", alias="AGENT_NAME", max_length=255)

    # Which model drives the loop.
    provider: Literal["anthropic", "openai"] = Field("anthropic", alias="ROBUST_PROVIDER")
    anthropic_api_key: SecretStr | None = Field(None, alias="ANTHROPIC_API_KEY")
    anthropic_model: str = Field("claude-opus-5-5", alias="ANTHROPIC_MODEL")
    anthropic_effort: Literal["low", "medium", "high", "xhigh", "max"] = Field(
        "high", alias="ANTHROPIC_EFFORT"
    )
    llm_base_url: str | None = Field(None, alias="LLM_BASE_URL")
    llm_api_key: SecretStr | None = Field(None, alias="LLM_API_KEY")
    llm_default_model: str | None = Field(None, alias="LLM_DEFAULT_MODEL")
    llm_timeout_seconds: float = Field(180.0, alias="LLM_TIMEOUT_SECONDS", gt=0)
    llm_max_completion_tokens: int = Field(16_384, alias="LLM_MAX_COMPLETION_TOKENS", gt=0)

    # Investigation limits.
    soft_budget: int = Field(12, alias="ROBUST_SOFT_BUDGET", ge=1)
    max_tool_calls: int = Field(30, alias="ROBUST_MAX_TOOL_CALLS", ge=1, le=100)
    max_turns: int = Field(45, alias="ROBUST_MAX_TURNS", ge=1, le=200)
    max_result_chars: int = Field(24_000, alias="ROBUST_MAX_RESULT_CHARS", ge=1000)
    trace_dir: Path = Field(Path("traces"), alias="ROBUST_TRACE_DIR")

    # Parallel tasks. The runtime may allow fewer; the agent then learns its limit.
    concurrency: int = Field(1, alias="ROBUST_CONCURRENCY", ge=1, le=16)
    # Hard submission deadline (ISO 8601 with timezone, or --deadline HH:MM Moscow time).
    deadline: datetime.datetime | None = Field(None, alias="ROBUST_DEADLINE")
    # Ablation: comma-separated components to turn off (see ABLATIONS); label names the run.
    ablate: str = Field("", alias="ROBUST_ABLATE")
    run_label: str | None = Field(None, alias="ROBUST_LABEL", max_length=120)
    lease_stop_minutes: float = Field(6.0, alias="ROBUST_LEASE_STOP_MINUTES", ge=0)
    finish_minutes: float = Field(2.0, alias="ROBUST_FINISH_MINUTES", ge=0)

    def ablations(self) -> list[str]:
        items = sorted({x.strip().lower() for x in self.ablate.split(",") if x.strip()})
        unknown = set(items) - set(ABLATIONS)
        if unknown:
            raise ValueError(
                f"unknown ablation(s) {sorted(unknown)}; choose from {list(ABLATIONS)}"
            )
        return items

    def config_label(self) -> str:
        if self.run_label:
            return self.run_label
        return "full" if not self.ablations() else "no " + "+".join(self.ablations())

    def model_label(self) -> str:
        if self.provider == "anthropic":
            return self.anthropic_model
        return self.llm_default_model or "unknown"

    def missing(self, *, need_runtime: bool) -> list[str]:
        out = []
        if need_runtime and not self.scenario_runtime_token:
            out.append("SCENARIO_RUNTIME_TOKEN")
        if self.provider == "anthropic" and not self.anthropic_api_key:
            out.append("ANTHROPIC_API_KEY")
        if self.provider == "openai":
            for name, value in (("LLM_BASE_URL", self.llm_base_url),
                                ("LLM_API_KEY", self.llm_api_key),
                                ("LLM_DEFAULT_MODEL", self.llm_default_model)):
                if not value:
                    out.append(name)
        return out
