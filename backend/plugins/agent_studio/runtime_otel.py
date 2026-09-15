"""OpenTelemetry GenAI receiver for Agent Studio Runtime Monitor.

Accepts OTLP-style spans matching the GenAI semantic conventions
(https://github.com/open-telemetry/semantic-conventions/blob/main/docs/gen-ai/llm-spans.md)
and feeds them into the runtime_monitor event stream. Customer agents
instrumented with the AegisAgents Kit or any OpenTelemetry GenAI
auto-instrumentation (OpenLLMetry / Traceloop / Langtrace) ship spans
to this endpoint and they surface live in the Runtime Monitor.

Two consumption paths:
  receive_otlp_json — full OTLP JSON envelope (production)
  receive_span      — single trimmed span dict (lightweight ingestion)

Both convert to the runtime_monitor.Event schema and call ingest().
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from plugins.agent_studio.runtime_monitor import ingest

# OTel GenAI semantic-convention attribute names
ATTR_OP_NAME = "gen_ai.operation.name"           # chat, embedding, text_completion, tool_call
ATTR_SYSTEM = "gen_ai.system"                    # openai, anthropic, google, deepseek
ATTR_MODEL = "gen_ai.request.model"
ATTR_AGENT_NAME = "gen_ai.agent.name"
ATTR_FRAMEWORK = "gen_ai.framework"              # langgraph, crewai, openai_agents, etc.
ATTR_TOOL_NAME = "gen_ai.tool.name"
ATTR_DECISION = "robustidps.aegis.decision"      # allow / warn / block (custom)
ATTR_FINDING_CODES = "robustidps.aegis.findings" # comma-separated codes (custom)


@dataclass
class GenAISpan:
    trace_id: str
    span_id: str
    name: str
    start_ns: int
    end_ns: int
    attributes: dict[str, Any]


def _to_event(span: GenAISpan) -> dict:
    """Convert a GenAI span into a runtime_monitor.ingest payload."""
    attrs = span.attributes or {}
    agent_id = (attrs.get(ATTR_AGENT_NAME) or
                attrs.get("service.name") or
                "unknown-agent")
    framework = attrs.get(ATTR_FRAMEWORK) or attrs.get(ATTR_SYSTEM) or "otel"
    decision = attrs.get(ATTR_DECISION) or "allow"
    findings_str = attrs.get(ATTR_FINDING_CODES) or ""
    finding_codes = [c.strip() for c in str(findings_str).split(",") if c.strip()]
    latency_ms = max(0.0, (span.end_ns - span.start_ns) / 1_000_000)
    return {
        "agent_id": agent_id,
        "framework": framework,
        "decision": decision,
        "finding_codes": finding_codes,
        "latency_ms": latency_ms,
    }


def receive_span(span_dict: dict) -> dict:
    """Ingest a single trimmed span: {trace_id, span_id, name,
    start_time_unix_nano, end_time_unix_nano, attributes}."""
    span = GenAISpan(
        trace_id=span_dict.get("trace_id", ""),
        span_id=span_dict.get("span_id", ""),
        name=span_dict.get("name", ""),
        start_ns=int(span_dict.get("start_time_unix_nano", 0)),
        end_ns=int(span_dict.get("end_time_unix_nano", time.time_ns())),
        attributes=span_dict.get("attributes") or {},
    )
    payload = _to_event(span)
    return ingest(**payload)


def receive_otlp_json(otlp_payload: dict) -> dict:
    """Ingest a full OTLP/JSON traces payload. Walks
    resourceSpans → scopeSpans → spans and ingests each one."""
    n_ingested = 0
    alerts = []
    for rs in otlp_payload.get("resourceSpans", []):
        resource_attrs = {
            kv.get("key"): _flatten_attr_value(kv.get("value"))
            for kv in (rs.get("resource", {}).get("attributes") or [])
        }
        for ss in rs.get("scopeSpans", []):
            for sp in ss.get("spans", []):
                span_attrs = {
                    kv.get("key"): _flatten_attr_value(kv.get("value"))
                    for kv in (sp.get("attributes") or [])
                }
                merged = {**resource_attrs, **span_attrs}
                span = GenAISpan(
                    trace_id=sp.get("traceId", ""),
                    span_id=sp.get("spanId", ""),
                    name=sp.get("name", ""),
                    start_ns=int(sp.get("startTimeUnixNano", 0)),
                    end_ns=int(sp.get("endTimeUnixNano", time.time_ns())),
                    attributes=merged,
                )
                result = ingest(**_to_event(span))
                n_ingested += 1
                if result.get("alert_fired") and result.get("alert"):
                    alerts.append(result["alert"])
    return {
        "ingested": True,
        "n_spans": n_ingested,
        "alerts_fired": len(alerts),
        "alerts": alerts,
    }


def _flatten_attr_value(value: Any) -> Any:
    """OTel-JSON wraps values in {stringValue, intValue, boolValue, ...}
    — unwrap to the bare Python value."""
    if isinstance(value, dict):
        for k in ("stringValue", "intValue", "doubleValue", "boolValue"):
            if k in value:
                return value[k]
        if "arrayValue" in value:
            return [_flatten_attr_value(v) for v in value["arrayValue"].get("values", [])]
    return value


def receiver_info() -> dict:
    """Surface the runtime status for a UI badge."""
    return {
        "receiver": "robustidps.aegis.otel_genai_receiver",
        "version": "0.1.0",
        "semconv_version": "1.27.0",
        "endpoints": [
            "POST /api/agent-studio/runtime/otel/spans (single trimmed span)",
            "POST /api/agent-studio/runtime/otel/traces (full OTLP/JSON envelope)",
        ],
        "supported_attributes": [
            ATTR_OP_NAME, ATTR_SYSTEM, ATTR_MODEL, ATTR_AGENT_NAME,
            ATTR_FRAMEWORK, ATTR_TOOL_NAME, ATTR_DECISION, ATTR_FINDING_CODES,
        ],
    }
