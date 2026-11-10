"""Turn the task's `available_tools` into LLM tool definitions and validators.

The runtime advertises the enabled tools and their argument schemas inside
every task observation. That catalog is authoritative; the pydantic models
shipped with the reference agent are used only to fill in a schema or a
description the catalog leaves out.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any

try:  # optional: install with `uv run --with jsonschema`
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - validation is then left to the server
    Draft202012Validator = None  # type: ignore[assignment,misc]

FINISH_TOOL = "finish_investigation"
_SCHEMA_KEYS = ("parameters", "input_schema", "inputSchema", "arguments_schema", "schema")


@dataclass
class ToolSpec:
    name: str
    description: str
    schema: dict[str, Any]
    _validator: Any = field(default=None, repr=False)
    llm_schema: dict[str, Any] = field(default_factory=dict)
    aliased: bool = False

    def from_llm(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Map the model-facing field names back to the runtime's."""
        return unalias(arguments) if self.aliased else arguments

    def validate(self, arguments: dict[str, Any]) -> list[str]:
        """Return readable schema violations (empty when valid or unknown)."""
        if self._validator is None:
            return []
        errors = sorted(self._validator.iter_errors(arguments), key=lambda e: list(e.path))
        out = []
        for err in errors[:4]:
            where = "/".join(str(p) for p in err.path) or "(root)"
            out.append(f"{where}: {err.message[:300]}")
        return out


class ToolCatalog:
    def __init__(self, specs: list[ToolSpec]) -> None:
        self.specs = {s.name: s for s in specs}

    @classmethod
    def from_observation(cls, observation: dict[str, Any]) -> ToolCatalog:
        raw = observation.get("available_tools")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError("available_tools is not valid JSON.") from exc
        if not isinstance(raw, list) or not all(isinstance(s, dict) for s in raw):
            raise ValueError("Observation has no usable available_tools list.")
        fallback = _reference_schemas()
        specs = []
        for entry in raw:
            name = entry.get("name")
            if not isinstance(name, str) or not name:
                continue
            schema = next((entry[k] for k in _SCHEMA_KEYS if isinstance(entry.get(k), dict)), None)
            ref_schema, ref_doc = fallback.get(name, (None, ""))
            if not _has_properties(schema) and ref_schema is not None:
                schema = ref_schema
            schema = prepare_schema(schema or {"type": "object"})
            description = str(entry.get("description") or ref_doc or name)
            validator = None
            if Draft202012Validator is not None and _has_properties(schema):
                try:
                    Draft202012Validator.check_schema(schema)
                    validator = Draft202012Validator(schema)
                except Exception:  # an exotic schema: let the server judge
                    validator = None
            llm_schema, aliased = alias_schema(schema)
            specs.append(ToolSpec(name, description, schema, validator, llm_schema, aliased))
        if FINISH_TOOL not in {s.name for s in specs}:
            raise ValueError("The runtime did not advertise finish_investigation.")
        return cls(specs)

    def __contains__(self, name: str) -> bool:
        return name in self.specs

    def names(self) -> list[str]:
        return sorted(self.specs)

    def anthropic_tools(self) -> list[dict[str, Any]]:
        return [
            {"name": s.name, "description": s.description, "input_schema": s.llm_schema}
            for s in self.specs.values()
        ]

    def openai_tools(self) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {"name": s.name, "description": s.description,
                             "parameters": s.llm_schema},
            }
            for s in self.specs.values()
        ]

    def public(self) -> list[dict[str, Any]]:
        return [{"name": s.name, "description": s.description} for s in self.specs.values()]


def _has_properties(schema: Any) -> bool:
    return isinstance(schema, dict) and bool(schema.get("properties"))


def prepare_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Inline local $refs, drop pydantic-only keys and guarantee an object root."""
    schema = copy.deepcopy(schema)
    defs = {**schema.pop("$defs", {}), **schema.pop("definitions", {})}

    def resolve(node: Any, depth: int = 0) -> Any:
        if depth > 40:
            return {}
        if isinstance(node, list):
            return [resolve(n, depth + 1) for n in node]
        if not isinstance(node, dict):
            return node
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.split("/")[-1] in defs:
            target = resolve(defs[ref.split("/")[-1]], depth + 1)
            extra = {k: v for k, v in node.items() if k != "$ref"}
            return {**target, **resolve(extra, depth + 1)}
        out = {}
        for key, value in node.items():
            if key == "properties" and isinstance(value, dict):
                out[key] = {k: resolve(v, depth + 1) for k, v in value.items()}
            elif key == "discriminator" and ("oneOf" in node or "anyOf" in node):
                continue  # OpenAPI keyword, not JSON Schema; providers choke on it
            elif key == "title":
                continue
            elif key == "oneOf":
                # Branches here are told apart by a const; anyOf is equivalent and
                # is the form OpenAI-compatible providers accept.
                out["anyOf"] = resolve(value, depth + 1)
            else:
                out[key] = resolve(value, depth + 1)
        return out

    schema = resolve(schema)
    if schema.get("type") != "object":
        schema = {"type": "object", **{k: v for k, v in schema.items() if k != "type"}}
    return schema


# The runtime names its free-text fields `reasoning`. Asking a model to write
# its reasoning into the response can be declined (stop_details category
# "reasoning_extraction"); a short statement of what a call checks, or a
# summary of the outcome, is fine. So the model sees `purpose` / `summary`,
# and the runtime still receives `reasoning`.
PURPOSE = {"type": "string", "minLength": 1, "maxLength": 1000,
           "description": "One short sentence naming what this call checks, e.g. "
                          "'Find which process launched the trigger process'."}
SUMMARY = {"type": "string", "minLength": 1,
           "description": "Short incident summary: what happened, in order, and the "
                          "evidence the verdict rests on."}


def alias_schema(schema: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    dumped = json.dumps(schema)
    if '"reasoning"' not in dumped or '"purpose"' in dumped or '"summary"' in dumped:
        return schema, False
    out = copy.deepcopy(schema)

    def rename(node: Any, top: bool) -> None:
        if isinstance(node, list):
            for n in node:
                rename(n, top)
            return
        if not isinstance(node, dict):
            return
        props = node.get("properties")
        if isinstance(props, dict) and "reasoning" in props:
            new = "purpose" if top else "summary"
            node["properties"] = {(new if k == "reasoning" else k):
                                  (dict(PURPOSE if top else SUMMARY) if k == "reasoning" else v)
                                  for k, v in props.items()}
            if isinstance(node.get("required"), list):
                node["required"] = [new if r == "reasoning" else r for r in node["required"]]
        for key, value in node.items():
            if key == "properties" and isinstance(value, dict):
                for v in value.values():
                    rename(v, False)
            elif key != "required":
                rename(value, False)

    rename(out, True)
    return out, True


def unalias(arguments: dict[str, Any]) -> dict[str, Any]:
    def back(node: Any) -> Any:
        if isinstance(node, list):
            return [back(n) for n in node]
        if isinstance(node, dict):
            return {("reasoning" if k == "summary" else k): back(v) for k, v in node.items()}
        return node

    out = {("reasoning" if k == "purpose" else k): v for k, v in arguments.items()}
    return {k: (back(v) if isinstance(v, dict | list) else v) for k, v in out.items()}


def _reference_schemas() -> dict[str, tuple[dict[str, Any], str]]:
    """Schemas from the reference agent's models, minus their `tool` tag."""
    try:
        from bluesec1_agent import models as ref
    except Exception:
        return {}
    pairs = {
        "search": "SearchRequest",
        "get_entity": "GetEntityRequest",
        "get_relation": "GetRelationRequest",
        "get_ad_object_info": "GetADObjectInfoRequest",
        "finish_investigation": "FinishInvestigationRequest",
    }
    out: dict[str, tuple[dict[str, Any], str]] = {}
    for tool, cls_name in pairs.items():
        model = getattr(ref, cls_name, None)
        if model is None:
            continue
        schema = model.model_json_schema(by_alias=True)
        schema.get("properties", {}).pop("tool", None)
        if "required" in schema:
            schema["required"] = [r for r in schema["required"] if r != "tool"]
        out[tool] = (schema, (model.__doc__ or "").strip())
    return out
