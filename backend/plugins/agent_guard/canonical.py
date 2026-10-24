"""L0: put a proposed call into the form the policy judges.

- Unicode NFKC, then removal of characters a human reviewer cannot see
  (zero-width, bidirectional controls, tag characters, variation selectors).
  Hidden text in tool metadata or arguments makes what a human approves differ
  from what the model or tool receives, so every removal is reported.
- Rationale fields (the agent's own explanation of the call) are kept for the
  tool but excluded from rule matching: a justification the agent or an
  attacker writes must not change the verdict.
- A stable JSON form of the arguments identifies "the same call" for sticky
  denials.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from typing import Any

# Invisible or direction-changing code points.
_HIDDEN = re.compile(
    "[­͏؜ᅟᅠ឴឵᠋-᠏​-‏"
    "‪-‮⁠-⁤⁦-⁯ㅤ︀-️﻿ﾠ"
    "\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)

RATIONALE_KEYS = frozenset({
    "reasoning", "reason", "purpose", "rationale", "justification",
    "explanation", "thought", "thoughts", "why", "intent", "description",
})

MAX_STRING = 20_000  # longer strings are cut before regex matching


def clean_text(text: str) -> tuple[str, list[str]]:
    """NFKC-normalise and drop hidden characters; return (clean, removed code points)."""
    norm = unicodedata.normalize("NFKC", text)
    removed = [f"U+{ord(ch):04X}" for ch in _HIDDEN.findall(norm)]
    return _HIDDEN.sub("", norm), removed


def clean_value(value: Any, path: str, found: list[str]) -> Any:
    """Recursively clean strings (keys included) in a JSON-like value."""
    if isinstance(value, str):
        clean, removed = clean_text(value)
        if removed:
            found.append(f"{path or '$'}: {', '.join(sorted(set(removed)))}")
        return clean
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            ck = clean_value(str(k), f"{path}.{k}" if path else str(k), found)
            out[ck] = clean_value(v, f"{path}.{ck}" if path else ck, found)
        return out
    if isinstance(value, list):
        return [clean_value(v, f"{path}[{i}]", found) for i, v in enumerate(value)]
    return value


def canonical_tool(name: str) -> tuple[str, list[str]]:
    clean, removed = clean_text(name)
    return clean.strip().lower(), removed


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def call_key(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def matchable_strings(args: dict[str, Any]) -> list[tuple[str, str]]:
    """(key path, string value) pairs for rule matching, rationale fields excluded."""
    out: list[tuple[str, str]] = []

    def walk(value: Any, path: str, top: str) -> None:
        if top.lower() in RATIONALE_KEYS:
            return
        if isinstance(value, dict):
            for k, v in value.items():
                walk(v, f"{path}.{k}" if path else str(k), top or str(k))
        elif isinstance(value, list):
            for i, v in enumerate(value):
                walk(v, f"{path}[{i}]", top)
        elif value is not None and not isinstance(value, bool):
            out.append((path, str(value)[:MAX_STRING]))

    for k, v in args.items():
        walk(v, str(k), str(k))
    return out
