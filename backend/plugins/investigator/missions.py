"""Practice missions: an incident brief, the evidence behind it, and the
expected answer used for scoring.

Missions are JSON files in ./missions so practice sets (including a
competition's own practice tasks) can be added without code changes.
Fields:

  id, title, difficulty ("simple" | "complex")
  brief       what the agent receives when the investigation starts
  events      evidence records the agent can query (opaque ids, so an id
              never hints at whether an event matters)
  hosts       asset inventory returned by get_host_info
  intel       threat-intelligence entries returned by lookup_indicator
  answer      expected verdict and findings; omit for unseen incidents
  optimal_tool_calls   reference count for the efficiency score
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

MISSIONS_DIR = Path(__file__).parent / "missions"
REQUIRED = ("id", "title", "difficulty", "brief", "events")


@dataclass(frozen=True)
class Mission:
    id: str
    title: str
    difficulty: str
    brief: dict
    events: list[dict]
    hosts: dict[str, dict]
    intel: dict[str, dict]
    answer: dict | None
    optimal_tool_calls: int | None

    def public(self) -> dict:
        """What may be shown before a run: never the answer."""
        return {"id": self.id, "title": self.title,
                "difficulty": self.difficulty, "brief": self.brief}


def _parse(raw: dict, origin: str) -> Mission:
    missing = [k for k in REQUIRED if k not in raw]
    if missing:
        raise ValueError(f"{origin}: missing fields {missing}")
    return Mission(
        id=raw["id"], title=raw["title"], difficulty=raw["difficulty"],
        brief=raw["brief"], events=raw["events"],
        hosts={k.lower(): v for k, v in raw.get("hosts", {}).items()},
        intel={k.lower(): v for k, v in raw.get("intel", {}).items()},
        answer=raw.get("answer"),
        optimal_tool_calls=raw.get("optimal_tool_calls"),
    )


def load_missions(directory: Path = MISSIONS_DIR) -> dict[str, Mission]:
    missions: dict[str, Mission] = {}
    for path in sorted(directory.glob("*.json")):
        m = _parse(json.loads(path.read_text(encoding="utf-8")), path.name)
        if m.id in missions:
            raise ValueError(f"{path.name}: duplicate mission id {m.id!r}")
        missions[m.id] = m
    return missions
