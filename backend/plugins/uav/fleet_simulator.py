"""Multi-UAV fleet simulator — live demo of 3+ UAVs under coordinated /
uncoordinated attack scenarios.

Each UAV runs its own state machine (mission progress, link quality,
GNSS spoof confidence, autopilot mode). The user can inject attacks
per-UAV from the React UI; the simulator steps the fleet forward and
emits per-UAV telemetry that the page renders as a live grid.

Deliberately framework-less: no torch needed for this module — the
attack effects are statistical, not gradient-driven. Keeps the live
demo fast (sub-100 ms per step) and decouples the fleet demo from
model training state.
"""
from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field, asdict
from typing import Literal

UAVKind = Literal["delivery", "patrol", "search_rescue", "logistics"]
DefenseConfig = Literal["no_def", "caf_cnn", "seq2seq", "framework"]
AttackKind = Literal["none", "fgsm", "pgd", "cw", "deepfool", "gaussian",
                     "spoof_gnss", "jam_link", "label_flip"]


@dataclass
class UAVState:
    uav_id: str
    kind: UAVKind
    defense: DefenseConfig = "framework"
    mission_progress_pct: float = 0.0
    battery_pct: float = 100.0
    link_quality_pct: float = 100.0
    gnss_spoof_confidence: float = 0.0
    autopilot_mode: str = "nominal"     # nominal / gnss_degraded / rtl
    position: tuple[float, float, float] = (0.0, 0.0, 80.0)
    last_attack: AttackKind = "none"
    attack_caught: bool = False
    completed: bool | None = None
    mcr_running: float = 1.0

    def as_dict(self) -> dict:
        d = asdict(self)
        d["position"] = list(self.position)
        return d


# ── Per-attack damage profile ──────────────────────────────────────────

ATTACK_DAMAGE = {
    "none":        {"link": 0.0,  "gnss": 0.0,  "battery": 0.5,  "stealth": 1.0},
    "fgsm":        {"link": 0.0,  "gnss": 0.20, "battery": 1.0,  "stealth": 0.2},
    "pgd":         {"link": 0.0,  "gnss": 0.55, "battery": 1.0,  "stealth": 0.4},
    "cw":          {"link": 0.0,  "gnss": 0.85, "battery": 1.0,  "stealth": 0.7},
    "deepfool":    {"link": 0.0,  "gnss": 0.65, "battery": 1.0,  "stealth": 0.6},
    "gaussian":    {"link": 5.0,  "gnss": 0.05, "battery": 1.0,  "stealth": 0.1},
    "spoof_gnss":  {"link": 2.0,  "gnss": 0.80, "battery": 1.0,  "stealth": 0.5},
    "jam_link":    {"link": 35.0, "gnss": 0.10, "battery": 1.0,  "stealth": 0.1},
    "label_flip":  {"link": 0.0,  "gnss": 0.0,  "battery": 1.0,  "stealth": 0.9},
}

# How often the defense catches an attack (per step) — matches the
# Phase D simulator's coverage values.
DEFENSE_CATCH_RATE = {
    "no_def":     0.0,
    "caf_cnn":    0.55,
    "seq2seq":    0.70,
    "framework":  0.95,
}


def _spawn_fleet(n: int, defaults: dict | None = None) -> list[UAVState]:
    kinds: list[UAVKind] = ["delivery", "patrol", "search_rescue", "logistics"]
    out = []
    rng = random.Random(42)
    for i in range(n):
        out.append(UAVState(
            uav_id=f"UAV-{i + 1:02d}",
            kind=kinds[i % len(kinds)],
            defense=(defaults or {}).get("defense", "framework"),
            position=(rng.uniform(-200, 200), rng.uniform(-200, 200), rng.uniform(60, 120)),
        ))
    return out


_FLEET_STORE: dict[str, list[UAVState]] = {}


def get_fleet(session_id: str, n: int = 3) -> list[UAVState]:
    if session_id not in _FLEET_STORE:
        _FLEET_STORE[session_id] = _spawn_fleet(n)
    return _FLEET_STORE[session_id]


def reset_fleet(session_id: str, n: int = 3) -> list[UAVState]:
    _FLEET_STORE[session_id] = _spawn_fleet(n)
    return _FLEET_STORE[session_id]


def step_fleet(
    session_id: str,
    per_uav_attack: dict[str, AttackKind] | None = None,
    js_db: float = 10.0,
    dt_s: float = 1.0,
) -> dict:
    """Advance every UAV in the fleet by dt_s, applying the per-UAV
    attack and the global J/S level. Returns the new fleet snapshot
    plus an aggregate fleet MCR."""
    fleet = get_fleet(session_id)
    per_uav_attack = per_uav_attack or {}
    rng = random.Random(int(time.time() * 1000) % 2_000_000_000)

    completed_count = 0
    in_flight_count = 0

    for uav in fleet:
        attack: AttackKind = per_uav_attack.get(uav.uav_id, "none")
        damage = ATTACK_DAMAGE[attack]
        catch_rate = DEFENSE_CATCH_RATE[uav.defense]

        # Stealthy attacks are harder to catch
        effective_catch = catch_rate * (1.0 - 0.6 * damage["stealth"]) if attack != "none" else 0.0
        caught = attack != "none" and rng.random() < effective_catch
        uav.last_attack = attack
        uav.attack_caught = caught

        # GNSS spoof confidence rises if attack lands and isn't caught
        if attack != "none" and not caught:
            uav.gnss_spoof_confidence = min(1.0, uav.gnss_spoof_confidence + damage["gnss"] * dt_s)
        else:
            uav.gnss_spoof_confidence = max(0.0, uav.gnss_spoof_confidence - 0.15 * dt_s)

        # Link quality degrades under jamming + ambient J/S
        link_loss = damage["link"] * dt_s + max(0.0, (js_db - 10) * 0.4 * dt_s)
        uav.link_quality_pct = max(0.0, uav.link_quality_pct - link_loss)
        # Trickle recovery when no attack
        if attack == "none" and uav.link_quality_pct < 100:
            uav.link_quality_pct = min(100.0, uav.link_quality_pct + 1.5 * dt_s)

        # Autopilot mode flips when uncertainty is high or link is critical
        if uav.gnss_spoof_confidence > 0.7 or uav.link_quality_pct < 25:
            if uav.gnss_spoof_confidence > 0.85 or uav.link_quality_pct < 10:
                uav.autopilot_mode = "rtl"
            else:
                uav.autopilot_mode = "gnss_degraded"
        elif uav.autopilot_mode != "nominal" and uav.gnss_spoof_confidence < 0.3:
            uav.autopilot_mode = "nominal"

        # Battery drain
        uav.battery_pct = max(0.0, uav.battery_pct - damage["battery"] * dt_s)

        # Mission progress — slowed by attacks not caught
        if uav.autopilot_mode == "rtl":
            uav.mission_progress_pct = max(0.0, uav.mission_progress_pct - 5 * dt_s)
        elif uav.completed is None:
            progress_rate = 1.5 if uav.autopilot_mode == "nominal" else 0.4
            if attack != "none" and not caught:
                progress_rate *= 0.3
            uav.mission_progress_pct = min(100.0, uav.mission_progress_pct + progress_rate * dt_s)

        # Mission outcome decision
        if uav.completed is None:
            if uav.mission_progress_pct >= 100.0:
                uav.completed = True
            elif uav.battery_pct < 5.0 or (
                uav.autopilot_mode == "rtl" and uav.mission_progress_pct < 20.0
            ):
                uav.completed = False
            else:
                in_flight_count += 1
        if uav.completed is True:
            completed_count += 1

        # Position drift — minor + per-tick wiggle
        x, y, z = uav.position
        x += rng.uniform(-2, 2); y += rng.uniform(-2, 2); z += rng.uniform(-0.5, 0.5)
        uav.position = (round(x, 1), round(y, 1), round(z, 1))

        # Running MCR: completed / (completed + failed). Live estimate.
        # Use the in-progress UAV's expected outcome via progress as soft signal.
        soft = uav.mission_progress_pct / 100.0 if uav.completed is None else (1.0 if uav.completed else 0.0)
        uav.mcr_running = round(0.7 * uav.mcr_running + 0.3 * soft, 3)

    fleet_mcr = (completed_count / len(fleet)) if fleet else 0.0
    return {
        "session_id": session_id,
        "js_db": js_db,
        "fleet_mcr": round(fleet_mcr, 3),
        "n_completed": completed_count,
        "n_in_flight": in_flight_count,
        "n_failed": sum(1 for u in fleet if u.completed is False),
        "uavs": [u.as_dict() for u in fleet],
    }


# ── Sample pack + upload ───────────────────────────────────────────────

def sample_pack() -> dict:
    """Returns a downloadable fleet-sample JSON bundle — mixed-data,
    chapter-6-shaped, ready to be re-uploaded for the live demo."""
    rng = random.Random(2026)
    n_uavs = 5
    n_steps = 60   # 60 s of telemetry per UAV
    bundle = {
        "schema": "robustidps.uav.fleet/v1",
        "n_uavs": n_uavs,
        "n_steps": n_steps,
        "step_seconds": 1.0,
        "uavs": [],
    }
    for i in range(n_uavs):
        uav = {
            "uav_id": f"UAV-{i + 1:02d}",
            "kind": ["delivery", "patrol", "search_rescue", "logistics", "delivery"][i],
            "defense": ["framework", "framework", "seq2seq", "caf_cnn", "no_def"][i],
            "telemetry": [
                {
                    "t_s": float(t),
                    "battery_pct": round(100.0 - t * 0.5 + rng.uniform(-1, 1), 1),
                    "link_quality_pct": round(95 + rng.uniform(-5, 5), 1),
                    "gnss_cno_db_hz": round(45 + rng.uniform(-3, 3), 1),
                    "position_xyz": [
                        round(rng.uniform(-200, 200), 1),
                        round(rng.uniform(-200, 200), 1),
                        round(rng.uniform(60, 120), 1),
                    ],
                    "satellites_visible": rng.randint(7, 12),
                }
                for t in range(n_steps)
            ],
        }
        bundle["uavs"].append(uav)
    return bundle


def validate_upload(raw: bytes) -> dict:
    """Return {ok: bool, error?: str, parsed?: dict, summary?: dict}."""
    try:
        text = raw.decode("utf-8")
        data = json.loads(text)
    except Exception as e:
        return {"ok": False, "error": f"Not valid JSON: {e}"}
    if not isinstance(data, dict) or data.get("schema") != "robustidps.uav.fleet/v1":
        return {"ok": False,
                "error": "Wrong schema. Expected 'robustidps.uav.fleet/v1' — "
                         "download a fresh sample pack and use that shape."}
    uavs = data.get("uavs") or []
    if not isinstance(uavs, list) or not uavs:
        return {"ok": False, "error": "Field 'uavs' must be a non-empty list."}
    for u in uavs:
        if not isinstance(u, dict) or "uav_id" not in u or "telemetry" not in u:
            return {"ok": False, "error": "Each UAV needs uav_id + telemetry fields."}
    return {
        "ok": True,
        "parsed": data,
        "summary": {
            "n_uavs": len(uavs),
            "n_steps": data.get("n_steps", len(uavs[0].get("telemetry") or [])),
            "uav_ids": [u["uav_id"] for u in uavs[:10]],
        },
    }
