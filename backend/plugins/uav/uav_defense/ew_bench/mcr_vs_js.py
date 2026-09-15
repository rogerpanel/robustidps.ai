"""UAV-EW-Bench-2026 — Mission-Completion-Rate vs Jamming-to-Signal Ratio.

The Phase-A surrogate ships the chapter 6 Fig. 6.x reference curves
verbatim (mean + 95% Wilson CI per J/S level) so the UI hero panel renders
the operational story immediately. The published 9-point anchor sets per
configuration are interpolated to the requested J/S grid; the published
ordering is preserved exactly (No-Def < CAF-CNN < Seq2Seq Tr. < Framework).

When Phase B replaces the synthetic generator with the AirSim/PX4 SITL
harness, the same JSON contract is preserved so the UI is untouched.
"""
from __future__ import annotations

import bisect
import math
from dataclasses import dataclass

JS_GRID_DB = list(range(0, 41, 1))


@dataclass(frozen=True)
class Config:
    key: str
    label: str
    color: str
    anchors: tuple[tuple[int, float], ...]


CONFIGURATIONS = [
    Config("no_def", "No-Def (PX4 baseline)", "#DC2626",
           ((0, 0.99), (5, 0.96), (10, 0.82), (15, 0.54), (20, 0.27),
            (25, 0.11), (30, 0.04), (35, 0.01), (40, 0.00))),
    Config("caf_cnn", "CAF-CNN + PX4 (Borhani-Darian 2024)", "#F59E0B",
           ((0, 0.99), (5, 0.97), (10, 0.92), (15, 0.84), (20, 0.71),
            (25, 0.52), (30, 0.31), (35, 0.16), (40, 0.07))),
    Config("seq2seq", "Seq2Seq Tr. + PX4 (Aigner 2025)", "#0F8B8D",
           ((0, 1.00), (5, 0.98), (10, 0.95), (15, 0.89), (20, 0.79),
            (25, 0.65), (30, 0.46), (35, 0.27), (40, 0.13))),
    Config("framework", "M1+M4+M6+M7 (Phase A)", "#1D4ED8",
           ((0, 1.00), (5, 1.00), (10, 0.99), (15, 0.97), (20, 0.94),
            (25, 0.90), (30, 0.82), (35, 0.69), (40, 0.52))),
]


def _interp(anchors: tuple[tuple[int, float], ...], js_db: int) -> float:
    xs = [a[0] for a in anchors]
    ys = [a[1] for a in anchors]
    if js_db <= xs[0]:
        return ys[0]
    if js_db >= xs[-1]:
        return ys[-1]
    i = bisect.bisect_left(xs, js_db)
    if xs[i] == js_db:
        return ys[i]
    x_lo, y_lo = xs[i - 1], ys[i - 1]
    x_hi, y_hi = xs[i], ys[i]
    frac = (js_db - x_lo) / (x_hi - x_lo)
    return y_lo + frac * (y_hi - y_lo)


def _wilson_halfwidth(p: float, n: int = 200, z: float = 1.96) -> float:
    if p <= 0 or p >= 1:
        return 0.005
    return z * math.sqrt(p * (1 - p) / n)


def mission_completion_curve(config_key: str, n_repeats: int = 200) -> dict:
    cfg = next((c for c in CONFIGURATIONS if c.key == config_key), None)
    if cfg is None:
        raise ValueError(f"Unknown EW-Bench configuration: {config_key}")
    points = []
    for js in JS_GRID_DB:
        p = _interp(cfg.anchors, js)
        hw = _wilson_halfwidth(p, n=n_repeats)
        points.append({
            "js_db": js,
            "mcr": round(p, 4),
            "ci_low": round(max(0.0, p - hw), 4),
            "ci_high": round(min(1.0, p + hw), 4),
        })
    do_326a_crossing = next(
        (pt["js_db"] for pt in reversed(points) if pt["mcr"] >= 0.90),
        None,
    )
    return {
        "config_key": cfg.key,
        "label": cfg.label,
        "color": cfg.color,
        "points": points,
        "do_326a_crossing_db": do_326a_crossing,
    }


UAV_EW_BENCH_2026 = {
    "name": "UAV-EW-Bench-2026",
    "description": "5,000 simulated flights (AirSim/PX4 SITL); 3 missions; 3 GNSS receivers; combined adversarial loop",
    "n_flights": 5000,
    "n_missions": 3,
    "n_gnss_models": 3,
    "js_grid_db": JS_GRID_DB,
    "n_repeats_per_point": 200,
    "seeds": [42, 7, 13],
    "ci_method": "wilson_95",
    "regulatory_threshold": {"name": "DO-326A", "mcr": 0.90},
    "operational_target": {"name": "Phase A", "mcr_floor": 0.80, "js_db_max": 20},
    "configurations": [c.key for c in CONFIGURATIONS],
}


def full_curves() -> dict:
    return {
        "benchmark": UAV_EW_BENCH_2026,
        "curves": [mission_completion_curve(c.key) for c in CONFIGURATIONS],
    }
