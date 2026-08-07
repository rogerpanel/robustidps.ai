from plugins.uav.uav_defense.ew_bench.mcr_vs_js import (
    UAV_EW_BENCH_2026, mission_completion_curve, full_curves,
)
from plugins.uav.uav_defense.ew_bench.simulator import (
    BenchConfig, run_bench, latest_measured,
)


def best_available_curves() -> dict:
    """Prefer measured Phase-D simulator output when available;
    fall back to the chapter-anchored Phase-A interpolation."""
    measured = latest_measured()
    if measured is not None:
        return {**measured, "source": "phase_d_measured"}
    chapter = full_curves()
    return {**chapter, "source": "phase_a_chapter_anchored"}


__all__ = [
    "UAV_EW_BENCH_2026", "mission_completion_curve", "full_curves",
    "BenchConfig", "run_bench", "latest_measured", "best_available_curves",
]
