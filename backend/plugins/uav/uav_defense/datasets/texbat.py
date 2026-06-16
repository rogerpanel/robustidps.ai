"""TEXBAT loader stub.

The Texas Spoofing Test Battery (TEXBAT) requires registration at
UT Austin Radionavigation Laboratory. This loader expects the binary IQ
files to be unpacked under TEXBAT_ROOT and exposes per-scenario manifests.

Phase A uses SyntheticTEXBAT instead; this class is the production-time
hook for the real corpus.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TEXBATScenario:
    scenario_id: int
    description: str
    duration_s: float
    sample_rate_hz: float


KNOWN_SCENARIOS = [
    TEXBATScenario(1, "Static, matched-power overlapped time-pushing", 460.0, 25.0e6),
    TEXBATScenario(2, "Static, matched-power overlapped position-pushing", 460.0, 25.0e6),
    TEXBATScenario(3, "Static, 10dB-power overlapped time-pushing", 460.0, 25.0e6),
    TEXBATScenario(4, "Static, 10dB-power overlapped position-pushing", 460.0, 25.0e6),
    TEXBATScenario(5, "Static, security-code-estimation-and-replay (SCER)", 460.0, 25.0e6),
    TEXBATScenario(6, "Dynamic, matched-power overlapped position-pushing", 460.0, 25.0e6),
    TEXBATScenario(7, "Static, matched-power non-coherent zero-Doppler", 460.0, 25.0e6),
    TEXBATScenario(8, "Static, 1.3dB-power overlapped position-pushing", 460.0, 25.0e6),
]


class TEXBATLoader:
    def __init__(self, root: str | os.PathLike | None = None):
        self.root = Path(root or os.getenv("TEXBAT_ROOT", "")).expanduser()

    def available(self) -> bool:
        return self.root.exists() and any(self.root.glob("ds[0-9].bin"))

    def scenario_path(self, scenario_id: int) -> Path | None:
        if not self.available():
            return None
        candidates = list(self.root.glob(f"ds{scenario_id}.bin"))
        return candidates[0] if candidates else None

    @staticmethod
    def registration_url() -> str:
        return "https://radionavlab.ae.utexas.edu/datastore/texbat/"
