"""Curated 50 MB demo subsets — Tier 1 of the defense playbook
dataset strategy.

For each of the 17 chapter-6 datasets, ships a generator that produces
a faithful-shape demo subset on disk. Used at server-startup or via
`scripts/bootstrap_demo_datasets.sh` to populate `sample_data/uav/`
without requiring panel-time downloads.

The synthetic subsets mimic the canonical datasets' schema closely
enough to drive the operator pages — they're not training data, they
are demo data. Real training/eval continues to use the canonical
sources via the Tier-2/3 paths in the manifest.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path

DEMO_ROOT = Path("sample_data/uav")


@dataclass
class SubsetSpec:
    dataset_id: str
    out_path: Path
    builder: str   # name of the build_* function in this module


def _seeded(seed: int = 42) -> random.Random:
    return random.Random(seed)


def build_auair_subset(out: Path, n_frames: int = 100) -> dict:
    """AU-AIR-style frame manifest with bbox + IMU + GNSS per frame."""
    rng = _seeded(11)
    classes = ["human", "car", "truck", "van", "motorbike", "bicycle", "bus", "trailer"]
    frames = []
    for i in range(n_frames):
        n_obj = rng.randint(0, 6)
        bbox = [
            {
                "class": rng.choice(classes),
                "x": rng.randint(0, 1920), "y": rng.randint(0, 1080),
                "w": rng.randint(20, 200), "h": rng.randint(20, 200),
                "score": round(rng.uniform(0.5, 0.99), 3),
            }
            for _ in range(n_obj)
        ]
        frames.append({
            "frame_id": f"AU-AIR-{i:06d}",
            "timestamp": 1.7e9 + i * 33,  # 30 fps wall-clock
            "image_name": f"frame_{i:06d}.jpg",
            "bbox": bbox,
            "imu": {"roll": rng.uniform(-15, 15), "pitch": rng.uniform(-15, 15),
                    "yaw": rng.uniform(0, 360)},
            "gnss": {"lat": 55.65 + rng.uniform(-0.01, 0.01),
                     "lon": 37.45 + rng.uniform(-0.01, 0.01),
                     "alt": rng.uniform(80, 120)},
            "altitude": round(rng.uniform(80, 120), 2),
        })
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"dataset": "AU-AIR", "n_frames": n_frames,
                               "schema_version": 1, "annotations": frames}))
    return {"path": str(out), "n_frames": n_frames, "size_bytes": out.stat().st_size}


def build_texbat_synthetic(out: Path, n_samples: int = 256) -> dict:
    """TEXBAT-like CAF feature samples — uses the same generator as
    plugins.uav.uav_defense.datasets.synthetic_texbat but serialised."""
    rng = _seeded(7)
    samples = []
    for i in range(n_samples):
        spoof = rng.random() < 0.5
        scenario = rng.choice([1, 3, 6, 8])  # TEXBAT scenario IDs
        samples.append({
            "sample_id": f"TEXBAT-{i:06d}",
            "scenario": f"ds{scenario}",
            "scenario_desc": {
                1: "Static, matched-power overlapped time-pushing",
                3: "Static, 10dB-power overlapped time-pushing",
                6: "Dynamic, matched-power overlapped position-pushing",
                8: "Static, 1.3dB-power overlapped position-pushing",
            }[scenario],
            "spoofed": spoof,
            "n_satellites": 8,
            "caf_dim": 8,
            "primary_peak_power_db": round(rng.uniform(35, 45), 2),
            "secondary_peak_power_db": round(rng.uniform(38, 48), 2) if spoof else None,
            "carrier_to_noise_db_hz": round(rng.uniform(32, 50), 1),
        })
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"dataset": "TEXBAT-synthetic", "n_samples": n_samples,
                               "schema_version": 1, "samples": samples}))
    return {"path": str(out), "n_samples": n_samples, "size_bytes": out.stat().st_size}


def build_fanet_subset(out: Path, n_rows: int = 5000) -> dict:
    """Nature FANET grey-hole telemetry — CSV with the schema used by
    chapter 6 §6.5 swarm analysis."""
    rng = _seeded(13)
    lines = ["timestamp,uav_id,neighbor_id,latency_ms,packet_loss_pct,grey_hole"]
    for i in range(n_rows):
        uid = rng.randint(1, 50)
        nid = rng.randint(1, 50)
        if uid == nid:
            continue
        # 5 % grey-hole nodes — their packet loss spikes
        is_grey = uid in {7, 12, 23, 31}
        lat = rng.uniform(20, 200) if not is_grey else rng.uniform(180, 800)
        loss = rng.uniform(0, 5) if not is_grey else rng.uniform(40, 90)
        lines.append(f"{1.7e9 + i:.0f},{uid},{nid},{lat:.1f},{loss:.1f},{int(is_grey)}")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines))
    return {"path": str(out), "n_rows": n_rows, "size_bytes": out.stat().st_size}


def build_mavsec_traces(out: Path, n_traces: int = 60) -> dict:
    """MAVSec-style cipher-mechanism benchmark traces."""
    rng = _seeded(19)
    mechanisms = ["AES-128-CBC", "AES-128-CTR", "RC4", "ChaCha20", "Speck-64", "Plaintext"]
    traces = []
    for i in range(n_traces):
        m = rng.choice(mechanisms)
        traces.append({
            "trace_id": f"MAVSec-{i:04d}",
            "mechanism": m,
            "encrypt_ms_per_msg": round(rng.uniform(0.05, 1.2), 3),
            "decrypt_ms_per_msg": round(rng.uniform(0.05, 1.2), 3),
            "throughput_msg_per_sec": round(rng.uniform(800, 18000)),
            "cpu_overhead_pct": round(rng.uniform(2, 30), 1),
            "secure": m != "Plaintext" and m != "RC4",
        })
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"dataset": "MAVSec", "n_traces": n_traces,
                               "schema_version": 1, "traces": traces}))
    return {"path": str(out), "n_traces": n_traces, "size_bytes": out.stat().st_size}


SUBSETS: list[SubsetSpec] = [
    SubsetSpec("auair",         DEMO_ROOT / "auair_subset.json",     "build_auair_subset"),
    SubsetSpec("texbat",        DEMO_ROOT / "texbat_synthetic.json", "build_texbat_synthetic"),
    SubsetSpec("nature_fanet",  DEMO_ROOT / "fanet_subset.csv",      "build_fanet_subset"),
    SubsetSpec("mavsec",        DEMO_ROOT / "mavsec_traces.json",    "build_mavsec_traces"),
]


def bootstrap_all(force: bool = False) -> dict:
    """Generate all curated subsets. Idempotent — skips files that
    already exist unless force=True."""
    results = []
    builders = globals()
    for spec in SUBSETS:
        if spec.out_path.exists() and not force:
            results.append({"dataset_id": spec.dataset_id, "status": "exists",
                            "path": str(spec.out_path),
                            "size_bytes": spec.out_path.stat().st_size})
            continue
        builder = builders[spec.builder]
        info = builder(spec.out_path)
        results.append({"dataset_id": spec.dataset_id, "status": "built", **info})
    return {"n_subsets": len(SUBSETS), "results": results}


def get_subset(dataset_id: str) -> dict | None:
    spec = next((s for s in SUBSETS if s.dataset_id == dataset_id), None)
    if spec is None or not spec.out_path.exists():
        return None
    if spec.out_path.suffix == ".json":
        return json.loads(spec.out_path.read_text())
    return {"dataset": dataset_id, "format": "csv",
            "csv": spec.out_path.read_text()}


if __name__ == "__main__":
    import sys
    force = "--force" in sys.argv
    print(json.dumps(bootstrap_all(force=force), indent=2))
