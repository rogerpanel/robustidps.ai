"""AU-AIR (Bozcan & Kayacan, ICRA 2020) loader stub.

The dataset is ~12 GB and openly downloadable from the official site.
This loader walks an unpacked tree under AUAIR_ROOT and yields per-frame
dicts that combine RGB, bounding boxes, IMU, GNSS, and altitude — the
multi-modal channels chapter 6 §6.5.1 binds to node features X_t.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterator


class AUAIRLoader:
    OBJECT_CLASSES = [
        "human", "car", "truck", "van", "motorbike", "bicycle", "bus", "trailer",
    ]

    def __init__(self, root: str | os.PathLike | None = None):
        self.root = Path(root or os.getenv("AUAIR_ROOT", "")).expanduser()

    def available(self) -> bool:
        return self.root.exists() and (self.root / "annotations.json").exists()

    def iter_frames(self) -> Iterator[dict]:
        if not self.available():
            return iter(())
        ann = json.loads((self.root / "annotations.json").read_text())
        for frame in ann.get("annotations", []):
            yield {
                "image_path": str(self.root / "images" / frame["image_name"]),
                "bboxes": frame.get("bbox", []),
                "imu": frame.get("imu", {}),
                "gnss": frame.get("gnss", {}),
                "altitude": frame.get("altitude", None),
                "timestamp": frame.get("time", None),
            }

    @staticmethod
    def download_url() -> str:
        return "https://bozcani.github.io/auairdataset"
