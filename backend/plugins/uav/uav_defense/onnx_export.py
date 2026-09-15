"""ONNX export pipeline for the airframe-edge deployment target.

Exports a trained CT-TGNN or MambaShield to ONNX, validates round-trip
inference against the PyTorch reference, and measures per-frame latency
on CPU (proxy for Jetson Orin Nano latency — chapter 6 §6.7 reports
1.8 ms/frame at 30 fps with 384 MiB RAM).

The latency number lands in `weights/uav_onnx_latency.json` so the
Phase B panel can show measured-vs-target without re-running the export.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import torch

from plugins.uav.uav_defense.models import CTTGNN, MambaShield

LATENCY_LOG_PATH = Path("weights/uav_onnx_latency.json")


def export(
    model_kind: str = "ct_tgnn",
    checkpoint: str = "weights/uav_ct_tgnn.pt",
    output: str = "weights/uav_ct_tgnn.onnx",
    n_satellites: int = 8,
    feat_dim: int = 8,
    n_warmup: int = 5,
    n_benchmark: int = 30,
) -> dict:
    import onnxruntime as ort

    if model_kind == "ct_tgnn":
        model = CTTGNN()
        takes_adj = True
    elif model_kind == "mamba_shield":
        model = MambaShield()
        takes_adj = False
    else:
        raise ValueError(f"Unknown model_kind: {model_kind}")

    ckpt = Path(checkpoint)
    if ckpt.exists():
        model.load_state_dict(torch.load(ckpt, map_location="cpu"))
    model.eval()

    x = torch.randn(1, n_satellites, feat_dim)
    inputs = (x, torch.ones(1, n_satellites, n_satellites) - torch.eye(n_satellites).unsqueeze(0)) if takes_adj else (x,)
    input_names = ["x", "adj"] if takes_adj else ["x"]
    dynamic_axes = {"x": {0: "batch"}, "adj": {0: "batch"}} if takes_adj else {"x": {0: "batch"}}

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    torch.onnx.export(
        model, inputs, str(output_path),
        input_names=input_names, output_names=["logits"],
        dynamic_axes=dynamic_axes, opset_version=17,
    )

    sess = ort.InferenceSession(str(output_path), providers=["CPUExecutionProvider"])
    ort_inputs = {n: arr.numpy() for n, arr in zip(input_names, inputs)}

    with torch.no_grad():
        torch_logits = model(*inputs).numpy()
    onnx_logits = sess.run(None, ort_inputs)[0]
    max_diff = float(abs(torch_logits - onnx_logits).max())

    for _ in range(n_warmup):
        sess.run(None, ort_inputs)
    times_ms = []
    for _ in range(n_benchmark):
        t0 = time.perf_counter()
        sess.run(None, ort_inputs)
        times_ms.append((time.perf_counter() - t0) * 1000.0)

    times_ms.sort()
    result = {
        "model_kind": model_kind,
        "onnx_path": str(output_path),
        "opset": 17,
        "round_trip_max_diff": max_diff,
        "round_trip_ok": max_diff < 1e-3,
        "latency_ms": {
            "min":    round(times_ms[0], 3),
            "median": round(times_ms[len(times_ms) // 2], 3),
            "p95":    round(times_ms[int(len(times_ms) * 0.95)], 3),
            "max":    round(times_ms[-1], 3),
            "samples": n_benchmark,
        },
        "edge_target_ms_per_frame": 5.0,
        "edge_target_platform": "Jetson Orin Nano (chapter 6 §6.7 reports 1.8 ms/frame)",
    }

    LATENCY_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if LATENCY_LOG_PATH.exists():
        existing = json.loads(LATENCY_LOG_PATH.read_text())
    else:
        existing = {}
    existing[model_kind] = result
    LATENCY_LOG_PATH.write_text(json.dumps(existing, indent=2))
    return result


def latest_results() -> dict:
    if not LATENCY_LOG_PATH.exists():
        return {}
    try:
        return json.loads(LATENCY_LOG_PATH.read_text())
    except json.JSONDecodeError:
        return {}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="ct_tgnn", choices=["ct_tgnn", "mamba_shield"])
    parser.add_argument("--checkpoint", default="weights/uav_ct_tgnn.pt")
    parser.add_argument("--out", default="weights/uav_ct_tgnn.onnx")
    args = parser.parse_args()
    print(json.dumps(export(args.model, args.checkpoint, args.out), indent=2))
