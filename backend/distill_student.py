"""Distill the SurrogateIDS teacher into a tiny INT8 ONNX student for the edge agent.

The teacher (``backend/models/surrogate.py``) ingests 83 features and emits 34-class
logits. The Rust ``agent/agent-features`` crate emits 77 columns, so the student is
trained to approximate the teacher's softmax distribution from only the first 77 of
those 83 features.

Outputs (default ``agent/agent-inference/weights/``): ``student_int8.onnx`` (INT8 QDQ,
falls back to FP32 if onnxruntime is missing), ``labels.json``, ``distill_report.json``.
Run from repo root: ``python backend/distill_student.py``.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import tempfile
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from models.surrogate import SurrogateIDS  # noqa: E402

LOGGER = logging.getLogger("distill_student")

STUDENT_IN_DIM = 77
TEACHER_IN_DIM = SurrogateIDS.N_FEATURES  # 83
N_CLASSES = SurrogateIDS.N_CLASSES        # 34
DISTILL_T = 4.0
KD_WEIGHT = 0.9
CE_WEIGHT = 0.1


# Parameter count analytical (in_dim=77, hidden=128, mid=64, out_dim=34):
#   Linear1: (77 + 1) * 128 = 9984
#   Linear2: (128 + 1) * 64 = 8256
#   Linear3: (64 + 1) * 34  = 2210
#   Total                   = 20450 params (well under the 50K budget).
class StudentMLP(nn.Module):
    def __init__(self, in_dim: int = 77, hidden: int = 128, mid: int = 64, out_dim: int = 34):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, hidden),
            nn.GELU(),
            nn.Linear(hidden, mid),
            nn.GELU(),
            nn.Linear(mid, out_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Distill SurrogateIDS into an INT8 ONNX student")
    p.add_argument("--n-train", type=int, default=20_000)
    p.add_argument("--n-val", type=int, default=5_000)
    p.add_argument("--epochs", type=int, default=50)
    p.add_argument("--output-dir", type=Path,
                   default=REPO_ROOT / "agent" / "agent-inference" / "weights")
    p.add_argument("--skip-quant", action="store_true", help="Skip INT8 quant; emit FP32 only.")
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


def seed_everything(seed: int) -> None:
    torch.manual_seed(seed)
    np.random.seed(seed)


def load_teacher() -> SurrogateIDS:
    weights_path = BACKEND_DIR / "weights" / "surrogate.pt"
    LOGGER.info("Loading teacher weights from %s", weights_path)
    model = SurrogateIDS(dropout=0.05)
    state = torch.load(weights_path, map_location="cpu", weights_only=True)
    model.load_state_dict(state)
    model.eval()
    for p in model.parameters():
        p.requires_grad_(False)
    return model


@torch.no_grad()
def teacher_forward(teacher: SurrogateIDS, x83: torch.Tensor, batch: int = 1024) -> torch.Tensor:
    outs = []
    for i in range(0, x83.shape[0], batch):
        outs.append(teacher(x83[i:i + batch]))
    return torch.cat(outs, dim=0)


def build_synthetic_dataset(teacher: SurrogateIDS, n: int) -> tuple[torch.Tensor, torch.Tensor]:
    """Generate synthetic features (same convention as ``backend/create_alt_weights.py``)
    and label them with the teacher's logits."""
    LOGGER.info("Generating %d synthetic samples (83-d) and teacher logits", n)
    x83 = torch.randn(n, TEACHER_IN_DIM)
    logits = teacher_forward(teacher, x83)
    return x83, logits


def distill_loss(student_logits: torch.Tensor, teacher_logits: torch.Tensor) -> torch.Tensor:
    soft_teacher = F.softmax(teacher_logits / DISTILL_T, dim=-1)
    soft_student = F.log_softmax(student_logits / DISTILL_T, dim=-1)
    kd = F.kl_div(soft_student, soft_teacher, reduction="batchmean") * (DISTILL_T ** 2)
    ce = F.cross_entropy(student_logits, teacher_logits.argmax(dim=-1))
    return KD_WEIGHT * kd + CE_WEIGHT * ce


def train_student(
    student: StudentMLP,
    train_x83: torch.Tensor,
    train_logits: torch.Tensor,
    val_x83: torch.Tensor,
    val_logits: torch.Tensor,
    epochs: int,
    batch_size: int = 256,
) -> float:
    optim = torch.optim.Adam(student.parameters(), lr=3e-3)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(optim, T_max=epochs)
    train_x77 = train_x83[:, :STUDENT_IN_DIM]
    val_x77 = val_x83[:, :STUDENT_IN_DIM]
    ds = TensorDataset(train_x77, train_logits)
    loader = DataLoader(ds, batch_size=batch_size, shuffle=True, drop_last=False)

    last_loss = float("nan")
    for epoch in range(1, epochs + 1):
        student.train()
        running = 0.0
        n_seen = 0
        for xb, tb in loader:
            optim.zero_grad()
            sb = student(xb)
            loss = distill_loss(sb, tb)
            loss.backward()
            optim.step()
            running += loss.item() * xb.shape[0]
            n_seen += xb.shape[0]
        sched.step()
        last_loss = running / max(n_seen, 1)

        if epoch % 10 == 0 or epoch == 1 or epoch == epochs:
            agree, acc = evaluate_agreement(student, val_x77, val_logits)
            LOGGER.info(
                "epoch %3d/%d  train_loss=%.4f  val_agree=%.2f%%  val_acc_vs_teacher=%.2f%%",
                epoch, epochs, last_loss, agree * 100.0, acc * 100.0,
            )
    return last_loss


@torch.no_grad()
def evaluate_agreement(student: StudentMLP, val_x77: torch.Tensor,
                       val_logits: torch.Tensor) -> tuple[float, float]:
    student.eval()
    s_pred = student(val_x77).argmax(dim=-1)
    t_pred = val_logits.argmax(dim=-1)
    agree = (s_pred == t_pred).float().mean().item()
    return agree, agree  # second value kept for log-line symmetry


def export_fp32_onnx(student: StudentMLP, path: Path) -> None:
    LOGGER.info("Exporting FP32 ONNX to %s", path)
    student.eval()
    dummy = torch.randn(1, STUDENT_IN_DIM, dtype=torch.float32)
    torch.onnx.export(
        student,
        dummy,
        path.as_posix(),
        input_names=["input"],
        output_names=["output"],
        opset_version=17,
        dynamic_axes={"input": {0: "batch"}, "output": {0: "batch"}},
    )


def try_import_onnxruntime() -> bool:
    try:
        import onnxruntime  # noqa: F401
        from onnxruntime.quantization import quantize_static  # noqa: F401
        return True
    except Exception as exc:  # pragma: no cover - depends on host env
        LOGGER.warning("onnxruntime/quantization unavailable: %s -- pip install onnxruntime", exc)
        return False


def quantize_int8(fp32_path: Path, int8_path: Path, val_x77: torch.Tensor,
                  n_batches: int = 200) -> None:
    from onnxruntime.quantization import (CalibrationDataReader, QuantFormat,
                                          QuantType, quantize_static)
    calib = val_x77.detach().cpu().numpy().astype(np.float32)
    if calib.shape[0] < n_batches:
        reps = (n_batches + calib.shape[0] - 1) // calib.shape[0]
        calib = np.tile(calib, (reps, 1))

    class _Reader(CalibrationDataReader):
        def __init__(self, data: np.ndarray, limit: int):
            self._iter = iter(data[:limit, None, :])  # batch=1 per step

        def get_next(self):
            try:
                arr = next(self._iter)
            except StopIteration:
                return None
            return {"input": arr.astype(np.float32)}

    LOGGER.info("Quantising to INT8 (QDQ, per-channel) -> %s", int8_path)
    quantize_static(
        model_input=fp32_path.as_posix(), model_output=int8_path.as_posix(),
        calibration_data_reader=_Reader(calib, n_batches),
        quant_format=QuantFormat.QDQ, per_channel=True,
        weight_type=QuantType.QInt8, activation_type=QuantType.QInt8,
        reduce_range=False,
    )


def measure_latency(onnx_path: Path, batch_size: int, iters: int) -> tuple[float, float]:
    import onnxruntime as ort

    sess = ort.InferenceSession(onnx_path.as_posix(), providers=["CPUExecutionProvider"])
    rng = np.random.default_rng(0)
    x = rng.standard_normal((batch_size, STUDENT_IN_DIM)).astype(np.float32)
    # Warm-up.
    for _ in range(10):
        sess.run(None, {"input": x})
    times_ms: list[float] = []
    for _ in range(iters):
        t0 = time.perf_counter()
        sess.run(None, {"input": x})
        times_ms.append((time.perf_counter() - t0) * 1000.0)
    arr = np.asarray(times_ms)
    return float(arr.mean()), float(np.percentile(arr, 99))


def write_labels(path: Path) -> None:
    labels = list(SurrogateIDS.CLASS_NAMES)
    assert len(labels) == N_CLASSES, f"expected {N_CLASSES} labels, got {len(labels)}"
    path.write_text(json.dumps({"labels": labels}, indent=2) + "\n")
    LOGGER.info("Wrote labels JSON (%d classes) -> %s", len(labels), path)


def file_size_kb(path: Path) -> float:
    return path.stat().st_size / 1024.0


def main() -> int:
    setup_logging()
    args = parse_args()
    seed_everything(args.seed)

    args.output_dir.mkdir(parents=True, exist_ok=True)

    teacher = load_teacher()
    train_x83, train_logits = build_synthetic_dataset(teacher, args.n_train)
    val_x83, val_logits = build_synthetic_dataset(teacher, args.n_val)

    student = StudentMLP(in_dim=STUDENT_IN_DIM, out_dim=N_CLASSES)
    param_count = sum(p.numel() for p in student.parameters())
    LOGGER.info("Student parameter count: %d", param_count)

    final_train_loss = train_student(
        student, train_x83, train_logits, val_x83, val_logits, epochs=args.epochs,
    )

    val_x77 = val_x83[:, :STUDENT_IN_DIM]
    agree, _ = evaluate_agreement(student, val_x77, val_logits)
    LOGGER.info("Final validation agreement with teacher: %.2f%%", agree * 100.0)

    write_labels(args.output_dir / "labels.json")

    with tempfile.TemporaryDirectory() as tmpdir:
        fp32_path = Path(tmpdir) / "student_fp32.onnx"
        export_fp32_onnx(student, fp32_path)
        fp32_size_kb = file_size_kb(fp32_path)

        int8_path = args.output_dir / "student_int8.onnx"
        have_ort = try_import_onnxruntime()
        quantised = False
        if args.skip_quant or not have_ort:
            if args.skip_quant:
                LOGGER.info("--skip-quant set: emitting FP32 ONNX in place of INT8")
            else:
                LOGGER.info("onnxruntime missing: emitting FP32 ONNX in place of INT8")
            int8_path.write_bytes(fp32_path.read_bytes())
        else:
            try:
                quantize_int8(fp32_path, int8_path, val_x77)
                quantised = True
            except Exception as exc:  # pragma: no cover
                LOGGER.error("Quantisation failed (%s); falling back to FP32", exc)
                int8_path.write_bytes(fp32_path.read_bytes())

        int8_size_kb = file_size_kb(int8_path)

    compression = fp32_size_kb / max(int8_size_kb, 1e-9)

    lat1_avg = lat1_p99 = lat256_avg = lat256_p99 = float("nan")
    if have_ort:
        try:
            lat1_avg, lat1_p99 = measure_latency(int8_path, batch_size=1, iters=1000)
            lat256_avg, lat256_p99 = measure_latency(int8_path, batch_size=256, iters=100)
        except Exception as exc:  # pragma: no cover
            LOGGER.error("Latency measurement failed: %s", exc)

    report = {
        "student_param_count": param_count,
        "final_train_loss": final_train_loss,
        "val_agreement_pct": agree * 100.0,
        "fp32_onnx_kb": fp32_size_kb,
        "int8_onnx_kb": int8_size_kb,
        "compression_ratio": compression,
        "quantised": quantised,
        "latency_bs1_avg_ms": lat1_avg, "latency_bs1_p99_ms": lat1_p99,
        "latency_bs256_avg_ms": lat256_avg, "latency_bs256_p99_ms": lat256_p99,
        "labels_path": str(args.output_dir / "labels.json"),
        "model_path": str(int8_path),
    }
    report_path = args.output_dir / "distill_report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    LOGGER.info("==== Distillation report ====")
    for k, v in report.items():
        LOGGER.info("  %-22s %s", k, v)
    LOGGER.info("Report written to %s", report_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
