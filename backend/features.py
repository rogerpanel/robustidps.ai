"""
Feature extraction for CIC-IoT-2023 and CICIDS2018 CSV uploads.
"""

import io
import os
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.preprocessing import StandardScaler

WEIGHTS_DIR = Path(__file__).parent / "weights"

CIC_IOT_2023_FEATURES = [
    "flow_duration", "Header_Length", "Protocol Type",
    "Duration", "Rate", "Srate", "Drate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ece_flag_number",
    "cwr_flag_number", "ack_count", "syn_count", "fin_count",
    "urg_count", "rst_count", "HTTP", "HTTPS", "DNS", "Telnet",
    "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP", "ARP", "ICMP",
    "IPv", "LLC", "Tot sum", "Min", "Max", "AVG", "Std",
    "Tot size", "IAT", "Number", "Magnitue", "Radius", "Covariance",
    "Variance", "Weight",
]

CICIDS2018_FEATURES = [
    "Dst Port", "Protocol", "Flow Duration",
    "Tot Fwd Pkts", "Tot Bwd Pkts",
    "TotLen Fwd Pkts", "TotLen Bwd Pkts",
    "Fwd Pkt Len Max", "Fwd Pkt Len Min", "Fwd Pkt Len Mean", "Fwd Pkt Len Std",
    "Bwd Pkt Len Max", "Bwd Pkt Len Min", "Bwd Pkt Len Mean", "Bwd Pkt Len Std",
    "Flow Byts/s", "Flow Pkts/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
]

METADATA_COLS = ["src_ip", "dst_ip", "timestamp", "label", "Label"]

N_FEATURES = 83


def detect_format(df: pd.DataFrame) -> str:
    cols = set(df.columns)
    cic_iot_overlap = len(cols & set(CIC_IOT_2023_FEATURES))
    cicids_overlap = len(cols & set(CICIDS2018_FEATURES))
    if cic_iot_overlap > cicids_overlap:
        return "ciciot2023"
    if cicids_overlap > 0:
        return "cicids2018"
    return "generic"


def _select_numeric(df: pd.DataFrame) -> pd.DataFrame:
    numeric = df.select_dtypes(include=[np.number])
    meta = [c for c in numeric.columns if c.lower() in {m.lower() for m in METADATA_COLS}]
    numeric = numeric.drop(columns=meta, errors="ignore")
    return numeric


def _extract_metadata(df: pd.DataFrame) -> pd.DataFrame:
    meta = {}
    for col in METADATA_COLS:
        for c in df.columns:
            if c.lower() == col.lower():
                meta[col] = df[c]
                break
    return pd.DataFrame(meta, index=df.index)


def _load_or_fit_scaler(data: np.ndarray) -> StandardScaler:
    scaler_path = WEIGHTS_DIR / "scaler.pkl"
    if scaler_path.exists():
        with open(scaler_path, "rb") as f:
            scaler = pickle.load(f)
        return scaler
    scaler = StandardScaler()
    scaler.fit(data)
    WEIGHTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)
    return scaler


def extract_features(file_bytes: bytes, filename: str = "upload.csv"):
    """
    Parse an uploaded CSV, normalise, and return a tensor + metadata.

    Returns:
        features: torch.Tensor [N, 83]
        metadata: pd.DataFrame  with src_ip, dst_ip, timestamp, label cols
        labels_encoded: torch.Tensor [N] or None (if ground truth absent)
        label_names: list[str] | None
    """
    df = pd.read_csv(io.BytesIO(file_bytes), low_memory=False)

    metadata = _extract_metadata(df)
    fmt = detect_format(df)

    numeric = _select_numeric(df)

    # Pad or truncate to N_FEATURES columns
    n_cols = numeric.shape[1]
    if n_cols >= N_FEATURES:
        numeric = numeric.iloc[:, :N_FEATURES]
    else:
        for i in range(n_cols, N_FEATURES):
            numeric[f"pad_{i}"] = 0.0

    values = numeric.values.astype(np.float32)
    values = np.nan_to_num(values, nan=0.0, posinf=0.0, neginf=0.0)

    scaler = _load_or_fit_scaler(values)
    scaled = scaler.transform(values)

    features = torch.tensor(scaled, dtype=torch.float32)

    # Encode labels if present
    label_col = None
    for col in ("label", "Label"):
        if col in df.columns:
            label_col = col
            break

    labels_encoded = None
    label_names = None
    if label_col is not None:
        from models.surrogate import SurrogateIDS
        label_names = df[label_col].astype(str).tolist()
        # Use the model's class name mapping for consistent indices
        cls_names = SurrogateIDS.CLASS_NAMES
        cls_map = {name: idx for idx, name in enumerate(cls_names)}
        labels_encoded = torch.tensor(
            [cls_map.get(n, 0) for n in label_names], dtype=torch.long
        )
        metadata["label"] = label_names

    return features, metadata, labels_encoded, label_names
