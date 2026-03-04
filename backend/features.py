"""
Feature extraction for CIC-IoT-2023, CSE-CIC-IDS2018, UNSW-NB15, and PCAP uploads.
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

# ── CIC-IoT-2023 canonical feature names ─────────────────────────────────────
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

# ── CSE-CIC-IDS2018 (full column names as they appear in the CSV) ────────────
# The CSV uses full names like "Destination Port", "Total Fwd Packets", etc.
CICIDS2018_FEATURES_FULL = [
    "Destination Port", "Flow Duration",
    "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min",
    "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

# Abbreviated variants (some CSVs use these)
CICIDS2018_FEATURES_SHORT = [
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

# ── UNSW-NB15 feature names ───────────────────────────────────────────────────
UNSW_NB15_FEATURES = [
    "dur", "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss",
    "sload", "dload", "spkts", "dpkts", "swin", "dwin",
    "stcpb", "dtcpb", "smeansz", "dmeansz",
    "trans_depth", "res_bdy_len", "sjit", "djit",
    "sintpkt", "dintpkt", "tcprtt", "synack", "ackdat",
    "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd",
    "is_ftp_login", "ct_ftp_cmd",
    "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
]

METADATA_COLS = ["src_ip", "dst_ip", "timestamp", "label", "Label",
                 "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol",
                 "srcip", "dstip", "sport", "dsport", "attack_cat"]

# Known label aliases → canonical label in CLASS_NAMES
# Handles CSE-CIC-2018 label names, case differences, and common variants
LABEL_ALIASES = {
    # Case normalization
    "benign": "Benign",
    "BENIGN": "Benign",
    # CSE-CIC-IDS2018 labels
    "FTP-BruteForce": "BruteForce-FTP",
    "SSH-Bruteforce": "BruteForce-SSH",
    "SSH-BruteForce": "BruteForce-SSH",
    "Brute Force -Web": "BruteForce-HTTP",
    "Brute Force -XSS": "WebAttack-XSS",
    "SQL Injection": "WebAttack-SQLi",
    "Infiltration": "Malware-Backdoor",
    "Infilteration": "Malware-Backdoor",
    "Bot": "Malware-Trojan",
    "DoS attacks-GoldenEye": "DoS-Hulk",
    "DoS attacks-Slowloris": "DDoS-SlowLoris",
    "DoS attacks-SlowHTTPTest": "DoS-Slowhttptest",
    "DoS attacks-Hulk": "DoS-Hulk",
    "DDoS attacks-LOIC-HTTP": "DDoS-HTTP_Flood",
    "DDoS attack-LOIC-UDP": "DDoS-UDP_Flood",
    "DDoS attack-HOIC": "DDoS-HTTP_Flood",
    "DDOS attack-LOIC-UDP": "DDoS-UDP_Flood",
    "DDOS attack-HOIC": "DDoS-HTTP_Flood",
    # CICIDS2017 variants
    "DoS Hulk": "DoS-Hulk",
    "DoS GoldenEye": "DoS-Hulk",
    "DoS slowloris": "DDoS-SlowLoris",
    "DoS Slowhttptest": "DoS-Slowhttptest",
    "Heartbleed": "DoS-Hulk",
    "PortScan": "Recon-PortScan",
    "FTP-Patator": "BruteForce-FTP",
    "SSH-Patator": "BruteForce-SSH",
    "Web Attack - Brute Force": "BruteForce-HTTP",
    "Web Attack - XSS": "WebAttack-XSS",
    "Web Attack - Sql Injection": "WebAttack-SQLi",
    # UNSW-NB15 attack_cat values
    "Normal": "Benign",
    "normal": "Benign",
    "Fuzzers": "BruteForce-Dictionary",
    "Analysis": "Recon-PortScan",
    "Backdoor": "Malware-Backdoor",
    "Backdoors": "Malware-Backdoor",
    "DoS": "DoS-Hulk",
    "Exploits": "WebAttack-CommandInjection",
    "Generic": "DDoS-TCP_Flood",
    "Reconnaissance": "Recon-PortScan",
    "Shellcode": "Malware-Backdoor",
    "Worms": "Malware-Trojan",
}

N_FEATURES = 83


# ── Format detection ─────────────────────────────────────────────────────────

def _normalize_col(name: str) -> str:
    """Lowercase and strip whitespace for column matching."""
    return name.strip().lower()


def detect_format(df: pd.DataFrame) -> str:
    cols_lower = {_normalize_col(c) for c in df.columns}

    cic_iot_overlap = sum(1 for f in CIC_IOT_2023_FEATURES if _normalize_col(f) in cols_lower)
    cicids_full = sum(1 for f in CICIDS2018_FEATURES_FULL if _normalize_col(f) in cols_lower)
    cicids_short = sum(1 for f in CICIDS2018_FEATURES_SHORT if _normalize_col(f) in cols_lower)
    cicids_overlap = max(cicids_full, cicids_short)
    unsw_overlap = sum(1 for f in UNSW_NB15_FEATURES if _normalize_col(f) in cols_lower)

    # Pick the format with the highest column overlap
    best = max(
        ("ciciot2023", cic_iot_overlap),
        ("cicids2018", cicids_overlap),
        ("unsw", unsw_overlap),
        key=lambda x: x[1],
    )
    if best[1] > 5:
        return best[0]
    return "generic"


# ── Column selection ─────────────────────────────────────────────────────────

def _find_column(df: pd.DataFrame, name: str) -> str | None:
    """Find a column by case-insensitive match."""
    name_lower = _normalize_col(name)
    for c in df.columns:
        if _normalize_col(c) == name_lower:
            return c
    return None


def _select_features_cicids2018(df: pd.DataFrame) -> pd.DataFrame:
    """Extract features in canonical CICIDS2018 order."""
    selected = []
    for feat_name in CICIDS2018_FEATURES_FULL:
        col = _find_column(df, feat_name)
        if col is not None:
            # Force numeric — coerce non-numeric values (control chars, Infinity, etc.) to NaN
            series = pd.to_numeric(df[col], errors="coerce").fillna(0.0)
            series.name = feat_name
            selected.append(series)
        else:
            selected.append(pd.Series(0.0, index=df.index, name=feat_name))

    result = pd.concat(selected, axis=1)
    result.columns = CICIDS2018_FEATURES_FULL[:len(result.columns)]
    return result


def _select_features_unsw(df: pd.DataFrame) -> pd.DataFrame:
    """Extract features in canonical UNSW-NB15 order."""
    selected = []
    for feat_name in UNSW_NB15_FEATURES:
        col = _find_column(df, feat_name)
        if col is not None:
            series = pd.to_numeric(df[col], errors="coerce").fillna(0.0)
            series.name = feat_name
            selected.append(series)
        else:
            selected.append(pd.Series(0.0, index=df.index, name=feat_name))

    result = pd.concat(selected, axis=1)
    result.columns = UNSW_NB15_FEATURES[:len(result.columns)]
    return result


def _select_numeric(df: pd.DataFrame) -> pd.DataFrame:
    """Select numeric columns, excluding metadata."""
    numeric = df.select_dtypes(include=[np.number])
    meta_lower = {_normalize_col(m) for m in METADATA_COLS}
    keep = [c for c in numeric.columns if _normalize_col(c) not in meta_lower]
    return numeric[keep]


def _extract_metadata(df: pd.DataFrame) -> pd.DataFrame:
    meta = {}
    for col in METADATA_COLS:
        found = _find_column(df, col)
        if found is not None:
            meta[col] = df[found]
    return pd.DataFrame(meta, index=df.index)


# ── Scaler ───────────────────────────────────────────────────────────────────

def _get_scaler(data: np.ndarray, fmt: str) -> StandardScaler:
    """
    Get or fit a scaler specific to the dataset format.
    Each format gets its own scaler file to avoid cross-contamination.
    """
    scaler_path = WEIGHTS_DIR / f"scaler_{fmt}.pkl"
    if scaler_path.exists():
        with open(scaler_path, "rb") as f:
            scaler = pickle.load(f)
        # Validate feature count matches
        if hasattr(scaler, 'n_features_in_') and scaler.n_features_in_ == data.shape[1]:
            return scaler

    # Fit new scaler on this data
    scaler = StandardScaler()
    scaler.fit(data)
    WEIGHTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)
    return scaler


# ── Label mapping ────────────────────────────────────────────────────────────

def _normalize_label(raw_label: str) -> str:
    """Map a raw label from any CIC dataset to a canonical CLASS_NAME."""
    label = raw_label.strip()
    # Exact alias match
    if label in LABEL_ALIASES:
        return LABEL_ALIASES[label]
    # Case-insensitive match against CLASS_NAMES
    from models.surrogate import SurrogateIDS
    for cn in SurrogateIDS.CLASS_NAMES:
        if cn.lower() == label.lower():
            return cn
    # Partial match
    label_lower = label.lower()
    for cn in SurrogateIDS.CLASS_NAMES:
        if cn.lower() in label_lower or label_lower in cn.lower():
            return cn
    return label  # return as-is if no match found


# ── PCAP support ─────────────────────────────────────────────────────────────

def pcap_to_dataframe(file_bytes: bytes, filename: str) -> pd.DataFrame:
    """
    Convert a PCAP/PCAPNG file to a DataFrame of flow-level features
    using NFStream.
    """
    import tempfile
    from nfstream import NFStreamer

    suffix = ".pcap" if filename.lower().endswith(".pcap") else ".pcapng"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        streamer = NFStreamer(
            source=tmp_path,
            statistical_analysis=True,
        )
        df = streamer.to_pandas()
    finally:
        os.unlink(tmp_path)

    if df.empty:
        raise ValueError("No flows extracted from PCAP file")

    # Map NFStream columns → CICIDS2018-like columns
    col_map = {
        "dst_port": "Destination Port",
        "bidirectional_duration_ms": "Flow Duration",
        "src2dst_packets": "Total Fwd Packets",
        "dst2src_packets": "Total Backward Packets",
        "src2dst_bytes": "Total Length of Fwd Packets",
        "dst2src_bytes": "Total Length of Bwd Packets",
        "src2dst_max_ps": "Fwd Packet Length Max",
        "src2dst_min_ps": "Fwd Packet Length Min",
        "src2dst_mean_ps": "Fwd Packet Length Mean",
        "src2dst_stddev_ps": "Fwd Packet Length Std",
        "dst2src_max_ps": "Bwd Packet Length Max",
        "dst2src_min_ps": "Bwd Packet Length Min",
        "dst2src_mean_ps": "Bwd Packet Length Mean",
        "dst2src_stddev_ps": "Bwd Packet Length Std",
        "bidirectional_mean_piat_ms": "Flow IAT Mean",
        "bidirectional_stddev_piat_ms": "Flow IAT Std",
        "bidirectional_max_piat_ms": "Flow IAT Max",
        "bidirectional_min_piat_ms": "Flow IAT Min",
        "src2dst_mean_piat_ms": "Fwd IAT Mean",
        "src2dst_stddev_piat_ms": "Fwd IAT Std",
        "src2dst_max_piat_ms": "Fwd IAT Max",
        "src2dst_min_piat_ms": "Fwd IAT Min",
        "dst2src_mean_piat_ms": "Bwd IAT Mean",
        "dst2src_stddev_piat_ms": "Bwd IAT Std",
        "dst2src_max_piat_ms": "Bwd IAT Max",
        "dst2src_min_piat_ms": "Bwd IAT Min",
        "bidirectional_syn_packets": "SYN Flag Count",
        "bidirectional_fin_packets": "FIN Flag Count",
        "bidirectional_rst_packets": "RST Flag Count",
        "bidirectional_psh_packets": "PSH Flag Count",
        "bidirectional_ack_packets": "ACK Flag Count",
        "bidirectional_urg_packets": "URG Flag Count",
        "bidirectional_ece_packets": "ECE Flag Count",
        "bidirectional_cwr_packets": "CWE Flag Count",
    }

    renamed = df.rename(columns={k: v for k, v in col_map.items() if k in df.columns})

    # Compute derived features
    duration_s = (renamed.get("Flow Duration", pd.Series(0, index=df.index)) / 1000.0).clip(lower=1e-6)
    total_bytes = renamed.get("Total Length of Fwd Packets", 0) + renamed.get("Total Length of Bwd Packets", 0)
    total_pkts = renamed.get("Total Fwd Packets", 0) + renamed.get("Total Backward Packets", 0)
    renamed["Flow Bytes/s"] = total_bytes / duration_s
    renamed["Flow Packets/s"] = total_pkts / duration_s
    renamed["Fwd Packets/s"] = renamed.get("Total Fwd Packets", 0) / duration_s
    renamed["Bwd Packets/s"] = renamed.get("Total Backward Packets", 0) / duration_s

    # Add metadata columns
    if "src_ip" in df.columns:
        renamed["src_ip"] = df["src_ip"]
    if "dst_ip" in df.columns:
        renamed["dst_ip"] = df["dst_ip"]

    return renamed


# ── Main extraction entry point ──────────────────────────────────────────────

def extract_features(file_bytes: bytes, filename: str = "upload.csv"):
    """
    Parse an uploaded CSV or PCAP, normalise, and return a tensor + metadata.

    Returns:
        features: torch.Tensor [N, 83]
        metadata: pd.DataFrame
        labels_encoded: torch.Tensor [N] or None
        label_names: list[str] | None
    """
    # Handle PCAP files
    is_pcap = filename.lower().endswith(('.pcap', '.pcapng'))
    if is_pcap:
        df = pcap_to_dataframe(file_bytes, filename)
        fmt = "cicids2018"  # PCAP → flow features → treated as CICIDS2018
    else:
        # Clean raw bytes: strip control characters that break CSV parsing
        # CSE-CIC-2018 files often contain \x1a (Ctrl-Z / EOF) from Windows
        cleaned = file_bytes.replace(b'\x1a', b'').replace(b'\x00', b'')
        df = pd.read_csv(io.BytesIO(cleaned), low_memory=False, encoding_errors="replace")
        # Strip whitespace from column names
        df.columns = [c.strip() for c in df.columns]
        fmt = detect_format(df)

    metadata = _extract_metadata(df)

    # Select features based on detected format
    if fmt == "cicids2018":
        numeric = _select_features_cicids2018(df)
    elif fmt == "unsw":
        numeric = _select_features_unsw(df)
    else:
        numeric = _select_numeric(df)

    # Pad or truncate to N_FEATURES columns
    n_cols = numeric.shape[1]
    if n_cols >= N_FEATURES:
        numeric = numeric.iloc[:, :N_FEATURES]
    else:
        for i in range(n_cols, N_FEATURES):
            numeric[f"pad_{i}"] = 0.0

    # Force all columns to numeric (handles stray strings, control chars, "Infinity")
    for col in numeric.columns:
        numeric[col] = pd.to_numeric(numeric[col], errors="coerce")
    values = numeric.values.astype(np.float32)
    values = np.nan_to_num(values, nan=0.0, posinf=0.0, neginf=0.0)

    scaler = _get_scaler(values, fmt)
    scaled = scaler.transform(values)

    features = torch.tensor(scaled, dtype=torch.float32)

    # Encode labels if present
    # Prefer attack_cat (UNSW-NB15 categorical labels) over binary label column
    label_col = None
    for col in ("attack_cat", "label", "Label"):
        found = _find_column(df, col)
        if found is not None:
            # Skip UNSW binary label column (0/1) — prefer attack_cat for category names
            if col in ("label", "Label") and fmt == "unsw" and _find_column(df, "attack_cat"):
                continue
            label_col = found
            break

    labels_encoded = None
    label_names = None
    if label_col is not None:
        from models.surrogate import SurrogateIDS
        raw_labels = df[label_col].astype(str).tolist()
        # Normalise labels (case, aliases)
        label_names = [_normalize_label(l) for l in raw_labels]
        cls_names = SurrogateIDS.CLASS_NAMES
        cls_map = {name: idx for idx, name in enumerate(cls_names)}
        labels_encoded = torch.tensor(
            [cls_map.get(n, 0) for n in label_names], dtype=torch.long
        )
        metadata["label"] = label_names

    return features, metadata, labels_encoded, label_names
