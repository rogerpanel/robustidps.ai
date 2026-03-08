#!/usr/bin/env python3
"""
Generate a realistic PQC-IDS dataset for PQ-IDPS testing and model comparison.

Produces flows simulating post-quantum TLS handshakes (Kyber-512/768/1024,
X25519 classical baseline) mixed with attack traffic.  Output uses the
83-feature CIC-IoT-2023 format so it feeds directly into the existing
RobustIDPS.ai feature pipeline.

Extra metadata columns (pq_algorithm, handshake_type, key_size_bytes,
signature_size_bytes) are included for filtering/analysis but are ignored
by the model's 83-feature input.

Usage:
    python generate_pqc_dataset.py [--rows 50000] [--output pqc_test_dataset.csv]
"""

import argparse
import numpy as np
import pandas as pd

np.random.seed(2025)

# ── PQ Traffic Profiles (realistic sizes from NIST PQC benchmarks) ────────

PQ_PROFILES = {
    "kyber768_tls13": {
        "label": "Benign",
        "pq_algorithm": "Kyber-768",
        "handshake_type": "PQ-TLS1.3",
        "key_size_bytes": 1184,
        "signature_size_bytes": 2420,
        "client_hello_bytes": 1450,
        "server_hello_bytes": 2850,
        "flow_duration_mean": 12.5,
        "fwd_pkt_len_mean": 1217,
        "bwd_pkt_len_mean": 1117,
        "flow_bytes_per_s_mean": 560000,
        "flow_iat_mean": 2.1,
        "total_fwd_packets": 3,
        "total_bwd_packets": 3,
        "header_length": 240,
    },
    "kyber512_tls13": {
        "label": "Benign",
        "pq_algorithm": "Kyber-512",
        "handshake_type": "PQ-TLS1.3",
        "key_size_bytes": 800,
        "signature_size_bytes": 2420,
        "client_hello_bytes": 1100,
        "server_hello_bytes": 2200,
        "flow_duration_mean": 10.2,
        "fwd_pkt_len_mean": 933,
        "bwd_pkt_len_mean": 867,
        "flow_bytes_per_s_mean": 530000,
        "flow_iat_mean": 1.7,
        "total_fwd_packets": 3,
        "total_bwd_packets": 3,
        "header_length": 240,
    },
    "kyber1024_tls13": {
        "label": "Benign",
        "pq_algorithm": "Kyber-1024",
        "handshake_type": "PQ-TLS1.3",
        "key_size_bytes": 1568,
        "signature_size_bytes": 2420,
        "client_hello_bytes": 1900,
        "server_hello_bytes": 3500,
        "flow_duration_mean": 15.8,
        "fwd_pkt_len_mean": 1467,
        "bwd_pkt_len_mean": 1400,
        "flow_bytes_per_s_mean": 640000,
        "flow_iat_mean": 2.3,
        "total_fwd_packets": 4,
        "total_bwd_packets": 3,
        "header_length": 280,
    },
    "x25519_classical": {
        "label": "Benign",
        "pq_algorithm": "X25519-Classical",
        "handshake_type": "Classical-TLS1.3",
        "key_size_bytes": 32,
        "signature_size_bytes": 64,
        "client_hello_bytes": 350,
        "server_hello_bytes": 450,
        "flow_duration_mean": 6.2,
        "fwd_pkt_len_mean": 303,
        "bwd_pkt_len_mean": 265,
        "flow_bytes_per_s_mean": 232000,
        "flow_iat_mean": 1.2,
        "total_fwd_packets": 3,
        "total_bwd_packets": 2,
        "header_length": 200,
    },
}

# ── Attack Profiles (PQ-specific + standard) ──────────────────────────────

ATTACK_PROFILES = {
    # PQ-specific attacks
    "downgrade_attack": {
        "label": "Spoofing-DNS",
        "pq_algorithm": "Downgrade-Attack",
        "handshake_type": "PQ-Downgrade",
        "description": "MitM strips PQ key share, forces classical-only",
        "flow_duration_mean": 18.5,
        "fwd_pkt_len_mean": 350,  # Reduced from PQ sizes
        "bwd_pkt_len_mean": 450,
        "flow_bytes_per_s_mean": 120000,
        "flow_iat_mean": 4.5,
        "total_fwd_packets": 5,
        "total_bwd_packets": 4,
        "header_length": 200,
        "syn_flag": 2,  # Extra SYN from re-negotiation
        "rst_flag": 1,
    },
    "harvest_now_decrypt_later": {
        "label": "Recon-PortScan",
        "pq_algorithm": "HNDL-Capture",
        "handshake_type": "Passive-Capture",
        "description": "Mass traffic capture for future quantum decryption",
        "flow_duration_mean": 0.3,
        "fwd_pkt_len_mean": 80,
        "bwd_pkt_len_mean": 0,
        "flow_bytes_per_s_mean": 1200000,
        "flow_iat_mean": 0.01,
        "total_fwd_packets": 1,
        "total_bwd_packets": 0,
        "header_length": 60,
        "syn_flag": 1,
        "rst_flag": 0,
    },
    "pq_side_channel": {
        "label": "WebAttack-CommandInjection",
        "pq_algorithm": "PQ-SideChannel",
        "handshake_type": "Timing-Attack",
        "description": "Lattice timing side-channel on ML-KEM decapsulation",
        "flow_duration_mean": 45.0,
        "fwd_pkt_len_mean": 1200,
        "bwd_pkt_len_mean": 1100,
        "flow_bytes_per_s_mean": 85000,
        "flow_iat_mean": 0.5,
        "total_fwd_packets": 50,
        "total_bwd_packets": 50,
        "header_length": 240,
        "syn_flag": 1,
        "rst_flag": 0,
    },
    "pq_key_exhaustion": {
        "label": "DDoS-TCP_Flood",
        "pq_algorithm": "PQ-KeyExhaustion",
        "handshake_type": "DoS-Handshake",
        "description": "Floods server with PQ key exchange requests",
        "flow_duration_mean": 0.8,
        "fwd_pkt_len_mean": 1450,
        "bwd_pkt_len_mean": 0,
        "flow_bytes_per_s_mean": 5000000,
        "flow_iat_mean": 0.001,
        "total_fwd_packets": 200,
        "total_bwd_packets": 5,
        "header_length": 240,
        "syn_flag": 200,
        "rst_flag": 0,
    },
    # Standard network attacks mixed in
    "ddos_udp": {
        "label": "DDoS-UDP_Flood",
        "pq_algorithm": "N/A",
        "handshake_type": "N/A",
        "flow_duration_mean": 0.5,
        "fwd_pkt_len_mean": 1400,
        "bwd_pkt_len_mean": 0,
        "flow_bytes_per_s_mean": 8000000,
        "flow_iat_mean": 0.001,
        "total_fwd_packets": 500,
        "total_bwd_packets": 0,
        "header_length": 60,
        "syn_flag": 0,
        "rst_flag": 0,
    },
    "bruteforce_ssh": {
        "label": "BruteForce-SSH",
        "pq_algorithm": "N/A",
        "handshake_type": "N/A",
        "flow_duration_mean": 5.0,
        "fwd_pkt_len_mean": 120,
        "bwd_pkt_len_mean": 300,
        "flow_bytes_per_s_mean": 45000,
        "flow_iat_mean": 0.8,
        "total_fwd_packets": 10,
        "total_bwd_packets": 8,
        "header_length": 160,
        "syn_flag": 1,
        "rst_flag": 3,
    },
    "recon_osscan": {
        "label": "Recon-OSScan",
        "pq_algorithm": "N/A",
        "handshake_type": "N/A",
        "flow_duration_mean": 2.0,
        "fwd_pkt_len_mean": 60,
        "bwd_pkt_len_mean": 80,
        "flow_bytes_per_s_mean": 25000,
        "flow_iat_mean": 0.3,
        "total_fwd_packets": 15,
        "total_bwd_packets": 12,
        "header_length": 120,
        "syn_flag": 5,
        "rst_flag": 8,
    },
    "malware_backdoor": {
        "label": "Malware-Backdoor",
        "pq_algorithm": "N/A",
        "handshake_type": "N/A",
        "flow_duration_mean": 120.0,
        "fwd_pkt_len_mean": 200,
        "bwd_pkt_len_mean": 500,
        "flow_bytes_per_s_mean": 15000,
        "flow_iat_mean": 10.0,
        "total_fwd_packets": 8,
        "total_bwd_packets": 12,
        "header_length": 180,
        "syn_flag": 1,
        "rst_flag": 0,
    },
}

# CIC-IoT-2023 canonical 83 feature names
FEATURE_COLS = [
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


def _generate_flows(profile: dict, n: int) -> np.ndarray:
    """Generate n flows from a traffic profile, returning 83-feature array."""
    rows = np.zeros((n, 83), dtype=np.float32)

    noise = lambda mean, scale=0.15: np.random.normal(mean, abs(mean) * scale, n).clip(0)

    # Core flow features
    rows[:, 0] = noise(profile["flow_duration_mean"])  # flow_duration
    rows[:, 1] = noise(profile["header_length"])  # Header_Length
    rows[:, 2] = np.random.choice([6, 17], n, p=[0.8, 0.2])  # Protocol Type (TCP/UDP)
    rows[:, 3] = noise(profile["flow_duration_mean"])  # Duration
    rows[:, 4] = noise(profile["flow_bytes_per_s_mean"] / 1000)  # Rate
    rows[:, 5] = noise(profile["flow_bytes_per_s_mean"] / 2000)  # Srate
    rows[:, 6] = noise(profile["flow_bytes_per_s_mean"] / 3000)  # Drate

    # Flags
    syn_flag = profile.get("syn_flag", 1)
    rst_flag = profile.get("rst_flag", 0)
    rows[:, 7] = np.random.poisson(0.5, n)  # fin_flag_number
    rows[:, 8] = np.random.poisson(syn_flag, n)  # syn_flag_number
    rows[:, 9] = np.random.poisson(rst_flag, n)  # rst_flag_number
    rows[:, 10] = np.random.poisson(max(1, profile["total_fwd_packets"] // 2), n)  # psh_flag_number
    rows[:, 11] = np.random.poisson(profile["total_fwd_packets"], n)  # ack_flag_number
    rows[:, 12] = np.random.poisson(0.1, n)  # ece_flag_number
    rows[:, 13] = np.random.poisson(0.05, n)  # cwr_flag_number
    rows[:, 14] = noise(profile["total_fwd_packets"] * 2)  # ack_count
    rows[:, 15] = noise(syn_flag)  # syn_count
    rows[:, 16] = noise(0.5)  # fin_count
    rows[:, 17] = np.random.poisson(0.01, n)  # urg_count
    rows[:, 18] = noise(rst_flag)  # rst_count

    # Protocol flags (one-hot-ish)
    rows[:, 19] = np.random.binomial(1, 0.3, n)  # HTTP
    rows[:, 20] = np.random.binomial(1, 0.5, n)  # HTTPS
    rows[:, 21] = np.random.binomial(1, 0.1, n)  # DNS
    rows[:, 22] = np.random.binomial(1, 0.01, n)  # Telnet
    rows[:, 23] = np.random.binomial(1, 0.02, n)  # SMTP
    rows[:, 24] = np.random.binomial(1, 0.05, n)  # SSH
    rows[:, 25] = np.random.binomial(1, 0.001, n)  # IRC
    rows[:, 26] = np.random.binomial(1, 0.8, n)  # TCP
    rows[:, 27] = np.random.binomial(1, 0.2, n)  # UDP
    rows[:, 28] = np.random.binomial(1, 0.01, n)  # DHCP
    rows[:, 29] = np.random.binomial(1, 0.02, n)  # ARP
    rows[:, 30] = np.random.binomial(1, 0.05, n)  # ICMP
    rows[:, 31] = np.random.binomial(1, 0.95, n)  # IPv
    rows[:, 32] = np.random.binomial(1, 0.02, n)  # LLC

    # Packet size statistics
    fwd_mean = profile["fwd_pkt_len_mean"]
    bwd_mean = profile["bwd_pkt_len_mean"]
    total_bytes = fwd_mean * profile["total_fwd_packets"] + bwd_mean * profile["total_bwd_packets"]

    rows[:, 33] = noise(total_bytes)  # Tot sum
    rows[:, 34] = noise(min(fwd_mean, bwd_mean) * 0.3)  # Min
    rows[:, 35] = noise(max(fwd_mean, bwd_mean) * 1.5)  # Max
    rows[:, 36] = noise((fwd_mean + bwd_mean) / 2)  # AVG
    rows[:, 37] = noise(abs(fwd_mean - bwd_mean) * 0.4)  # Std
    rows[:, 38] = noise(total_bytes)  # Tot size
    rows[:, 39] = noise(profile["flow_iat_mean"])  # IAT
    rows[:, 40] = noise(profile["total_fwd_packets"] + profile["total_bwd_packets"])  # Number
    rows[:, 41] = noise(np.sqrt(fwd_mean**2 + bwd_mean**2))  # Magnitude
    rows[:, 42] = noise(np.sqrt(total_bytes))  # Radius
    rows[:, 43] = noise(fwd_mean * bwd_mean / max(total_bytes, 1) * 100)  # Covariance
    rows[:, 44] = noise(abs(fwd_mean - bwd_mean) ** 2)  # Variance

    # Fill remaining features (45-82) with correlated noise
    for i in range(45, 83):
        base_feat = i % 45
        rows[:, i] = rows[:, base_feat] * np.random.uniform(0.3, 1.5) + np.random.normal(0, 0.5, n)

    return rows


def generate_pqc_dataset(n_rows: int = 50000) -> pd.DataFrame:
    """Generate a complete PQC-IDS dataset."""
    # Distribution: 55% benign PQ, 10% benign classical, 35% attacks
    n_benign_pq = int(n_rows * 0.55)
    n_benign_classical = int(n_rows * 0.10)
    n_attacks = n_rows - n_benign_pq - n_benign_classical

    all_features = []
    all_labels = []
    all_meta = []

    # ── Benign PQ traffic (distributed across Kyber variants) ──
    pq_profiles = ["kyber768_tls13", "kyber512_tls13", "kyber1024_tls13"]
    pq_weights = [0.5, 0.3, 0.2]

    for profile_name, weight in zip(pq_profiles, pq_weights):
        profile = PQ_PROFILES[profile_name]
        n = int(n_benign_pq * weight)
        features = _generate_flows(profile, n)
        all_features.append(features)
        all_labels.extend([profile["label"]] * n)
        all_meta.extend([{
            "pq_algorithm": profile["pq_algorithm"],
            "handshake_type": profile["handshake_type"],
            "key_size_bytes": profile["key_size_bytes"],
            "signature_size_bytes": profile["signature_size_bytes"],
        }] * n)

    # ── Benign classical traffic ──
    profile = PQ_PROFILES["x25519_classical"]
    features = _generate_flows(profile, n_benign_classical)
    all_features.append(features)
    all_labels.extend([profile["label"]] * n_benign_classical)
    all_meta.extend([{
        "pq_algorithm": profile["pq_algorithm"],
        "handshake_type": profile["handshake_type"],
        "key_size_bytes": profile["key_size_bytes"],
        "signature_size_bytes": profile["signature_size_bytes"],
    }] * n_benign_classical)

    # ── Attack traffic ──
    attack_names = list(ATTACK_PROFILES.keys())
    attack_weights = [0.15, 0.10, 0.10, 0.15, 0.15, 0.15, 0.10, 0.10]
    for atk_name, weight in zip(attack_names, attack_weights):
        profile = ATTACK_PROFILES[atk_name]
        n = int(n_attacks * weight)
        features = _generate_flows(profile, n)
        # Add attack-specific signal perturbation
        features += np.random.uniform(0.3, 1.5, size=features.shape)
        all_features.append(features)
        all_labels.extend([profile["label"]] * n)
        all_meta.extend([{
            "pq_algorithm": profile["pq_algorithm"],
            "handshake_type": profile["handshake_type"],
            "key_size_bytes": profile.get("key_size_bytes", 0),
            "signature_size_bytes": profile.get("signature_size_bytes", 0),
        }] * n)

    # Combine
    data = np.concatenate(all_features, axis=0)

    # Pad/truncate column names to match 83 features
    col_names = FEATURE_COLS[:]
    while len(col_names) < 83:
        col_names.append(f"feature_{len(col_names)}")
    col_names = col_names[:83]

    df = pd.DataFrame(data, columns=col_names)
    df["label"] = all_labels[:len(df)]

    # Add PQ metadata columns
    meta_df = pd.DataFrame(all_meta[:len(df)])
    df["pq_algorithm"] = meta_df["pq_algorithm"].values
    df["handshake_type"] = meta_df["handshake_type"].values
    df["key_size_bytes"] = meta_df["key_size_bytes"].values
    df["signature_size_bytes"] = meta_df["signature_size_bytes"].values

    # Add network metadata
    df["src_ip"] = [
        f"192.168.{np.random.randint(1, 10)}.{np.random.randint(1, 255)}"
        for _ in range(len(df))
    ]
    df["dst_ip"] = [
        f"10.0.{np.random.randint(0, 5)}.{np.random.randint(1, 255)}"
        for _ in range(len(df))
    ]

    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate PQC-IDS test dataset")
    parser.add_argument("--rows", type=int, default=50000, help="Number of flows (default: 50000)")
    parser.add_argument("--output", type=str, default="pqc_test_dataset.csv", help="Output filename")
    args = parser.parse_args()

    df = generate_pqc_dataset(args.rows)
    output_path = args.output
    df.to_csv(output_path, index=False)

    size_mb = len(df.to_csv(index=False).encode()) / (1024 * 1024)
    n_benign = (df["label"] == "Benign").sum()
    n_attacks = len(df) - n_benign

    print(f"Generated {output_path}")
    print(f"  Rows:     {len(df):,}")
    print(f"  Size:     {size_mb:.1f} MB")
    print(f"  Benign:   {n_benign:,} ({n_benign/len(df)*100:.1f}%)")
    print(f"  Attacks:  {n_attacks:,} ({n_attacks/len(df)*100:.1f}%)")
    print(f"  Features: {83} CIC-IoT-2023 + 4 PQ metadata columns")
    print(f"  Labels:   {df['label'].nunique()} classes")
    print(f"\nPQ algorithm distribution:")
    for alg, count in df["pq_algorithm"].value_counts().items():
        print(f"    {alg}: {count:,} ({count/len(df)*100:.1f}%)")
    print(f"\nAttack type distribution:")
    for label, count in df["label"].value_counts().items():
        print(f"    {label}: {count:,} ({count/len(df)*100:.1f}%)")
