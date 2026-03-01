#!/usr/bin/env python3
"""Generate synthetic CIC-IoT-2023-style CSV for demo."""

import numpy as np
import pandas as pd

np.random.seed(42)
n = 1000

labels = np.random.choice(
    [
        "Benign", "DDoS-TCP_Flood", "DDoS-UDP_Flood", "DDoS-ICMP_Flood",
        "Recon-PortScan", "Recon-OSScan", "BruteForce-SSH", "BruteForce-FTP",
        "Spoofing-ARP", "Spoofing-DNS", "WebAttack-SQLi", "WebAttack-XSS",
        "Malware-Backdoor",
    ],
    size=n,
    p=[0.60, 0.08, 0.05, 0.03, 0.04, 0.03, 0.03, 0.02, 0.02, 0.02, 0.03, 0.03, 0.02],
)

feature_cols = [f"feature_{i}" for i in range(83)]
data = np.random.randn(n, 83).astype(np.float32)

# Make attack traffic have different distributions
for i in range(n):
    if labels[i] != "Benign":
        data[i] += np.random.uniform(0.5, 2.0, size=83)

df = pd.DataFrame(data, columns=feature_cols)
df["label"] = labels
df["src_ip"] = [
    f"192.168.{np.random.randint(1, 10)}.{np.random.randint(1, 255)}"
    for _ in range(n)
]
df["dst_ip"] = [
    f"10.0.{np.random.randint(0, 5)}.{np.random.randint(1, 255)}"
    for _ in range(n)
]
df.to_csv("ciciot_sample.csv", index=False)
print(f"Generated ciciot_sample.csv with {n} rows, {len(feature_cols)} features")
