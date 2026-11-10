"""
Multi-Agent PQC-IDS — Post-Quantum Cryptography-Aware Intrusion Detection.

Four specialized cooperative agents with attention-weighted fusion:
  Agent 1 (Traffic Analyst): 83->[128,64]->34 attack classification
  Agent 2 (PQC Specialist): 83->[128,64]->14 PQC algorithm identification
  Agent 3 (Anomaly Detector): Autoencoder 83->32->16->32->83 reconstruction
  Agent 4 (Coordinator): Attention fusion of all agent outputs

Total parameters: ~70,598
Source: https://github.com/rogerpanel/Multi-Agent-PQC-models
Dataset: https://doi.org/10.34740/kaggle/dsv/15424420

Author: Roger Nick Anaedevha
"""
import torch
import torch.nn as nn
import torch.nn.functional as F

PQC_CLASSES = [
    "Kyber-512", "Kyber-768", "Kyber-1024",
    "NTRU-HPS-2048", "McEliece-348864",
    "Dilithium-2", "Dilithium-3", "Dilithium-5",
    "Falcon-512", "SPHINCS+-128f",
    "Classical-RSA", "Classical-ECDSA", "Classical-X25519",
    "Unknown-PQC",
]

ATTACK_CLASSES = [
    "Benign",
    "DDoS-TCP_Flood",
    "DDoS-UDP_Flood",
    "DDoS-ICMP_Flood",
    "DDoS-HTTP_Flood",
    "DDoS-SYN_Flood",
    "DDoS-SlowLoris",
    "DDoS-RSTFIN_Flood",
    "DDoS-Pshack_Flood",
    "DDoS-ACK_Fragmentation",
    "DDoS-UDP_Fragmentation",
    "DDoS-ICMP_Fragmentation",
    "Recon-PortScan",
    "Recon-OSScan",
    "Recon-HostDiscovery",
    "Recon-PingSweep",
    "BruteForce-SSH",
    "BruteForce-FTP",
    "BruteForce-HTTP",
    "BruteForce-Dictionary",
    "Spoofing-ARP",
    "Spoofing-DNS",
    "Spoofing-IP",
    "WebAttack-SQLi",
    "WebAttack-XSS",
    "WebAttack-CommandInjection",
    "WebAttack-BrowserHijacking",
    "Malware-Backdoor",
    "Malware-Ransomware",
    "Malware-Trojan",
    "DoS-Slowhttptest",
    "DoS-Hulk",
    "Mirai-greeth_flood",
    "Mirai-greip_flood",
]


class TrafficAnalystAgent(nn.Module):
    """Agent 1: Network attack classification (83->34)."""

    def __init__(self, in_dim=83, hidden=[128, 64], out_dim=34, dropout=0.1):
        super().__init__()
        layers = []
        prev = in_dim
        for h in hidden:
            layers += [nn.Linear(prev, h), nn.BatchNorm1d(h), nn.ReLU(), nn.Dropout(dropout)]
            prev = h
        self.backbone = nn.Sequential(*layers)
        self.head = nn.Linear(prev, out_dim)

    def forward(self, x):
        feat = self.backbone(x)
        return self.head(feat), feat


class PQCSpecialistAgent(nn.Module):
    """Agent 2: PQC algorithm identification (83->14)."""

    def __init__(self, in_dim=83, hidden=[128, 64], out_dim=14, dropout=0.1):
        super().__init__()
        layers = []
        prev = in_dim
        for h in hidden:
            layers += [nn.Linear(prev, h), nn.BatchNorm1d(h), nn.ReLU(), nn.Dropout(dropout)]
            prev = h
        self.backbone = nn.Sequential(*layers)
        self.head = nn.Linear(prev, out_dim)

    def forward(self, x):
        feat = self.backbone(x)
        return self.head(feat), feat


class AnomalyDetectorAgent(nn.Module):
    """Agent 3: Autoencoder-based anomaly detection (83->16->83)."""

    def __init__(self, in_dim=83, bottleneck=16, dropout=0.1):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(in_dim, 32), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(32, bottleneck), nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck, 32), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(32, in_dim),
        )

    def forward(self, x):
        z = self.encoder(x)
        recon = self.decoder(z)
        anomaly_score = ((x - recon) ** 2).mean(dim=-1, keepdim=True)
        return recon, anomaly_score, z


class CoordinatorAgent(nn.Module):
    """Agent 4: Attention-weighted fusion of all agents."""

    def __init__(self, n_agents=3, feat_dim=64, bottleneck_dim=16):
        super().__init__()
        total_dim = feat_dim * 2 + bottleneck_dim  # traffic(64) + pqc(64) + anomaly(16)
        self.attn = nn.Sequential(
            nn.Linear(total_dim, 32), nn.Tanh(),
            nn.Linear(32, n_agents), nn.Softmax(dim=-1),
        )

    def forward(self, feats_list):
        concat = torch.cat(feats_list, dim=-1)
        weights = self.attn(concat)
        return weights


class MultiAgentPQCIDS(nn.Module):
    """Composite 4-agent PQC-aware IDS."""

    def __init__(self, dropout=0.1):
        super().__init__()
        self.traffic_agent = TrafficAnalystAgent(dropout=dropout)
        self.pqc_agent = PQCSpecialistAgent(dropout=dropout)
        self.anomaly_agent = AnomalyDetectorAgent(dropout=dropout)
        self.coordinator = CoordinatorAgent()

    def forward(self, x):
        attack_logits, traffic_feat = self.traffic_agent(x)
        pqc_logits, pqc_feat = self.pqc_agent(x)
        recon, anomaly_scores, anomaly_feat = self.anomaly_agent(x)

        agent_weights = self.coordinator([traffic_feat, pqc_feat, anomaly_feat])

        # Weighted fusion for final attack classification
        w = agent_weights  # (B, 3)
        fused = (w[:, 0:1] * attack_logits +
                 w[:, 1:2] * F.pad(pqc_logits, (0, 34 - 14)) +
                 w[:, 2:3] * anomaly_scores.expand(-1, 34))

        return {
            "attack_logits": fused,
            "pqc_logits": pqc_logits,
            "agent_weights": agent_weights,
            "anomaly_scores": anomaly_scores,
            "raw_attack": attack_logits,
            "raw_pqc": pqc_logits,
        }

    def predict(self, x):
        """Return attack class index predictions."""
        out = self.forward(x)
        return out["attack_logits"].argmax(dim=-1)
