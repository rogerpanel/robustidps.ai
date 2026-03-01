"""
Surrogate IDS — lightweight MLP that approximates the UnifiedIDS ensemble.

Input:  83 CIC-IoT-2023 flow features (normalised)
Output: 34 classes (33 attack types + Benign)

Seven conceptual "branches" simulate the 7 dissertation methods so that
disabling any single branch reproduces the ablation table.
"""

import torch
import torch.nn as nn


class SurrogateIDS(nn.Module):

    N_FEATURES = 83
    N_CLASSES = 34
    HIDDEN = 256
    N_BRANCHES = 7

    BRANCH_NAMES = [
        "CT-TGNN (Neural ODE)",
        "TripleE-TGNN (Multi-scale)",
        "FedLLM-API (Zero-shot)",
        "PQ-IDPS (Post-quantum)",
        "MambaShield (State-space)",
        "Stochastic Transformer",
        "Game-Theoretic Defence",
    ]

    CLASS_NAMES = [
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

    SEVERITY_MAP = {
        "Benign": "benign",
        "Recon-PortScan": "low",
        "Recon-OSScan": "low",
        "Recon-HostDiscovery": "low",
        "Recon-PingSweep": "low",
        "Spoofing-ARP": "medium",
        "Spoofing-DNS": "medium",
        "Spoofing-IP": "medium",
        "BruteForce-SSH": "high",
        "BruteForce-FTP": "high",
        "BruteForce-HTTP": "high",
        "BruteForce-Dictionary": "high",
        "WebAttack-SQLi": "high",
        "WebAttack-XSS": "high",
        "WebAttack-CommandInjection": "critical",
        "WebAttack-BrowserHijacking": "high",
        "DoS-Slowhttptest": "high",
        "DoS-Hulk": "high",
    }

    def __init__(self, dropout: float = 0.3):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(self.N_FEATURES, self.HIDDEN),
            nn.ReLU(),
            nn.Dropout(dropout),
        )
        self.branches = nn.ModuleList(
            [
                nn.Sequential(
                    nn.Linear(self.HIDDEN, self.HIDDEN // self.N_BRANCHES),
                    nn.ReLU(),
                    nn.Dropout(dropout),
                )
                for _ in range(self.N_BRANCHES)
            ]
        )
        branch_out = self.HIDDEN // self.N_BRANCHES * self.N_BRANCHES
        self.fusion = nn.Sequential(
            nn.Linear(branch_out, self.HIDDEN),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(self.HIDDEN, self.N_CLASSES),
        )

    def forward(self, x, disabled_branches=None):
        h = self.encoder(x)
        branch_outputs = []
        for i, branch in enumerate(self.branches):
            if disabled_branches and i in disabled_branches:
                branch_outputs.append(
                    torch.zeros(
                        x.size(0),
                        self.HIDDEN // self.N_BRANCHES,
                        device=x.device,
                    )
                )
            else:
                branch_outputs.append(branch(h))
        fused = torch.cat(branch_outputs, dim=-1)
        return self.fusion(fused)

    @classmethod
    def severity_for(cls, label: str) -> str:
        if label in cls.SEVERITY_MAP:
            return cls.SEVERITY_MAP[label]
        if label.startswith("DDoS") or label.startswith("Mirai"):
            return "critical"
        if label.startswith("Malware"):
            return "critical"
        return "medium"
