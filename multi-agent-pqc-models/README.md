# Multi-Agent PQC-IDS

**Post-Quantum Cryptography-Aware Intrusion Detection System**

A cooperative multi-agent deep learning architecture for network intrusion detection that is aware of post-quantum cryptographic (PQC) traffic patterns.

## Architecture

The system consists of four specialized cooperative agents:

| Agent | Role | Architecture | Output |
|-------|------|-------------|--------|
| Agent 1 | Traffic Analyst | MLP 83->[128,64]->34 | 34-class attack classification |
| Agent 2 | PQC Specialist | MLP 83->[128,64]->14 | 14 PQC algorithm identification |
| Agent 3 | Anomaly Detector | Autoencoder 83->32->16->32->83 | Reconstruction-based anomaly scores |
| Agent 4 | Coordinator | Attention network | Attention-weighted fusion of all agents |

**Total parameters:** ~53,142

### Agent Details

- **Traffic Analyst Agent:** Classifies network flows into 34 attack categories (33 attacks + Benign) from the CIC-IoT-2023 taxonomy. Uses BatchNorm and dropout regularisation.

- **PQC Specialist Agent:** Identifies post-quantum cryptographic algorithms in network traffic, covering Kyber, NTRU, McEliece, Dilithium, Falcon, SPHINCS+, and classical algorithms (RSA, ECDSA, X25519).

- **Anomaly Detector Agent:** Autoencoder-based anomaly detection via reconstruction error. The bottleneck (16-dim) captures compressed representations, and per-sample MSE provides anomaly scores.

- **Coordinator Agent:** Learns attention weights over the three agent feature vectors to produce a weighted fusion for final classification. Encourages agent specialisation through diversity regularisation.

## Dataset

This model is designed for the PQC-IDS dataset:

- **Source:** [https://doi.org/10.34740/kaggle/dsv/15424420](https://doi.org/10.34740/kaggle/dsv/15424420)
- **Features:** 83 CIC-IoT-2023 flow features (normalised)
- **Attack classes:** 34 (33 attack types + Benign)
- **PQC classes:** 14 (10 PQC + 3 classical + Unknown)

## Installation

```bash
pip install -e .
```

Or install dependencies directly:

```bash
pip install -r requirements.txt
```

## Usage

### Training

```bash
# With config file
python scripts/train.py --config configs/default.yaml --csv data/pqc_ids_dataset.csv

# With CLI arguments
python scripts/train.py --csv data/dataset.csv --epochs 50 --batch-size 256 --lr 0.001
```

### Evaluation

```bash
# Basic evaluation
python scripts/evaluate.py --checkpoint checkpoints/best_model.pt --csv data/test.csv

# With plots
python scripts/evaluate.py --checkpoint checkpoints/best_model.pt --csv data/test.csv --plot
```

### Programmatic Usage

```python
import torch
from models import MultiAgentPQCIDS, ATTACK_CLASSES, PQC_CLASSES

model = MultiAgentPQCIDS(dropout=0.1)
model.eval()

x = torch.randn(1, 83)  # Single sample with 83 features
outputs = model(x)

# Attack classification
attack_idx = outputs["attack_logits"].argmax(dim=-1).item()
print(f"Predicted attack: {ATTACK_CLASSES[attack_idx]}")

# PQC identification
pqc_idx = outputs["pqc_logits"].argmax(dim=-1).item()
print(f"Predicted PQC algorithm: {PQC_CLASSES[pqc_idx]}")

# Agent weights (how much each agent contributed)
weights = outputs["agent_weights"][0]
print(f"Agent weights: Traffic={weights[0]:.3f}, PQC={weights[1]:.3f}, Anomaly={weights[2]:.3f}")

# Anomaly score
print(f"Anomaly score: {outputs['anomaly_scores'].item():.4f}")
```

## Multi-Task Training Loss

The training objective combines four losses:

1. **Attack Classification Loss** (weight=1.0): Cross-entropy on 34 attack classes
2. **PQC Identification Loss** (weight=0.5): Cross-entropy on 14 PQC algorithm classes
3. **Reconstruction Loss** (weight=0.3): MSE autoencoder reconstruction error
4. **Diversity Regularisation** (weight=0.1): Entropy maximisation on coordinator attention weights

## PQC Algorithm Classes

| Category | Algorithms |
|----------|-----------|
| Key Encapsulation | Kyber-512, Kyber-768, Kyber-1024 |
| Code-based | NTRU-HPS-2048, McEliece-348864 |
| Digital Signatures | Dilithium-2/3/5, Falcon-512, SPHINCS+-128f |
| Classical (baseline) | RSA, ECDSA, X25519 |
| Unknown | Unknown-PQC |

## Project Structure

```
multi-agent-pqc-models/
  models/
    __init__.py              # Package re-exports
    multi_agent_ids.py       # Core model definitions
  scripts/
    train.py                 # Training script
    evaluate.py              # Evaluation script
  configs/
    default.yaml             # Default hyperparameters
  requirements.txt
  setup.py
  README.md
  LICENSE                    # MIT
  CITATION.cff
```

## Citation

```bibtex
@software{anaedevha2026multiagentpqcids,
  author = {Anaedevha, Roger Nick},
  title = {Multi-Agent PQC-IDS: Post-Quantum Cryptography-Aware Intrusion Detection System},
  year = {2026},
  url = {https://github.com/rogerpanel/Multi-Agent-PQC-models},
}
```

## License

MIT License. See [LICENSE](LICENSE) for details.

## Author

Roger Nick Anaedevha
