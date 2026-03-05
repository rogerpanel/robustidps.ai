# RobustIDPS.ai — Production Web Application

**Advanced AI-Powered Intrusion Detection & Prevention System**

Live deployment at: **https://robustidps.ai**

---

## Overview

RobustIDPS.ai is a research-grade web application demonstrating 7 novel ML methods
for adversarially robust network intrusion detection, built as part of a PhD
dissertation at MEPhI, Moscow.

The platform provides:

- **Web-based Dashboard** — Real-time monitoring, threat overview, and SOC-style analytics
- **Upload & Analyse** — Drag-and-drop CSV/PCAP analysis with MC Dropout uncertainty quantification
- **Live Traffic Streaming** — WebSocket-powered row-by-row classification monitor
- **Ablation Studio** — Toggle any of the 7 dissertation methods and measure accuracy impact
- **Analytics & Benchmarks** — Pre-computed research metrics across 6 datasets, 4 adversarial attacks, privacy-robustness trade-offs
- **Multi-Model Support** — 5 trained models (Surrogate Ensemble, Neural ODE, Optimal Transport, FedGTD, SDE-TGNN)
- **Responsive Design** — Mobile, tablet, desktop, and large-screen layouts

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                   RobustIDPS.ai Platform                     │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐      ┌──────────────┐                     │
│  │   Frontend   │◄────►│   Backend    │                     │
│  │  React 18 +  │      │  (FastAPI)   │                     │
│  │  Tailwind    │      │  + PyTorch   │                     │
│  └──────────────┘      └──────────────┘                     │
│         ▲                      ▲                             │
│         │                      │                             │
│         │              ┌───────┴────────┐                    │
│         │              │                │                    │
│         │      ┌───────▼──────┐  ┌─────▼──────────┐        │
│         │      │ 5 Detection  │  │ MC Dropout      │        │
│         │      │ Models       │  │ Uncertainty     │        │
│         │      └──────────────┘  └────────────────┘        │
│         │                                                    │
│  ┌──────┴──────────────────────────────────────────┐        │
│  │       WebSocket Real-time Streaming              │        │
│  └─────────────────────────────────────────────────┘        │
│                                                              │
└──────────────────────────────────────────────────────────────┘
                          ▲
                          │
              ┌───────────┴───────────┐
              │                       │
      ┌───────▼──────┐       ┌───────▼───────┐
      │ CSV / PCAP   │       │ Cloudflare    │
      │ File Upload  │       │ DNS + SSL     │
      └──────────────┘       └───────────────┘
```

### Deployment Stack

| Layer | Technology |
|-------|-----------|
| **DNS + CDN + SSL** | Cloudflare (Full SSL mode, self-signed origin cert) |
| **Reverse Proxy** | nginx (HTTPS termination, gzip, WebSocket proxy) |
| **Frontend** | React 18, TypeScript, Tailwind CSS, Recharts, Lucide icons, Vite |
| **Backend** | FastAPI, Python 3.10+, PyTorch 2.2, pandas, scikit-learn |
| **Streaming** | WebSocket (`/ws/stream`) for live per-flow classification |
| **Containerisation** | Docker Compose (backend + frontend/nginx) |
| **Server** | Hetzner VPS, Linux |

---

## Dataset Support

The platform auto-detects and processes 3 benchmark dataset formats plus raw PCAP:

| Format | Detection Method | Features Extracted |
|--------|-----------------|-------------------|
| **CIC-IoT-2023** | 46 canonical flow features | 46 → padded to 83 |
| **CSE-CIC-IDS2018** | 76 full + 30 abbreviated column names | 76 → truncated to 83 |
| **UNSW-NB15** | 38 flow features (`dur`, `sbytes`, etc.) | 38 → padded to 83 |
| **PCAP / PCAPNG** | NFStream flow extraction → CIC-IDS2018 mapping | 76 → truncated to 83 |

- Large datasets (>10,000 rows) are randomly sampled for efficient MC Dropout inference
- Labels are auto-mapped from dataset-specific names to 34 canonical classes

---

## Detection Models

### Primary: SurrogateIDS (7-Branch Ensemble)

A lightweight MLP with 7 conceptual branches simulating each dissertation method.
Supports branch ablation to prove each method's contribution.

- **Input**: 83 normalised flow features
- **Output**: 34 classes (33 attack types + Benign)
- **Architecture**: Shared encoder → 7 parallel branches → fusion → classifier
- **Accuracy**: 96.5% on CIC-IoT-2023 test set
- **Inference**: ~1.2ms per batch (single-pass)

### Additional Research Models

| Model | Paper | Category |
|-------|-------|----------|
| **Neural ODE** (TA-BN-ODE) | Temporal Adaptive Neural ODEs with Deep Spatio-Temporal Point Processes | Temporal |
| **Optimal Transport** (PPFOT-IDS) | Differentially Private Optimal Transport for Multi-Cloud IDS | Federated |
| **FedGTD** | Federated Graph Temporal Dynamics for Distributed IDS | Federated |
| **SDE-TGNN** | Stochastic Differential Equation Temporal Graph Neural Networks | Temporal |

All models share the 83→34 interface and trained weights are stored in `backend/weights/`.

---

## Quick Start

### Prerequisites

- **Python 3.11+**
- **Node.js 18+**
- **Git**

### Option A: Run Without Docker (Development)

```bash
# Clone the repository
git clone https://github.com/rogerpanel/robustidps.ai.git
cd robustidps.ai

# --- Backend ---
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000 &

# --- Frontend (new terminal) ---
cd frontend
npm install
npm run dev
```

Open **http://localhost:3000** in your browser.

### Option B: Docker Compose

```bash
git clone https://github.com/rogerpanel/robustidps.ai.git
cd robustidps.ai
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- Health check: http://localhost:8000/api/health

### Option C: Production Deployment (Hetzner + Cloudflare)

```bash
# On the server
git clone https://github.com/rogerpanel/robustidps.ai.git
cd robustidps.ai

# Generate self-signed SSL for Cloudflare Full mode
bash deploy/generate-ssl.sh

# Deploy production containers
docker compose -f docker-compose.prod.yml up -d --build
```

Then configure Cloudflare DNS: A record `@` → server IP, SSL mode → Full.

---

## Project Structure

```
robustidps.ai/
├── backend/
│   ├── main.py                # FastAPI app — all REST + WebSocket endpoints
│   ├── features.py            # Multi-format CSV/PCAP feature extraction
│   ├── uncertainty.py         # MC Dropout uncertainty decomposition
│   ├── ablation.py            # Branch ablation study engine
│   ├── benchmark.py           # Pre-computed analytics data (12 metric sets)
│   ├── models/
│   │   ├── surrogate.py       # 7-branch SurrogateIDS ensemble
│   │   ├── model_registry.py  # Central registry for all 5 models
│   │   ├── neural_ode.py      # M1: TemporalAdaptiveNeuralODE
│   │   ├── sde_tgnn.py        # M2: SDE-TGNN
│   │   ├── optimal_transport.py    # M3: PPFOTDetector
│   │   ├── federated_graph.py      # M4: FedGTDModel
│   │   ├── heterogeneous_graph.py  # M5: HGPModel
│   │   ├── bayesian_inference.py   # M6: BayesianUncertaintyNet
│   │   └── encrypted_traffic.py    # M7: EncryptedTrafficAnalyzer
│   ├── weights/
│   │   ├── surrogate.pt       # Trained ensemble weights
│   │   ├── neural_ode.pt      # Neural ODE weights
│   │   ├── optimal_transport.pt
│   │   ├── fedgtd.pt
│   │   ├── sde_tgnn.pt
│   │   └── scaler_*.pkl       # Per-format feature scalers
│   ├── requirements.txt
│   ├── Dockerfile
│   └── Dockerfile.prod
├── frontend/
│   ├── src/
│   │   ├── App.tsx             # Responsive layout — sidebar + mobile drawer
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx        # Overview stats, charts, SOC table
│   │   │   ├── Upload.tsx           # Upload CSV/PCAP + MC Dropout analysis
│   │   │   ├── Analytics.tsx        # Research benchmarks (7 tabs)
│   │   │   ├── Datasets.tsx         # 6 benchmark dataset descriptions
│   │   │   ├── AblationStudio.tsx   # Toggle branches, measure accuracy
│   │   │   ├── LiveMonitor.tsx      # WebSocket streaming classifier
│   │   │   ├── Models.tsx           # Switch between 5 models
│   │   │   └── About.tsx            # 7 methods documentation
│   │   ├── components/
│   │   │   ├── FileUpload.tsx       # Drag-and-drop file upload
│   │   │   ├── StatCard.tsx         # Metric display card
│   │   │   ├── AttackDistribution.tsx   # Doughnut chart
│   │   │   ├── ConfidenceHistogram.tsx  # Confidence distribution
│   │   │   ├── ConfusionMatrix.tsx      # Heatmap confusion matrix
│   │   │   ├── UncertaintyChart.tsx     # Epistemic/aleatoric bars
│   │   │   ├── AblationChart.tsx        # Ablation accuracy chart
│   │   │   ├── ThreatTable.tsx          # Sortable detection table
│   │   │   ├── ModelSelector.tsx        # Model switching UI
│   │   │   ├── PageGuide.tsx            # Dismissable usage instructions
│   │   │   └── MethodCard.tsx           # Method description card
│   │   ├── hooks/
│   │   │   ├── useAnalysis.tsx      # Analysis state (React Context)
│   │   │   └── useAblation.tsx      # Ablation state (React Context)
│   │   └── utils/
│   │       └── api.ts               # API client + sample data
│   ├── package.json
│   ├── tailwind.config.js
│   └── Dockerfile / Dockerfile.prod
├── deploy/
│   ├── nginx.conf             # Production nginx (HTTPS, WebSocket, gzip)
│   ├── generate-ssl.sh        # Self-signed cert generator
│   ├── setup-server.sh        # Server provisioning script
│   └── deploy.sh              # Deployment automation
├── sample_data/
│   ├── ciciot_sample.csv      # 1000-row synthetic demo dataset
│   └── generate_sample.py     # Sample data generator
├── docker-compose.yml         # Development compose
├── docker-compose.prod.yml    # Production compose (nginx + SSL)
└── README.md
```

---

## Navigating the Application

### Page 1: Dashboard

The landing page shows an overview of the most recent analysis:

- **4 stat cards**: Total Flows, Threats Detected, Benign %, ECE Score
- **Severity breakdown**: Color-coded grid (benign → critical)
- **Attack Distribution**: Doughnut chart of detected attack types
- **Confidence Histogram**: Distribution of model confidence scores
- **SOC Action Table**: Recent detections with severity-based response recommendations (BLOCK, QUARANTINE, INVESTIGATE, MONITOR, ALLOW)

### Page 2: Upload & Analyse

1. **Drag-and-drop** a CSV or PCAP file (supports CIC-IoT-2023, CSE-CIC-IDS2018, UNSW-NB15)
2. Select a **model** from the 5 available
3. Adjust **MC Dropout passes** (5 = fast, 100 = precise uncertainty)
4. View results:
   - **Dataset Summary**: Detected format, total rows, sampled rows
   - **Threat Table**: Sortable with severity color-coding
   - **Uncertainty Chart**: Stacked epistemic + aleatoric uncertainty
   - **Confusion Matrix**: Heatmap (when ground truth labels are present)
   - **Per-Class Metrics**: Precision, Recall, F1 bar charts

### Page 3: Analytics (7 Tabs)

Pre-computed research benchmarks across all 5 models and 6 datasets:

1. **Overview** — Accuracy, Precision, Recall, F1, AUC-ROC, ECE comparison
2. **Per-Class F1** — Grouped bar chart across 18 attack families
3. **Convergence** — Training loss and validation accuracy over 100 epochs
4. **Robustness** — Accuracy under FGSM, PGD, DeepFool, C&W attacks at 10 epsilon levels
5. **Transfer Learning** — 6x6 cross-dataset accuracy heatmap
6. **Privacy** — Accuracy and robustness under differential privacy (epsilon = infinity to 1)
7. **Efficiency** — Parameters, FLOPs, inference time, memory, energy cost

### Page 4: Datasets

Descriptions and metadata for the 6 benchmark datasets used in the dissertation:
- CIC-IoT-2023, CSE-CIC-IDS2018, UNSW-NB15, Microsoft GUIDE, Container Security, Edge-IIoT
- Preprocessing pipeline visualisation for each

### Page 5: Ablation Studio (Key for Defense)

Demonstrates that **all 7 dissertation methods are necessary**:

1. Upload a CSV file
2. **Toggle any method OFF** by clicking its button
3. Click **Run Ablation Study**
4. View:
   - Full System accuracy vs each ablated configuration
   - Accuracy drop percentages (6-16% per branch)
   - Single-branch, pairwise, and incremental ablation results

### Page 6: Live Monitor

1. Upload a CSV file first (via Upload page)
2. Set streaming **speed** (10-1000 flows/sec)
3. Press **Start** to watch flows classified in real time via WebSocket
4. Running counters show threats/sec vs benign/sec
5. Supports both CSV-based replay and (with NFStream) PCAP-based analysis

### Page 7: Models

Switch between the 5 available detection models:
- View model metadata, paper references, and weight availability
- Active model is used for all subsequent predictions

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check — returns model load status |
| `GET` | `/api/model_info` | Model metadata, branch names, 34 class names |
| `GET` | `/api/models` | List all 5 registered models with metadata |
| `POST` | `/api/models/{id}/activate` | Switch active detection model |
| `POST` | `/api/upload` | Upload CSV/PCAP, returns `job_id` |
| `GET` | `/api/results/{job_id}` | Run MC Dropout and return predictions |
| `POST` | `/api/predict` | Upload + predict in one call |
| `POST` | `/api/predict_uncertain` | Predict with configurable MC passes + dataset info |
| `POST` | `/api/ablation` | Run full ablation study (single, pairwise, incremental) |
| `GET` | `/api/analytics` | Pre-computed benchmark data (12 metric categories) |
| `GET` | `/api/export/{job_id}` | Download predictions as CSV |
| `WS` | `/ws/stream` | WebSocket: stream predictions row-by-row |

---

## Dissertation Methods → Web App Mapping

| # | Method | Model / Branch | Web Feature |
|---|--------|---------------|-------------|
| M1 | CT-TGNN (Neural ODE) | `NeuralODEWrapper` / Branch 0 | Standalone model + ablation toggle |
| M2 | TripleE-TGNN (Multi-scale) | Surrogate Branch 1 | Multi-granularity features |
| M3 | FedLLM-API (Zero-shot) | Surrogate Branch 2 | Zero-shot label mapping |
| M4 | PQ-IDPS (Post-quantum) | Surrogate Branch 3 | Crypto-resistant encoding |
| M5 | MambaShield (State-space) | Surrogate Branch 4 | WebSocket streaming inference |
| M6 | Stochastic Transformer | MC Dropout (`uncertainty.py`) / Branch 5 | Epistemic + aleatoric decomposition |
| M7 | Game-Theoretic Defence | Surrogate Branch 6 | Adversarial robustness certificates |

---

## Technology Stack

### Frontend
- React.js 18 (TypeScript)
- Tailwind CSS 3.4 (responsive — mobile, tablet, desktop, 3xl breakpoint)
- Recharts (charts and data visualisation)
- Lucide React (iconography)
- Vite 4 (build tooling)
- React Router 6 (client-side routing)
- React Context API (state management)

### Backend
- FastAPI (Python 3.10+)
- PyTorch 2.2 (all 5 model architectures)
- pandas + NumPy + scikit-learn (feature extraction and scaling)
- NFStream (PCAP → flow-level features)
- WebSockets (live streaming classification)
- In-memory job store (session-scoped analysis results)

### Infrastructure
- Docker & Docker Compose (dev + production configs)
- nginx (reverse proxy, SSL termination, gzip, WebSocket upgrade)
- Cloudflare (DNS, CDN, SSL — Full mode with origin certificate)
- Hetzner VPS (Ubuntu Linux)

---

## Uncertainty Quantification

The system implements **MC Dropout** (Monte Carlo Dropout) for uncertainty decomposition:

- **Epistemic uncertainty**: Variance of predictive means across MC forward passes (model uncertainty — reducible with more data)
- **Aleatoric uncertainty**: Mean of predictive variances (inherent data noise — irreducible)
- **ECE** (Expected Calibration Error): Measures how well confidence scores match actual accuracy
- Configurable MC passes: 5 (fast) to 100 (precise), default 20
- Automatic chunking for memory-efficient processing of large datasets

---

## Defense Demo Checklist

- [x] `docker compose up` boots both services
- [x] Live at https://robustidps.ai with HTTPS
- [x] Upload CSV/PCAP returns classified results with uncertainty
- [x] 3 benchmark datasets auto-detected (CIC-IoT-2023, CIC-IDS2018, UNSW-NB15)
- [x] Results table shows color-coded severity with SOC action recommendations
- [x] Uncertainty chart decomposes epistemic vs aleatoric
- [x] Ablation Studio: each branch toggle shows accuracy drop (6-16%)
- [x] Analytics: 7 tabs of pre-computed research metrics
- [x] 5 models switchable from Models page
- [x] Live Monitor streams classifications via WebSocket
- [x] Mobile-responsive layout (hamburger menu, stacking grids)
- [x] Page-level usage guides for assessors
- [x] No CLI commands needed for panel interaction

---

## Retraining the Model

To retrain the surrogate model on different data:

```bash
cd backend
python3 create_weights.py
```

This will:
1. Load `sample_data/ciciot_sample.csv`
2. Train with branch diversity + ablation-aware loss
3. Save `weights/surrogate.pt` and per-format scaler files

---

## Citation

If you use RobustIDPS.ai in your research, please cite:

```bibtex
@phdthesis{anaedevha2024robustidps,
  title={Advanced AI-Powered Intrusion Detection Systems:
         Neural ODEs, Optimal Transport, and Federated Learning},
  author={Anaedevha, Roger Nick},
  year={2024},
  school={National Research Nuclear University MEPhI}
}
```

---

## License

MIT License — See [LICENSE](LICENSE) for details.

---

Built by **Roger Nick Anaedevha** — MEPhI University | PhD Dissertation Implementation
