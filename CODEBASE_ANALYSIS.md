# RobustIDPS.ai — Codebase Analysis

> Auto-generated analysis of the RobustIDPS.ai repository structure, architecture, and capabilities.

---

## 1. Project Overview

**RobustIDPS.ai** is a production-grade, research-driven web application implementing 7 novel machine learning methods for adversarially robust network intrusion detection. It is a PhD dissertation implementation by Roger Nick Anaedevha at MEPhI (National Research Nuclear University), Moscow.

- **Live deployment**: https://robustidps.ai
- **DOI**: 10.5281/zenodo.19129511
- **Detection**: 34 attack classes across 6 benchmark network datasets + raw PCAP analysis
- **Primary model**: SurrogateIDS — 7-branch ensemble (83 features → 34 classes, 96.5% accuracy)

---

## 2. Technology Stack

| Layer | Technology |
|-------|-----------|
| DNS + CDN + SSL | Cloudflare (Full SSL mode) |
| Reverse Proxy | nginx (HTTPS, gzip, WebSocket) |
| Frontend | React 18, TypeScript 5.3, Tailwind CSS, Recharts, Vite 4.5 |
| Backend | FastAPI 0.109, Python 3.11, PyTorch 2.2, pandas, scikit-learn |
| Streaming | WebSocket (`/ws/stream`, `/ws/live_capture`) |
| Database | PostgreSQL 16 (prod) / SQLite (dev) |
| Cache | Redis 7 (with in-memory fallback) |
| Monitoring | Prometheus + Grafana + node-exporter |
| Infrastructure | Hetzner VPS (CPX32), Docker Compose, Ubuntu |

---

## 3. Repository Structure

```
robustidps.ai/
├── frontend/                  # React 18 + TypeScript SPA
│   ├── src/
│   │   ├── App.tsx            # Router & navigation (dual sidebars)
│   │   ├── main.tsx           # Entry point, context providers, error boundary
│   │   ├── pages/             # ~25 lazy-loaded route components
│   │   ├── components/        # Reusable UI (charts, forms, tables)
│   │   ├── hooks/             # useAnalysis, useAblation, usePageState, etc.
│   │   └── utils/             # api.ts (1489 LOC), auth.ts, sessionReset.ts
│   ├── vite.config.ts         # Build optimization, chunk splitting
│   └── tailwind.config.js     # Dark theme, custom palette
├── backend/                   # FastAPI + PyTorch engine
│   ├── app/
│   │   ├── main.py            # FastAPI app, middleware, startup events
│   │   ├── routes/            # 13 routers, 80+ endpoints
│   │   ├── models/            # SQLAlchemy ORM (8 tables)
│   │   ├── ml/                # PyTorch models, feature extraction, inference
│   │   ├── services/          # Copilot, threat response, federated learning
│   │   └── auth.py            # JWT, RBAC, brute-force protection
│   ├── weights/               # Pre-trained model checkpoints
│   └── requirements.txt       # Python dependencies
├── sdk/                       # Python SDK & CLI client
│   └── robustidps/            # client.py, cli.py
├── docs/                      # LaTeX documentation, IP analysis
├── deploy/                    # nginx, SSL, server provisioning, deploy script
│   └── monitoring/            # Prometheus & Grafana configs
├── sample_data/               # Demo CSVs, data generators
├── docker-compose.yml         # Development environment
├── docker-compose.prod.yml    # Production (+ optional GPU & monitoring)
├── .env.example               # Configuration template
└── README.md                  # Full documentation
```

---

## 4. Frontend Architecture

### 4.1 Routing (React Router v6, lazy-loaded)

**AI Command Center:**
- `/` — Dashboard (attack overview & threat analysis)
- `/upload` — Upload & Analyse
- `/analytics` — Advanced multi-tab analytics
- `/live` — Live Monitor (WebSocket streaming)

**AI Data & Models:**
- `/datasets` — Dataset management
- `/models` — Model management & benchmarking
- `/ablation` — Ablation Studio

**AI Novel Methods:**
- `/continual` — Continual Learning (EWC-based)
- `/rl-agent` — RL Response Agent
- `/adversarial` — Adversarial Robustness Evaluation
- `/xai` — Explainability Studio (LIME, SHAP-like)

**AI Active Defence:**
- `/redteam` — Red Team Arena
- `/threat-response` — Threat Response automation
- `/copilot` — SOC Copilot (AI assistant)
- `/federated` — Federated Learning Simulator

**AI Security & Governance:**
- `/pq-crypto` — Post-Quantum Cryptography
- `/zero-trust` — Zero-Trust Governance
- `/supply-chain` — Model Supply Chain
- `/research` — Research Hub

**System:**
- `/admin` — Admin Dashboard (admin-only)
- `/architecture`, `/api-docs`, `/about`, `/benchmarks`

### 4.2 State Management

Context API + custom hooks (no Redux):
- **`AnalysisProvider`** — Upload results, caching in localStorage
- **`AblationProvider`** — Ablation study state
- **`MultiAblationProvider`** — Cross-dataset ablation comparison
- **`NoticeBoardProvider`** — Task notifications queue
- **`usePageState`** — Module-level Map for state persistence across navigation

### 4.3 API Integration (`src/utils/api.ts`)

- JWT Bearer tokens via `authFetch()` wrapper (auto-logout on 401)
- Async job polling with `pollJobResult()` (3s intervals, max 200 polls)
- WebSocket streaming via `connectStream()`
- Transient error tolerance (524, 502, 503) with retry backoff

### 4.4 Build Optimizations

- Lazy loading of all pages via `React.lazy()` + Suspense
- Manual chunk splitting: `vendor-react` (long-term cache), `vendor-recharts`, `vendor-export`
- Gzip + Brotli pre-compression at build time
- Source maps disabled in production
- Critical inline CSS in `index.html` (prevents FOIT)

---

## 5. Backend Architecture

### 5.1 Framework & Entry Point

FastAPI 0.109 with Uvicorn 0.27, single worker (enforced for in-memory job store).

### 5.2 API Endpoints (80+ across 13 routers)

| Category | Key Endpoints |
|----------|--------------|
| Core Prediction | `/api/predict`, `/api/upload`, `/api/results/{job_id}`, `/api/export/{job_id}` |
| Models | `/api/models`, `/api/models/{id}/activate`, `/api/model_info` |
| Ablation | `/api/ablation`, `/api/ablation/multi` |
| Red Team | `/api/redteam/run`, `/api/redteam/multi-run` |
| Explainability | `/api/xai/run`, `/api/xai/compare` |
| Federated Learning | `/api/federated/run`, `/api/federated/run-multi` |
| Continual Learning | `/api/continual/*`, `/api/clrl/*` |
| WebSockets | `/ws/stream`, `/ws/live_capture` |
| SOC Copilot | `/api/copilot` (multi-LLM chat agent) |
| Security | `/api/firewall`, `/api/pq`, `/api/zerotrust`, `/api/supply-chain` |
| Admin | `/api/auth/*`, `/api/tasks`, `/api/experiments`, `/api/reports` |
| Demo | `/api/demo/predict/{dataset_key}` (pre-computed results) |
| Health | `/api/health` |

### 5.3 Database Schema (SQLAlchemy ORM, 8 tables)

| Table | Purpose |
|-------|---------|
| `users` | Email, password_hash, role (admin/analyst/viewer), is_active |
| `jobs` | 8-char ID, user, filename, format, n_flows, n_threats, model_used |
| `audit_logs` | User actions, resource, IP address, user agent |
| `firewall_rules` | Generated iptables/pf rules from detections |
| `incidents` | Playbook info, severity, source/target IPs, effectiveness score |
| `incident_notes` | Notes on incidents |
| `background_tasks` | Async task tracking (type, status, progress, params/result JSON) |
| `experiments` | Experiment tracking (tags, dataset, model, params/results/metrics JSON) |

### 5.4 Authentication & Authorization

- JWT Bearer tokens (HS256, 8-hour expiry)
- 3 roles: admin, analyst, viewer (RBAC)
- Bcrypt password hashing with strength validation
- Brute-force protection (5 attempts → 5-minute lockout)
- Audit logging on all auth events
- Default admin auto-created on startup

### 5.5 ML Models (11 registered)

| Model | Type |
|-------|------|
| SurrogateIDS | 7-branch MLP ensemble (primary) |
| Neural ODE | Temporal Adaptive Batch-Norm ODEs (TA-BN-ODE) |
| Optimal Transport | Privacy-Preserving Feature OT (PPFOT-IDS) |
| FedGTD | Federated Graph Temporal Dynamics |
| SDE-TGNN | Stochastic Differential Equation Temporal GNN |
| CyberSec LLM | Large language model for security |
| CLRL Unified | Continual Learning + RL combined |
| CPO Policy / Value / Cost Value Net | Constrained policy optimization |
| Unified FIM | Fisher Information Matrix model |

All models share: 83-feature input → 34-class output.

### 5.6 Key Services

- **MC Dropout Uncertainty**: 20 forward passes (configurable), epistemic/aleatoric decomposition, ECE calibration
- **Feature Extraction**: 83 features from CSV (CIC-IoT-2023, CSE-CIC-IDS2018, UNSW-NB15) or PCAP (via nfstream)
- **Continual Learning**: EWC regularization, Fisher Information Matrix, experience replay (5000 samples), checkpointing
- **Adversarial Robustness**: FGSM, PGD, DeepFool, Gaussian noise, feature masking
- **Explainability**: Gradient saliency, LRP, attention maps
- **Federated Learning**: FedAvg, FedProx, Byzantine-resilient FedGTD, optional differential privacy
- **SOC Copilot**: Multi-LLM chat (Anthropic, OpenAI, Google Gemini, DeepSeek, local fallback) with tool calls
- **Threat Response**: 6 built-in playbooks (DDoS, brute force, recon, malware, web attack, spoofing)
- **Caching**: Redis with in-memory TTL fallback (`ridps:` key prefix)

---

## 6. SDK & CLI

Python SDK (`sdk/robustidps/`) provides programmatic access:

```bash
pip install robustidps
robustidps login --url https://robustidps.ai --email user@example.com
robustidps predict traffic.csv --model surrogate --uncertainty
robustidps redteam traffic.csv --attacks fgsm,pgd --epsilon 0.1
robustidps ablation traffic.csv --mode pairwise
robustidps experiments list --tag baseline
robustidps report latex exp1_id exp2_id --output table.tex
```

Key capabilities: prediction, ablation (single/pairwise/incremental), red team, XAI, federated learning, experiment tracking, LaTeX/CSV report generation, firewall rule generation, task queue management.

Dependencies: httpx, click, rich, tabulate.

---

## 7. Deployment

### Development
```bash
docker compose up          # postgres, redis, backend (8000), frontend (3000)
```

### Production
```bash
docker compose -f docker-compose.prod.yml up -d
```

**Production services**: postgres, redis, backend, frontend (nginx on 80/443), optional GPU backend, optional monitoring stack (Prometheus, Grafana, node-exporter, redis-exporter).

**Infrastructure**: Hetzner CPX32 (€13.49/mo, 4 vCPU, 8GB RAM), Cloudflare DNS/CDN/SSL, 4GB swap for PyTorch.

### Performance Metrics
- Detection latency: ~1.2ms single-pass, ~24ms with MC Dropout (20 passes)
- False positive rate: ~3.1% (ECE = 0.0312)
- Throughput: ~833 flows/sec (CPU) → ~41K flows/sec (GPU estimated)

---

## 8. Sample Data

- **CSV format**: 83 normalized features + label (34 classes) + optional src_ip/dst_ip
- **Generators**: `generate_sample.py` (CIC-IoT), `generate_pqc_dataset.py` (post-quantum TLS), `generate_adversarial_pcap.py` (adversarial benchmark PCAPs)
- **Attack classes**: Benign, DDoS variants, Reconnaissance, Brute Force, Spoofing, Web Attacks, Malware, Mirai variants, DNS Spoofing (34 total)

---

## 9. Environment Configuration

Key variables from `.env.example`:

| Variable | Purpose | Default |
|----------|---------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://...@postgres:5432/robustidps` |
| `SECRET_KEY` | JWT signing key | (must change) |
| `DEVICE` | Inference device | `cpu` (cpu/cuda/mps) |
| `MC_PASSES` | Uncertainty quantification passes | `20` |
| `MAX_ROWS` | Large dataset sampling limit | `10000` |
| `CORS_ORIGINS` | Allowed origins | `https://robustidps.ai` |
| `RATE_LIMIT_DEFAULT` | API rate limit | `100/minute` |
| `RATE_LIMIT_HEAVY` | Heavy endpoint rate limit | `10/minute` |
| `ANTHROPIC_API_KEY` | SOC Copilot (optional) | — |
| `OPENAI_API_KEY` | SOC Copilot (optional) | — |

---

## 10. Competitive Positioning

**vs. Snort/Suricata/Zeek:**
- **Advantages**: Uncertainty quantification (MC Dropout), zero-day generalization (6×6 cross-dataset transfer), adversarial robustness testing, 34-class granularity, built-in research validation
- **Challenges**: Throughput (833 flows/sec CPU vs. 10-40 Gbps for Suricata), newer platform
- **Recommended hybrid**: Suricata (Tier 1 — wire speed) → RobustIDPS.ai (Tier 2 — ML analysis) → SOC analyst (Tier 3)

**IP Breakdown**: ~75% proprietary (novel ML architectures, ablation framework, MC Dropout uncertainty, active prevention engine, drift detection, red team arena, XAI studio, federated simulator, PQ crypto, zero-trust governance) / ~25% open-source infrastructure (PyTorch, FastAPI, React, nfstream, PostgreSQL, Redis).
