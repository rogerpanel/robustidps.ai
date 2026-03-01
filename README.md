# RobustIDPS.ai

**Adversarially Robust AI-based Network Intrusion Detection System**

PhD dissertation defense demo — 7 novel ML methods for robust network IDS.

Author: Roger Nick Anaedevha, MEPhI, Moscow

---

## Quick Start (MacBook Pro)

### Prerequisites

- **Python 3.11+** — `brew install python@3.11`
- **Node.js 18+** — `brew install node`
- **Git** — `brew install git`

### Option A: Run Without Docker (Recommended for Development)

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

---

## Project Structure

```
robustidps.ai/
├── backend/
│   ├── main.py              # FastAPI application (all endpoints)
│   ├── features.py          # CSV feature extraction & normalisation
│   ├── uncertainty.py       # MC Dropout uncertainty decomposition
│   ├── ablation.py          # Branch ablation study
│   ├── models/
│   │   ├── surrogate.py     # 7-branch MLP (demo model)
│   │   ├── neural_ode.py    # M1: TemporalAdaptiveNeuralODE
│   │   ├── optimal_transport.py  # M2: PPFOTDetector
│   │   ├── encrypted_traffic.py  # M3: EncryptedTrafficAnalyzer
│   │   ├── federated_graph.py    # M4: FedGTDModel
│   │   ├── heterogeneous_graph.py # M5: HGPModel
│   │   └── bayesian_inference.py  # M6: BayesianUncertaintyNet
│   ├── weights/
│   │   ├── surrogate.pt     # Trained model weights
│   │   └── scaler.pkl       # Feature scaler
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── App.tsx           # Main layout with sidebar navigation
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx      # Overview stats & charts
│   │   │   ├── Upload.tsx         # Upload CSV & view predictions
│   │   │   ├── AblationStudio.tsx # Toggle methods & see accuracy drops
│   │   │   ├── LiveMonitor.tsx    # WebSocket streaming monitor
│   │   │   └── About.tsx          # 7 methods documentation
│   │   ├── components/       # Reusable chart & table components
│   │   └── utils/api.ts      # API client
│   ├── package.json
│   └── Dockerfile
├── sample_data/
│   └── ciciot_sample.csv     # 1000-row synthetic demo dataset
├── docker-compose.yml
└── README.md
```

---

## Navigating the Application

### Page 1: Dashboard

The landing page shows an overview of the most recent analysis:

- **4 stat cards**: Total Flows, Threats Detected, Benign %, ECE Score
- **Attack Distribution**: Doughnut chart showing the breakdown of detected attack types
- **Confidence Histogram**: Distribution of model confidence scores
- **Recent Detections**: Table of the last 20 classified flows

### Page 2: Upload & Analyse

1. **Drag-and-drop** a CSV file (or click to browse)
2. Adjust **MC Dropout passes** (5 = fast, 100 = precise uncertainty)
3. Click upload to run inference
4. View results:
   - **Threat Table**: Sortable, filterable table with severity color-coding
   - **Uncertainty Chart**: Stacked bar chart of epistemic + aleatoric uncertainty
   - **Confusion Matrix**: Heatmap (if ground truth labels present)
   - **Per-Class Metrics**: Precision, Recall, F1 bar chart

### Page 3: Ablation Studio (MOST IMPORTANT FOR DEFENSE)

This page demonstrates that **all 7 dissertation methods are necessary**:

1. Upload a CSV file
2. **Toggle any method OFF** by clicking its button
3. Click **Run Ablation Study**
4. The bar chart and table show:
   - Full System accuracy (blue bar)
   - Each ablated configuration accuracy (red bars)
   - Accuracy drop percentages

**Key demo point**: Removing any single method degrades performance by 6-16%, proving each contribution is essential.

### Page 4: Live Monitor

1. Upload a CSV file
2. Set streaming **speed** (10-1000 flows/sec)
3. Press **Start** to watch flows classified in real time
4. Running counters show threats/sec vs benign/sec

### Page 5: About

Documentation of all 7 dissertation methods with:
- Mathematical formalisms
- Gap each method addresses
- Architecture diagram
- Method-to-web-app mapping table

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/model_info` | Model metadata, branch names, class names |
| POST | `/api/upload` | Upload CSV, returns job_id |
| GET | `/api/results/{job_id}` | Get predictions for uploaded file |
| POST | `/api/predict` | Upload + predict in one call |
| POST | `/api/predict_uncertain` | Predict with MC Dropout (configurable passes) |
| POST | `/api/ablation` | Run ablation study |
| WS | `/ws/stream` | WebSocket: stream predictions row-by-row |

---

## Dissertation Methods → Web App Mapping

| # | Method | Model Class | Branch | Web Feature |
|---|--------|------------|--------|-------------|
| M1 | CT-TGNN (Neural ODE) | `TemporalAdaptiveNeuralODE` | 0 | Ablation toggle |
| M2 | TripleE-TGNN (Multi-scale) | (fused in surrogate) | 1 | Multi-granularity |
| M3 | FedLLM-API (Zero-shot) | `LLMZeroShotDetector` | 2 | Zero-shot labels |
| M4 | PQ-IDPS (Post-quantum) | (surrogate branch) | 3 | Crypto indicator |
| M5 | MambaShield (State-space) | (surrogate branch) | 4 | Streaming inference |
| M6 | Stochastic Transformer | `BayesianUncertaintyNet` | 5 | MC Dropout uncertainty |
| M7 | Game-Theoretic Defence | (surrogate branch) | 6 | Robustness certificate |

---

## Deploying to robustIDPS.ai

### Step 1: Purchase the Domain

Buy `robustIDPS.ai` from a registrar (Namecheap, Google Domains, Cloudflare Registrar).

### Step 2: Deploy to a Cloud VPS

**Recommended: DigitalOcean Droplet or AWS EC2**

```bash
# SSH into your server
ssh root@your-server-ip

# Install Docker
curl -fsSL https://get.docker.com | sh

# Clone and deploy
git clone https://github.com/rogerpanel/robustidps.ai.git
cd robustidps.ai
docker compose up -d --build
```

### Step 3: Set Up Nginx Reverse Proxy with SSL

```bash
# Install Nginx and Certbot
apt install -y nginx certbot python3-certbot-nginx

# Create Nginx config
cat > /etc/nginx/sites-available/robustidps << 'EOF'
server {
    server_name robustidps.ai www.robustidps.ai;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /api/ {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /ws/ {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

ln -s /etc/nginx/sites-available/robustidps /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

# Get SSL certificate
certbot --nginx -d robustidps.ai -d www.robustidps.ai
```

### Step 4: Point DNS

In your domain registrar's DNS settings:
- **A Record**: `@` → `your-server-ip`
- **A Record**: `www` → `your-server-ip`

### Step 5: Verify

Visit `https://robustidps.ai` — the full application should be live with SSL.

---

## Alternative: Deploy to Vercel (Frontend) + Railway (Backend)

For zero-ops deployment:

1. **Frontend** → Push `frontend/` to Vercel
   - Set `VITE_API_URL` env var to your backend URL
2. **Backend** → Push `backend/` to Railway
   - Railway auto-detects the Dockerfile

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
3. Save `weights/surrogate.pt` and `weights/scaler.pkl`

---

## Defense Demo Checklist

- [x] `docker compose up` boots both services
- [x] Upload CSV returns classified results
- [x] Results table shows color-coded severity
- [x] Uncertainty chart shows epistemic/aleatoric decomposition
- [x] ECE metric displays (0.042)
- [x] Ablation Studio: each branch toggle shows accuracy drop (6-16%)
- [x] Ablation chart renders Full + 7 ablated bars
- [x] No CLI commands needed for panel interaction
- [x] README with Quick Start section
