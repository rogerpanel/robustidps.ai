# RobustIDPS.ai — GPU Scaling & Desktop Distribution Analysis

## Date: 2026-03-17
## Scope: Comprehensive codebase analysis for (1) Hetzner GPU scaling to 2TB+/day, (2) Desktop application distribution

---

## PART 1: Improvements Required for 2TB+ Daily Processing on Hetzner GPU

### 1. Data Ingestion Pipeline — Critical Bottlenecks

**Current Limitations:**
- `backend/ingestion.py:192` — classifies records one-at-a-time (batch size 1)
- `backend/config.py:38` — `MAX_ROWS = 10,000` hard cap
- `backend/config.py:32` — `MAX_UPLOAD_SIZE_MB = 100`
- `backend/features.py` — entire CSV loaded in-memory via pandas
- WebSocket ingestion is single-threaded with no backpressure

**2TB/day = ~23 MB/sec sustained = ~1.4M flows/sec (NetFlow)**

**Required Changes:**

| Component | Current | Required |
|-----------|---------|----------|
| MAX_UPLOAD_SIZE_MB | 100 MB | 10,000+ MB + streaming upload |
| MAX_ROWS | 10,000 | Unlimited (streaming) |
| Batch inference | Size 1 | Size 1024–4096 |
| CSV processing | In-memory pandas | Chunked Dask/Polars |
| PCAP processing | NFStream single-threaded | Multi-process workers |
| File upload | Single file, sync | Multipart chunked, resumable |

---

### 2. GPU Acceleration — Not Yet Optimized

**Current:** `DEVICE=cpu` in docker-compose; no GPU-specific code paths.

**Required:**
- Docker NVIDIA Container Toolkit + GPU resource reservations
- CUDA base image in backend Dockerfile
- `torch.cuda.amp` mixed-precision (FP16) inference
- `torch.compile()` / TorchScript for all 7 models
- CUDA streams for parallel MC Dropout passes
- Dynamic batching (accumulate flows → batch inference)
- Multi-GPU: DataParallel/DistributedDataParallel
- Model warmup + GPU memory pre-allocation at startup

---

### 3. Task Queue — Replace In-Process Threading

**Current:** `backend/task_queue.py` uses `threading.Thread` — no fault tolerance, no distribution.

**Required:**
- Celery + Redis (or Dramatiq + Redis)
- Priority queues (real-time > batch > reports)
- Worker autoscaling (per GPU)
- Persistent progress tracking
- Dead letter queues

---

### 4. Database — Not Optimized for High Volume

**Required:**
- TimescaleDB extension for time-series flow data
- Table partitioning by date (Job, AuditLog, Incident)
- PgBouncer connection pooling
- ClickHouse or Kafka+ClickHouse for flow storage at 2TB/day
- Read replicas for dashboard queries
- Data retention policies

---

### 5. Streaming Architecture — Missing

**Required:**
- Apache Kafka or Redis Streams as ingestion buffer
- Producer → Kafka → GPU Consumer Workers → Results → Dashboard
- Decouples ingestion rate from inference rate
- Enables replay, fault tolerance, horizontal scaling

---

### 6. Horizontal Scaling

**Required:**
- Kubernetes or Docker Swarm
- NGINX/Traefik reverse proxy + load balancing
- GPU node pools on Hetzner
- Separate services: API, Inference Workers, WebSocket, Background Tasks

---

### 7. PCAP Processing at Scale

**Required:**
- Parallel PCAP splitting + multi-process NFStream
- Streaming processing (process during upload)
- PF_RING or DPDK for wire-speed capture
- Zeek cluster mode

---

### 8. Caching Layer

**Required:**
- Redis for sessions, prediction dedup, rate limiting, dashboard data
- Model/scaler pre-loading at startup
- Frontend CDN

---

### 9. Monitoring & Observability

**Required:**
- Prometheus + Grafana
- NVIDIA DCGM Exporter for GPU metrics
- Custom metrics: inference latency, queue depth, throughput/sec, GPU utilization
- Alertmanager
- Centralized logging (Loki/ELK)

---

### 10. Hetzner Server Recommendations

```
Minimum for 2TB/day:
- GEX130 (NVIDIA A100 80GB) or 2× RTX 4090
- NVMe: 2× 1.92TB RAID 1
- 10Gbps networking
- 128GB+ RAM

Architecture:
- 1× GPU server (inference workers)
- 1× CPU server (API, TimescaleDB, Redis, Kafka)
- Hetzner Cloud Load Balancer
- Hetzner Object Storage for PCAP/CSV archival
```

---

## PART 2: Desktop Application Distribution

### Recommended: Tauri (Rust) + Embedded Python Backend

```
Architecture:
  Tauri Window → Embedded React Frontend → Sidecar FastAPI Backend → SQLite
```

### Phase 1: Backend Packaging
- PyInstaller freeze of FastAPI + PyTorch (CPU-only default)
- SQLite mode (already supported in config.py)
- Pre-compiled models via torch.jit.script()

### Phase 2: Tauri Shell
- Sidecar process management (launch/stop/health-check FastAPI)
- System tray for background monitoring
- Native desktop notifications for threats
- File associations (.pcap, .csv)
- Auto-updater (built-in Tauri)

### Phase 3: Desktop-Specific Adaptations
- Direct libpcap/npcap integration (no upload needed)
- Remove CORS/rate-limiting (local only)
- Optional single-user mode (skip JWT auth)
- Direct filesystem access (no upload size limit)
- GPU detection + optional CUDA download

### Phase 4: Distribution
- Windows: .msi installer + code signing
- macOS: .dmg + Apple notarization ($99/yr)
- Linux: .AppImage + .deb + .rpm

### Phase 5: Licensing
- Hardware-bound or time-limited license keys
- Feature tiers: Community vs Enterprise
- Optional telemetry (opt-in)

### Estimated App Size
- Tauri runtime: ~5 MB
- React frontend: ~3 MB
- Python sidecar (CPU): ~400 MB
- Model weights: ~50–100 MB
- **Total: ~500–600 MB** (CPU), **~2 GB** (with CUDA)

---

## Current Strengths (Solid Foundation)

1. 7 research-grade ML models with unified interface
2. 11 XAI explainability methods
3. Federated learning with Byzantine resilience
4. Adversarial robustness testing (5 attack methods)
5. Post-quantum cryptography readiness
6. Real-time threat response playbooks
7. Active prevention engine
8. Multi-dataset auto-detection
9. MC Dropout uncertainty quantification
10. Clean modular architecture
