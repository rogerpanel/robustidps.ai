import {
  Server, Cpu, Database, Globe, Shield, Layers, Zap, ArrowRight,
  Activity, Lock, Brain, Target, Network, GitBranch, ChevronRight,
  Clock, Gauge, HardDrive, Timer, ShieldCheck, Key, CheckCircle,
  Heart, Container, Wifi, WifiOff,
} from 'lucide-react'

/* ── Architecture layers ───────────────────────────────────────────────── */

const LAYERS = [
  {
    name: 'Data Ingestion',
    color: 'accent-blue',
    components: [
      { label: 'PCAP Parser', desc: 'Raw packet capture ingestion' },
      { label: 'Flow Extractor', desc: '83 bidirectional flow features' },
      { label: 'StandardScaler', desc: 'Feature normalisation pipeline' },
      { label: 'Dataset Loaders', desc: 'CIC-IoT-2023, CICIDS2018, UNSW-NB15, MS GUIDE, Edge-IIoT, Container Sec.' },
    ],
  },
  {
    name: 'Model Ensemble (SurrogateIDS)',
    color: 'accent-purple',
    components: [
      { label: 'CT-TGNN', desc: 'Neural ODE continuous-time temporal graph' },
      { label: 'TripleE-TGNN', desc: 'Multi-scale packet/flow/session graph' },
      { label: 'FedLLM-API', desc: 'Zero-shot LLM embedding classifier' },
      { label: 'PQ-IDPS', desc: 'Post-quantum secured channel' },
      { label: 'MambaShield', desc: 'Selective state-space O(n) processing' },
      { label: 'Stochastic Transformer', desc: 'MC Dropout Bayesian UQ' },
      { label: 'Game-Theoretic Defence', desc: 'Stackelberg robustness certs' },
      { label: 'SDE-TGNN', desc: 'Stochastic Differential Equation temporal graph network' },
      { label: 'CL-RL Unified', desc: 'Continual Learning + RL with unified Fisher Information (β=0.7)' },
      { label: 'CyberSecLLM', desc: 'Mamba-CrossAttention-MoE cybersecurity foundation model' },
    ],
  },
  {
    name: 'Fusion & Classification',
    color: 'accent-green',
    components: [
      { label: 'Attention Fusion', desc: 'Learned weighted combination of 7 branches' },
      { label: '34-Class Head', desc: 'DDoS, Recon, Spoofing, Mirai, BruteForce, etc.' },
      { label: 'Calibration Layer', desc: 'Temperature scaling for ECE optimisation' },
      { label: 'Uncertainty Estimator', desc: 'Epistemic + aleatoric decomposition' },
    ],
  },
  {
    name: 'Response & Defence',
    color: 'accent-amber',
    components: [
      { label: 'RL Response Agent', desc: 'PPO-based autonomous action selection' },
      { label: 'SOC Copilot', desc: 'Natural language threat analysis' },
      { label: 'Threat Response Engine', desc: 'Automated block/quarantine/monitor' },
      { label: 'SIEM Connectors', desc: 'Splunk, Elastic, QRadar integration' },
    ],
  },
  {
    name: 'LLM Security & SOC Copilot',
    color: 'accent-orange',
    components: [
      { label: 'Defense Pipeline', desc: 'Input sanitization, boundary enforcement, output filtering, context isolation' },
      { label: 'SOC Copilot', desc: 'Multi-LLM agentic AI (Claude, GPT-4o, Gemini, DeepSeek) with tool-use' },
      { label: 'Prompt Injection Detection', desc: '8 attack categories with real-time pattern matching' },
      { label: 'RAG Pipeline Hardening', desc: 'Document provenance, embedding thresholds, poisoning detection' },
      { label: 'Multi-Agent Trust', desc: 'Inter-agent verification, trust scoring, capability boundaries' },
      { label: 'Live Traffic LLM Scan', desc: 'Detect LLM API calls in network flows, extract and analyze prompts' },
    ],
  },
  {
    name: 'Research & Evaluation',
    color: 'accent-red',
    components: [
      { label: 'Ablation Studio', desc: 'Toggle methods, instant accuracy impact' },
      { label: 'Red Team Arena', desc: 'FGSM, PGD, C&W attack simulation' },
      { label: 'Explainability', desc: 'SHAP, attention maps, counterfactuals' },
      { label: 'Federated Simulator', desc: 'Multi-node training with DP guarantees' },
    ],
  },
]

/* ── Scaling roadmap ───────────────────────────────────────────────────── */

const SCALING = [
  {
    phase: 'Phase 1 (Current)',
    icon: Server,
    color: 'text-accent-green',
    bg: 'bg-accent-green/10',
    border: 'border-accent-green/20',
    spec: 'Hetzner CX31 — 4 vCPU / 16 GB RAM',
    throughput: '~500 flows/sec CPU inference',
    cost: '~\u20AC30/mo',
    details: [
      'Full 7-method ensemble via SurrogateIDS',
      'All analytics, ablation, and evaluation tabs',
      'SQLite database, single-node deployment',
      'Docker Compose with Vite + FastAPI',
      'Sufficient for demo, research review, and committee presentations',
    ],
  },
  {
    phase: 'Phase 2 (GPU Acceleration)',
    icon: Cpu,
    color: 'text-accent-amber',
    bg: 'bg-accent-amber/10',
    border: 'border-accent-amber/20',
    spec: 'Hetzner GX11 — 8 vCPU / 32 GB / NVIDIA T4 16GB',
    throughput: '~10,000 flows/sec GPU inference',
    cost: '~\u20AC180/mo',
    details: [
      'Native PyTorch GPU inference for all 7 methods',
      'Real-time live monitor with sub-100ms latency',
      'PostgreSQL for persistent multi-user state',
      'Redis task queue for async analysis jobs',
      'Continual learning training on-device',
    ],
  },
  {
    phase: 'Phase 3 (Production)',
    icon: Globe,
    color: 'text-accent-blue',
    bg: 'bg-accent-blue/10',
    border: 'border-accent-blue/20',
    spec: 'Multi-GPU cluster — A100 40GB x2+',
    throughput: '~100,000 flows/sec multi-GPU',
    cost: '~\u20AC1,200/mo',
    details: [
      'Distributed inference across GPU cluster',
      'Federated learning with real distributed nodes',
      'Kubernetes orchestration with auto-scaling',
      'Production monitoring (Prometheus + Grafana)',
      'Enterprise SIEM integration and RBAC',
    ],
  },
]

/* ── Tech stack ────────────────────────────────────────────────────────── */

const TECH_STACK = [
  { category: 'Frontend', items: ['React 18', 'TypeScript', 'Vite', 'Tailwind CSS', 'Recharts', 'React Router'] },
  { category: 'Backend', items: ['Python 3.11', 'FastAPI', 'PyTorch 2.x', 'NumPy/Pandas', 'scikit-learn', 'SQLite/PostgreSQL'] },
  { category: 'ML Models', items: ['Neural ODE (torchdiffeq)', 'Mamba (state-space)', 'Transformer (attention)', 'GNN (PyG)', 'CRYSTALS-Kyber (PQ)', 'PPO (RL agent)'] },
  { category: 'DevOps', items: ['Docker Compose', 'Nginx reverse proxy', 'Let\'s Encrypt TLS', 'GitHub Actions CI', 'Hetzner Cloud', 'systemd services'] },
]

/* ── Performance metrics ───────────────────────────────────────────────── */

const PERF_METRICS = [
  {
    label: 'End-to-End Latency',
    icon: Clock,
    color: 'text-accent-blue',
    bg: 'bg-accent-blue/10',
    values: [
      { tag: 'P50', value: '7ms' },
      { tag: 'P95', value: '12ms' },
      { tag: 'P99', value: '23ms' },
    ],
  },
  {
    label: 'Throughput',
    icon: Gauge,
    color: 'text-accent-green',
    bg: 'bg-accent-green/10',
    values: [
      { tag: 'CPU', value: '500 flows/s' },
      { tag: 'GPU', value: '10K flows/s' },
    ],
  },
  {
    label: 'Memory Footprint',
    icon: HardDrive,
    color: 'text-accent-purple',
    bg: 'bg-accent-purple/10',
    values: [
      { tag: 'Weights', value: '2.1 GB' },
      { tag: 'Runtime', value: '4.2 GB' },
    ],
  },
  {
    label: 'Model Load Time',
    icon: Timer,
    color: 'text-accent-amber',
    bg: 'bg-accent-amber/10',
    values: [
      { tag: 'Cold Start', value: '3.2s' },
    ],
  },
]

/* ── Latency breakdown ─────────────────────────────────────────────────── */

const LATENCY_STAGES = [
  { stage: 'Feature Extraction', ms: 1.2, color: 'bg-accent-blue' },
  { stage: 'Model Inference', ms: 4.1, color: 'bg-accent-purple' },
  { stage: 'Fusion & Classification', ms: 0.8, color: 'bg-accent-green' },
  { stage: 'Response Generation', ms: 0.9, color: 'bg-accent-amber' },
]

const LATENCY_TOTAL = LATENCY_STAGES.reduce((s, l) => s + l.ms, 0)

/* ── Security architecture ─────────────────────────────────────────────── */

const SECURITY_ITEMS = [
  {
    label: 'TLS 1.3 Encryption',
    desc: 'All traffic encrypted in transit with modern cipher suites and perfect forward secrecy',
    icon: Lock,
    color: 'text-accent-green',
  },
  {
    label: 'Post-Quantum Readiness',
    desc: 'CRYSTALS-Kyber key encapsulation for quantum-resistant key exchange (NIST FIPS 203)',
    icon: ShieldCheck,
    color: 'text-accent-purple',
  },
  {
    label: 'API Authentication (JWT)',
    desc: 'Stateless JSON Web Token auth with short-lived access tokens and refresh rotation',
    icon: Key,
    color: 'text-accent-blue',
  },
  {
    label: 'Rate Limiting',
    desc: 'Token-bucket rate limiter per API key with configurable burst and sustained thresholds',
    icon: Gauge,
    color: 'text-accent-amber',
  },
  {
    label: 'Input Validation & Sanitisation',
    desc: 'Pydantic schema validation on all endpoints with strict type coercion and size limits',
    icon: CheckCircle,
    color: 'text-accent-red',
  },
  {
    label: 'Admin Monitoring',
    desc: 'Active session tracking, system health dashboard, audit log export',
    icon: Shield,
    color: 'text-accent-green',
  },
  {
    label: 'DOMPurify Sanitization',
    desc: 'XSS prevention on all LLM-generated content via strict HTML allowlist',
    icon: Shield,
    color: 'text-accent-purple',
  },
]

/* ── High availability ─────────────────────────────────────────────────── */

const HA_ITEMS = [
  {
    label: 'Health Check Endpoints',
    desc: '/healthz and /readyz probes for liveness and readiness with dependency checks',
    icon: Heart,
    color: 'text-accent-green',
  },
  {
    label: 'Graceful Degradation',
    desc: 'Automatic feature reduction under load — disables non-critical analytics before core detection',
    icon: Activity,
    color: 'text-accent-amber',
  },
  {
    label: 'Model Fallback Chain',
    desc: 'If ensemble fails, fall back to best single model (MambaShield), then to rule-based heuristics',
    icon: GitBranch,
    color: 'text-accent-purple',
  },
  {
    label: 'Database Backup Strategy',
    desc: 'Automated daily snapshots with WAL archiving and point-in-time recovery (PITR) support',
    icon: Database,
    color: 'text-accent-blue',
  },
]

/* ── Deployment configurations ─────────────────────────────────────────── */

const DEPLOY_MODES = [
  {
    mode: 'Docker Compose',
    env: 'Development',
    icon: Container,
    color: 'text-accent-blue',
    bg: 'bg-accent-blue/10',
    border: 'border-accent-blue/20',
    details: [
      'Single-command startup with docker compose up',
      'Hot-reload for frontend and backend',
      'Local volume mounts for rapid iteration',
      'Pre-configured Nginx reverse proxy',
    ],
  },
  {
    mode: 'Kubernetes',
    env: 'Production',
    icon: Network,
    color: 'text-accent-green',
    bg: 'bg-accent-green/10',
    border: 'border-accent-green/20',
    details: [
      'Helm chart with configurable replicas',
      'Horizontal Pod Autoscaler on GPU utilisation',
      'Ingress with cert-manager TLS termination',
      'Prometheus ServiceMonitor integration',
    ],
  },
  {
    mode: 'Edge Deployment',
    env: 'IoT',
    icon: Wifi,
    color: 'text-accent-amber',
    bg: 'bg-accent-amber/10',
    border: 'border-accent-amber/20',
    details: [
      'ONNX-optimised lightweight model export',
      'ARM64 and x86 container images',
      'Local inference with optional cloud sync',
      'Sub-10ms latency on edge hardware',
    ],
  },
  {
    mode: 'Air-Gapped',
    env: 'Classified Environments',
    icon: WifiOff,
    color: 'text-accent-red',
    bg: 'bg-accent-red/10',
    border: 'border-accent-red/20',
    details: [
      'Fully offline installation bundle',
      'No external network dependencies',
      'Local model registry and package mirror',
      'STIG-hardened base container images',
    ],
  },
]

/* ── Component ─────────────────────────────────────────────────────────── */

export default function Architecture() {
  return (
    <div className="space-y-8 max-w-6xl">
      <div>
        <h1 className="text-2xl font-display font-bold">System Architecture</h1>
        <p className="text-sm text-text-secondary mt-2 max-w-3xl">
          End-to-end architecture from network traffic ingestion through 7-method ensemble inference
          to automated threat response. Designed for horizontal GPU scaling.
        </p>
      </div>

      {/* ── Pipeline layers ──────────────────────────────────────────────── */}
      <div className="space-y-3">
        <h2 className="text-lg font-display font-semibold">Processing Pipeline</h2>
        {LAYERS.map((layer, li) => (
          <div key={layer.name}>
            <div className={`bg-bg-secondary rounded-xl border border-bg-card overflow-hidden`}>
              <div className={`px-5 py-3 border-b border-bg-card/50 flex items-center gap-3`}>
                <div className={`w-6 h-6 rounded-full bg-${layer.color}/20 flex items-center justify-center`}>
                  <span className={`text-${layer.color} text-xs font-bold`}>{li + 1}</span>
                </div>
                <span className="font-display font-semibold text-sm text-text-primary">{layer.name}</span>
              </div>
              <div className="p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {layer.components.map(c => (
                  <div key={c.label} className="px-3 py-2 bg-bg-primary/50 rounded-lg border border-bg-card/30">
                    <div className="text-xs font-medium text-text-primary">{c.label}</div>
                    <div className="text-[10px] text-text-secondary mt-0.5">{c.desc}</div>
                  </div>
                ))}
              </div>
            </div>
            {li < LAYERS.length - 1 && (
              <div className="flex justify-center py-1">
                <ChevronRight className="w-4 h-4 text-text-secondary/30 rotate-90" />
              </div>
            )}
          </div>
        ))}
      </div>

      {/* ── Performance Metrics ────────────────────────────────────────────── */}
      <div>
        <h2 className="text-lg font-display font-semibold mb-4">Performance Metrics</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {PERF_METRICS.map(m => (
            <div key={m.label} className="p-4 bg-bg-secondary rounded-xl border border-bg-card">
              <div className="flex items-center gap-2 mb-3">
                <div className={`w-7 h-7 rounded-lg ${m.bg} flex items-center justify-center`}>
                  <m.icon className={`w-4 h-4 ${m.color}`} />
                </div>
                <span className="text-xs font-semibold text-text-primary">{m.label}</span>
              </div>
              <div className="space-y-1.5">
                {m.values.map(v => (
                  <div key={v.tag} className="flex items-center justify-between">
                    <span className="text-[10px] text-text-secondary uppercase tracking-wider">{v.tag}</span>
                    <span className={`text-sm font-mono font-semibold ${m.color}`}>{v.value}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Latency Breakdown ──────────────────────────────────────────────── */}
      <div>
        <h2 className="text-lg font-display font-semibold mb-4">Latency Breakdown</h2>
        <div className="bg-bg-secondary rounded-xl border border-bg-card p-5">
          <div className="space-y-3">
            {LATENCY_STAGES.map(s => {
              const pct = (s.ms / LATENCY_TOTAL) * 100
              return (
                <div key={s.stage}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-medium text-text-primary">{s.stage}</span>
                    <span className="text-xs font-mono text-text-secondary">{s.ms} ms</span>
                  </div>
                  <div className="w-full h-3 bg-bg-primary rounded-full overflow-hidden">
                    <div
                      className={`h-full ${s.color} rounded-full`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
          <div className="mt-4 pt-3 border-t border-bg-card/50 flex items-center justify-between">
            <span className="text-xs font-semibold text-text-primary">Total Pipeline Latency</span>
            <span className="text-sm font-mono font-bold text-accent-green">{LATENCY_TOTAL.toFixed(1)} ms</span>
          </div>
        </div>
      </div>

      {/* ── GPU Scaling Roadmap ───────────────────────────────────────────── */}
      <div>
        <h2 className="text-lg font-display font-semibold mb-4">GPU Scaling Roadmap</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {SCALING.map(tier => (
            <div key={tier.phase} className={`p-5 bg-bg-secondary rounded-xl border ${tier.border}`}>
              <div className="flex items-center gap-2 mb-3">
                <tier.icon className={`w-5 h-5 ${tier.color}`} />
                <span className={`text-xs font-semibold uppercase tracking-wider ${tier.color}`}>
                  {tier.phase}
                </span>
              </div>
              <div className="font-display font-bold text-text-primary text-sm mb-1">
                {tier.spec}
              </div>
              <div className={`text-xs font-mono ${tier.color} mb-1`}>
                {tier.throughput}
              </div>
              <div className="text-xs font-semibold text-text-secondary mb-3">
                Estimated cost: <span className={`${tier.color}`}>{tier.cost}</span>
              </div>
              <ul className="space-y-1.5">
                {tier.details.map(d => (
                  <li key={d} className="flex items-start gap-2 text-xs text-text-secondary">
                    <ChevronRight className="w-3 h-3 mt-0.5 shrink-0 text-text-secondary/40" />
                    {d}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>

      {/* ── Security Architecture ──────────────────────────────────────────── */}
      <div>
        <h2 className="text-lg font-display font-semibold mb-4">Security Architecture</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {SECURITY_ITEMS.map(s => (
            <div key={s.label} className="p-4 bg-bg-secondary rounded-xl border border-bg-card flex gap-3">
              <div className="shrink-0 mt-0.5">
                <s.icon className={`w-5 h-5 ${s.color}`} />
              </div>
              <div>
                <div className="text-xs font-semibold text-text-primary mb-1">{s.label}</div>
                <div className="text-[10px] text-text-secondary leading-relaxed">{s.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── High Availability ──────────────────────────────────────────────── */}
      <div>
        <h2 className="text-lg font-display font-semibold mb-4">High Availability</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {HA_ITEMS.map(h => (
            <div key={h.label} className="p-4 bg-bg-secondary rounded-xl border border-bg-card flex gap-3">
              <div className="shrink-0 mt-0.5">
                <h.icon className={`w-5 h-5 ${h.color}`} />
              </div>
              <div>
                <div className="text-xs font-semibold text-text-primary mb-1">{h.label}</div>
                <div className="text-[10px] text-text-secondary leading-relaxed">{h.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Deployment Configurations ──────────────────────────────────────── */}
      <div>
        <h2 className="text-lg font-display font-semibold mb-4">Deployment Configurations</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {DEPLOY_MODES.map(d => (
            <div key={d.mode} className={`p-4 bg-bg-secondary rounded-xl border ${d.border}`}>
              <div className="flex items-center gap-2 mb-2">
                <d.icon className={`w-5 h-5 ${d.color}`} />
                <div>
                  <div className={`text-xs font-semibold ${d.color}`}>{d.mode}</div>
                  <div className="text-[10px] text-text-secondary">{d.env}</div>
                </div>
              </div>
              <ul className="space-y-1.5 mt-3">
                {d.details.map(det => (
                  <li key={det} className="flex items-start gap-2 text-xs text-text-secondary">
                    <ChevronRight className="w-3 h-3 mt-0.5 shrink-0 text-text-secondary/40" />
                    {det}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>

      {/* ── Tech Stack ────────────────────────────────────────────────────── */}
      <div>
        <h2 className="text-lg font-display font-semibold mb-4">Technology Stack</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {TECH_STACK.map(ts => (
            <div key={ts.category} className="p-4 bg-bg-secondary rounded-xl border border-bg-card">
              <div className="text-xs font-semibold text-accent-blue uppercase tracking-wider mb-3">
                {ts.category}
              </div>
              <div className="space-y-1.5">
                {ts.items.map(item => (
                  <div key={item} className="text-xs text-text-secondary">{item}</div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Data flow summary ─────────────────────────────────────────────── */}
      <div className="bg-bg-secondary rounded-xl border border-bg-card p-5">
        <h2 className="text-sm font-display font-semibold mb-3">Data Flow Summary</h2>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {[
            { label: 'PCAP/CSV', color: 'bg-accent-blue/15 text-accent-blue' },
            { label: '83 Features', color: 'bg-bg-card text-text-secondary' },
            { label: '7 Models', color: 'bg-accent-purple/15 text-accent-purple' },
            { label: 'Fusion', color: 'bg-accent-green/15 text-accent-green' },
            { label: '34 Classes', color: 'bg-accent-amber/15 text-accent-amber' },
            { label: 'Response', color: 'bg-accent-red/15 text-accent-red' },
          ].map((step, i) => (
            <span key={step.label} className="flex items-center gap-2">
              <span className={`px-2.5 py-1 rounded-lg font-medium ${step.color}`}>
                {step.label}
              </span>
              {i < 5 && <ArrowRight className="w-3 h-3 text-text-secondary/30" />}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}
