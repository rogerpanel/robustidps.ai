import {
  Server, Cpu, Database, Globe, Shield, Layers, Zap, ArrowRight,
  Activity, Lock, Brain, Target, Network, GitBranch, ChevronRight,
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
              <div className={`text-xs font-mono ${tier.color} mb-3`}>
                {tier.throughput}
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
