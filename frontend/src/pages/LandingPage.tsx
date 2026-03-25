import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ShieldCheck, ArrowRight, Brain, Zap, BarChart3, FlaskConical,
  Eye, Network, Shield, Lock, GitBranch, Target, Activity,
  ChevronRight, ExternalLink, Play, Database, Code, Layers,
  Cpu, Globe, Server, Fingerprint, BookOpen,
} from 'lucide-react'

/* ── Research method cards ─────────────────────────────────────────────── */

const METHODS = [
  {
    name: 'CT-TGNN',
    subtitle: 'Neural ODE',
    description: 'Continuous-time temporal graph network using Neural ODEs for non-stationary attack dynamics.',
    icon: Activity,
    color: 'text-accent-blue',
    bg: 'bg-accent-blue/10',
    border: 'border-accent-blue/20',
  },
  {
    name: 'TripleE-TGNN',
    subtitle: 'Multi-scale',
    description: 'Multi-granularity temporal graph capturing attack patterns at packet, flow, and session levels.',
    icon: Layers,
    color: 'text-accent-purple',
    bg: 'bg-accent-purple/10',
    border: 'border-accent-purple/20',
  },
  {
    name: 'FedLLM-API',
    subtitle: 'Zero-shot',
    description: 'Federated zero-shot detection leveraging LLM embeddings for novel attack recognition.',
    icon: Brain,
    color: 'text-accent-green',
    bg: 'bg-accent-green/10',
    border: 'border-accent-green/20',
  },
  {
    name: 'PQ-IDPS',
    subtitle: 'Post-quantum',
    description: 'Post-quantum cryptographic framework securing IDS communications against quantum adversaries.',
    icon: Lock,
    color: 'text-accent-amber',
    bg: 'bg-accent-amber/10',
    border: 'border-accent-amber/20',
  },
  {
    name: 'MambaShield',
    subtitle: 'State-space',
    description: 'Selective state-space model for linear-time processing of high-throughput network traffic.',
    icon: Zap,
    color: 'text-accent-red',
    bg: 'bg-accent-red/10',
    border: 'border-accent-red/20',
  },
  {
    name: 'Stochastic Transformer',
    subtitle: 'Bayesian UQ',
    description: 'Bayesian transformer with MC Dropout for calibrated uncertainty on every prediction.',
    icon: Target,
    color: 'text-accent-orange',
    bg: 'bg-accent-orange/10',
    border: 'border-accent-orange/20',
  },
  {
    name: 'Game-Theoretic Defence',
    subtitle: 'Robustness Cert.',
    description: 'Stackelberg game yielding provable adversarial robustness certificates for IDS models.',
    icon: Shield,
    color: 'text-accent-blue',
    bg: 'bg-accent-blue/10',
    border: 'border-accent-blue/20',
  },
]

/* ── Pre-loaded benchmark results (CIC-IoT-2023) ──────────────────────── */

const BENCHMARK = {
  dataset: 'CIC-IoT-2023',
  classes: 34,
  flows: '1.2M+',
  models: [
    { name: 'SurrogateIDS Ensemble', accuracy: 97.8, f1: 0.976, latency: '0.8ms' },
    { name: 'CT-TGNN (Neural ODE)', accuracy: 96.2, f1: 0.958, latency: '1.2ms' },
    { name: 'MambaShield (SSM)', accuracy: 95.9, f1: 0.954, latency: '0.5ms' },
    { name: 'Stochastic Transformer', accuracy: 95.4, f1: 0.949, latency: '1.8ms' },
    { name: 'CL-RL Unified', accuracy: 96.8, f1: 0.965, latency: '1.1ms' },
  ],
}

/* ── Platform capabilities ─────────────────────────────────────────────── */

const CAPABILITIES = [
  {
    icon: BarChart3,
    title: '10 Analytics Tabs',
    desc: 'Performance, convergence, robustness, ROC/AUC, calibration, privacy trade-offs, transfer learning, dataset comparison, statistical analysis, cross-module intel.',
  },
  {
    icon: FlaskConical,
    title: 'Interactive Ablation',
    desc: 'Toggle any combination of 7 methods and instantly see accuracy impact on CIC-IoT-2023.',
  },
  {
    icon: Eye,
    title: 'Explainability Studio',
    desc: 'SHAP values, feature importance, attention maps, and counterfactual explanations for every prediction.',
  },
  {
    icon: Network,
    title: 'Federated Learning',
    desc: 'Simulate distributed training across nodes with differential privacy guarantees.',
  },
  {
    icon: Fingerprint,
    title: 'Red Team Arena',
    desc: 'Adversarial attack simulation with FGSM, PGD, C&W, and custom perturbation methods.',
  },
  {
    icon: Cpu,
    title: 'RL Response Agent',
    desc: 'Reinforcement learning agent that autonomously selects threat response actions.',
  },
]

/* ── Architecture tiers ────────────────────────────────────────────────── */

const ARCH_TIERS = [
  { label: 'Current', spec: '4 vCPU / 16 GB', desc: 'Full demo with all 7 methods, CPU inference', color: 'text-accent-green' },
  { label: 'Phase 2', spec: '+ NVIDIA T4 GPU', desc: 'Real-time inference at 10K flows/sec', color: 'text-accent-amber' },
  { label: 'Phase 3', spec: '+ A100 Multi-GPU', desc: 'Production 100K flows/sec, federated training', color: 'text-accent-blue' },
]

/* ── Landing Page Component ────────────────────────────────────────────── */

interface Props {
  onEnterDemo: () => void
  onSignIn: () => void
}

export default function LandingPage({ onEnterDemo, onSignIn }: Props) {
  const [hoveredMethod, setHoveredMethod] = useState<number | null>(null)

  return (
    <div className="min-h-screen bg-bg-primary">
      {/* ── Navigation Bar ──────────────────────────────────────────────── */}
      <nav className="sticky top-0 z-50 bg-bg-primary/90 backdrop-blur-lg border-b border-bg-card/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between h-16">
          <div className="flex items-center gap-2.5">
            <ShieldCheck className="w-7 h-7 text-accent-blue" />
            <span className="font-display font-bold text-lg text-text-primary">
              RobustIDPS<span className="text-accent-blue">.ai</span>
            </span>
          </div>
          <div className="hidden md:flex items-center gap-6 text-sm text-text-secondary">
            <a href="#methods" className="hover:text-text-primary transition-colors">Methods</a>
            <a href="#results" className="hover:text-text-primary transition-colors">Results</a>
            <a href="#platform" className="hover:text-text-primary transition-colors">Platform</a>
            <a href="#architecture" className="hover:text-text-primary transition-colors">Architecture</a>
            <a href="#api" className="hover:text-text-primary transition-colors">API</a>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={onEnterDemo}
              className="px-4 py-2 text-sm font-medium text-accent-blue hover:text-accent-blue/80 transition-colors"
            >
              Live Demo
            </button>
            <button
              onClick={onSignIn}
              className="px-4 py-2 bg-accent-blue hover:bg-accent-blue/90 text-white text-sm font-medium rounded-lg transition-colors"
            >
              Sign In
            </button>
          </div>
        </div>
      </nav>

      {/* ── Hero Section ────────────────────────────────────────────────── */}
      <section className="relative overflow-hidden">
        {/* Gradient background effects */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute -top-40 -right-40 w-96 h-96 bg-accent-blue/5 rounded-full blur-3xl" />
          <div className="absolute -bottom-40 -left-40 w-96 h-96 bg-accent-purple/5 rounded-full blur-3xl" />
        </div>

        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-16">
          <div className="max-w-3xl">
            <div className="inline-flex items-center gap-2 px-3 py-1.5 bg-accent-blue/10 border border-accent-blue/20 rounded-full text-xs text-accent-blue font-medium mb-6">
              <BookOpen className="w-3.5 h-3.5" />
              PhD Dissertation — MEPhI University
            </div>

            <h1 className="text-4xl md:text-5xl lg:text-6xl font-display font-bold text-text-primary leading-tight">
              Adversarially Robust{' '}
              <span className="text-accent-blue">Intrusion Detection</span>{' '}
              with 7 Novel ML Methods
            </h1>

            <p className="mt-6 text-lg text-text-secondary max-w-2xl leading-relaxed">
              A production-grade research platform demonstrating Neural ODEs, State-Space Models,
              Game-Theoretic Defence, Post-Quantum Cryptography, and more — evaluated on CIC-IoT-2023
              with 34-class classification achieving <span className="text-accent-green font-semibold">97.8% accuracy</span>.
            </p>

            <div className="mt-8 flex flex-wrap gap-4">
              <button
                onClick={onEnterDemo}
                className="group flex items-center gap-2.5 px-6 py-3 bg-accent-blue hover:bg-accent-blue/90 text-white font-medium rounded-lg transition-all shadow-lg shadow-accent-blue/20"
              >
                <Play className="w-4 h-4" />
                Try Live Demo
                <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
              </button>
              <a
                href="#results"
                className="flex items-center gap-2.5 px-6 py-3 bg-bg-card/50 hover:bg-bg-card text-text-primary font-medium rounded-lg transition-colors border border-bg-card"
              >
                <BarChart3 className="w-4 h-4" />
                View Results
              </a>
            </div>

            {/* Quick stats */}
            <div className="mt-12 grid grid-cols-2 sm:grid-cols-4 gap-4">
              {[
                { value: '7', label: 'Novel Methods' },
                { value: '34', label: 'Attack Classes' },
                { value: '97.8%', label: 'Accuracy' },
                { value: '6', label: 'Datasets' },
              ].map((s) => (
                <div key={s.label} className="text-center">
                  <div className="text-2xl font-display font-bold text-text-primary">{s.value}</div>
                  <div className="text-xs text-text-secondary mt-1">{s.label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ── 7 Methods Section ───────────────────────────────────────────── */}
      <section id="methods" className="py-20 bg-bg-secondary/30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-display font-bold text-text-primary">
              7 Dissertation Methods
            </h2>
            <p className="mt-3 text-text-secondary max-w-xl mx-auto">
              Each method addresses a specific gap in existing intrusion detection systems,
              from continuous-time dynamics to post-quantum security.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {METHODS.map((m, i) => (
              <div
                key={m.name}
                onMouseEnter={() => setHoveredMethod(i)}
                onMouseLeave={() => setHoveredMethod(null)}
                className={`relative p-5 rounded-xl border transition-all duration-200 cursor-default ${
                  hoveredMethod === i
                    ? `${m.bg} ${m.border} scale-[1.02] shadow-lg`
                    : 'bg-bg-secondary border-bg-card hover:border-bg-card/80'
                }`}
              >
                <div className={`inline-flex p-2 rounded-lg ${m.bg} mb-3`}>
                  <m.icon className={`w-5 h-5 ${m.color}`} />
                </div>
                <h3 className="font-display font-semibold text-text-primary text-sm">
                  {m.name}
                </h3>
                <span className={`text-xs font-medium ${m.color}`}>{m.subtitle}</span>
                <p className="mt-2 text-xs text-text-secondary leading-relaxed">
                  {m.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Live Results Section (CIC-IoT-2023) ─────────────────────────── */}
      <section id="results" className="py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-display font-bold text-text-primary">
              Pre-loaded Benchmark Results
            </h2>
            <p className="mt-3 text-text-secondary">
              {BENCHMARK.dataset} — {BENCHMARK.classes} attack classes, {BENCHMARK.flows} flows
            </p>
          </div>

          <div className="bg-bg-secondary rounded-2xl border border-bg-card overflow-hidden">
            {/* Table header */}
            <div className="grid grid-cols-4 gap-4 px-6 py-3 bg-bg-card/30 text-xs font-semibold text-text-secondary uppercase tracking-wider">
              <div>Model</div>
              <div className="text-right">Accuracy</div>
              <div className="text-right">F1 Score</div>
              <div className="text-right">Latency</div>
            </div>
            {/* Rows */}
            {BENCHMARK.models.map((m, i) => (
              <div
                key={m.name}
                className={`grid grid-cols-4 gap-4 px-6 py-4 items-center ${
                  i % 2 === 0 ? 'bg-bg-secondary' : 'bg-bg-secondary/50'
                } ${i === 0 ? 'border-l-2 border-l-accent-green' : ''}`}
              >
                <div className="text-sm font-medium text-text-primary">
                  {i === 0 && <span className="text-accent-green text-xs mr-2">BEST</span>}
                  {m.name}
                </div>
                <div className="text-right">
                  <span className="font-mono text-sm text-text-primary">{m.accuracy}%</span>
                  <div className="mt-1 h-1.5 bg-bg-card rounded-full overflow-hidden">
                    <div
                      className="h-full bg-accent-blue rounded-full transition-all duration-1000"
                      style={{ width: `${m.accuracy}%` }}
                    />
                  </div>
                </div>
                <div className="text-right font-mono text-sm text-text-primary">{m.f1}</div>
                <div className="text-right font-mono text-sm text-text-secondary">{m.latency}</div>
              </div>
            ))}
          </div>

          <div className="mt-6 text-center">
            <button
              onClick={onEnterDemo}
              className="inline-flex items-center gap-2 text-sm text-accent-blue hover:text-accent-blue/80 font-medium transition-colors"
            >
              <Play className="w-4 h-4" />
              Explore all 10 analytics tabs in the live demo
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </section>

      {/* ── Platform Capabilities ───────────────────────────────────────── */}
      <section id="platform" className="py-20 bg-bg-secondary/30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-display font-bold text-text-primary">
              Research Platform Capabilities
            </h2>
            <p className="mt-3 text-text-secondary max-w-xl mx-auto">
              Production-grade tooling for adversarial ML research — not just a prototype.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {CAPABILITIES.map((c) => (
              <div
                key={c.title}
                className="p-5 bg-bg-secondary rounded-xl border border-bg-card hover:border-accent-blue/30 transition-colors"
              >
                <c.icon className="w-6 h-6 text-accent-blue mb-3" />
                <h3 className="font-display font-semibold text-text-primary text-sm mb-2">
                  {c.title}
                </h3>
                <p className="text-xs text-text-secondary leading-relaxed">{c.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Architecture & GPU Scaling Roadmap ──────────────────────────── */}
      <section id="architecture" className="py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-display font-bold text-text-primary">
              Architecture & Scaling Roadmap
            </h2>
          </div>

          {/* Architecture diagram */}
          <div className="bg-bg-secondary rounded-2xl border border-bg-card p-6 md:p-8 mb-8">
            <div className="font-mono text-xs text-text-secondary space-y-2 leading-relaxed max-w-2xl mx-auto">
              <div className="text-center text-text-primary font-semibold text-sm mb-4">System Architecture</div>

              <div className="flex flex-col items-center gap-1">
                <div className="px-4 py-2 bg-accent-blue/10 border border-accent-blue/20 rounded-lg text-accent-blue text-center">
                  Network Traffic / PCAP / CIC-IoT-2023
                </div>
                <div className="text-text-secondary">&#8595;</div>
                <div className="px-4 py-2 bg-bg-card/50 border border-bg-card rounded-lg text-center">
                  Feature Extraction (83 flow features + StandardScaler)
                </div>
                <div className="text-text-secondary">&#8595;</div>

                {/* 7-branch model */}
                <div className="w-full max-w-lg p-4 bg-bg-primary/50 border border-bg-card rounded-xl">
                  <div className="text-center text-accent-blue font-semibold mb-3">SurrogateIDS Ensemble (7-branch)</div>
                  <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
                    {METHODS.map((m) => (
                      <div key={m.name} className={`px-2 py-1.5 ${m.bg} border ${m.border} rounded text-center`}>
                        <span className={`text-[10px] ${m.color}`}>{m.name}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="text-text-secondary">&#8595;</div>
                <div className="px-4 py-2 bg-accent-green/10 border border-accent-green/20 rounded-lg text-accent-green text-center">
                  Fusion Layer &rarr; 34-class classification
                </div>
                <div className="text-text-secondary">&#8595;</div>

                <div className="flex flex-wrap justify-center gap-3">
                  <div className="px-3 py-1.5 bg-accent-purple/10 border border-accent-purple/20 rounded text-accent-purple text-[11px]">
                    SOC Dashboard
                  </div>
                  <div className="px-3 py-1.5 bg-accent-amber/10 border border-accent-amber/20 rounded text-accent-amber text-[11px]">
                    RL Response
                  </div>
                  <div className="px-3 py-1.5 bg-accent-red/10 border border-accent-red/20 rounded text-accent-red text-[11px]">
                    Threat Intel
                  </div>
                  <div className="px-3 py-1.5 bg-accent-blue/10 border border-accent-blue/20 rounded text-accent-blue text-[11px]">
                    REST API
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* GPU Scaling tiers */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {ARCH_TIERS.map((tier) => (
              <div key={tier.label} className="p-5 bg-bg-secondary rounded-xl border border-bg-card">
                <div className={`text-xs font-semibold uppercase tracking-wider ${tier.color} mb-1`}>
                  {tier.label}
                </div>
                <div className="font-display font-bold text-text-primary">{tier.spec}</div>
                <p className="text-xs text-text-secondary mt-2">{tier.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── API Documentation Section ───────────────────────────────────── */}
      <section id="api" className="py-20 bg-bg-secondary/30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-display font-bold text-text-primary">
              Production-Grade API
            </h2>
            <p className="mt-3 text-text-secondary max-w-xl mx-auto">
              RESTful API with OpenAPI documentation. Every capability accessible programmatically.
            </p>
          </div>

          <div className="bg-bg-secondary rounded-2xl border border-bg-card overflow-hidden">
            <div className="p-6">
              <div className="flex items-center gap-2 mb-4">
                <Code className="w-5 h-5 text-accent-green" />
                <span className="font-mono text-sm text-text-primary font-medium">API Endpoints</span>
              </div>

              <div className="space-y-2 font-mono text-xs">
                {[
                  { method: 'GET', path: '/api/health', desc: 'System health check' },
                  { method: 'POST', path: '/api/analyse', desc: 'Upload & analyse network flows (CSV/PCAP)' },
                  { method: 'GET', path: '/api/analytics', desc: 'Full model performance analytics' },
                  { method: 'GET', path: '/api/models', desc: 'List all available IDS models' },
                  { method: 'POST', path: '/api/ablation', desc: 'Run ablation study with method toggles' },
                  { method: 'GET', path: '/api/explainability/{flow_id}', desc: 'SHAP/attention explanations' },
                  { method: 'POST', path: '/api/redteam/attack', desc: 'Adversarial attack simulation' },
                  { method: 'GET', path: '/api/federated/status', desc: 'Federated learning node status' },
                  { method: 'POST', path: '/api/continual/train', desc: 'Trigger continual learning update' },
                  { method: 'GET', path: '/api/drift/status', desc: 'Concept drift detection metrics' },
                ].map((ep) => (
                  <div key={ep.path} className="flex items-center gap-3 px-3 py-2 bg-bg-primary/50 rounded-lg">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      ep.method === 'GET'
                        ? 'bg-accent-green/15 text-accent-green'
                        : 'bg-accent-blue/15 text-accent-blue'
                    }`}>
                      {ep.method}
                    </span>
                    <span className="text-text-primary flex-1">{ep.path}</span>
                    <span className="text-text-secondary hidden sm:block">{ep.desc}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Code example */}
            <div className="border-t border-bg-card p-6">
              <div className="text-xs text-text-secondary mb-3">Quick Start — Python</div>
              <pre className="bg-bg-primary rounded-lg p-4 text-xs font-mono text-text-secondary overflow-x-auto">
                <code>{`import requests

# Analyse network flows
resp = requests.post("https://robustidps.ai/api/analyse",
    files={"file": open("traffic.csv", "rb")})

results = resp.json()
print(f"Threats detected: {results['n_threats']}/{results['n_flows']}")
print(f"ECE (calibration): {results['ece']:.3f}")

for p in results["predictions"][:5]:
    print(f"  {p['src_ip']} -> {p['label_predicted']} "
          f"({p['confidence']:.1%}, {p['severity']})")`}</code>
              </pre>
            </div>
          </div>
        </div>
      </section>

      {/* ── CTA Section ─────────────────────────────────────────────────── */}
      <section className="py-20">
        <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl font-display font-bold text-text-primary mb-4">
            Explore the Research Platform
          </h2>
          <p className="text-text-secondary mb-8 max-w-lg mx-auto">
            Access all 7 methods, 10 analytics tabs, interactive ablation, and adversarial testing.
            No installation required.
          </p>

          <div className="flex flex-wrap justify-center gap-4">
            <button
              onClick={onEnterDemo}
              className="group flex items-center gap-2.5 px-8 py-3.5 bg-accent-blue hover:bg-accent-blue/90 text-white font-medium rounded-lg transition-all shadow-lg shadow-accent-blue/20"
            >
              <Play className="w-5 h-5" />
              Try with Demo Data
              <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
            </button>
            <button
              onClick={onSignIn}
              className="flex items-center gap-2.5 px-8 py-3.5 bg-bg-card/50 hover:bg-bg-card text-text-primary font-medium rounded-lg transition-colors border border-bg-card"
            >
              Sign In for Full Access
            </button>
          </div>
        </div>
      </section>

      {/* ── Footer ──────────────────────────────────────────────────────── */}
      <footer className="border-t border-bg-card py-8">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-accent-blue" />
              <span className="font-display font-bold text-sm text-text-primary">
                RobustIDPS<span className="text-accent-blue">.ai</span>
              </span>
            </div>
            <div className="text-xs text-text-secondary text-center">
              MEPhI University — PhD Dissertation Implementation — Roger Nick Anaedevha
            </div>
            <div className="flex items-center gap-4 text-xs text-text-secondary">
              <span>FastAPI + React + Vite</span>
              <span>Python 3.11 + PyTorch</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}
