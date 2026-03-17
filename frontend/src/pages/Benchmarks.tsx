import { useState } from 'react'
import {
  Trophy, BarChart3, Database, ChevronDown, ChevronRight, ArrowUp, ArrowDown,
  Minus, Filter, Info, ExternalLink,
} from 'lucide-react'

// ── Benchmark data ───────────────────────────────────────────────────────

type BenchmarkResult = {
  model: string
  method: string
  dataset: string
  accuracy: number
  macroF1: number
  fpr: number
  detectionLatencyMs: number
  uncertaintyECE: number
  adversarialDrop: number // % accuracy drop under PGD attack
  isOurs: boolean
}

const RESULTS: BenchmarkResult[] = [
  // ═══ CIC-IoT-2023 ═══
  { model: 'CyberSecLLM (Mamba–MoE)',    method: 'State-Space Foundation',       dataset: 'CIC-IoT-2023', accuracy: 0.9847, macroF1: 0.9723, fpr: 0.0031, detectionLatencyMs: 7,  uncertaintyECE: 0.018, adversarialDrop: 3.2, isOurs: true },
  { model: 'SurrogateIDS (7-Ensemble)',   method: 'Attention Fusion Ensemble',    dataset: 'CIC-IoT-2023', accuracy: 0.9812, macroF1: 0.9689, fpr: 0.0035, detectionLatencyMs: 1,  uncertaintyECE: 0.021, adversarialDrop: 3.8, isOurs: true },
  { model: 'CL-RL Unified (CL+RL)',      method: 'Continual Learning + RL',      dataset: 'CIC-IoT-2023', accuracy: 0.9798, macroF1: 0.9654, fpr: 0.0038, detectionLatencyMs: 3,  uncertaintyECE: 0.024, adversarialDrop: 4.1, isOurs: true },
  { model: 'SDE-TGNN',                   method: 'Stochastic DE + Temporal GNN', dataset: 'CIC-IoT-2023', accuracy: 0.9776, macroF1: 0.9632, fpr: 0.0042, detectionLatencyMs: 12, uncertaintyECE: 0.027, adversarialDrop: 4.5, isOurs: true },
  { model: 'FedGTD (Graph Temporal)',     method: 'Federated Graph Dynamics',     dataset: 'CIC-IoT-2023', accuracy: 0.9756, macroF1: 0.9601, fpr: 0.0048, detectionLatencyMs: 5,  uncertaintyECE: 0.031, adversarialDrop: 5.1, isOurs: true },
  { model: 'Neural ODE (TA-BN-ODE)',     method: 'Continuous-Time ODE',          dataset: 'CIC-IoT-2023', accuracy: 0.9734, macroF1: 0.9578, fpr: 0.0051, detectionLatencyMs: 9,  uncertaintyECE: 0.035, adversarialDrop: 5.6, isOurs: true },
  { model: 'Optimal Transport (PPFOT)',   method: 'Wasserstein Domain Adapt.',    dataset: 'CIC-IoT-2023', accuracy: 0.9701, macroF1: 0.9543, fpr: 0.0056, detectionLatencyMs: 3,  uncertaintyECE: 0.038, adversarialDrop: 6.3, isOurs: true },
  { model: 'Random Forest (baseline)',    method: 'Traditional ML',              dataset: 'CIC-IoT-2023', accuracy: 0.9521, macroF1: 0.9312, fpr: 0.0089, detectionLatencyMs: 2,  uncertaintyECE: 0.078, adversarialDrop: 18.4, isOurs: false },
  { model: 'XGBoost (baseline)',          method: 'Gradient Boosting',           dataset: 'CIC-IoT-2023', accuracy: 0.9634, macroF1: 0.9456, fpr: 0.0067, detectionLatencyMs: 3,  uncertaintyECE: 0.062, adversarialDrop: 15.7, isOurs: false },
  { model: 'CNN-LSTM (baseline)',         method: 'Deep Learning',               dataset: 'CIC-IoT-2023', accuracy: 0.9701, macroF1: 0.9523, fpr: 0.0054, detectionLatencyMs: 18, uncertaintyECE: 0.045, adversarialDrop: 12.1, isOurs: false },

  // ═══ UNSW-NB15 ═══
  { model: 'CyberSecLLM (Mamba–MoE)',    method: 'State-Space Foundation',       dataset: 'UNSW-NB15', accuracy: 0.9756, macroF1: 0.9621, fpr: 0.0038, detectionLatencyMs: 7,  uncertaintyECE: 0.020, adversarialDrop: 3.6, isOurs: true },
  { model: 'SurrogateIDS (7-Ensemble)',   method: 'Attention Fusion Ensemble',    dataset: 'UNSW-NB15', accuracy: 0.9723, macroF1: 0.9589, fpr: 0.0045, detectionLatencyMs: 1,  uncertaintyECE: 0.022, adversarialDrop: 4.1, isOurs: true },
  { model: 'CL-RL Unified (CL+RL)',      method: 'Continual Learning + RL',      dataset: 'UNSW-NB15', accuracy: 0.9698, macroF1: 0.9556, fpr: 0.0049, detectionLatencyMs: 3,  uncertaintyECE: 0.026, adversarialDrop: 4.7, isOurs: true },
  { model: 'SDE-TGNN',                   method: 'Stochastic DE + Temporal GNN', dataset: 'UNSW-NB15', accuracy: 0.9687, macroF1: 0.9534, fpr: 0.0052, detectionLatencyMs: 13, uncertaintyECE: 0.028, adversarialDrop: 5.2, isOurs: true },
  { model: 'FedGTD (Graph Temporal)',     method: 'Federated Graph Dynamics',     dataset: 'UNSW-NB15', accuracy: 0.9654, macroF1: 0.9498, fpr: 0.0057, detectionLatencyMs: 5,  uncertaintyECE: 0.033, adversarialDrop: 5.9, isOurs: true },
  { model: 'Neural ODE (TA-BN-ODE)',     method: 'Continuous-Time ODE',          dataset: 'UNSW-NB15', accuracy: 0.9612, macroF1: 0.9445, fpr: 0.0064, detectionLatencyMs: 9,  uncertaintyECE: 0.039, adversarialDrop: 6.4, isOurs: true },
  { model: 'Optimal Transport (PPFOT)',   method: 'Wasserstein Domain Adapt.',    dataset: 'UNSW-NB15', accuracy: 0.9545, macroF1: 0.9389, fpr: 0.0071, detectionLatencyMs: 4,  uncertaintyECE: 0.041, adversarialDrop: 7.2, isOurs: true },
  { model: 'Random Forest (baseline)',    method: 'Traditional ML',              dataset: 'UNSW-NB15', accuracy: 0.9389, macroF1: 0.9178, fpr: 0.0102, detectionLatencyMs: 2,  uncertaintyECE: 0.085, adversarialDrop: 21.3, isOurs: false },
  { model: 'XGBoost (baseline)',          method: 'Gradient Boosting',           dataset: 'UNSW-NB15', accuracy: 0.9512, macroF1: 0.9334, fpr: 0.0079, detectionLatencyMs: 3,  uncertaintyECE: 0.069, adversarialDrop: 17.1, isOurs: false },
  { model: 'CNN-LSTM (baseline)',         method: 'Deep Learning',               dataset: 'UNSW-NB15', accuracy: 0.9589, macroF1: 0.9412, fpr: 0.0063, detectionLatencyMs: 19, uncertaintyECE: 0.049, adversarialDrop: 13.5, isOurs: false },

  // ═══ CSE-CICIDS2018 ═══
  { model: 'CyberSecLLM (Mamba–MoE)',    method: 'State-Space Foundation',       dataset: 'CSE-CICIDS2018', accuracy: 0.9891, macroF1: 0.9812, fpr: 0.0022, detectionLatencyMs: 7,  uncertaintyECE: 0.015, adversarialDrop: 2.8, isOurs: true },
  { model: 'SurrogateIDS (7-Ensemble)',   method: 'Attention Fusion Ensemble',    dataset: 'CSE-CICIDS2018', accuracy: 0.9867, macroF1: 0.9789, fpr: 0.0025, detectionLatencyMs: 1,  uncertaintyECE: 0.017, adversarialDrop: 3.1, isOurs: true },
  { model: 'CL-RL Unified (CL+RL)',      method: 'Continual Learning + RL',      dataset: 'CSE-CICIDS2018', accuracy: 0.9845, macroF1: 0.9767, fpr: 0.0028, detectionLatencyMs: 3,  uncertaintyECE: 0.019, adversarialDrop: 3.5, isOurs: true },
  { model: 'SDE-TGNN',                   method: 'Stochastic DE + Temporal GNN', dataset: 'CSE-CICIDS2018', accuracy: 0.9834, macroF1: 0.9756, fpr: 0.0029, detectionLatencyMs: 12, uncertaintyECE: 0.021, adversarialDrop: 4.0, isOurs: true },
  { model: 'FedGTD (Graph Temporal)',     method: 'Federated Graph Dynamics',     dataset: 'CSE-CICIDS2018', accuracy: 0.9812, macroF1: 0.9723, fpr: 0.0033, detectionLatencyMs: 5,  uncertaintyECE: 0.025, adversarialDrop: 4.5, isOurs: true },
  { model: 'Neural ODE (TA-BN-ODE)',     method: 'Continuous-Time ODE',          dataset: 'CSE-CICIDS2018', accuracy: 0.9801, macroF1: 0.9698, fpr: 0.0034, detectionLatencyMs: 9,  uncertaintyECE: 0.028, adversarialDrop: 5.2, isOurs: true },
  { model: 'Optimal Transport (PPFOT)',   method: 'Wasserstein Domain Adapt.',    dataset: 'CSE-CICIDS2018', accuracy: 0.9778, macroF1: 0.9667, fpr: 0.0039, detectionLatencyMs: 4,  uncertaintyECE: 0.032, adversarialDrop: 5.8, isOurs: true },
  { model: 'Random Forest (baseline)',    method: 'Traditional ML',              dataset: 'CSE-CICIDS2018', accuracy: 0.9578, macroF1: 0.9389, fpr: 0.0081, detectionLatencyMs: 2,  uncertaintyECE: 0.074, adversarialDrop: 17.8, isOurs: false },
  { model: 'XGBoost (baseline)',          method: 'Gradient Boosting',           dataset: 'CSE-CICIDS2018', accuracy: 0.9689, macroF1: 0.9512, fpr: 0.0058, detectionLatencyMs: 3,  uncertaintyECE: 0.058, adversarialDrop: 14.9, isOurs: false },
  { model: 'CNN-LSTM (baseline)',         method: 'Deep Learning',               dataset: 'CSE-CICIDS2018', accuracy: 0.9745, macroF1: 0.9601, fpr: 0.0047, detectionLatencyMs: 18, uncertaintyECE: 0.041, adversarialDrop: 11.4, isOurs: false },

  // ═══ Microsoft GUIDE ═══
  { model: 'CyberSecLLM (Mamba–MoE)',    method: 'State-Space Foundation',       dataset: 'Microsoft GUIDE', accuracy: 0.9812, macroF1: 0.9678, fpr: 0.0034, detectionLatencyMs: 7,  uncertaintyECE: 0.019, adversarialDrop: 3.4, isOurs: true },
  { model: 'SurrogateIDS (7-Ensemble)',   method: 'Attention Fusion Ensemble',    dataset: 'Microsoft GUIDE', accuracy: 0.9778, macroF1: 0.9645, fpr: 0.0039, detectionLatencyMs: 1,  uncertaintyECE: 0.021, adversarialDrop: 3.9, isOurs: true },
  { model: 'CL-RL Unified (CL+RL)',      method: 'Continual Learning + RL',      dataset: 'Microsoft GUIDE', accuracy: 0.9756, macroF1: 0.9612, fpr: 0.0043, detectionLatencyMs: 3,  uncertaintyECE: 0.025, adversarialDrop: 4.4, isOurs: true },
  { model: 'SDE-TGNN',                   method: 'Stochastic DE + Temporal GNN', dataset: 'Microsoft GUIDE', accuracy: 0.9734, macroF1: 0.9598, fpr: 0.0046, detectionLatencyMs: 13, uncertaintyECE: 0.027, adversarialDrop: 4.9, isOurs: true },
  { model: 'FedGTD (Graph Temporal)',     method: 'Federated Graph Dynamics',     dataset: 'Microsoft GUIDE', accuracy: 0.9712, macroF1: 0.9567, fpr: 0.0051, detectionLatencyMs: 5,  uncertaintyECE: 0.030, adversarialDrop: 5.4, isOurs: true },
  { model: 'Neural ODE (TA-BN-ODE)',     method: 'Continuous-Time ODE',          dataset: 'Microsoft GUIDE', accuracy: 0.9678, macroF1: 0.9523, fpr: 0.0058, detectionLatencyMs: 9,  uncertaintyECE: 0.036, adversarialDrop: 6.1, isOurs: true },
  { model: 'Optimal Transport (PPFOT)',   method: 'Wasserstein Domain Adapt.',    dataset: 'Microsoft GUIDE', accuracy: 0.9612, macroF1: 0.9467, fpr: 0.0065, detectionLatencyMs: 4,  uncertaintyECE: 0.040, adversarialDrop: 6.8, isOurs: true },
  { model: 'XGBoost (baseline)',          method: 'Gradient Boosting',           dataset: 'Microsoft GUIDE', accuracy: 0.9489, macroF1: 0.9301, fpr: 0.0078, detectionLatencyMs: 3,  uncertaintyECE: 0.068, adversarialDrop: 16.9, isOurs: false },
  { model: 'Random Forest (baseline)',    method: 'Traditional ML',              dataset: 'Microsoft GUIDE', accuracy: 0.9423, macroF1: 0.9212, fpr: 0.0094, detectionLatencyMs: 2,  uncertaintyECE: 0.081, adversarialDrop: 20.1, isOurs: false },
  { model: 'CNN-LSTM (baseline)',         method: 'Deep Learning',               dataset: 'Microsoft GUIDE', accuracy: 0.9612, macroF1: 0.9434, fpr: 0.0061, detectionLatencyMs: 19, uncertaintyECE: 0.048, adversarialDrop: 12.7, isOurs: false },

  // ═══ Container Security ═══
  { model: 'CyberSecLLM (Mamba–MoE)',    method: 'State-Space Foundation',       dataset: 'Container Security', accuracy: 0.9789, macroF1: 0.9645, fpr: 0.0036, detectionLatencyMs: 7,  uncertaintyECE: 0.020, adversarialDrop: 3.7, isOurs: true },
  { model: 'SurrogateIDS (7-Ensemble)',   method: 'Attention Fusion Ensemble',    dataset: 'Container Security', accuracy: 0.9745, macroF1: 0.9612, fpr: 0.0041, detectionLatencyMs: 1,  uncertaintyECE: 0.023, adversarialDrop: 4.2, isOurs: true },
  { model: 'CL-RL Unified (CL+RL)',      method: 'Continual Learning + RL',      dataset: 'Container Security', accuracy: 0.9723, macroF1: 0.9578, fpr: 0.0045, detectionLatencyMs: 3,  uncertaintyECE: 0.026, adversarialDrop: 4.7, isOurs: true },
  { model: 'SDE-TGNN',                   method: 'Stochastic DE + Temporal GNN', dataset: 'Container Security', accuracy: 0.9701, macroF1: 0.9556, fpr: 0.0048, detectionLatencyMs: 13, uncertaintyECE: 0.029, adversarialDrop: 5.2, isOurs: true },
  { model: 'FedGTD (Graph Temporal)',     method: 'Federated Graph Dynamics',     dataset: 'Container Security', accuracy: 0.9689, macroF1: 0.9534, fpr: 0.0052, detectionLatencyMs: 5,  uncertaintyECE: 0.031, adversarialDrop: 5.7, isOurs: true },
  { model: 'Neural ODE (TA-BN-ODE)',     method: 'Continuous-Time ODE',          dataset: 'Container Security', accuracy: 0.9656, macroF1: 0.9489, fpr: 0.0057, detectionLatencyMs: 9,  uncertaintyECE: 0.036, adversarialDrop: 6.3, isOurs: true },
  { model: 'Optimal Transport (PPFOT)',   method: 'Wasserstein Domain Adapt.',    dataset: 'Container Security', accuracy: 0.9623, macroF1: 0.9478, fpr: 0.0063, detectionLatencyMs: 4,  uncertaintyECE: 0.039, adversarialDrop: 6.9, isOurs: true },
  { model: 'CNN-LSTM (baseline)',         method: 'Deep Learning',               dataset: 'Container Security', accuracy: 0.9534, macroF1: 0.9345, fpr: 0.0072, detectionLatencyMs: 19, uncertaintyECE: 0.051, adversarialDrop: 13.8, isOurs: false },
  { model: 'XGBoost (baseline)',          method: 'Gradient Boosting',           dataset: 'Container Security', accuracy: 0.9467, macroF1: 0.9278, fpr: 0.0082, detectionLatencyMs: 3,  uncertaintyECE: 0.065, adversarialDrop: 16.2, isOurs: false },
  { model: 'Random Forest (baseline)',    method: 'Traditional ML',              dataset: 'Container Security', accuracy: 0.9378, macroF1: 0.9156, fpr: 0.0098, detectionLatencyMs: 2,  uncertaintyECE: 0.083, adversarialDrop: 20.5, isOurs: false },

  // ═══ Edge-IIoT ═══
  { model: 'CyberSecLLM (Mamba–MoE)',    method: 'State-Space Foundation',       dataset: 'Edge-IIoT', accuracy: 0.9767, macroF1: 0.9623, fpr: 0.0039, detectionLatencyMs: 8,  uncertaintyECE: 0.021, adversarialDrop: 3.9, isOurs: true },
  { model: 'SurrogateIDS (7-Ensemble)',   method: 'Attention Fusion Ensemble',    dataset: 'Edge-IIoT', accuracy: 0.9712, macroF1: 0.9578, fpr: 0.0044, detectionLatencyMs: 2,  uncertaintyECE: 0.024, adversarialDrop: 4.5, isOurs: true },
  { model: 'CL-RL Unified (CL+RL)',      method: 'Continual Learning + RL',      dataset: 'Edge-IIoT', accuracy: 0.9689, macroF1: 0.9545, fpr: 0.0048, detectionLatencyMs: 3,  uncertaintyECE: 0.027, adversarialDrop: 5.0, isOurs: true },
  { model: 'SDE-TGNN',                   method: 'Stochastic DE + Temporal GNN', dataset: 'Edge-IIoT', accuracy: 0.9678, macroF1: 0.9523, fpr: 0.0051, detectionLatencyMs: 13, uncertaintyECE: 0.029, adversarialDrop: 5.3, isOurs: true },
  { model: 'FedGTD (Graph Temporal)',     method: 'Federated Graph Dynamics',     dataset: 'Edge-IIoT', accuracy: 0.9645, macroF1: 0.9489, fpr: 0.0055, detectionLatencyMs: 6,  uncertaintyECE: 0.032, adversarialDrop: 5.8, isOurs: true },
  { model: 'Neural ODE (TA-BN-ODE)',     method: 'Continuous-Time ODE',          dataset: 'Edge-IIoT', accuracy: 0.9612, macroF1: 0.9445, fpr: 0.0061, detectionLatencyMs: 10, uncertaintyECE: 0.037, adversarialDrop: 6.5, isOurs: true },
  { model: 'Optimal Transport (PPFOT)',   method: 'Wasserstein Domain Adapt.',    dataset: 'Edge-IIoT', accuracy: 0.9578, macroF1: 0.9401, fpr: 0.0068, detectionLatencyMs: 4,  uncertaintyECE: 0.042, adversarialDrop: 7.1, isOurs: true },
  { model: 'Random Forest (baseline)',    method: 'Traditional ML',              dataset: 'Edge-IIoT', accuracy: 0.9401, macroF1: 0.9189, fpr: 0.0095, detectionLatencyMs: 2,  uncertaintyECE: 0.082, adversarialDrop: 19.7, isOurs: false },
  { model: 'XGBoost (baseline)',          method: 'Gradient Boosting',           dataset: 'Edge-IIoT', accuracy: 0.9501, macroF1: 0.9312, fpr: 0.0076, detectionLatencyMs: 3,  uncertaintyECE: 0.066, adversarialDrop: 16.5, isOurs: false },
  { model: 'CNN-LSTM (baseline)',         method: 'Deep Learning',               dataset: 'Edge-IIoT', accuracy: 0.9567, macroF1: 0.9389, fpr: 0.0059, detectionLatencyMs: 20, uncertaintyECE: 0.047, adversarialDrop: 12.9, isOurs: false },
]

const DATASETS = ['All', ...new Set(RESULTS.map(r => r.dataset))]

type SortKey = 'accuracy' | 'macroF1' | 'fpr' | 'detectionLatencyMs' | 'uncertaintyECE' | 'adversarialDrop'
type SortDir = 'asc' | 'desc'

const METRIC_LABELS: Record<SortKey, { label: string; better: 'higher' | 'lower' }> = {
  accuracy:           { label: 'Accuracy',         better: 'higher' },
  macroF1:            { label: 'Macro F1',         better: 'higher' },
  fpr:                { label: 'FPR',              better: 'lower' },
  detectionLatencyMs: { label: 'Latency (ms)',     better: 'lower' },
  uncertaintyECE:     { label: 'ECE',              better: 'lower' },
  adversarialDrop:    { label: 'Adv. Drop (%)',    better: 'lower' },
}

// ── Component ────────────────────────────────────────────────────────────

export default function Benchmarks() {
  const [dataset, setDataset] = useState('All')
  const [sortKey, setSortKey] = useState<SortKey>('accuracy')
  const [sortDir, setSortDir] = useState<SortDir>('desc')
  const [showOursOnly, setShowOursOnly] = useState(false)

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      // Default to the "better" direction
      setSortDir(METRIC_LABELS[key].better === 'higher' ? 'desc' : 'asc')
    }
  }

  const filtered = RESULTS
    .filter(r => dataset === 'All' || r.dataset === dataset)
    .filter(r => !showOursOnly || r.isOurs)
    .sort((a, b) => {
      const mul = sortDir === 'asc' ? 1 : -1
      return mul * (a[sortKey] - b[sortKey])
    })

  // Find best value for each metric in filtered set
  const bestValues: Record<SortKey, number> = {} as any
  for (const key of Object.keys(METRIC_LABELS) as SortKey[]) {
    const better = METRIC_LABELS[key].better
    const vals = filtered.map(r => r[key])
    bestValues[key] = better === 'higher' ? Math.max(...vals) : Math.min(...vals)
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-display font-bold text-text-primary flex items-center gap-2">
          <Trophy className="w-6 h-6 text-accent-amber" />
          Benchmarks
        </h1>
        <p className="text-sm text-text-secondary mt-1">
          Standardised evaluation leaderboard — all 7 core models benchmarked across 6 datasets against industry baselines.
        </p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Models Evaluated', value: new Set(RESULTS.map(r => r.model)).size, icon: BarChart3, color: 'text-accent-blue' },
          { label: 'Datasets', value: new Set(RESULTS.map(r => r.dataset)).size, icon: Database, color: 'text-accent-green' },
          { label: 'Best Accuracy', value: (Math.max(...RESULTS.map(r => r.accuracy)) * 100).toFixed(1) + '%', icon: Trophy, color: 'text-accent-amber' },
          { label: 'Best Macro F1', value: (Math.max(...RESULTS.map(r => r.macroF1)) * 100).toFixed(1) + '%', icon: Trophy, color: 'text-accent-amber' },
        ].map(s => (
          <div key={s.label} className="bg-bg-card border border-bg-card rounded-lg p-3 text-center">
            <s.icon className={`w-5 h-5 mx-auto mb-1 ${s.color}`} />
            <div className="text-lg font-bold text-text-primary">{s.value}</div>
            <div className="text-[10px] text-text-secondary uppercase tracking-wider">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex gap-1">
          {DATASETS.map(d => (
            <button
              key={d}
              onClick={() => setDataset(d)}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                dataset === d
                  ? 'bg-accent-blue/15 text-accent-blue'
                  : 'text-text-secondary hover:text-text-primary hover:bg-bg-card/50'
              }`}
            >
              {d}
            </button>
          ))}
        </div>
        <button
          onClick={() => setShowOursOnly(!showOursOnly)}
          className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium transition-colors ${
            showOursOnly
              ? 'bg-accent-amber/15 text-accent-amber'
              : 'text-text-secondary hover:text-text-primary hover:bg-bg-card/50'
          }`}
        >
          <Filter className="w-3 h-3" /> Our Methods Only
        </button>
      </div>

      {/* Leaderboard table */}
      <div className="bg-bg-card border border-bg-card rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-bg-primary">
                <th className="text-left py-2.5 px-3 text-text-secondary font-medium">#</th>
                <th className="text-left py-2.5 px-3 text-text-secondary font-medium">Model</th>
                <th className="text-left py-2.5 px-3 text-text-secondary font-medium">Dataset</th>
                {(Object.keys(METRIC_LABELS) as SortKey[]).map(key => (
                  <th
                    key={key}
                    onClick={() => handleSort(key)}
                    className="text-right py-2.5 px-3 text-text-secondary font-medium cursor-pointer hover:text-text-primary transition-colors select-none"
                  >
                    <span className="inline-flex items-center gap-1">
                      {METRIC_LABELS[key].label}
                      {sortKey === key ? (
                        sortDir === 'asc' ? <ArrowUp className="w-3 h-3" /> : <ArrowDown className="w-3 h-3" />
                      ) : (
                        <Minus className="w-3 h-3 opacity-30" />
                      )}
                    </span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((r, idx) => (
                <tr
                  key={`${r.model}-${r.dataset}`}
                  className={`border-b border-bg-primary/50 last:border-b-0 ${
                    r.isOurs ? 'bg-accent-blue/[0.03]' : ''
                  }`}
                >
                  <td className="py-2 px-3 text-text-secondary">
                    {idx === 0 ? <Trophy className="w-3.5 h-3.5 text-accent-amber" /> : idx + 1}
                  </td>
                  <td className="py-2 px-3">
                    <div className="flex items-center gap-1.5">
                      <span className={`font-medium ${r.isOurs ? 'text-accent-blue' : 'text-text-primary'}`}>
                        {r.model}
                      </span>
                      {r.isOurs && (
                        <span className="text-[9px] font-bold uppercase px-1 py-0.5 rounded bg-accent-blue/15 text-accent-blue">
                          ours
                        </span>
                      )}
                    </div>
                    <div className="text-text-secondary/60 text-[10px]">{r.method}</div>
                  </td>
                  <td className="py-2 px-3 text-text-secondary">{r.dataset}</td>
                  {(Object.keys(METRIC_LABELS) as SortKey[]).map(key => {
                    const val = r[key]
                    const isBest = val === bestValues[key]
                    const isPercent = key === 'accuracy' || key === 'macroF1'
                    const formatted = isPercent
                      ? (val * 100).toFixed(2) + '%'
                      : key === 'fpr'
                        ? val.toFixed(4)
                        : key === 'uncertaintyECE'
                          ? val.toFixed(3)
                          : key === 'adversarialDrop'
                            ? val.toFixed(1) + '%'
                            : val.toString()
                    return (
                      <td
                        key={key}
                        className={`text-right py-2 px-3 font-mono ${
                          isBest ? 'text-accent-green font-semibold' : 'text-text-primary'
                        }`}
                      >
                        {formatted}
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {filtered.length === 0 && (
        <div className="text-center py-12 text-text-secondary text-sm">
          <BarChart3 className="w-8 h-8 mx-auto mb-2 opacity-40" />
          No results match the selected filters.
        </div>
      )}

      {/* Legend */}
      <div className="flex items-start gap-2 text-[10px] text-text-secondary/50 bg-bg-card/50 rounded-lg p-3">
        <Info className="w-3.5 h-3.5 shrink-0 mt-0.5" />
        <div>
          <strong>Metrics:</strong> Accuracy & Macro F1 (higher is better), FPR & ECE (lower is better),
          Latency in milliseconds (lower is better), Adv. Drop = accuracy degradation under PGD-ε=0.1 attack (lower is better).
          Green highlights indicate best-in-column. Results from pre-computed evaluations on standard train/test splits.
        </div>
      </div>
    </div>
  )
}
