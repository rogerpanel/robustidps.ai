import { useEffect, useState } from 'react'
import {
  Network, Loader2, Server, Shield, Lock, Unlock,
  TrendingUp, BarChart3, Brain, Zap, ChevronDown, ChevronUp,
  Upload, Layers, GitCompare, ArrowRightLeft, Activity,
  ShieldAlert, Target, Sparkles,
} from 'lucide-react'
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid, Legend, BarChart, Bar, Cell, RadarChart, PolarGrid,
  PolarAngleAxis, PolarRadiusAxis, Radar, AreaChart, Area,
  ScatterChart, Scatter, ZAxis,
} from 'recharts'
import FileUpload from '../components/FileUpload'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import { runFederated, runFederatedMulti, runTransferAnalysis, fetchSampleData, fetchModels } from '../utils/api'
import { usePageState } from '../hooks/usePageState'
import { useNoticeBoard } from '../hooks/useNoticeBoard'

const PAGE = 'federated'
const TT = { background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }

const NODE_COLORS = ['#3B82F6', '#22C55E', '#F59E0B', '#EF4444', '#A855F7', '#06B6D4']
const NODE_NAMES = ['Enterprise-HQ', 'Branch-Office-A', 'Branch-Office-B', 'Cloud-DC-1', 'IoT-Gateway', 'Remote-SOC']
const DATASET_COLORS = ['#3B82F6', '#22C55E', '#F59E0B']
const MODEL_COLORS = ['#3B82F6', '#22C55E', '#F59E0B', '#EF4444', '#A855F7', '#06B6D4', '#EC4899']

const STRATEGY_OPTS = [
  { id: 'fedavg', label: 'FedAvg', desc: 'Federated Averaging — equal weight aggregation' },
  { id: 'fedprox', label: 'FedProx', desc: 'Proximal regularisation to prevent local drift' },
  { id: 'weighted', label: 'Weighted', desc: 'Weight by dataset size per node' },
  { id: 'fedgtd', label: 'FedGTD', desc: 'Graph Temporal Dynamics — similarity-graph + temporal momentum aggregation' },
]

interface ModelInfo {
  id: string
  name: string
  description: string
  category: string
  weights_available: boolean
  enabled?: boolean
}

interface NodeResult {
  node: string
  n_samples: number
  local_accuracy: number
  global_accuracy: number
  final_loss: number
  loss_curve: number[]
}

interface RoundResult {
  round: number
  global_accuracy: number
  global_confidence: number
  nodes: NodeResult[]
}

interface RoundAnalytics {
  fedgtd?: {
    byzantine_flags: boolean[]
    n_byzantine_detected: number
    reputation_scores: number[]
    graph_weights: number[]
    final_weights: number[]
    temporal_decay: number
    similarity_matrix: number[][]
    gradient_norms: number[]
  }
  game_dynamics?: {
    drift_magnitude: number
    diffusion_magnitude: number
    poisson_jumps: number
    nash_gap: number
    game_value: number
    defender_strategy: number[]
  }
  convergence?: {
    lyapunov_value: number
    lyapunov_history: number[]
    node_divergences: number[]
    adaptive_lr: number
    is_supermartingale: boolean
    convergence_rate: number
    convergence_detected: boolean
    convergence_round: number | null
  }
  distillation?: {
    kd_losses: number[]
    mean_kd_loss: number
    agreement_rates: number[]
    mean_agreement: number
    confidence_gaps: number[]
    mean_confidence_gap: number
  }
}

interface FedResult {
  sim_id: string
  n_nodes: number
  n_rounds: number
  local_epochs: number
  strategy: string
  dp_enabled: boolean
  dp_sigma: number | null
  iid: boolean
  n_samples_total: number
  node_distribution: { node: string; n_samples: number }[]
  baseline_accuracy: number
  final_accuracy: number
  accuracy_gain: number
  rounds: (RoundResult & { analytics?: RoundAnalytics })[]
  per_class: Record<string, { count: number; accuracy: number }>
  model_used: string
  dataset_name?: string
  dataset_format?: string
  time_ms: number
  convergence_summary?: {
    lyapunov_history: number[]
    converged: boolean
    convergence_round: number | null
  }
  distillation_summary?: {
    mean_kd_loss_history: number[]
    mean_agreement_history: number[]
  }
  game_dynamics_summary?: {
    nash_gap_history: number[]
    drift_history: number[]
    diffusion_history: number[]
    final_defender_strategy: number[]
  }
}

interface TransferMetric {
  source_dataset: string
  target_dataset: string
  source_accuracy: number
  target_accuracy: number
  accuracy_drop: number
  feature_similarity_cka: number
  domain_divergence_mmd: number
  class_distribution_overlap: number
  transferability_score: number
  target_mean_confidence: number
}

interface TransferResult {
  transfer_id: string
  n_datasets: number
  dataset_names: string[]
  n_models: number
  model_names: string[]
  transfer_results: Record<string, {
    cross_dataset: TransferMetric[]
    cross_model: {
      model_accuracies: Record<string, number>
      prediction_agreement: Record<string, number>
      representation_similarity: Record<string, number>
      ensemble_diversity: number
    } | null
  }>
}

interface MultiResult {
  multi_run_id: string
  n_files: number
  n_models: number
  model_names: string[]
  dataset_names: string[]
  runs: FedResult[]
  comparison: Record<string, {
    dataset: string
    model: string
    baseline_accuracy: number
    final_accuracy: number
    accuracy_gain: number
    time_ms: number
    strategy: string
  }>
}

interface SlotState {
  file: File | null
  fileName: string | null
  fileReady: boolean
  fileLoading: boolean
  nNodes: number
  rounds: number
  localEpochs: number
  lr: number
}

const defaultSlot = (): SlotState => ({
  file: null, fileName: null, fileReady: false, fileLoading: false,
  nNodes: 4, rounds: 5, localEpochs: 3, lr: 0.0001,
})

export default function FederatedSimulator() {
  // Mode: 'single' for legacy single-file, 'multi' for multi-file comparison
  const [mode, setMode] = usePageState<'single' | 'multi'>(PAGE, 'mode', 'multi')

  // ── Single mode state (legacy) ──
  const [file, setFile] = usePageState<File | null>(PAGE, 'file', null)
  const [fileName, setFileName] = usePageState<string | null>(PAGE, 'fileName', null)
  const [fileReady, setFileReady] = usePageState(PAGE, 'fileReady', false)
  const [fileLoading, setFileLoading] = usePageState(PAGE, 'fileLoading', false)
  const [selectedModel, setSelectedModel] = usePageState(PAGE, 'selectedModel', 'surrogate')

  // ── Multi mode state ──
  const [slots, setSlots] = useState<SlotState[]>([defaultSlot(), defaultSlot(), defaultSlot()])
  const [selectedModels, setSelectedModels] = usePageState<string[]>(PAGE, 'selectedModels', ['surrogate'])
  const [availableModels, setAvailableModels] = useState<ModelInfo[]>([])

  // ── Shared config ──
  const [nNodes, setNNodes] = usePageState(PAGE, 'nNodes', 4)
  const [rounds, setRounds] = usePageState(PAGE, 'rounds', 5)
  const [localEpochs, setLocalEpochs] = usePageState(PAGE, 'localEpochs', 3)
  const [lr, setLr] = usePageState(PAGE, 'lr', 0.0001)
  const [strategy, setStrategy] = usePageState(PAGE, 'strategy', 'fedavg')
  const [dpEnabled, setDpEnabled] = usePageState(PAGE, 'dpEnabled', false)
  const [dpSigma, setDpSigma] = usePageState(PAGE, 'dpSigma', 0.01)
  const [iid, setIid] = usePageState(PAGE, 'iid', true)
  const [running, setRunning] = usePageState(PAGE, 'running', false)
  const [error, setError] = usePageState(PAGE, 'error', '')
  const [expandedRound, setExpandedRound] = usePageState<number | null>(PAGE, 'expandedRound', null)

  // ── Results ──
  const [result, setResult] = usePageState<FedResult | null>(PAGE, 'result', null)
  const [multiResult, setMultiResult] = usePageState<MultiResult | null>(PAGE, 'multiResult', null)
  const [activeRunIdx, setActiveRunIdx] = usePageState(PAGE, 'activeRunIdx', 0)
  const [transferResult, setTransferResult] = usePageState<TransferResult | null>(PAGE, 'transferResult', null)
  const [transferRunning, setTransferRunning] = usePageState(PAGE, 'transferRunning', false)
  const [showAdvancedAnalytics, setShowAdvancedAnalytics] = usePageState(PAGE, 'showAdvanced', false)

  // Load available models
  useEffect(() => {
    fetchModels()
      .then((data) => {
        const enabled = (data.models ?? []).filter(
          (m: ModelInfo) => m.enabled !== false && m.weights_available
        )
        setAvailableModels(enabled)
      })
      .catch(() => {})
  }, [])

  const { addNotice, updateNotice } = useNoticeBoard()

  // ── Slot handlers ──
  const updateSlot = (idx: number, updates: Partial<SlotState>) => {
    setSlots(prev => prev.map((s, i) => i === idx ? { ...s, ...updates } : s))
  }

  const handleSlotFileSelect = (idx: number, f: File) => {
    updateSlot(idx, { file: f, fileName: f.name, fileLoading: true, fileReady: false })
    const delay = Math.min(Math.max(f.size / 100000, 400), 3000)
    setTimeout(() => {
      updateSlot(idx, { fileLoading: false, fileReady: true })
    }, delay)
  }

  // ── Single mode handler (legacy) ──
  const handleFileSelect = (f: File) => {
    setFileLoading(true)
    setFileReady(false)
    setFile(f)
    setFileName(f.name)
    const delay = Math.min(Math.max(f.size / 100000, 400), 3000)
    setTimeout(() => {
      setFileLoading(false)
      setFileReady(true)
    }, delay)
  }

  const handleRunSingle = async () => {
    if (!file) return
    setRunning(true)
    setError('')
    setResult(null)
    setMultiResult(null)
    const nid = addNotice({ title: `Federated Learning: ${fileName || 'dataset'}`, description: `${nNodes} nodes, ${rounds} rounds, ${strategy}`, status: 'running', page: '/federated' })
    try {
      const data = await runFederated(file, {
        nNodes, rounds, localEpochs, lr, strategy,
        dpEnabled, dpSigma, iid, modelName: selectedModel,
      })
      setResult(data)
      updateNotice(nid, { status: 'completed', title: `Federated Learning complete: ${fileName}` })
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Simulation failed'
      setError(msg)
      updateNotice(nid, { status: 'error', title: `Federated Learning failed`, description: msg })
    } finally {
      setRunning(false)
    }
  }

  // ── Multi mode handler ──
  const handleRunMulti = async () => {
    const activeFiles = slots.filter(s => s.file && s.fileReady)
    if (activeFiles.length === 0 || selectedModels.length === 0) return
    setRunning(true)
    setError('')
    setResult(null)
    setMultiResult(null)
    try {
      const files = slots.map(s => s.file)
      const slotOverrides = slots.map(s => ({
        nNodes: s.nNodes,
        rounds: s.rounds,
        localEpochs: s.localEpochs,
        lr: s.lr,
      }))
      const data = await runFederatedMulti(
        files,
        selectedModels,
        { strategy, dpEnabled, dpSigma, iid },
        slotOverrides,
      )
      setMultiResult(data)
      setActiveRunIdx(0)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Multi-run simulation failed')
    } finally {
      setRunning(false)
    }
  }

  const toggleModel = (modelId: string) => {
    setSelectedModels(prev =>
      prev.includes(modelId)
        ? prev.filter(m => m !== modelId)
        : [...prev, modelId]
    )
  }

  // ── Transfer analysis handler ──
  const handleTransferAnalysis = async () => {
    const activeFiles = slots.filter(s => s.file && s.fileReady)
    if (activeFiles.length < 2 || selectedModels.length === 0) return
    setTransferRunning(true)
    setError('')
    setTransferResult(null)
    try {
      const files = slots.map(s => s.file)
      const data = await runTransferAnalysis(files, selectedModels)
      setTransferResult(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Transfer analysis failed')
    } finally {
      setTransferRunning(false)
    }
  }

  // ── Derived data for charts ──
  const activeResult = mode === 'multi' && multiResult
    ? multiResult.runs[activeRunIdx] || null
    : result

  const convergenceData = activeResult?.rounds.map(r => ({
    round: `R${r.round}`,
    'Global Accuracy': Math.round(r.global_accuracy * 1000) / 10,
    'Confidence': Math.round(r.global_confidence * 1000) / 10,
  })) || []

  const nodeAccData = activeResult?.rounds.map(r => {
    const entry: Record<string, string | number> = { round: `R${r.round}` }
    r.nodes.forEach(n => { entry[n.node] = Math.round(n.local_accuracy * 1000) / 10 })
    return entry
  }) || []

  const nodeNames = activeResult?.node_distribution.map(n => n.node) || []

  const distData = activeResult?.node_distribution.map((n, i) => ({
    name: n.node,
    samples: n.n_samples,
    color: NODE_COLORS[i % NODE_COLORS.length],
  })) || []

  // Cross-dataset comparison data
  const comparisonTableData = multiResult
    ? Object.values(multiResult.comparison)
    : []

  const comparisonChartData = multiResult
    ? multiResult.dataset_names.map(ds => {
        const entry: Record<string, string | number> = { dataset: ds.replace(/\.[^.]+$/, '') }
        multiResult.model_names.forEach(m => {
          const key = `${ds}|${m}`
          const c = multiResult.comparison[key]
          if (c) entry[m] = Math.round(c.final_accuracy * 1000) / 10
        })
        return entry
      })
    : []

  // ── Derived data for advanced analytics ──
  const convergenceAnalytics = activeResult?.rounds.map((r, i) => ({
    round: `R${i + 1}`,
    lyapunov: r.analytics?.convergence?.lyapunov_value ?? 0,
    adaptiveLR: (r.analytics?.convergence?.adaptive_lr ?? 0) * 1e4,
    convergenceRate: r.analytics?.convergence?.convergence_rate ?? 0,
  })) || []

  const distillationAnalytics = activeResult?.rounds.map((r, i) => ({
    round: `R${i + 1}`,
    'KD Loss': r.analytics?.distillation?.mean_kd_loss ?? 0,
    'Agreement': Math.round((r.analytics?.distillation?.mean_agreement ?? 0) * 100 * 10) / 10,
    'Confidence Gap': Math.round(Math.abs(r.analytics?.distillation?.mean_confidence_gap ?? 0) * 100 * 10) / 10,
  })) || []

  const gameDynamicsData = activeResult?.rounds
    .filter(r => r.analytics?.game_dynamics)
    .map((r, i) => ({
      round: `R${i + 1}`,
      'Nash Gap': r.analytics!.game_dynamics!.nash_gap,
      'Drift': r.analytics!.game_dynamics!.drift_magnitude * 1e3,
      'Diffusion': r.analytics!.game_dynamics!.diffusion_magnitude * 1e3,
    })) || []

  const byzantineData = activeResult?.rounds
    .filter(r => r.analytics?.fedgtd)
    .map((r, i) => ({
      round: `R${i + 1}`,
      'Byzantine Detected': r.analytics!.fedgtd!.n_byzantine_detected,
      ...Object.fromEntries(
        r.analytics!.fedgtd!.reputation_scores.map((s, j) =>
          [`Node ${j + 1}`, Math.round(s * 100)]
        )
      ),
    })) || []

  const hasAdvancedAnalytics = activeResult?.rounds.some(r => r.analytics?.convergence || r.analytics?.distillation)
  const hasGameDynamics = activeResult?.rounds.some(r => r.analytics?.game_dynamics)
  const hasByzantine = activeResult?.rounds.some(r => r.analytics?.fedgtd)

  const hasMultiFiles = slots.filter(s => s.file && s.fileReady).length > 0
  const canRunMulti = hasMultiFiles && selectedModels.length > 0 && !running
  const canRunTransfer = slots.filter(s => s.file && s.fileReady).length >= 2 && selectedModels.length > 0 && !transferRunning

  return (
    <div className="space-y-6">
      <PageGuide
        title="How to use Federated Learning Simulator"
        steps={[
          { title: 'Upload datasets', desc: 'Drop up to 3 network traffic CSV files — each can have different hyperparameters.' },
          { title: 'Select models', desc: 'Choose multiple models including the surrogate ensemble for cross-comparison.' },
          { title: 'Configure & run', desc: 'Set strategy, privacy options, and run federated training across all combinations.' },
          { title: 'Compare results', desc: 'View cross-dataset model performance comparison charts and tables.' },
        ]}
        tip="Upload multiple datasets and select multiple models to compare federated learning performance across different data sources."
      />

      {/* Header */}
      <div className="flex items-center gap-3">
        <Network className="w-7 h-7 text-accent-blue" />
        <div className="flex-1">
          <h1 className="text-xl md:text-2xl font-display font-bold">Federated Learning Simulator</h1>
          <p className="text-sm text-text-secondary mt-0.5">Privacy-preserving distributed model training with multi-dataset comparison</p>
        </div>
        <ExportMenu filename="federated-learning" />
      </div>

      {/* Mode Toggle */}
      <div className="flex gap-2">
        <button
          onClick={() => setMode('single')}
          className={`px-4 py-2 rounded-lg text-sm font-medium border transition-colors flex items-center gap-2 ${
            mode === 'single'
              ? 'bg-accent-blue/15 border-accent-blue/40 text-accent-blue'
              : 'bg-bg-secondary border-bg-card text-text-secondary hover:text-text-primary'
          }`}
        >
          <Upload className="w-4 h-4" /> Single Dataset
        </button>
        <button
          onClick={() => setMode('multi')}
          className={`px-4 py-2 rounded-lg text-sm font-medium border transition-colors flex items-center gap-2 ${
            mode === 'multi'
              ? 'bg-accent-green/15 border-accent-green/40 text-accent-green'
              : 'bg-bg-secondary border-bg-card text-text-secondary hover:text-text-primary'
          }`}
        >
          <GitCompare className="w-4 h-4" /> Multi-Dataset Comparison
        </button>
      </div>

      {/* ════════ MULTI MODE ════════ */}
      {mode === 'multi' && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-5">
          {/* 3 File Upload Slots */}
          <div>
            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
              <Layers className="w-4 h-4 text-accent-blue" />
              Dataset Slots (up to 3)
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {slots.map((slot, idx) => (
                <div key={idx} className={`p-4 rounded-lg border ${
                  slot.fileReady ? 'border-accent-green/40 bg-accent-green/5' : 'border-bg-card bg-bg-primary'
                }`}>
                  <div className="flex items-center gap-2 mb-2">
                    <span className={`text-xs font-bold px-2 py-0.5 rounded ${
                      DATASET_COLORS[idx] === '#3B82F6' ? 'bg-accent-blue/15 text-accent-blue' :
                      DATASET_COLORS[idx] === '#22C55E' ? 'bg-accent-green/15 text-accent-green' :
                      'bg-accent-amber/15 text-accent-amber'
                    }`}>
                      Slot {idx + 1}
                    </span>
                    {slot.fileReady && <span className="text-[10px] text-accent-green">Ready</span>}
                  </div>
                  <FileUpload
                    onFile={(f) => handleSlotFileSelect(idx, f)}
                    label={`Dataset ${idx + 1}`}
                    accept=".csv,.parquet,.pcap,.pcapng"
                    fileName={slot.fileName}
                    fileLoading={slot.fileLoading}
                  />
                  {idx === 0 && (
                    <button
                      onClick={async () => {
                        try {
                          const f = await fetchSampleData()
                          handleSlotFileSelect(idx, f)
                        } catch {
                          setError('Failed to load demo data')
                        }
                      }}
                      className="text-[10px] text-accent-blue hover:text-accent-blue/80 underline mt-1"
                    >
                      use demo data
                    </button>
                  )}
                  {/* Per-slot hyperparameters — always visible, disabled until file ready */}
                  <div className={`grid grid-cols-2 gap-2 mt-3 ${!slot.fileReady ? 'opacity-50' : ''}`}>
                    <div>
                      <label className="text-[10px] text-text-secondary block mb-0.5">Nodes</label>
                      <input
                        type="number" min={2} max={6} value={slot.nNodes}
                        disabled={!slot.fileReady}
                        onChange={e => updateSlot(idx, { nNodes: parseInt(e.target.value) || 4 })}
                        className="w-full px-2 py-1 bg-bg-primary border border-bg-card rounded text-xs text-text-primary disabled:cursor-not-allowed"
                      />
                    </div>
                    <div>
                      <label className="text-[10px] text-text-secondary block mb-0.5">Rounds</label>
                      <input
                        type="number" min={1} max={20} value={slot.rounds}
                        disabled={!slot.fileReady}
                        onChange={e => updateSlot(idx, { rounds: parseInt(e.target.value) || 5 })}
                        className="w-full px-2 py-1 bg-bg-primary border border-bg-card rounded text-xs text-text-primary disabled:cursor-not-allowed"
                      />
                    </div>
                    <div>
                      <label className="text-[10px] text-text-secondary block mb-0.5">Local Epochs</label>
                      <input
                        type="number" min={1} max={10} value={slot.localEpochs}
                        disabled={!slot.fileReady}
                        onChange={e => updateSlot(idx, { localEpochs: parseInt(e.target.value) || 3 })}
                        className="w-full px-2 py-1 bg-bg-primary border border-bg-card rounded text-xs text-text-primary disabled:cursor-not-allowed"
                      />
                    </div>
                    <div>
                      <label className="text-[10px] text-text-secondary block mb-0.5">Learning Rate</label>
                      <input
                        type="number" min={0.0001} max={0.1} step={0.0001} value={slot.lr}
                        disabled={!slot.fileReady}
                        onChange={e => updateSlot(idx, { lr: parseFloat(e.target.value) || 0.0001 })}
                        className="w-full px-2 py-1 bg-bg-primary border border-bg-card rounded text-xs text-text-primary disabled:cursor-not-allowed"
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Multi-Model Selection */}
          <div>
            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
              <Brain className="w-4 h-4 text-accent-purple" />
              Select Models (multi-select)
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
              {availableModels.map(m => (
                <button
                  key={m.id}
                  onClick={() => toggleModel(m.id)}
                  className={`text-left px-3 py-2.5 rounded-lg border transition-all ${
                    selectedModels.includes(m.id)
                      ? 'border-accent-blue bg-accent-blue/10'
                      : 'border-bg-card bg-bg-primary hover:border-bg-card/80'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={selectedModels.includes(m.id)}
                      onChange={() => toggleModel(m.id)}
                      className="rounded accent-accent-blue"
                    />
                    <span className="text-xs font-medium">{m.name}</span>
                  </div>
                  <p className="text-[10px] text-text-secondary mt-0.5 ml-5 line-clamp-1">{m.description}</p>
                </button>
              ))}
            </div>
            {selectedModels.length > 0 && (
              <p className="text-[10px] text-text-secondary mt-1">
                {selectedModels.length} model{selectedModels.length > 1 ? 's' : ''} selected
              </p>
            )}
          </div>

          {/* Shared strategy + DP config */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-3">
              <label className="text-xs text-text-secondary block mb-1">Aggregation Strategy</label>
              <div className="flex flex-wrap gap-1.5">
                {STRATEGY_OPTS.map(s => (
                  <button
                    key={s.id}
                    onClick={() => setStrategy(s.id)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                      strategy === s.id
                        ? 'bg-accent-blue/15 border-accent-blue/40 text-accent-blue'
                        : 'bg-bg-primary border-bg-card text-text-secondary hover:text-text-primary'
                    }`}
                    title={s.desc}
                  >
                    {s.label}
                  </button>
                ))}
              </div>

              <div className="flex gap-2">
                <button
                  onClick={() => setIid(true)}
                  className={`flex-1 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                    iid ? 'bg-accent-blue/15 border-accent-blue/40 text-accent-blue' : 'bg-bg-primary border-bg-card text-text-secondary'
                  }`}
                >
                  IID (uniform)
                </button>
                <button
                  onClick={() => setIid(false)}
                  className={`flex-1 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                    !iid ? 'bg-accent-amber/15 border-accent-amber/40 text-accent-amber' : 'bg-bg-primary border-bg-card text-text-secondary'
                  }`}
                >
                  Non-IID (skewed)
                </button>
              </div>
            </div>

            <div className="p-3 rounded-lg border border-bg-card bg-bg-primary">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox" checked={dpEnabled}
                  onChange={e => setDpEnabled(e.target.checked)}
                  className="rounded accent-accent-green"
                />
                <span className="text-xs font-medium flex items-center gap-1">
                  {dpEnabled ? <Lock className="w-3 h-3 text-accent-green" /> : <Unlock className="w-3 h-3 text-text-secondary" />}
                  Differential Privacy
                </span>
              </label>
              {dpEnabled && (
                <div className="mt-2">
                  <label className="text-[10px] text-text-secondary block mb-1">Noise sigma</label>
                  <input
                    type="range" min={0.001} max={0.1} step={0.001}
                    value={dpSigma}
                    onChange={e => setDpSigma(parseFloat(e.target.value))}
                    className="w-full accent-accent-green"
                  />
                  <div className="flex justify-between text-[10px] text-text-secondary">
                    <span>Low noise</span>
                    <span className="font-mono text-accent-green">{dpSigma.toFixed(3)}</span>
                    <span>High privacy</span>
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="flex gap-3">
            <button
              onClick={handleRunMulti}
              disabled={!canRunMulti}
              className="px-5 py-2.5 bg-accent-green text-white rounded-lg text-sm font-medium hover:bg-accent-green/80 transition-colors disabled:opacity-40 flex items-center gap-2"
            >
              {running ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Running multi-dataset comparison...
                </>
              ) : (
                <>
                  <GitCompare className="w-4 h-4" />
                  Run Multi-Dataset Comparison
                </>
              )}
            </button>
            <button
              onClick={handleTransferAnalysis}
              disabled={!canRunTransfer}
              className="px-5 py-2.5 bg-accent-purple/80 text-white rounded-lg text-sm font-medium hover:bg-accent-purple/60 transition-colors disabled:opacity-40 flex items-center gap-2"
            >
              {transferRunning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Analysing transfer...
                </>
              ) : (
                <>
                  <ArrowRightLeft className="w-4 h-4" />
                  Transfer Learning Analysis
                </>
              )}
            </button>
          </div>

          {error && (
            <div className="px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">
              {error}
            </div>
          )}
        </div>
      )}

      {/* ════════ SINGLE MODE ════════ */}
      {mode === 'single' && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="space-y-3">
              <FileUpload
                onFile={handleFileSelect}
                label="Upload traffic dataset"
                accept=".csv,.parquet,.pcap,.pcapng"
                fileName={fileName}
                fileLoading={fileLoading}
              />
              <button
                onClick={async () => {
                  try {
                    setFileLoading(true)
                    setFileReady(false)
                    const f = await fetchSampleData()
                    handleFileSelect(f)
                  } catch {
                    setFileLoading(false)
                    setError('Failed to load demo data')
                  }
                }}
                className="text-xs text-accent-blue hover:text-accent-blue/80 underline"
              >
                or use built-in demo data (1000 flows)
              </button>
              {/* Single model selector — pick from available models */}
              <div className="space-y-2">
                <h3 className="text-sm font-medium text-text-secondary flex items-center gap-2">
                  <Brain className="w-4 h-4" /> Select Model
                </h3>
                <div className="grid grid-cols-1 gap-1.5">
                  {availableModels.map(m => (
                    <button
                      key={m.id}
                      onClick={() => setSelectedModel(m.id)}
                      className={`text-left px-3 py-2 rounded-lg border text-xs transition-all ${
                        selectedModel === m.id
                          ? 'border-accent-blue bg-accent-blue/10 text-accent-blue'
                          : 'border-bg-card bg-bg-primary text-text-secondary hover:text-text-primary'
                      }`}
                    >
                      {m.name}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-xs text-text-secondary block mb-1">Nodes</label>
                  <input
                    type="number" min={2} max={6} value={nNodes}
                    onChange={e => setNNodes(parseInt(e.target.value) || 4)}
                    className="w-full px-2 py-1 bg-bg-primary border border-bg-card rounded text-sm text-text-primary"
                  />
                </div>
                <div>
                  <label className="text-xs text-text-secondary block mb-1">Rounds</label>
                  <input
                    type="number" min={1} max={20} value={rounds}
                    onChange={e => setRounds(parseInt(e.target.value) || 5)}
                    className="w-full px-2 py-1 bg-bg-primary border border-bg-card rounded text-sm text-text-primary"
                  />
                </div>
                <div>
                  <label className="text-xs text-text-secondary block mb-1">Local Epochs</label>
                  <input
                    type="number" min={1} max={10} value={localEpochs}
                    onChange={e => setLocalEpochs(parseInt(e.target.value) || 3)}
                    className="w-full px-2 py-1 bg-bg-primary border border-bg-card rounded text-sm text-text-primary"
                  />
                </div>
                <div>
                  <label className="text-xs text-text-secondary block mb-1">Learning Rate</label>
                  <input
                    type="number" min={0.0001} max={0.1} step={0.0001} value={lr}
                    onChange={e => setLr(parseFloat(e.target.value) || 0.001)}
                    className="w-full px-2 py-1 bg-bg-primary border border-bg-card rounded text-sm text-text-primary"
                  />
                </div>
              </div>
              <div>
                <label className="text-xs text-text-secondary block mb-1">Data Distribution</label>
                <div className="flex gap-2">
                  <button
                    onClick={() => setIid(true)}
                    className={`flex-1 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                      iid ? 'bg-accent-blue/15 border-accent-blue/40 text-accent-blue' : 'bg-bg-primary border-bg-card text-text-secondary'
                    }`}
                  >
                    IID (uniform)
                  </button>
                  <button
                    onClick={() => setIid(false)}
                    className={`flex-1 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                      !iid ? 'bg-accent-amber/15 border-accent-amber/40 text-accent-amber' : 'bg-bg-primary border-bg-card text-text-secondary'
                    }`}
                  >
                    Non-IID (skewed)
                  </button>
                </div>
              </div>
            </div>

            <div className="space-y-3">
              <div>
                <label className="text-xs text-text-secondary block mb-2">Aggregation Strategy</label>
                <div className="flex flex-col gap-1.5">
                  {STRATEGY_OPTS.map(s => (
                    <button
                      key={s.id}
                      onClick={() => setStrategy(s.id)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors text-left ${
                        strategy === s.id
                          ? 'bg-accent-blue/15 border-accent-blue/40 text-accent-blue'
                          : 'bg-bg-primary border-bg-card text-text-secondary hover:text-text-primary'
                      }`}
                      title={s.desc}
                    >
                      {s.label}
                      <span className="text-[10px] text-text-secondary ml-1.5">{s.desc.split('—')[1]?.trim()}</span>
                    </button>
                  ))}
                </div>
              </div>
              <div className="p-3 rounded-lg border border-bg-card bg-bg-primary">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox" checked={dpEnabled}
                    onChange={e => setDpEnabled(e.target.checked)}
                    className="rounded accent-accent-green"
                  />
                  <span className="text-xs font-medium flex items-center gap-1">
                    {dpEnabled ? <Lock className="w-3 h-3 text-accent-green" /> : <Unlock className="w-3 h-3 text-text-secondary" />}
                    Differential Privacy
                  </span>
                </label>
                {dpEnabled && (
                  <div className="mt-2">
                    <label className="text-[10px] text-text-secondary block mb-1">Noise sigma</label>
                    <input
                      type="range" min={0.001} max={0.1} step={0.001}
                      value={dpSigma}
                      onChange={e => setDpSigma(parseFloat(e.target.value))}
                      className="w-full accent-accent-green"
                    />
                    <div className="flex justify-between text-[10px] text-text-secondary">
                      <span>Low noise</span>
                      <span className="font-mono text-accent-green">{dpSigma.toFixed(3)}</span>
                      <span>High privacy</span>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>

          <button
            onClick={handleRunSingle}
            disabled={!file || !fileReady || running || fileLoading}
            className="px-5 py-2.5 bg-accent-blue text-white rounded-lg text-sm font-medium hover:bg-accent-blue/80 transition-colors disabled:opacity-40 flex items-center gap-2"
          >
            {running ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Running simulation...
              </>
            ) : (
              <>
                <Network className="w-4 h-4" />
                Run Simulation
              </>
            )}
          </button>

          {error && (
            <div className="px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">
              {error}
            </div>
          )}
        </div>
      )}

      {/* ════════ MULTI-RESULT: Cross-Dataset Comparison ════════ */}
      {multiResult && (
        <>
          {/* Comparison Summary */}
          <div className="bg-bg-secondary rounded-xl p-5 border border-accent-green/30 space-y-4">
            <h3 className="text-sm font-semibold flex items-center gap-2">
              <GitCompare className="w-4 h-4 text-accent-green" />
              Cross-Dataset Model Comparison
              <span className="text-[10px] text-text-secondary ml-2">
                {multiResult.n_files} datasets × {multiResult.n_models} models = {multiResult.runs.length} runs
              </span>
            </h3>

            {/* Comparison Bar Chart */}
            {comparisonChartData.length > 0 && (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={comparisonChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="dataset" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" domain={[0, 100]} />
                  <Tooltip contentStyle={TT} />
                  {multiResult.model_names.map((m, i) => (
                    <Bar key={m} dataKey={m} fill={MODEL_COLORS[i % MODEL_COLORS.length]} radius={[4, 4, 0, 0]} />
                  ))}
                  <Legend wrapperStyle={{ fontSize: 10, color: '#94A3B8' }} />
                </BarChart>
              </ResponsiveContainer>
            )}

            {/* Comparison Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-bg-card">
                    <th className="text-left py-2 px-3 text-text-secondary font-medium">Dataset</th>
                    <th className="text-left py-2 px-3 text-text-secondary font-medium">Model</th>
                    <th className="text-right py-2 px-3 text-text-secondary font-medium">Baseline</th>
                    <th className="text-right py-2 px-3 text-text-secondary font-medium">Final Acc</th>
                    <th className="text-right py-2 px-3 text-text-secondary font-medium">Gain</th>
                    <th className="text-right py-2 px-3 text-text-secondary font-medium">Strategy</th>
                    <th className="text-right py-2 px-3 text-text-secondary font-medium">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {comparisonTableData.map((c, i) => (
                    <tr key={i} className="border-b border-bg-card/50 hover:bg-bg-card/20 transition-colors">
                      <td className="py-2 px-3 font-mono">{c.dataset.replace(/\.[^.]+$/, '')}</td>
                      <td className="py-2 px-3">{c.model}</td>
                      <td className="py-2 px-3 text-right font-mono text-text-secondary">
                        {(c.baseline_accuracy * 100).toFixed(1)}%
                      </td>
                      <td className="py-2 px-3 text-right font-mono text-accent-green font-bold">
                        {(c.final_accuracy * 100).toFixed(1)}%
                      </td>
                      <td className={`py-2 px-3 text-right font-mono font-bold ${
                        c.accuracy_gain >= 0 ? 'text-accent-green' : 'text-accent-red'
                      }`}>
                        {c.accuracy_gain >= 0 ? '+' : ''}{(c.accuracy_gain * 100).toFixed(1)}%
                      </td>
                      <td className="py-2 px-3 text-right uppercase">{c.strategy}</td>
                      <td className="py-2 px-3 text-right font-mono text-text-secondary">{c.time_ms.toFixed(0)}ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Run selector tabs */}
          <div className="flex gap-1 flex-wrap">
            {multiResult.runs.map((r, i) => (
              <button
                key={i}
                onClick={() => setActiveRunIdx(i)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                  activeRunIdx === i
                    ? 'bg-accent-blue/15 border-accent-blue/40 text-accent-blue'
                    : 'bg-bg-secondary border-bg-card text-text-secondary hover:text-text-primary'
                }`}
              >
                {(r.dataset_name || `Dataset ${r.slot_index !== undefined ? r.slot_index + 1 : i + 1}`).replace(/\.[^.]+$/, '')}
                {' / '}
                {r.model_used}
              </button>
            ))}
          </div>
        </>
      )}

      {/* ════════ RESULTS (shared between single + multi active run) ════════ */}
      {activeResult && (
        <>
          {/* Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <TrendingUp className="w-3.5 h-3.5" /> Baseline
              </div>
              <div className="text-xl font-mono font-bold text-text-secondary">
                {(activeResult.baseline_accuracy * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Shield className="w-3.5 h-3.5" /> Final
              </div>
              <div className={`text-xl font-mono font-bold ${
                activeResult.accuracy_gain >= 0 ? 'text-accent-green' : 'text-accent-red'
              }`}>
                {(activeResult.final_accuracy * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Zap className="w-3.5 h-3.5" /> Gain
              </div>
              <div className={`text-xl font-mono font-bold ${
                activeResult.accuracy_gain >= 0 ? 'text-accent-green' : 'text-accent-red'
              }`}>
                {activeResult.accuracy_gain >= 0 ? '+' : ''}{(activeResult.accuracy_gain * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Server className="w-3.5 h-3.5" /> Nodes
              </div>
              <div className="text-xl font-mono font-bold text-accent-blue">
                {activeResult.n_nodes}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                {activeResult.dp_enabled ? <Lock className="w-3.5 h-3.5" /> : <Unlock className="w-3.5 h-3.5" />}
                {activeResult.dp_enabled ? 'DP On' : 'DP Off'}
              </div>
              <div className="text-sm font-mono font-bold text-text-primary">
                {activeResult.strategy.toUpperCase()}
                {activeResult.dp_enabled && ` σ=${activeResult.dp_sigma}`}
              </div>
            </div>
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h3 className="text-sm font-semibold mb-3">Global Convergence</h3>
              <ResponsiveContainer width="100%" height={280}>
                <LineChart data={convergenceData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="round" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" domain={['auto', 'auto']} />
                  <Tooltip contentStyle={TT} />
                  <Line type="monotone" dataKey="Global Accuracy" stroke="#22C55E" strokeWidth={2} dot={{ r: 3 }} />
                  <Line type="monotone" dataKey="Confidence" stroke="#3B82F6" strokeWidth={2} dot={{ r: 3 }} strokeDasharray="5 5" />
                  <Legend wrapperStyle={{ fontSize: 11, color: '#94A3B8' }} />
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h3 className="text-sm font-semibold mb-3">Data Distribution per Node</h3>
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={distData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="name" tick={{ fill: '#94A3B8', fontSize: 9 }} />
                  <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} />
                  <Tooltip contentStyle={TT} />
                  <Bar dataKey="samples" radius={[4, 4, 0, 0]}>
                    {distData.map((d, i) => (
                      <Cell key={i} fill={d.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Per-node accuracy over rounds */}
          {nodeNames.length > 0 && (
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h3 className="text-sm font-semibold mb-3">Per-Node Local Accuracy</h3>
              <ResponsiveContainer width="100%" height={280}>
                <LineChart data={nodeAccData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="round" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" domain={['auto', 'auto']} />
                  <Tooltip contentStyle={TT} />
                  {nodeNames.map((name, i) => (
                    <Line
                      key={name}
                      type="monotone"
                      dataKey={name}
                      stroke={NODE_COLORS[i % NODE_COLORS.length]}
                      strokeWidth={1.5}
                      dot={{ r: 2 }}
                    />
                  ))}
                  <Legend wrapperStyle={{ fontSize: 10, color: '#94A3B8' }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* ════════ ADVANCED ANALYTICS TOGGLE ════════ */}
          {hasAdvancedAnalytics && (
            <button
              onClick={() => setShowAdvancedAnalytics(!showAdvancedAnalytics)}
              className="w-full px-4 py-3 bg-bg-secondary rounded-xl border border-accent-purple/30 hover:border-accent-purple/50 transition-colors flex items-center gap-3"
            >
              <Sparkles className="w-4 h-4 text-accent-purple" />
              <span className="text-sm font-semibold flex-1 text-left">
                Advanced Analytics
                <span className="text-[10px] text-text-secondary ml-2">
                  Convergence · Distillation · {hasGameDynamics ? 'Game Dynamics · ' : ''}{hasByzantine ? 'Byzantine Detection' : ''}
                </span>
              </span>
              {showAdvancedAnalytics ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
          )}

          {/* ════════ ADVANCED ANALYTICS PANELS ════════ */}
          {showAdvancedAnalytics && hasAdvancedAnalytics && (
            <>
              {/* Convergence Analysis (Lyapunov + Adaptive LR) */}
              {convergenceAnalytics.length > 0 && (
                <div className="bg-bg-secondary rounded-xl p-5 border border-accent-purple/20 space-y-3">
                  <h3 className="text-sm font-semibold flex items-center gap-2">
                    <Activity className="w-4 h-4 text-accent-purple" />
                    Martingale Convergence Analysis
                    {activeResult?.convergence_summary?.converged && (
                      <span className="text-[10px] bg-accent-green/15 text-accent-green px-2 py-0.5 rounded">
                        Converged at R{activeResult.convergence_summary.convergence_round}
                      </span>
                    )}
                  </h3>
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    <div>
                      <p className="text-[10px] text-text-secondary mb-2">Lyapunov Function V(t) — Supermartingale Decay</p>
                      <ResponsiveContainer width="100%" height={220}>
                        <AreaChart data={convergenceAnalytics}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                          <XAxis dataKey="round" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                          <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} />
                          <Tooltip contentStyle={TT} />
                          <Area type="monotone" dataKey="lyapunov" stroke="#A855F7" fill="#A855F7" fillOpacity={0.15} strokeWidth={2} name="Lyapunov V(t)" />
                          <Legend wrapperStyle={{ fontSize: 10, color: '#94A3B8' }} />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                    <div>
                      <p className="text-[10px] text-text-secondary mb-2">Convergence Rate & Adaptive Learning Rate</p>
                      <ResponsiveContainer width="100%" height={220}>
                        <LineChart data={convergenceAnalytics}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                          <XAxis dataKey="round" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                          <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} />
                          <Tooltip contentStyle={TT} />
                          <Line type="monotone" dataKey="convergenceRate" stroke="#22C55E" strokeWidth={2} dot={{ r: 2 }} name="Conv. Rate" />
                          <Line type="monotone" dataKey="adaptiveLR" stroke="#F59E0B" strokeWidth={1.5} dot={{ r: 2 }} name="η(t) ×10⁴" strokeDasharray="4 4" />
                          <Legend wrapperStyle={{ fontSize: 10, color: '#94A3B8' }} />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                  {/* Convergence summary cards */}
                  <div className="grid grid-cols-3 gap-3">
                    <div className="bg-bg-primary rounded-lg p-3 text-center">
                      <p className="text-[10px] text-text-secondary">Final Lyapunov</p>
                      <p className="text-sm font-mono font-bold text-accent-purple">
                        {convergenceAnalytics[convergenceAnalytics.length - 1]?.lyapunov.toFixed(4) || '—'}
                      </p>
                    </div>
                    <div className="bg-bg-primary rounded-lg p-3 text-center">
                      <p className="text-[10px] text-text-secondary">Conv. Rate</p>
                      <p className="text-sm font-mono font-bold text-accent-green">
                        {convergenceAnalytics[convergenceAnalytics.length - 1]?.convergenceRate.toFixed(4) || '—'}
                      </p>
                    </div>
                    <div className="bg-bg-primary rounded-lg p-3 text-center">
                      <p className="text-[10px] text-text-secondary">Status</p>
                      <p className={`text-sm font-bold ${activeResult?.convergence_summary?.converged ? 'text-accent-green' : 'text-accent-amber'}`}>
                        {activeResult?.convergence_summary?.converged ? 'Converged' : 'In Progress'}
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Knowledge Distillation Metrics */}
              {distillationAnalytics.length > 0 && (
                <div className="bg-bg-secondary rounded-xl p-5 border border-accent-blue/20 space-y-3">
                  <h3 className="text-sm font-semibold flex items-center gap-2">
                    <Brain className="w-4 h-4 text-accent-blue" />
                    Knowledge Distillation Analysis
                    <span className="text-[10px] text-text-secondary ml-2">Teacher (global) → Student (local) alignment</span>
                  </h3>
                  <ResponsiveContainer width="100%" height={260}>
                    <LineChart data={distillationAnalytics}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis dataKey="round" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                      <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} />
                      <Tooltip contentStyle={TT} />
                      <Line type="monotone" dataKey="KD Loss" stroke="#EF4444" strokeWidth={2} dot={{ r: 2 }} />
                      <Line type="monotone" dataKey="Agreement" stroke="#22C55E" strokeWidth={2} dot={{ r: 2 }} />
                      <Line type="monotone" dataKey="Confidence Gap" stroke="#F59E0B" strokeWidth={1.5} dot={{ r: 2 }} strokeDasharray="4 4" />
                      <Legend wrapperStyle={{ fontSize: 10, color: '#94A3B8' }} />
                    </LineChart>
                  </ResponsiveContainer>
                  <div className="grid grid-cols-3 gap-3">
                    <div className="bg-bg-primary rounded-lg p-3 text-center">
                      <p className="text-[10px] text-text-secondary">Final KD Loss</p>
                      <p className="text-sm font-mono font-bold text-accent-red">
                        {activeResult?.distillation_summary?.mean_kd_loss_history.slice(-1)[0]?.toFixed(3) || '—'}
                      </p>
                    </div>
                    <div className="bg-bg-primary rounded-lg p-3 text-center">
                      <p className="text-[10px] text-text-secondary">Final Agreement</p>
                      <p className="text-sm font-mono font-bold text-accent-green">
                        {((activeResult?.distillation_summary?.mean_agreement_history.slice(-1)[0] ?? 0) * 100).toFixed(1)}%
                      </p>
                    </div>
                    <div className="bg-bg-primary rounded-lg p-3 text-center">
                      <p className="text-[10px] text-text-secondary">KD Loss Δ</p>
                      <p className="text-sm font-mono font-bold text-accent-blue">
                        {(() => {
                          const h = activeResult?.distillation_summary?.mean_kd_loss_history
                          if (!h || h.length < 2) return '—'
                          const d = h[h.length - 1] - h[0]
                          return `${d >= 0 ? '+' : ''}${d.toFixed(3)}`
                        })()}
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Stochastic Game Dynamics (FedGTD only) */}
              {hasGameDynamics && gameDynamicsData.length > 0 && (
                <div className="bg-bg-secondary rounded-xl p-5 border border-accent-amber/20 space-y-3">
                  <h3 className="text-sm font-semibold flex items-center gap-2">
                    <Target className="w-4 h-4 text-accent-amber" />
                    Stochastic Game Dynamics (SDE + Nash Equilibrium)
                    <span className="text-[10px] text-text-secondary ml-2">dX = μdt + ΣdW + JdN(λ)</span>
                  </h3>
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    <div>
                      <p className="text-[10px] text-text-secondary mb-2">Nash Gap & Game Dynamics Evolution</p>
                      <ResponsiveContainer width="100%" height={220}>
                        <LineChart data={gameDynamicsData}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                          <XAxis dataKey="round" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                          <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} />
                          <Tooltip contentStyle={TT} />
                          <Line type="monotone" dataKey="Nash Gap" stroke="#F59E0B" strokeWidth={2} dot={{ r: 3 }} />
                          <Line type="monotone" dataKey="Drift" stroke="#3B82F6" strokeWidth={1.5} dot={{ r: 2 }} name="Drift ×10³" />
                          <Line type="monotone" dataKey="Diffusion" stroke="#A855F7" strokeWidth={1.5} dot={{ r: 2 }} name="Diffusion ×10³" strokeDasharray="4 4" />
                          <Legend wrapperStyle={{ fontSize: 10, color: '#94A3B8' }} />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                    <div>
                      <p className="text-[10px] text-text-secondary mb-2">Final Defender Strategy (Nash Equilibrium)</p>
                      <ResponsiveContainer width="100%" height={220}>
                        <BarChart data={
                          activeResult?.game_dynamics_summary?.final_defender_strategy.map((s, i) => ({
                            node: NODE_NAMES[i] || `Node ${i + 1}`,
                            strategy: Math.round(s * 1000) / 10,
                          })) || []
                        }>
                          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                          <XAxis dataKey="node" tick={{ fill: '#94A3B8', fontSize: 8 }} />
                          <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" />
                          <Tooltip contentStyle={TT} />
                          <Bar dataKey="strategy" name="Defence Weight" radius={[4, 4, 0, 0]}>
                            {(activeResult?.game_dynamics_summary?.final_defender_strategy || []).map((_, i) => (
                              <Cell key={i} fill={NODE_COLORS[i % NODE_COLORS.length]} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                  <div className="grid grid-cols-4 gap-3">
                    <div className="bg-bg-primary rounded-lg p-3 text-center">
                      <p className="text-[10px] text-text-secondary">Final Nash Gap</p>
                      <p className="text-sm font-mono font-bold text-accent-amber">
                        {activeResult?.game_dynamics_summary?.nash_gap_history.slice(-1)[0]?.toFixed(4) || '—'}
                      </p>
                    </div>
                    <div className="bg-bg-primary rounded-lg p-3 text-center">
                      <p className="text-[10px] text-text-secondary">Final Drift</p>
                      <p className="text-sm font-mono font-bold text-accent-blue">
                        {activeResult?.game_dynamics_summary?.drift_history.slice(-1)[0]?.toFixed(6) || '—'}
                      </p>
                    </div>
                    <div className="bg-bg-primary rounded-lg p-3 text-center">
                      <p className="text-[10px] text-text-secondary">Final Diffusion</p>
                      <p className="text-sm font-mono font-bold text-accent-purple">
                        {activeResult?.game_dynamics_summary?.diffusion_history.slice(-1)[0]?.toFixed(6) || '—'}
                      </p>
                    </div>
                    <div className="bg-bg-primary rounded-lg p-3 text-center">
                      <p className="text-[10px] text-text-secondary">Nash Convergence</p>
                      <p className={`text-sm font-bold ${
                        (activeResult?.game_dynamics_summary?.nash_gap_history.slice(-1)[0] ?? 1) < 0.1
                          ? 'text-accent-green' : 'text-accent-amber'
                      }`}>
                        {(activeResult?.game_dynamics_summary?.nash_gap_history.slice(-1)[0] ?? 1) < 0.1 ? 'Near Nash' : 'Evolving'}
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Byzantine Detection (FedGTD only) */}
              {hasByzantine && byzantineData.length > 0 && (
                <div className="bg-bg-secondary rounded-xl p-5 border border-accent-red/20 space-y-3">
                  <h3 className="text-sm font-semibold flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-accent-red" />
                    Byzantine-Resilient Aggregation
                    <span className="text-[10px] text-text-secondary ml-2">Projection-based detection + trimmed mean</span>
                  </h3>
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    <div>
                      <p className="text-[10px] text-text-secondary mb-2">Byzantine Detections per Round</p>
                      <ResponsiveContainer width="100%" height={220}>
                        <BarChart data={byzantineData}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                          <XAxis dataKey="round" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                          <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} />
                          <Tooltip contentStyle={TT} />
                          <Bar dataKey="Byzantine Detected" fill="#EF4444" radius={[4, 4, 0, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                    <div>
                      <p className="text-[10px] text-text-secondary mb-2">Node Reputation Scores Over Rounds (%)</p>
                      <ResponsiveContainer width="100%" height={220}>
                        <LineChart data={byzantineData}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                          <XAxis dataKey="round" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                          <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" domain={[0, 100]} />
                          <Tooltip contentStyle={TT} />
                          {Array.from({ length: activeResult?.n_nodes || 0 }, (_, i) => (
                            <Line
                              key={i}
                              type="monotone"
                              dataKey={`Node ${i + 1}`}
                              stroke={NODE_COLORS[i % NODE_COLORS.length]}
                              strokeWidth={1.5}
                              dot={{ r: 2 }}
                            />
                          ))}
                          <Legend wrapperStyle={{ fontSize: 10, color: '#94A3B8' }} />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                  {/* Similarity Heatmap (last round) */}
                  {(() => {
                    const lastRound = activeResult?.rounds.slice(-1)[0]
                    const simMatrix = lastRound?.analytics?.fedgtd?.similarity_matrix
                    if (!simMatrix) return null
                    return (
                      <div>
                        <p className="text-[10px] text-text-secondary mb-2">Node Similarity Matrix (Final Round)</p>
                        <div className="overflow-x-auto">
                          <table className="text-[10px] font-mono">
                            <thead>
                              <tr>
                                <th className="px-2 py-1"></th>
                                {simMatrix.map((_, i) => (
                                  <th key={i} className="px-2 py-1 text-text-secondary">{NODE_NAMES[i]?.split('-')[0] || `N${i}`}</th>
                                ))}
                              </tr>
                            </thead>
                            <tbody>
                              {simMatrix.map((row, i) => (
                                <tr key={i}>
                                  <td className="px-2 py-1 text-text-secondary">{NODE_NAMES[i]?.split('-')[0] || `N${i}`}</td>
                                  {row.map((val, j) => (
                                    <td key={j} className="px-2 py-1 text-center" style={{
                                      backgroundColor: `rgba(${val > 0.5 ? '34,197,94' : val > 0 ? '245,158,11' : '239,68,68'}, ${Math.abs(val) * 0.3})`,
                                    }}>
                                      {val.toFixed(2)}
                                    </td>
                                  ))}
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )
                  })()}
                </div>
              )}
            </>
          )}

          {/* Round details */}
          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-text-secondary">Round Details</h3>
            {activeResult.rounds.map(r => (
              <div key={r.round} className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
                <button
                  onClick={() => setExpandedRound(expandedRound === r.round ? null : r.round)}
                  className="w-full px-4 py-3 flex items-center gap-3 hover:bg-bg-card/30 transition-colors"
                >
                  <span className="text-xs font-mono bg-accent-blue/15 text-accent-blue px-2 py-0.5 rounded">
                    R{r.round}
                  </span>
                  <span className="text-sm flex-1 text-left">
                    Global: <span className="font-mono text-accent-green">{(r.global_accuracy * 100).toFixed(1)}%</span>
                  </span>
                  <span className="text-xs text-text-secondary">
                    Confidence: <span className="font-mono">{(r.global_confidence * 100).toFixed(1)}%</span>
                  </span>
                  {expandedRound === r.round ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>

                {expandedRound === r.round && (
                  <div className="px-4 pb-4 border-t border-bg-card">
                    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2 mt-3">
                      {r.nodes.map((n, i) => (
                        <div key={n.node} className="bg-bg-primary rounded-lg p-3 text-xs">
                          <div className="flex items-center gap-2 mb-2">
                            <Server className="w-3 h-3" style={{ color: NODE_COLORS[i % NODE_COLORS.length] }} />
                            <span className="font-medium truncate">{n.node}</span>
                          </div>
                          <div className="space-y-1">
                            <div className="flex justify-between">
                              <span className="text-text-secondary">Local acc:</span>
                              <span className="font-mono text-accent-green">{(n.local_accuracy * 100).toFixed(1)}%</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-text-secondary">Global acc:</span>
                              <span className="font-mono text-accent-blue">{(n.global_accuracy * 100).toFixed(1)}%</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-text-secondary">Loss:</span>
                              <span className="font-mono">{n.final_loss.toFixed(3)}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-text-secondary">Samples:</span>
                              <span className="font-mono">{n.n_samples}</span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </>
      )}

      {/* ════════ TRANSFER LEARNING ANALYSIS RESULTS ════════ */}
      {transferResult && (
        <div className="space-y-4">
          <div className="bg-bg-secondary rounded-xl p-5 border border-accent-purple/30 space-y-4">
            <h3 className="text-sm font-semibold flex items-center gap-2">
              <ArrowRightLeft className="w-4 h-4 text-accent-purple" />
              Transfer Learning Analysis
              <span className="text-[10px] text-text-secondary ml-2">
                {transferResult.n_datasets} datasets × {transferResult.n_models} models
              </span>
            </h3>

            {/* Transfer matrix for each model */}
            {transferResult.model_names.map(modelName => {
              const modelTransfer = transferResult.transfer_results[modelName]
              if (!modelTransfer) return null

              const crossDataset = modelTransfer.cross_dataset
              const crossModel = modelTransfer.cross_model

              return (
                <div key={modelName} className="space-y-4">
                  <h4 className="text-xs font-semibold flex items-center gap-2">
                    <Brain className="w-3.5 h-3.5 text-accent-blue" />
                    {modelName}
                  </h4>

                  {/* Cross-Dataset Transfer Table */}
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b border-bg-card">
                          <th className="text-left py-2 px-3 text-text-secondary font-medium">Source → Target</th>
                          <th className="text-right py-2 px-3 text-text-secondary font-medium">Src Acc</th>
                          <th className="text-right py-2 px-3 text-text-secondary font-medium">Tgt Acc</th>
                          <th className="text-right py-2 px-3 text-text-secondary font-medium">Drop</th>
                          <th className="text-right py-2 px-3 text-text-secondary font-medium">CKA Sim.</th>
                          <th className="text-right py-2 px-3 text-text-secondary font-medium">MMD Div.</th>
                          <th className="text-right py-2 px-3 text-text-secondary font-medium">Class Overlap</th>
                          <th className="text-right py-2 px-3 text-text-secondary font-medium">Transfer Score</th>
                        </tr>
                      </thead>
                      <tbody>
                        {crossDataset.map((t, i) => (
                          <tr key={i} className="border-b border-bg-card/50 hover:bg-bg-card/20">
                            <td className="py-2 px-3 font-mono text-[10px]">
                              {t.source_dataset.replace(/\.[^.]+$/, '')} → {t.target_dataset.replace(/\.[^.]+$/, '')}
                            </td>
                            <td className="py-2 px-3 text-right font-mono text-accent-blue">
                              {(t.source_accuracy * 100).toFixed(1)}%
                            </td>
                            <td className="py-2 px-3 text-right font-mono text-accent-green">
                              {(t.target_accuracy * 100).toFixed(1)}%
                            </td>
                            <td className={`py-2 px-3 text-right font-mono font-bold ${
                              t.accuracy_drop > 0.1 ? 'text-accent-red' : t.accuracy_drop > 0 ? 'text-accent-amber' : 'text-accent-green'
                            }`}>
                              {t.accuracy_drop >= 0 ? '-' : '+'}{Math.abs(t.accuracy_drop * 100).toFixed(1)}%
                            </td>
                            <td className="py-2 px-3 text-right font-mono">
                              <span className="inline-block w-12 h-2 rounded-full overflow-hidden bg-bg-card">
                                <span className="block h-full bg-accent-purple rounded-full" style={{ width: `${t.feature_similarity_cka * 100}%` }} />
                              </span>
                              <span className="ml-1">{(t.feature_similarity_cka * 100).toFixed(0)}%</span>
                            </td>
                            <td className="py-2 px-3 text-right font-mono text-text-secondary">
                              {t.domain_divergence_mmd.toFixed(3)}
                            </td>
                            <td className="py-2 px-3 text-right font-mono">
                              {(t.class_distribution_overlap * 100).toFixed(0)}%
                            </td>
                            <td className="py-2 px-3 text-right">
                              <span className={`font-mono font-bold px-2 py-0.5 rounded ${
                                t.transferability_score >= 0.7 ? 'bg-accent-green/15 text-accent-green' :
                                t.transferability_score >= 0.4 ? 'bg-accent-amber/15 text-accent-amber' :
                                'bg-accent-red/15 text-accent-red'
                              }`}>
                                {(t.transferability_score * 100).toFixed(0)}%
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {/* Transfer Score Visualisation */}
                  {crossDataset.length > 0 && (
                    <ResponsiveContainer width="100%" height={200}>
                      <BarChart data={crossDataset.map(t => ({
                        pair: `${t.source_dataset.replace(/\.[^.]+$/, '').slice(0, 12)} → ${t.target_dataset.replace(/\.[^.]+$/, '').slice(0, 12)}`,
                        'Transfer Score': Math.round(t.transferability_score * 100),
                        'Feature Similarity': Math.round(t.feature_similarity_cka * 100),
                        'Class Overlap': Math.round(t.class_distribution_overlap * 100),
                      }))}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                        <XAxis dataKey="pair" tick={{ fill: '#94A3B8', fontSize: 8 }} />
                        <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" domain={[0, 100]} />
                        <Tooltip contentStyle={TT} />
                        <Bar dataKey="Transfer Score" fill="#A855F7" radius={[4, 4, 0, 0]} />
                        <Bar dataKey="Feature Similarity" fill="#3B82F6" radius={[4, 4, 0, 0]} />
                        <Bar dataKey="Class Overlap" fill="#22C55E" radius={[4, 4, 0, 0]} />
                        <Legend wrapperStyle={{ fontSize: 10, color: '#94A3B8' }} />
                      </BarChart>
                    </ResponsiveContainer>
                  )}

                  {/* Cross-Model Analysis */}
                  {crossModel && (
                    <div className="space-y-3">
                      <h4 className="text-xs font-semibold flex items-center gap-2">
                        <GitCompare className="w-3.5 h-3.5 text-accent-green" />
                        Cross-Model Representation Alignment
                        <span className="text-[10px] text-text-secondary ml-1">
                          Ensemble Diversity: {(crossModel.ensemble_diversity * 100).toFixed(1)}%
                        </span>
                      </h4>
                      <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
                        {/* Model Accuracies */}
                        {Object.entries(crossModel.model_accuracies).map(([name, acc]) => (
                          <div key={name} className="bg-bg-primary rounded-lg p-3 text-xs">
                            <p className="text-text-secondary truncate">{name}</p>
                            <p className="text-lg font-mono font-bold text-accent-green">{(acc * 100).toFixed(1)}%</p>
                          </div>
                        ))}
                      </div>

                      {/* Agreement Matrix */}
                      <div className="overflow-x-auto">
                        <p className="text-[10px] text-text-secondary mb-1">Prediction Agreement & Representation Similarity</p>
                        <table className="text-xs">
                          <thead>
                            <tr>
                              <th className="px-3 py-1.5 text-text-secondary font-medium text-left">Model Pair</th>
                              <th className="px-3 py-1.5 text-text-secondary font-medium text-right">Agreement</th>
                              <th className="px-3 py-1.5 text-text-secondary font-medium text-right">CKA Similarity</th>
                            </tr>
                          </thead>
                          <tbody>
                            {Object.entries(crossModel.prediction_agreement).map(([pair, agree]) => {
                              const simKey = pair
                              const sim = crossModel.representation_similarity[simKey]
                              return (
                                <tr key={pair} className="border-b border-bg-card/30">
                                  <td className="px-3 py-1.5 font-mono text-[10px]">{pair.replace('|', ' ↔ ')}</td>
                                  <td className="px-3 py-1.5 text-right font-mono text-accent-green">{(agree * 100).toFixed(1)}%</td>
                                  <td className="px-3 py-1.5 text-right font-mono text-accent-purple">
                                    {sim !== undefined ? `${(sim * 100).toFixed(1)}%` : '—'}
                                  </td>
                                </tr>
                              )
                            })}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
