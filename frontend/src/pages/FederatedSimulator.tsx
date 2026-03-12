import { useEffect, useState } from 'react'
import {
  Network, Loader2, Server, Shield, Lock, Unlock,
  TrendingUp, BarChart3, Brain, Zap, ChevronDown, ChevronUp,
  Upload, Layers, GitCompare,
} from 'lucide-react'
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid, Legend, BarChart, Bar, Cell, RadarChart, PolarGrid,
  PolarAngleAxis, PolarRadiusAxis, Radar,
} from 'recharts'
import FileUpload from '../components/FileUpload'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import { runFederated, runFederatedMulti, fetchSampleData, fetchModels } from '../utils/api'
import { usePageState } from '../hooks/usePageState'

const PAGE = 'federated'
const TT = { background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }

const NODE_COLORS = ['#3B82F6', '#22C55E', '#F59E0B', '#EF4444', '#A855F7', '#06B6D4']
const DATASET_COLORS = ['#3B82F6', '#22C55E', '#F59E0B']
const MODEL_COLORS = ['#3B82F6', '#22C55E', '#F59E0B', '#EF4444', '#A855F7', '#06B6D4']

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
  rounds: RoundResult[]
  per_class: Record<string, { count: number; accuracy: number }>
  model_used: string
  dataset_name?: string
  dataset_format?: string
  time_ms: number
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
    try {
      const data = await runFederated(file, {
        nNodes, rounds, localEpochs, lr, strategy,
        dpEnabled, dpSigma, iid, modelName: selectedModel,
      })
      setResult(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Simulation failed')
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

  const hasMultiFiles = slots.filter(s => s.file && s.fileReady).length > 0
  const canRunMulti = hasMultiFiles && selectedModels.length > 0 && !running

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
                    accept=".csv,.parquet"
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
                accept=".csv,.parquet"
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
    </div>
  )
}
