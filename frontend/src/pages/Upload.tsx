import { useState, useEffect, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import FileUpload from '../components/FileUpload'
import ThreatTable from '../components/ThreatTable'
import UncertaintyChart from '../components/UncertaintyChart'
import ConfusionMatrix from '../components/ConfusionMatrix'
import ModelSelector from '../components/ModelSelector'
import ModelMultiSelector from '../components/ModelMultiSelector'
import ModelAnalyticsPanel from '../components/ModelAnalyticsPanel'
import ExportMenu from '../components/ExportMenu'
import { useAnalysis } from '../hooks/useAnalysis'
import { useAblation } from '../hooks/useAblation'
import { usePageState } from '../hooks/usePageState'
import PageGuide from '../components/PageGuide'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  Legend, LineChart, Line, Cell,
} from 'recharts'
import {
  Loader2, Database, AlertTriangle, Trash2, X, Radio,
  Upload as UploadIcon, ChevronDown, ChevronUp, TrendingUp, FlaskConical,
  ToggleRight, ToggleLeft, TrendingDown, Brain, Shield, FolderOpen, Download,
  Layers, GitCompare, Activity, BarChart3, Target, Zap,
} from 'lucide-react'
import {
  fetchDatasets, fetchSampleData, downloadAdversarialBenchmark,
  uploadAndPredictMulti, fetchModels,
  type DatasetMeta,
} from '../utils/api'

const PAGE = 'upload'
const TT = { background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }
const MODEL_COLORS = ['#3B82F6', '#22C55E', '#F59E0B', '#EF4444', '#A855F7', '#06B6D4']
const DATASET_COLORS = ['#3B82F6', '#22C55E', '#F59E0B']

interface DatasetInfo {
  total_rows: number
  analysed_rows: number
  sampled: boolean
  format: string
  columns: string[]
}

interface ModelInfo {
  id: string
  name: string
  description: string
  category: string
  weights_available: boolean
  enabled?: boolean
}

interface SlotState {
  file: File | null
  fileName: string | null
  fileReady: boolean
  fileLoading: boolean
}

const defaultSlot = (): SlotState => ({
  file: null, fileName: null, fileReady: false, fileLoading: false,
})

// ── Types for multi-run results ──
interface MultiPredictionEntry {
  model: string
  dataset: string
  n_flows: number
  n_threats: number
  n_benign: number
  threat_rate: number
  accuracy: number
  ece: number
  mean_confidence: number
  mean_epistemic: number
  mean_aleatoric: number
  predictions: Array<Record<string, unknown>>
  per_class_metrics: Record<string, { precision: number; recall: number; f1: number }>
  confusion_matrix: number[][] | null
  dataset_info: DatasetInfo
  model_used: string
}

interface MultiRunResult {
  multi_run_id: string
  n_models: number
  n_datasets: number
  model_names: string[]
  dataset_names: string[]
  mc_passes: number
  results_matrix: Record<string, MultiPredictionEntry>
  cross_dataset_comparison: Record<string, {
    model: string
    datasets: string[]
    accuracy_by_dataset: Record<string, number>
    threat_rate_by_dataset: Record<string, number>
    ece_by_dataset: Record<string, number>
    confidence_by_dataset: Record<string, number>
  }>
  cross_model_comparison: Record<string, {
    dataset: string
    models: string[]
    accuracy_by_model: Record<string, number>
    threat_rate_by_model: Record<string, number>
    ece_by_model: Record<string, number>
    confidence_by_model: Record<string, number>
  }>
  model_ranking: { model: string; avg_accuracy: number; avg_ece: number; avg_confidence: number }[]
  time_ms: number
}

function DatasetSummary({ info, fileName }: { info: DatasetInfo; fileName: string | null }) {
  return (
    <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
      <h3 className="text-sm font-medium text-text-secondary mb-3 flex items-center gap-2">
        <Database className="w-4 h-4" /> Dataset Summary
      </h3>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 md:gap-4">
        <div>
          <div className="text-xs text-text-secondary">File</div>
          <div className="text-sm font-mono text-text-primary truncate">
            {fileName || 'Unknown'}
          </div>
        </div>
        <div>
          <div className="text-xs text-text-secondary">Format Detected</div>
          <div className="text-sm font-medium text-accent-blue">{info.format}</div>
        </div>
        <div>
          <div className="text-xs text-text-secondary">Total Rows</div>
          <div className="text-sm font-mono text-text-primary">
            {info.total_rows.toLocaleString()}
          </div>
        </div>
        <div>
          <div className="text-xs text-text-secondary">Rows Analysed</div>
          <div className="text-sm font-mono text-text-primary">
            {info.analysed_rows.toLocaleString()}
            {info.sampled && (
              <span className="ml-1 text-xs text-accent-yellow">(sampled)</span>
            )}
          </div>
        </div>
      </div>
      {info.sampled && (
        <div className="mt-3 flex items-center gap-2 text-xs text-accent-yellow">
          <AlertTriangle className="w-3.5 h-3.5" />
          Large dataset: {info.analysed_rows.toLocaleString()} rows randomly sampled from {info.total_rows.toLocaleString()} for analysis
        </div>
      )}
    </div>
  )
}

const BRANCH_NAMES = [
  'CT-TGNN (Neural ODE)',
  'TripleE-TGNN (Multi-scale)',
  'FedLLM-API (Zero-shot)',
  'PQ-IDPS (Post-quantum)',
  'MambaShield (State-space)',
  'Stochastic Transformer',
  'Game-Theoretic Defence',
]

const MULTI_VIEWS = [
  { key: 'overview', label: 'Overview', icon: BarChart3 },
  { key: 'accuracy', label: 'Accuracy Matrix', icon: Target },
  { key: 'uncertainty', label: 'Uncertainty', icon: Activity },
  { key: 'ranking', label: 'Model Ranking', icon: TrendingUp },
  { key: 'detail', label: 'Drill-Down', icon: Zap },
] as const

type MultiViewKey = typeof MULTI_VIEWS[number]['key']

export default function UploadPage() {
  const navigate = useNavigate()
  const ablation = useAblation()
  const [mode, setMode] = usePageState<'single' | 'multi'>(PAGE, 'mode', 'single')
  const [mcPasses, setMcPasses] = useState(20)
  const [selectedModel, setSelectedModel] = useState(ablation.selectedModel || 'surrogate')
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [showModelAnalytics, setShowModelAnalytics] = useState(true)
  const [showAblation, setShowAblation] = useState(true)
  const [showDatasets, setShowDatasets] = useState(true)
  const [datasets, setDatasets] = useState<DatasetMeta[]>([])
  const [loadingDataset, setLoadingDataset] = useState<string | null>(null)
  const [downloadingPcap, setDownloadingPcap] = useState(false)
  const [pcapError, setPcapError] = useState('')
  const { loading, results, error, fileName, jobId, source, runAnalysis, deleteJob } = useAnalysis()

  // ── Multi-mode state ──
  const [slots, setSlots] = usePageState<SlotState[]>(PAGE, 'slots', [defaultSlot(), defaultSlot(), defaultSlot()])
  const [selectedModels, setSelectedModels] = usePageState<string[]>(PAGE, 'selectedModels', ['surrogate'])
  const [availableModels, setAvailableModels] = useState<ModelInfo[]>([])
  const [multiRunning, setMultiRunning] = usePageState(PAGE, 'multiRunning', false)
  const [multiResult, setMultiResult] = usePageState<MultiRunResult | null>(PAGE, 'multiResult', null)
  const [multiError, setMultiError] = usePageState(PAGE, 'multiError', '')
  const [multiView, setMultiView] = usePageState<MultiViewKey>(PAGE, 'multiView', 'overview')
  const [inspectKey, setInspectKey] = usePageState<string>(PAGE, 'inspectKey', '')

  // Sync model selection from Ablation Studio
  useEffect(() => {
    if (ablation.selectedModel && ablation.selectedModel !== selectedModel) {
      setSelectedModel(ablation.selectedModel)
    }
  }, [ablation.selectedModel]) // eslint-disable-line react-hooks/exhaustive-deps

  // Fetch available datasets and models on mount
  useEffect(() => {
    fetchDatasets()
      .then((data) => setDatasets(data.datasets || []))
      .catch(() => {})
    fetchModels()
      .then((data) => {
        const enabled = (data.models ?? []).filter(
          (m: ModelInfo) => m.enabled !== false && m.weights_available
        )
        setAvailableModels(enabled)
      })
      .catch(() => {})
  }, [])

  // ── Single-mode handlers ──
  const handleUpload = (file: File) => {
    runAnalysis(file, mcPasses, selectedModel)
  }

  const handleDelete = async () => {
    setDeleting(true)
    await deleteJob()
    setDeleting(false)
    setShowDeleteConfirm(false)
  }

  // ── Multi-mode handlers ──
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

  const handleSlotSample = async (idx: number, dataset: 'pqc' | 'ciciot') => {
    try {
      updateSlot(idx, { fileLoading: true, fileReady: false })
      const f = await fetchSampleData(dataset)
      updateSlot(idx, { file: f, fileName: f.name, fileLoading: false, fileReady: true })
    } catch {
      updateSlot(idx, { fileLoading: false })
    }
  }

  const toggleModel = (modelId: string) => {
    setSelectedModels(prev =>
      prev.includes(modelId)
        ? prev.length > 1 ? prev.filter(m => m !== modelId) : prev
        : [...prev, modelId]
    )
  }

  const handleRunMulti = async () => {
    const activeSlots = slots.filter(s => s.file && s.fileReady)
    if (activeSlots.length === 0 || selectedModels.length === 0) return
    setMultiRunning(true); setMultiError(''); setMultiResult(null)
    try {
      const files = slots.map(s => s.file)
      const data = await uploadAndPredictMulti(files, selectedModels, mcPasses) as unknown as MultiRunResult
      setMultiResult(data)
      setMultiView('overview')
    } catch (e) {
      setMultiError(e instanceof Error ? e.message : 'Multi-dataset analysis failed')
    } finally {
      setMultiRunning(false)
    }
  }

  // ── Derived single-mode data ──
  const predictions = (results?.predictions ?? []) as Array<Record<string, unknown>>
  const datasetInfo = results?.dataset_info as DatasetInfo | undefined
  const perClass = (results?.per_class_metrics ?? {}) as Record<
    string,
    { precision: number; recall: number; f1: number }
  >
  const perClassData = Object.entries(perClass)
    .filter(([, m]) => m != null)
    .map(([label, m]) => ({
      label: label.length > 18 ? label.slice(0, 16) + '..' : label,
      precision: +((m.precision ?? 0) * 100).toFixed(1),
      recall: +((m.recall ?? 0) * 100).toFixed(1),
      f1: +((m.f1 ?? 0) * 100).toFixed(1),
    }))

  // ── Multi-mode derived data ──
  const multiModelNames = multiResult?.model_names || []
  const multiDatasetNames = multiResult?.dataset_names || []

  // Accuracy matrix: dataset × model
  const accuracyMatrixData = useMemo(() => {
    if (!multiResult?.results_matrix) return []
    return multiDatasetNames.map(ds => {
      const entry: Record<string, string | number> = {
        dataset: ds.length > 22 ? ds.slice(0, 20) + '…' : ds,
      }
      multiModelNames.forEach(m => {
        const key = `${m}|${ds}`
        const r = multiResult.results_matrix[key]
        entry[m] = r ? Math.round(r.accuracy * 1000) / 10 : 0
      })
      return entry
    })
  }, [multiResult, multiModelNames, multiDatasetNames])

  // Threat rate matrix
  const threatRateData = useMemo(() => {
    if (!multiResult?.results_matrix) return []
    return multiDatasetNames.map(ds => {
      const entry: Record<string, string | number> = {
        dataset: ds.length > 22 ? ds.slice(0, 20) + '…' : ds,
      }
      multiModelNames.forEach(m => {
        const key = `${m}|${ds}`
        const r = multiResult.results_matrix[key]
        entry[m] = r ? Math.round(r.threat_rate * 1000) / 10 : 0
      })
      return entry
    })
  }, [multiResult, multiModelNames, multiDatasetNames])

  // Uncertainty comparison (epistemic + aleatoric per model across datasets)
  const uncertaintyData = useMemo(() => {
    if (!multiResult?.results_matrix) return []
    return multiModelNames.flatMap(m =>
      multiDatasetNames.map(ds => {
        const key = `${m}|${ds}`
        const r = multiResult.results_matrix[key]
        return {
          model: m,
          dataset: ds.length > 15 ? ds.slice(0, 13) + '…' : ds,
          epistemic: r ? +(r.mean_epistemic * 100).toFixed(2) : 0,
          aleatoric: r ? +(r.mean_aleatoric * 100).toFixed(2) : 0,
          confidence: r ? +(r.mean_confidence * 100).toFixed(1) : 0,
        }
      })
    )
  }, [multiResult, multiModelNames, multiDatasetNames])

  // ECE comparison for radar chart
  const calibrationRadarData = useMemo(() => {
    if (!multiResult?.results_matrix) return []
    return multiDatasetNames.map(ds => {
      const entry: Record<string, string | number> = { dataset: ds.length > 15 ? ds.slice(0, 13) + '…' : ds }
      multiModelNames.forEach(m => {
        const key = `${m}|${ds}`
        const r = multiResult.results_matrix[key]
        // Lower ECE is better, so invert for radar (100 - ECE*100)
        entry[m] = r ? Math.round((1 - r.ece) * 1000) / 10 : 0
      })
      return entry
    })
  }, [multiResult, multiModelNames, multiDatasetNames])

  // Ranking data
  const rankingData = useMemo(() => {
    if (!multiResult?.model_ranking) return []
    return multiResult.model_ranking.map((r, i) => ({
      rank: i + 1,
      model: r.model,
      accuracy: Math.round(r.avg_accuracy * 1000) / 10,
      ece: Math.round(r.avg_ece * 10000) / 100,
      confidence: Math.round(r.avg_confidence * 1000) / 10,
    }))
  }, [multiResult])

  // Inspected entry for drill-down
  const inspectEntry = multiResult?.results_matrix?.[inspectKey] || null
  const inspectPerClass = inspectEntry?.per_class_metrics
    ? Object.entries(inspectEntry.per_class_metrics)
        .filter(([, m]) => m != null)
        .map(([label, m]) => ({
          label: label.length > 18 ? label.slice(0, 16) + '..' : label,
          precision: +((m.precision ?? 0) * 100).toFixed(1),
          recall: +((m.recall ?? 0) * 100).toFixed(1),
          f1: +((m.f1 ?? 0) * 100).toFixed(1),
        }))
    : []

  const activeSlotCount = slots.filter(s => s.file && s.fileReady).length

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl md:text-2xl font-display font-bold">Upload & Analyse</h1>
        <ExportMenu filename="upload-analyse" />
      </div>

      <PageGuide
        title="How to use Upload & Analyse"
        steps={[
          { title: 'Choose a mode', desc: 'Single mode for quick analysis of one dataset with one model. Multi mode for cross-dataset, cross-model comparative analysis.' },
          { title: 'Upload dataset(s)', desc: 'Drag & drop CSV (CIC-IoT-2023, CSE-CIC-IDS2018, UNSW-NB15) or PCAP files. Multi mode supports up to 3 datasets simultaneously.' },
          { title: 'Select model(s)', desc: 'Single mode: pick one model. Multi mode: select multiple models for cross-comparison of accuracy, uncertainty, and calibration.' },
          { title: 'Review results', desc: 'Single: Threat Table, Uncertainty Chart, Confusion Matrix. Multi: Accuracy matrix, uncertainty decomposition, model ranking, per-cell drill-down.' },
        ]}
        tip="Multi mode compares model×dataset combinations — revealing which models generalise best and where uncertainty is highest. Use drill-down to inspect any cell."
      />

      {/* ── Mode Toggle ── */}
      <div className="flex gap-2">
        <button
          onClick={() => setMode('single')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            mode === 'single' ? 'bg-accent-blue text-white' : 'bg-bg-secondary text-text-secondary border border-bg-card hover:text-text-primary'
          }`}
        >
          <UploadIcon className="w-4 h-4 inline mr-1.5" />Single Analysis
        </button>
        <button
          onClick={() => setMode('multi')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            mode === 'multi' ? 'bg-accent-blue text-white' : 'bg-bg-secondary text-text-secondary border border-bg-card hover:text-text-primary'
          }`}
        >
          <Layers className="w-4 h-4 inline mr-1.5" />Multi-Dataset / Multi-Model
        </button>
      </div>

      {/* Sample Datasets Panel */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <button
          onClick={() => setShowDatasets(!showDatasets)}
          className="w-full flex items-center justify-between text-sm font-medium text-text-primary"
        >
          <span className="flex items-center gap-2">
            <FolderOpen className="w-4 h-4 text-accent-purple" />
            Sample Datasets
            {datasets.length > 0 && (
              <span className="text-xs bg-accent-purple/15 text-accent-purple px-2 py-0.5 rounded-full">
                {datasets.length}
              </span>
            )}
          </span>
          {showDatasets ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>
        {showDatasets && (
          <div className="mt-4 space-y-3">
            {/* Quick-load buttons */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <button
                onClick={async () => {
                  setLoadingDataset('pqc');
                  try {
                    const file = await fetchSampleData('pqc');
                    if (mode === 'single') {
                      handleUpload(file);
                    } else {
                      // Load into first empty slot in multi-mode
                      const emptyIdx = slots.findIndex(s => !s.file)
                      if (emptyIdx >= 0) {
                        updateSlot(emptyIdx, { file, fileName: file.name, fileLoading: false, fileReady: true })
                      }
                    }
                  } catch { /* ignore */ }
                  setLoadingDataset(null);
                }}
                disabled={loading || loadingDataset !== null}
                className="flex items-center gap-2 px-3 py-2.5 rounded-lg border border-accent-purple/30 bg-accent-purple/5 hover:bg-accent-purple/15 text-sm transition-colors disabled:opacity-50"
              >
                {loadingDataset === 'pqc' ? <Loader2 className="w-4 h-4 animate-spin text-accent-purple" /> : <Shield className="w-4 h-4 text-accent-purple" />}
                <div className="text-left">
                  <div className="font-medium text-text-primary">PQC Test Dataset</div>
                  <div className="text-[10px] text-text-secondary">5K flows | Kyber + attacks | ~4 MB</div>
                </div>
              </button>
              <button
                onClick={async () => {
                  setLoadingDataset('ciciot');
                  try {
                    const file = await fetchSampleData('ciciot');
                    if (mode === 'single') {
                      handleUpload(file);
                    } else {
                      const emptyIdx = slots.findIndex(s => !s.file)
                      if (emptyIdx >= 0) {
                        updateSlot(emptyIdx, { file, fileName: file.name, fileLoading: false, fileReady: true })
                      }
                    }
                  } catch { /* ignore */ }
                  setLoadingDataset(null);
                }}
                disabled={loading || loadingDataset !== null}
                className="flex items-center gap-2 px-3 py-2.5 rounded-lg border border-accent-blue/30 bg-accent-blue/5 hover:bg-accent-blue/15 text-sm transition-colors disabled:opacity-50"
              >
                {loadingDataset === 'ciciot' ? <Loader2 className="w-4 h-4 animate-spin text-accent-blue" /> : <Database className="w-4 h-4 text-accent-blue" />}
                <div className="text-left">
                  <div className="font-medium text-text-primary">CIC-IoT-2023 Sample</div>
                  <div className="text-[10px] text-text-secondary">1K flows | Standard IDS | 0.9 MB</div>
                </div>
              </button>
            </div>

            {/* Adversarial Benchmark PCAP Download */}
            <div className="border-t border-bg-card pt-3">
              <div className="text-xs text-text-secondary mb-2">Adversarial Benchmark (Download to Device)</div>
              <button
                onClick={async () => {
                  setDownloadingPcap(true);
                  setPcapError('');
                  try {
                    await downloadAdversarialBenchmark();
                  } catch (e) {
                    setPcapError(e instanceof Error ? e.message : 'Download failed');
                  }
                  setDownloadingPcap(false);
                }}
                disabled={downloadingPcap}
                className="w-full flex items-center gap-2 px-3 py-2.5 rounded-lg border border-accent-green/30 bg-accent-green/5 hover:bg-accent-green/15 text-sm transition-colors disabled:opacity-50"
              >
                {downloadingPcap ? <Loader2 className="w-4 h-4 animate-spin text-accent-green" /> : <Download className="w-4 h-4 text-accent-green" />}
                <div className="text-left flex-1">
                  <div className="font-medium text-text-primary">Adversarial Benchmark PCAP</div>
                  <div className="text-[10px] text-text-secondary">34 attack classes + PQ-TLS + FGSM/PGD/DeepFool/C&W + banking/gov scenarios | ~10 MB</div>
                </div>
                {downloadingPcap && <span className="text-[10px] text-accent-green">Downloading...</span>}
                {pcapError && <span className="text-[10px] text-accent-red">{pcapError}</span>}
              </button>
            </div>

            {/* Server-side datasets */}
            {datasets.length > 0 && (
              <div className="border-t border-bg-card pt-3">
                <div className="text-xs text-text-secondary mb-2">Server Datasets ({datasets.length})</div>
                <div className="space-y-1.5 max-h-40 overflow-y-auto">
                  {datasets.map((ds) => (
                    <div
                      key={ds.name}
                      className="flex items-center justify-between px-2 py-1.5 rounded bg-bg-card/50 text-xs"
                    >
                      <div className="flex items-center gap-2">
                        {ds.has_pq_metadata ? <Shield className="w-3 h-3 text-accent-purple" /> : <Database className="w-3 h-3 text-accent-blue" />}
                        <span className="font-mono text-text-primary">{ds.name}</span>
                        <span className="text-text-secondary">{ds.n_rows.toLocaleString()} rows | {ds.size_mb} MB</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ═══════════════════ SINGLE MODE ═══════════════════ */}
      {mode === 'single' && (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 md:gap-6">
            <div className="lg:col-span-2">
              <FileUpload onFileSelect={handleUpload} loading={loading} fileLoading={loading} />
            </div>

            <div className="space-y-4">
              <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-4">
                <h3 className="text-sm font-medium text-text-secondary">Settings</h3>
                <ModelSelector value={selectedModel} onChange={(v) => { setSelectedModel(v); ablation.setSelectedModel(v) }} compact />
                <div>
                  <label className="text-xs text-text-secondary block mb-1">
                    MC Dropout Passes: {mcPasses}
                  </label>
                  <input
                    type="range"
                    min={5}
                    max={100}
                    value={mcPasses}
                    onChange={(e) => setMcPasses(+e.target.value)}
                    className="w-full accent-accent-blue"
                  />
                  <div className="flex justify-between text-xs text-text-secondary">
                    <span>5 (fast)</span>
                    <span>100 (precise)</span>
                  </div>
                </div>
              </div>

              {/* Ablation Configuration Card */}
              {ablation.data && (
                <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                  <button
                    onClick={() => setShowAblation(!showAblation)}
                    className="w-full flex items-center justify-between text-xs font-medium text-text-secondary"
                  >
                    <span className="flex items-center gap-1.5">
                      <FlaskConical className="w-3.5 h-3.5 text-accent-blue" />
                      Ablation Configuration
                    </span>
                    {showAblation ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                  </button>
                  {showAblation && (
                    <div className="mt-3 space-y-2">
                      <div className="grid grid-cols-1 gap-1">
                        {BRANCH_NAMES.map((name, i) => (
                          <div key={i} className={`flex items-center gap-2 px-2 py-1 rounded text-[10px] ${
                            ablation.enabled[i]
                              ? 'text-accent-green bg-accent-green/5'
                              : 'text-accent-red/60 bg-accent-red/5 line-through'
                          }`}>
                            {ablation.enabled[i] ? <ToggleRight className="w-3 h-3 shrink-0" /> : <ToggleLeft className="w-3 h-3 shrink-0" />}
                            <span className="font-mono opacity-60">M{i + 1}</span>
                            <span className="truncate">{name}</span>
                          </div>
                        ))}
                      </div>
                      {ablation.data.ablation?.['Full System'] && (
                        <div className="pt-2 border-t border-bg-card space-y-1.5">
                          <div className="flex justify-between text-[10px]">
                            <span className="text-text-secondary">Full Ensemble</span>
                            <span className="font-mono text-accent-blue font-semibold">
                              {(ablation.data.ablation['Full System'].accuracy * 100).toFixed(2)}%
                            </span>
                          </div>
                          {(() => {
                            const entries = Object.entries(ablation.data.ablation)
                              .filter(([k]) => k !== 'Full System' && k !== 'Custom')
                            const most = entries.sort((a, b) => b[1].accuracy_drop - a[1].accuracy_drop)[0]
                            if (!most) return null
                            return (
                              <div className="flex justify-between text-[10px]">
                                <span className="text-text-secondary flex items-center gap-1">
                                  <TrendingDown className="w-2.5 h-2.5 text-accent-red" />
                                  Most impactful
                                </span>
                                <span className="font-mono text-accent-red">
                                  {most[0].split('(')[0].trim()} (-{(most[1].accuracy_drop * 100).toFixed(1)}%)
                                </span>
                              </div>
                            )
                          })()}
                          <div className="text-[9px] text-text-secondary/50">
                            {ablation.enabled.filter(v => !v).length > 0
                              ? `${ablation.enabled.filter(v => !v).length} branch(es) disabled`
                              : 'All branches active'}
                            {' · '}
                            <span className="text-accent-blue cursor-pointer hover:underline" onClick={() => navigate('/ablation')}>
                              Edit in Ablation Studio
                            </span>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {loading && (
            <div className="flex items-center gap-3 text-accent-blue">
              <Loader2 className="w-5 h-5 animate-spin" />
              <span>Analysing traffic flows with {mcPasses} MC passes...</span>
            </div>
          )}

          {error && (
            <div className="px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">
              {error}
            </div>
          )}

          {results && (
            <>
              <div className="flex items-center justify-between">
                {datasetInfo && (
                  <div className="flex-1">
                    <DatasetSummary info={datasetInfo} fileName={fileName} />
                  </div>
                )}
              </div>

              <div className="flex items-center justify-between px-4 py-2.5 bg-bg-secondary rounded-lg border border-bg-card">
                <div className="text-xs text-text-secondary flex items-center gap-2">
                  {source === 'live-monitor' ? (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-accent-green/15 text-accent-green text-[10px] font-semibold uppercase">
                      <Radio className="w-3 h-3" /> Live Monitor
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-accent-blue/15 text-accent-blue text-[10px] font-semibold uppercase">
                      <UploadIcon className="w-3 h-3" /> Upload &amp; Analyse
                    </span>
                  )}
                  <span className="font-medium text-text-primary">{fileName}</span>
                  {jobId && <span className="ml-2 opacity-50">Job: {jobId}</span>}
                  {results?.model_used && (
                    <span className="flex items-center gap-1 ml-2 text-[10px] text-accent-purple bg-accent-purple/10 px-2 py-0.5 rounded-full">
                      <Brain className="w-3 h-3" /> {String(results.model_used)}
                    </span>
                  )}
                </div>
                {!showDeleteConfirm ? (
                  <button
                    onClick={() => setShowDeleteConfirm(true)}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-accent-red hover:bg-accent-red/10 rounded-lg transition-colors"
                  >
                    <Trash2 className="w-3.5 h-3.5" /> Remove Dataset
                  </button>
                ) : (
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-accent-red">Delete this analysis?</span>
                    <button
                      onClick={handleDelete}
                      disabled={deleting}
                      className="px-3 py-1.5 text-xs font-medium bg-accent-red text-white rounded-lg hover:bg-accent-red/90 disabled:opacity-50 transition-colors"
                    >
                      {deleting ? 'Deleting...' : 'Confirm Delete'}
                    </button>
                    <button
                      onClick={() => setShowDeleteConfirm(false)}
                      className="p-1.5 text-text-secondary hover:text-text-primary rounded transition-colors"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                )}
              </div>

              <ThreatTable predictions={predictions as never} />

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <UncertaintyChart predictions={predictions as never} />
                <ConfusionMatrix
                  matrix={results.confusion_matrix as number[][] | null}
                  labels={
                    results.per_class_metrics
                      ? Object.keys(results.per_class_metrics as Record<string, unknown>)
                      : undefined
                  }
                  source={source}
                />
              </div>

              {perClassData.length > 0 && (
                <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                  <h3 className="text-sm font-medium text-text-secondary mb-4">Per-Class Metrics</h3>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={perClassData} layout="vertical" margin={{ left: 120 }}>
                      <XAxis
                        type="number"
                        domain={[0, 100]}
                        tick={{ fill: '#94A3B8', fontSize: 10 }}
                        axisLine={{ stroke: '#334155' }}
                        tickFormatter={(v) => `${v}%`}
                      />
                      <YAxis
                        type="category"
                        dataKey="label"
                        tick={{ fill: '#94A3B8', fontSize: 10 }}
                        axisLine={{ stroke: '#334155' }}
                        width={115}
                      />
                      <Tooltip contentStyle={TT} />
                      <Bar dataKey="precision" fill="#3B82F6" name="Precision" />
                      <Bar dataKey="recall" fill="#22C55E" name="Recall" />
                      <Bar dataKey="f1" fill="#A855F7" name="F1" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </>
          )}
        </>
      )}

      {/* ═══════════════════ MULTI MODE ═══════════════════ */}
      {mode === 'multi' && (
        <>
          <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-5">
            {/* Dataset slots */}
            <div>
              <h3 className="text-sm font-medium text-text-secondary flex items-center gap-2 mb-3">
                <UploadIcon className="w-4 h-4" /> Upload Datasets (up to 3)
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {slots.map((slot, idx) => (
                  <div key={idx} className={`rounded-lg border p-3 ${
                    slot.fileReady ? 'border-accent-green/40 bg-accent-green/5' : 'border-bg-card bg-bg-primary'
                  }`}>
                    <div className="text-xs text-text-secondary mb-1.5 font-medium flex items-center justify-between">
                      <span>Dataset {idx + 1} {idx === 0 && <span className="text-accent-red">*</span>}</span>
                      {slot.file && (
                        <button
                          onClick={() => updateSlot(idx, defaultSlot())}
                          className="text-accent-red/60 hover:text-accent-red"
                        >
                          <X className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                    <FileUpload
                      onFile={(f) => handleSlotFileSelect(idx, f)}
                      label={`Dataset ${idx + 1}`}
                      accept=".csv,.parquet,.pcap,.pcapng"
                      fileName={slot.fileName}
                      fileLoading={slot.fileLoading}
                    />
                    {!slot.file && (
                      <div className="flex gap-1 mt-2">
                        <button
                          onClick={() => handleSlotSample(idx, 'pqc')}
                          className="text-[9px] text-accent-purple hover:underline"
                          disabled={slot.fileLoading}
                        >PQC sample</button>
                        <span className="text-text-secondary text-[9px]">·</span>
                        <button
                          onClick={() => handleSlotSample(idx, 'ciciot')}
                          className="text-[9px] text-accent-blue hover:underline"
                          disabled={slot.fileLoading}
                        >CIC-IoT sample</button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Model multi-select */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-text-secondary flex items-center gap-1 mb-2">
                  <Brain className="w-3.5 h-3.5" />
                  Models ({selectedModels.length} selected)
                </label>
                <div className="space-y-1.5 max-h-52 overflow-y-auto">
                  {availableModels.map((m) => {
                    const selected = selectedModels.includes(m.id)
                    return (
                      <button
                        key={m.id}
                        onClick={() => toggleModel(m.id)}
                        className={`w-full text-left px-3 py-2 rounded-lg border transition-all text-xs ${
                          selected
                            ? 'border-accent-blue bg-accent-blue/10'
                            : 'border-bg-card bg-bg-card/30 hover:border-bg-card/80'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-medium">{m.name}</span>
                          {selected && <span className="text-accent-blue text-[10px] font-bold">ON</span>}
                        </div>
                      </button>
                    )
                  })}
                </div>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="text-xs text-text-secondary block mb-1">
                    MC Dropout Passes: {mcPasses}
                  </label>
                  <input
                    type="range"
                    min={5}
                    max={100}
                    value={mcPasses}
                    onChange={(e) => setMcPasses(+e.target.value)}
                    className="w-full accent-accent-blue"
                  />
                  <div className="flex justify-between text-xs text-text-secondary">
                    <span>5 (fast)</span>
                    <span>100 (precise)</span>
                  </div>
                </div>

                {/* Summary badge */}
                <div className="bg-bg-card/50 rounded-lg p-3 space-y-1">
                  <div className="text-[10px] text-text-secondary uppercase tracking-wider font-semibold">Analysis Plan</div>
                  <div className="text-xs text-text-primary">
                    <span className="font-mono text-accent-blue font-semibold">{activeSlotCount}</span> dataset{activeSlotCount !== 1 ? 's' : ''} ×{' '}
                    <span className="font-mono text-accent-purple font-semibold">{selectedModels.length}</span> model{selectedModels.length !== 1 ? 's' : ''} ={' '}
                    <span className="font-mono text-accent-green font-semibold">{activeSlotCount * selectedModels.length}</span> analysis runs
                  </div>
                  <div className="text-[10px] text-text-secondary">
                    {mcPasses} MC passes per run · Uncertainty decomposition included
                  </div>
                </div>
              </div>
            </div>

            {/* Launch button */}
            <button
              onClick={handleRunMulti}
              disabled={activeSlotCount === 0 || selectedModels.length === 0 || multiRunning}
              className="px-5 py-2.5 bg-accent-blue text-white rounded-lg text-sm font-medium hover:bg-accent-blue/80 transition-colors disabled:opacity-40 flex items-center gap-2"
            >
              {multiRunning ? (
                <><Loader2 className="w-4 h-4 animate-spin" />Running {activeSlotCount * selectedModels.length} analyses...</>
              ) : (
                <><GitCompare className="w-4 h-4" />Launch Multi-Analysis</>
              )}
            </button>

            {multiError && (
              <div className="px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">{multiError}</div>
            )}
          </div>

          {/* ── Multi-mode Results ── */}
          {multiResult && (
            <div className="space-y-4">
              {/* Summary banner */}
              <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-medium text-text-primary flex items-center gap-2">
                    <GitCompare className="w-4 h-4 text-accent-blue" />
                    Multi-Analysis Results
                  </h3>
                  <div className="text-[10px] text-text-secondary">
                    {multiResult.n_models} model{multiResult.n_models > 1 ? 's' : ''} × {multiResult.n_datasets} dataset{multiResult.n_datasets > 1 ? 's' : ''} · {multiResult.mc_passes} MC passes · {(multiResult.time_ms / 1000).toFixed(1)}s
                  </div>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="bg-bg-card/50 rounded-lg p-3 text-center">
                    <div className="text-lg font-mono font-bold text-accent-blue">{multiResult.n_datasets}</div>
                    <div className="text-[10px] text-text-secondary">Datasets</div>
                  </div>
                  <div className="bg-bg-card/50 rounded-lg p-3 text-center">
                    <div className="text-lg font-mono font-bold text-accent-purple">{multiResult.n_models}</div>
                    <div className="text-[10px] text-text-secondary">Models</div>
                  </div>
                  <div className="bg-bg-card/50 rounded-lg p-3 text-center">
                    <div className="text-lg font-mono font-bold text-accent-green">
                      {Object.keys(multiResult.results_matrix).length}
                    </div>
                    <div className="text-[10px] text-text-secondary">Cells Analysed</div>
                  </div>
                  <div className="bg-bg-card/50 rounded-lg p-3 text-center">
                    <div className="text-lg font-mono font-bold text-accent-amber">
                      {rankingData.length > 0 ? `${rankingData[0].accuracy}%` : '—'}
                    </div>
                    <div className="text-[10px] text-text-secondary">Best Avg Accuracy</div>
                  </div>
                </div>
              </div>

              {/* View tabs */}
              <div className="flex flex-wrap gap-1.5">
                {MULTI_VIEWS.map(v => (
                  <button
                    key={v.key}
                    onClick={() => setMultiView(v.key)}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                      multiView === v.key
                        ? 'bg-accent-blue text-white'
                        : 'bg-bg-secondary text-text-secondary border border-bg-card hover:text-text-primary'
                    }`}
                  >
                    <v.icon className="w-3.5 h-3.5" />
                    {v.label}
                  </button>
                ))}
              </div>

              {/* ── Overview ── */}
              {multiView === 'overview' && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Accuracy by dataset × model */}
                  <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                    <h4 className="text-xs font-medium text-text-secondary mb-3">Accuracy by Dataset (per model)</h4>
                    <ResponsiveContainer width="100%" height={250}>
                      <BarChart data={accuracyMatrixData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                        <XAxis dataKey="dataset" tick={{ fill: '#94A3B8', fontSize: 9 }} axisLine={{ stroke: '#334155' }} />
                        <YAxis domain={[0, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} tickFormatter={v => `${v}%`} axisLine={{ stroke: '#334155' }} />
                        <Tooltip contentStyle={TT} />
                        <Legend wrapperStyle={{ fontSize: 10 }} />
                        {multiModelNames.map((m, i) => (
                          <Bar key={m} dataKey={m} fill={MODEL_COLORS[i % MODEL_COLORS.length]} name={m} />
                        ))}
                      </BarChart>
                    </ResponsiveContainer>
                  </div>

                  {/* Threat rate by dataset × model */}
                  <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                    <h4 className="text-xs font-medium text-text-secondary mb-3">Threat Detection Rate (per model)</h4>
                    <ResponsiveContainer width="100%" height={250}>
                      <BarChart data={threatRateData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                        <XAxis dataKey="dataset" tick={{ fill: '#94A3B8', fontSize: 9 }} axisLine={{ stroke: '#334155' }} />
                        <YAxis domain={[0, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} tickFormatter={v => `${v}%`} axisLine={{ stroke: '#334155' }} />
                        <Tooltip contentStyle={TT} />
                        <Legend wrapperStyle={{ fontSize: 10 }} />
                        {multiModelNames.map((m, i) => (
                          <Bar key={m} dataKey={m} fill={MODEL_COLORS[i % MODEL_COLORS.length]} name={m} />
                        ))}
                      </BarChart>
                    </ResponsiveContainer>
                  </div>

                  {/* Calibration radar */}
                  <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                    <h4 className="text-xs font-medium text-text-secondary mb-3">Calibration Quality (1 - ECE)</h4>
                    <ResponsiveContainer width="100%" height={280}>
                      <RadarChart data={calibrationRadarData}>
                        <PolarGrid stroke="#334155" />
                        <PolarAngleAxis dataKey="dataset" tick={{ fill: '#94A3B8', fontSize: 9 }} />
                        <PolarRadiusAxis domain={[0, 100]} tick={{ fill: '#64748B', fontSize: 8 }} />
                        {multiModelNames.map((m, i) => (
                          <Radar key={m} name={m} dataKey={m} stroke={MODEL_COLORS[i % MODEL_COLORS.length]}
                            fill={MODEL_COLORS[i % MODEL_COLORS.length]} fillOpacity={0.15} />
                        ))}
                        <Legend wrapperStyle={{ fontSize: 10 }} />
                        <Tooltip contentStyle={TT} />
                      </RadarChart>
                    </ResponsiveContainer>
                  </div>

                  {/* Results matrix heatmap-style table */}
                  <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                    <h4 className="text-xs font-medium text-text-secondary mb-3">Results Matrix (click to drill down)</h4>
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead>
                          <tr>
                            <th className="text-left py-1.5 px-2 text-text-secondary font-medium">Model \ Dataset</th>
                            {multiDatasetNames.map((ds, i) => (
                              <th key={ds} className="py-1.5 px-2 text-text-secondary font-medium text-center">
                                <span className="inline-block w-2 h-2 rounded-full mr-1" style={{ backgroundColor: DATASET_COLORS[i % DATASET_COLORS.length] }} />
                                {ds.length > 15 ? ds.slice(0, 13) + '…' : ds}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {multiModelNames.map((m, mi) => (
                            <tr key={m} className="border-t border-bg-card">
                              <td className="py-2 px-2 font-medium text-text-primary">
                                <span className="inline-block w-2 h-2 rounded-full mr-1.5" style={{ backgroundColor: MODEL_COLORS[mi % MODEL_COLORS.length] }} />
                                {m}
                              </td>
                              {multiDatasetNames.map(ds => {
                                const key = `${m}|${ds}`
                                const r = multiResult.results_matrix[key]
                                const acc = r ? (r.accuracy * 100).toFixed(1) : '—'
                                const threats = r ? r.n_threats : 0
                                const bg = r
                                  ? r.accuracy > 0.9 ? 'bg-accent-green/10' : r.accuracy > 0.7 ? 'bg-accent-amber/10' : 'bg-accent-red/10'
                                  : ''
                                return (
                                  <td
                                    key={ds}
                                    className={`py-2 px-2 text-center cursor-pointer hover:ring-1 hover:ring-accent-blue/50 rounded transition-all ${bg}`}
                                    onClick={() => { setInspectKey(key); setMultiView('detail') }}
                                  >
                                    <div className="font-mono font-semibold text-text-primary">{acc}%</div>
                                    <div className="text-[9px] text-text-secondary">{threats} threats</div>
                                  </td>
                                )
                              })}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* ── Accuracy Matrix ── */}
              {multiView === 'accuracy' && (
                <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                  <h4 className="text-sm font-medium text-text-secondary mb-4">Accuracy Comparison (all model × dataset cells)</h4>
                  <ResponsiveContainer width="100%" height={350}>
                    <BarChart data={accuracyMatrixData} layout="vertical" margin={{ left: 100 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis type="number" domain={[0, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} tickFormatter={v => `${v}%`} axisLine={{ stroke: '#334155' }} />
                      <YAxis type="category" dataKey="dataset" tick={{ fill: '#94A3B8', fontSize: 10 }} width={95} axisLine={{ stroke: '#334155' }} />
                      <Tooltip contentStyle={TT} />
                      <Legend wrapperStyle={{ fontSize: 10 }} />
                      {multiModelNames.map((m, i) => (
                        <Bar key={m} dataKey={m} fill={MODEL_COLORS[i % MODEL_COLORS.length]} name={m} />
                      ))}
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}

              {/* ── Uncertainty ── */}
              {multiView === 'uncertainty' && (
                <div className="space-y-4">
                  <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                    <h4 className="text-sm font-medium text-text-secondary mb-4">Uncertainty Decomposition (Epistemic vs Aleatoric)</h4>
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="text-text-secondary">
                            <th className="text-left py-2 px-2">Model</th>
                            <th className="text-left py-2 px-2">Dataset</th>
                            <th className="text-center py-2 px-2">Confidence</th>
                            <th className="text-center py-2 px-2">Epistemic</th>
                            <th className="text-center py-2 px-2">Aleatoric</th>
                            <th className="text-center py-2 px-2">Total UQ</th>
                          </tr>
                        </thead>
                        <tbody>
                          {uncertaintyData.map((u, i) => (
                            <tr key={i} className="border-t border-bg-card hover:bg-bg-card/30">
                              <td className="py-2 px-2 font-medium text-text-primary">{u.model}</td>
                              <td className="py-2 px-2 text-text-secondary">{u.dataset}</td>
                              <td className="py-2 px-2 text-center">
                                <span className="font-mono text-accent-blue">{u.confidence}%</span>
                              </td>
                              <td className="py-2 px-2 text-center">
                                <div className="flex items-center justify-center gap-1">
                                  <div className="w-12 h-1.5 bg-bg-card rounded-full overflow-hidden">
                                    <div className="h-full bg-accent-purple rounded-full" style={{ width: `${Math.min(u.epistemic * 5, 100)}%` }} />
                                  </div>
                                  <span className="font-mono text-accent-purple text-[10px]">{u.epistemic}%</span>
                                </div>
                              </td>
                              <td className="py-2 px-2 text-center">
                                <div className="flex items-center justify-center gap-1">
                                  <div className="w-12 h-1.5 bg-bg-card rounded-full overflow-hidden">
                                    <div className="h-full bg-accent-amber rounded-full" style={{ width: `${Math.min(u.aleatoric * 5, 100)}%` }} />
                                  </div>
                                  <span className="font-mono text-accent-amber text-[10px]">{u.aleatoric}%</span>
                                </div>
                              </td>
                              <td className="py-2 px-2 text-center font-mono text-accent-red text-[10px]">
                                {(u.epistemic + u.aleatoric).toFixed(2)}%
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* Confidence comparison chart */}
                  <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                    <h4 className="text-xs font-medium text-text-secondary mb-3">Mean Confidence by Model × Dataset</h4>
                    <ResponsiveContainer width="100%" height={250}>
                      <BarChart data={accuracyMatrixData.map((d, i) => {
                        const entry: Record<string, string | number> = { dataset: d.dataset }
                        multiModelNames.forEach(m => {
                          const key = `${m}|${multiDatasetNames[i]}`
                          const r = multiResult.results_matrix[key]
                          entry[m] = r ? Math.round(r.mean_confidence * 1000) / 10 : 0
                        })
                        return entry
                      })}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                        <XAxis dataKey="dataset" tick={{ fill: '#94A3B8', fontSize: 9 }} axisLine={{ stroke: '#334155' }} />
                        <YAxis domain={[0, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} tickFormatter={v => `${v}%`} axisLine={{ stroke: '#334155' }} />
                        <Tooltip contentStyle={TT} />
                        <Legend wrapperStyle={{ fontSize: 10 }} />
                        {multiModelNames.map((m, i) => (
                          <Bar key={m} dataKey={m} fill={MODEL_COLORS[i % MODEL_COLORS.length]} name={m} />
                        ))}
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              )}

              {/* ── Ranking ── */}
              {multiView === 'ranking' && rankingData.length > 0 && (
                <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                  <h4 className="text-sm font-medium text-text-secondary mb-4">Model Ranking (averaged across datasets)</h4>
                  <div className="space-y-3">
                    {rankingData.map((r, i) => (
                      <div key={r.model} className={`flex items-center gap-4 px-4 py-3 rounded-lg border ${
                        i === 0 ? 'border-accent-green/40 bg-accent-green/5' : 'border-bg-card bg-bg-card/30'
                      }`}>
                        <div className={`w-8 h-8 rounded-full flex items-center justify-center font-bold text-sm ${
                          i === 0 ? 'bg-accent-green text-white' : i === 1 ? 'bg-accent-blue/20 text-accent-blue' : 'bg-bg-card text-text-secondary'
                        }`}>
                          #{r.rank}
                        </div>
                        <div className="flex-1">
                          <div className="text-sm font-medium text-text-primary">{r.model}</div>
                          <div className="flex gap-4 mt-1">
                            <span className="text-[10px] text-text-secondary">
                              Avg Accuracy: <span className="font-mono text-accent-blue font-semibold">{r.accuracy}%</span>
                            </span>
                            <span className="text-[10px] text-text-secondary">
                              Avg ECE: <span className="font-mono text-accent-purple font-semibold">{r.ece}%</span>
                            </span>
                            <span className="text-[10px] text-text-secondary">
                              Avg Confidence: <span className="font-mono text-accent-green font-semibold">{r.confidence}%</span>
                            </span>
                          </div>
                        </div>
                        {/* Accuracy bar */}
                        <div className="w-32 h-2 bg-bg-card rounded-full overflow-hidden">
                          <div
                            className="h-full rounded-full transition-all"
                            style={{
                              width: `${r.accuracy}%`,
                              backgroundColor: MODEL_COLORS[i % MODEL_COLORS.length],
                            }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ── Drill-Down ── */}
              {multiView === 'detail' && (
                <div className="space-y-4">
                  {/* Cell selector */}
                  <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                    <h4 className="text-xs font-medium text-text-secondary mb-2">Select a cell to inspect</h4>
                    <div className="flex flex-wrap gap-2">
                      {multiModelNames.flatMap(m =>
                        multiDatasetNames.map(ds => {
                          const key = `${m}|${ds}`
                          const r = multiResult.results_matrix[key]
                          return (
                            <button
                              key={key}
                              onClick={() => setInspectKey(key)}
                              className={`px-3 py-1.5 rounded-lg text-xs border transition-colors ${
                                inspectKey === key
                                  ? 'bg-accent-blue text-white border-accent-blue'
                                  : 'bg-bg-primary text-text-secondary border-bg-card hover:text-text-primary'
                              }`}
                            >
                              <span className="font-medium">{m}</span>
                              <span className="mx-1 opacity-50">×</span>
                              <span>{ds.length > 12 ? ds.slice(0, 10) + '…' : ds}</span>
                              {r && <span className="ml-1 font-mono opacity-70">({(r.accuracy * 100).toFixed(1)}%)</span>}
                            </button>
                          )
                        })
                      )}
                    </div>
                  </div>

                  {inspectEntry && (
                    <>
                      {/* Summary */}
                      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                        <div className="flex items-center gap-2 mb-3">
                          <Brain className="w-4 h-4 text-accent-purple" />
                          <span className="text-sm font-medium text-text-primary">{inspectEntry.model_used}</span>
                          <span className="text-text-secondary text-xs">on</span>
                          <Database className="w-4 h-4 text-accent-blue" />
                          <span className="text-sm font-medium text-text-primary">{inspectEntry.dataset}</span>
                        </div>
                        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                          <div className="bg-bg-card/50 rounded-lg p-3 text-center">
                            <div className="text-lg font-mono font-bold text-accent-blue">{(inspectEntry.accuracy * 100).toFixed(1)}%</div>
                            <div className="text-[10px] text-text-secondary">Accuracy</div>
                          </div>
                          <div className="bg-bg-card/50 rounded-lg p-3 text-center">
                            <div className="text-lg font-mono font-bold text-accent-red">{inspectEntry.n_threats}</div>
                            <div className="text-[10px] text-text-secondary">Threats</div>
                          </div>
                          <div className="bg-bg-card/50 rounded-lg p-3 text-center">
                            <div className="text-lg font-mono font-bold text-accent-green">{inspectEntry.n_benign}</div>
                            <div className="text-[10px] text-text-secondary">Benign</div>
                          </div>
                          <div className="bg-bg-card/50 rounded-lg p-3 text-center">
                            <div className="text-lg font-mono font-bold text-accent-purple">{(inspectEntry.ece * 100).toFixed(2)}%</div>
                            <div className="text-[10px] text-text-secondary">ECE</div>
                          </div>
                          <div className="bg-bg-card/50 rounded-lg p-3 text-center">
                            <div className="text-lg font-mono font-bold text-accent-amber">{(inspectEntry.mean_confidence * 100).toFixed(1)}%</div>
                            <div className="text-[10px] text-text-secondary">Confidence</div>
                          </div>
                        </div>
                      </div>

                      {/* Dataset info */}
                      {inspectEntry.dataset_info && (
                        <DatasetSummary info={inspectEntry.dataset_info} fileName={inspectEntry.dataset} />
                      )}

                      {/* Threat table + charts for inspected cell */}
                      {inspectEntry.predictions?.length > 0 && (
                        <ThreatTable predictions={inspectEntry.predictions as never} />
                      )}

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {inspectEntry.predictions?.length > 0 && (
                          <UncertaintyChart predictions={inspectEntry.predictions as never} />
                        )}
                        <ConfusionMatrix
                          matrix={inspectEntry.confusion_matrix}
                          labels={
                            inspectEntry.per_class_metrics
                              ? Object.keys(inspectEntry.per_class_metrics)
                              : undefined
                          }
                          source="upload"
                        />
                      </div>

                      {inspectPerClass.length > 0 && (
                        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                          <h4 className="text-sm font-medium text-text-secondary mb-4">Per-Class Metrics</h4>
                          <ResponsiveContainer width="100%" height={300}>
                            <BarChart data={inspectPerClass} layout="vertical" margin={{ left: 120 }}>
                              <XAxis type="number" domain={[0, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} tickFormatter={v => `${v}%`} axisLine={{ stroke: '#334155' }} />
                              <YAxis type="category" dataKey="label" tick={{ fill: '#94A3B8', fontSize: 10 }} width={115} axisLine={{ stroke: '#334155' }} />
                              <Tooltip contentStyle={TT} />
                              <Bar dataKey="precision" fill="#3B82F6" name="Precision" />
                              <Bar dataKey="recall" fill="#22C55E" name="Recall" />
                              <Bar dataKey="f1" fill="#A855F7" name="F1" />
                            </BarChart>
                          </ResponsiveContainer>
                        </div>
                      )}
                    </>
                  )}

                  {!inspectEntry && (
                    <div className="bg-bg-secondary rounded-xl p-8 border border-bg-card text-center text-text-secondary text-sm">
                      Select a model × dataset cell above to inspect detailed results
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* Model Analytics — always available */}
      <div className="space-y-3">
        <button
          onClick={() => setShowModelAnalytics(!showModelAnalytics)}
          className="flex items-center gap-2 text-sm font-semibold text-text-primary hover:text-accent-blue transition-colors"
        >
          <TrendingUp className="w-4 h-4 text-accent-blue" />
          Model Analytics & Evaluation
          {showModelAnalytics ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>
        {!results && !loading && !multiResult && (
          <p className="text-xs text-text-secondary">
            Pre-computed benchmark metrics for all dissertation models. Upload a dataset above or send results from Live Monitor to see per-dataset analysis alongside these model evaluations.
          </p>
        )}
        {showModelAnalytics && <ModelAnalyticsPanel />}
      </div>
    </div>
  )
}
