import { useEffect, useState } from 'react'
import {
  Swords, Loader2, ShieldAlert, ShieldCheck, Target, Zap,
  BarChart3, TrendingDown, AlertTriangle, ChevronDown, ChevronUp, Brain,
  Upload, Layers, GitCompare, Activity, Crosshair, Shield,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  Legend, CartesianGrid, Cell, LineChart, Line, AreaChart, Area,
  ScatterChart, Scatter, ZAxis,
} from 'recharts'
import FileUpload from '../components/FileUpload'
import ModelSelector from '../components/ModelSelector'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import { runRedteam, runRedteamMulti, fetchSampleData, fetchModels } from '../utils/api'
import { usePageState } from '../hooks/usePageState'

const PAGE = 'redteam'
const TT = { background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }

const ATTACK_OPTS = [
  { id: 'fgsm', label: 'FGSM', desc: 'Fast Gradient Sign — single-step, fast' },
  { id: 'pgd', label: 'PGD (10-step)', desc: 'Projected Gradient Descent — iterative, stronger' },
  { id: 'deepfool', label: 'DeepFool', desc: 'Minimal perturbation to cross boundary' },
  { id: 'cw', label: 'C&W (L2)', desc: 'Carlini & Wagner — optimisation-based, strong' },
  { id: 'gaussian', label: 'Gaussian Noise', desc: 'Random Gaussian perturbation' },
  { id: 'feature_mask', label: 'Feature Masking', desc: 'Randomly zero-out features' },
]

const SEV_COLORS: Record<string, string> = {
  fgsm: '#EF4444', pgd: '#F97316', deepfool: '#F59E0B', cw: '#EC4899', gaussian: '#3B82F6', feature_mask: '#A855F7',
}

const MODEL_COLORS = ['#3B82F6', '#22C55E', '#F59E0B', '#EF4444', '#A855F7', '#06B6D4', '#EC4899']
const DATASET_COLORS = ['#3B82F6', '#22C55E', '#F59E0B']

interface ModelInfo {
  id: string
  name: string
  description: string
  category: string
  weights_available: boolean
  enabled?: boolean
}

interface AttackResult {
  attack: string
  label: string
  epsilon: number
  accuracy_clean: number
  accuracy_adversarial: number
  accuracy_drop: number
  confidence_clean: number
  confidence_adversarial: number
  confidence_drop: number
  flip_rate: number
  perturbation_l2: number
  time_ms: number
  per_class: Record<string, { count: number; clean_acc: number; adv_acc: number; flip_rate: number }>
  error?: string
}

interface ArenaResult {
  arena_id: string
  n_samples: number
  epsilon: number
  clean_accuracy: number
  clean_confidence: number
  attacks: AttackResult[]
  robustness_score: number
  model_used?: string
  dataset_name?: string
}

interface MultiArenaResult {
  multi_arena_id: string
  n_models: number
  n_datasets: number
  model_names: string[]
  dataset_names: string[]
  epsilon: number
  attacks_used: string[]
  arena_matrix: Record<string, ArenaResult>
  cross_model_comparison: Record<string, {
    model_names: string[]
    per_model_results: Record<string, ArenaResult>
    evasion_matrix: Record<string, Record<string, number | null>>
    risk_scores: Record<string, number>
    robustness_ranking: string[]
  }>
  cross_dataset_transferability: Record<string, {
    attack: string
    epsilon: number
    dataset_names: string[]
    transfer_matrix: Record<string, {
      source: string
      target: string
      clean_accuracy: number
      transferred_accuracy: number
      accuracy_drop: number
      flip_rate: number
      is_self: boolean
    }>
  }>
  epsilon_profiles: Record<string, {
    per_attack: Record<string, {
      attack: string
      epsilon_curve: { epsilon: number; accuracy: number }[]
      breaking_epsilon: number | null
    }>
    worst_attack: string | null
    worst_breaking_epsilon: number | null
  }>
  confidence_erosion: Record<string, {
    erosion_curves: Record<string, { epsilon: number; confidence: number; accuracy: number }[]>
  }>
  robustness_heatmap: { model: string; dataset: string; robustness_score: number; clean_accuracy: number }[]
  time_ms: number
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

export default function RedTeamArena() {
  const [mode, setMode] = usePageState<'single' | 'multi'>(PAGE, 'mode', 'multi')

  // ── Single mode state ──
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
  const [epsilon, setEpsilon] = usePageState(PAGE, 'epsilon', 0.1)
  const [nSamples, setNSamples] = usePageState(PAGE, 'nSamples', 500)
  const [selectedAttacks, setSelectedAttacks] = usePageState<string[]>(PAGE, 'selectedAttacks', ATTACK_OPTS.map(a => a.id))
  const [running, setRunning] = usePageState(PAGE, 'running', false)
  const [error, setError] = usePageState(PAGE, 'error', '')

  // ── Results ──
  const [result, setResult] = usePageState<ArenaResult | null>(PAGE, 'result', null)
  const [multiResult, setMultiResult] = usePageState<MultiArenaResult | null>(PAGE, 'multiResult', null)
  const [activeView, setActiveView] = usePageState<string>(PAGE, 'activeView', 'overview')
  const [expandedAttack, setExpandedAttack] = usePageState<string | null>(PAGE, 'expandedAttack', null)

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

  // ── Single mode handlers ──
  const handleFileSelect = (f: File) => {
    setFileLoading(true)
    setFileReady(false)
    setFile(f)
    setFileName(f.name)
    const delay = Math.min(Math.max(f.size / 100000, 400), 3000)
    setTimeout(() => { setFileLoading(false); setFileReady(true) }, delay)
  }

  const handleRunSingle = async () => {
    if (!file) return
    setRunning(true); setError(''); setResult(null); setMultiResult(null)
    try {
      const data = await runRedteam(file, selectedAttacks, epsilon, nSamples, selectedModel)
      setResult(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Arena failed')
    } finally { setRunning(false) }
  }

  // ── Multi mode handlers ──
  const handleRunMulti = async () => {
    const activeFiles = slots.filter(s => s.file && s.fileReady)
    if (activeFiles.length === 0 || selectedModels.length === 0) return
    setRunning(true); setError(''); setResult(null); setMultiResult(null)
    try {
      const files = slots.map(s => s.file)
      const data = await runRedteamMulti(files, selectedModels, selectedAttacks, epsilon, nSamples)
      setMultiResult(data)
      setActiveView('overview')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Multi-arena failed')
    } finally { setRunning(false) }
  }

  const toggleModel = (modelId: string) => {
    setSelectedModels(prev =>
      prev.includes(modelId) ? prev.filter(m => m !== modelId) : [...prev, modelId]
    )
  }

  const toggleAttack = (id: string) => {
    setSelectedAttacks(prev =>
      prev.includes(id) ? prev.filter(a => a !== id) : [...prev, id]
    )
  }

  // ── Derived data for single-mode charts ──
  const radarData = result?.attacks
    .filter(a => !a.error)
    .map(a => ({
      attack: a.label,
      'Accuracy Retained': Math.round(a.accuracy_adversarial * 100),
      'Confidence Retained': Math.round(a.confidence_adversarial * 100),
    })) || []

  const barData = result?.attacks
    .filter(a => !a.error)
    .map(a => ({
      name: a.label,
      'Accuracy Drop': Math.round(a.accuracy_drop * 100 * 10) / 10,
      'Flip Rate': Math.round(a.flip_rate * 100 * 10) / 10,
    })) || []

  // ── Multi-mode derived data ──
  const heatmapData = multiResult?.robustness_heatmap || []
  const modelNames = multiResult?.model_names || []
  const datasetNames = multiResult?.dataset_names || []

  // Robustness comparison bar (model × dataset)
  const comparisonBarData = datasetNames.map(ds => {
    const entry: Record<string, string | number> = { dataset: ds.length > 20 ? ds.slice(0, 18) + '…' : ds }
    modelNames.forEach(m => {
      const key = `${m}|${ds}`
      const arena = multiResult?.arena_matrix?.[key]
      entry[m] = arena ? Math.round(arena.robustness_score * 1000) / 10 : 0
    })
    return entry
  })

  // ── Attack selector state for epsilon & erosion tabs ──
  const [epsilonAttack, setEpsilonAttack] = usePageState<string>(PAGE, 'epsilonAttack', 'fgsm')
  const [erosionAttack, setErosionAttack] = usePageState<string>(PAGE, 'erosionAttack', 'fgsm')

  // Available attacks from epsilon profiles (per_attack keys)
  const availableEpsilonAttacks = (() => {
    if (!multiResult?.epsilon_profiles) return [] as string[]
    const firstModel = Object.values(multiResult.epsilon_profiles)[0]
    return firstModel?.per_attack ? Object.keys(firstModel.per_attack) : [] as string[]
  })()

  // Available attacks from confidence erosion
  const availableErosionAttacks = (() => {
    if (!multiResult?.confidence_erosion) return [] as string[]
    const firstModel = Object.values(multiResult.confidence_erosion)[0]
    return firstModel?.erosion_curves ? Object.keys(firstModel.erosion_curves) : [] as string[]
  })()

  // Epsilon profile chart data — driven by selected attack
  const epsilonChartData = (() => {
    if (!multiResult?.epsilon_profiles) return []
    const allEps = new Set<number>()
    Object.values(multiResult.epsilon_profiles).forEach(p => {
      p.per_attack?.[epsilonAttack]?.epsilon_curve?.forEach(pt => allEps.add(pt.epsilon))
    })
    return [...allEps].sort((a, b) => a - b).map(eps => {
      const entry: Record<string, string | number> = { epsilon: eps }
      modelNames.forEach(m => {
        const profile = multiResult.epsilon_profiles[m]?.per_attack?.[epsilonAttack]
        const pt = profile?.epsilon_curve?.find(p => p.epsilon === eps)
        entry[m] = pt ? Math.round(pt.accuracy * 1000) / 10 : 0
      })
      return entry
    })
  })()

  // Confidence erosion chart data — driven by selected attack
  const erosionChartData = (() => {
    if (!multiResult?.confidence_erosion) return []
    const allEps = new Set<number>()
    Object.values(multiResult.confidence_erosion).forEach(e => {
      e.erosion_curves?.[erosionAttack]?.forEach((pt: { epsilon: number }) => allEps.add(pt.epsilon))
    })
    return [...allEps].sort((a, b) => a - b).map(eps => {
      const entry: Record<string, string | number> = { epsilon: eps }
      modelNames.forEach(m => {
        const curves = multiResult.confidence_erosion[m]?.erosion_curves
        const pt = curves?.[erosionAttack]?.find((p: { epsilon: number }) => p.epsilon === eps)
        entry[m] = pt ? Math.round(pt.confidence * 1000) / 10 : 0
      })
      return entry
    })
  })()

  // Active arena for detail inspection
  const [inspectKey, setInspectKey] = usePageState<string>(PAGE, 'inspectKey', '')
  const inspectArena = multiResult?.arena_matrix?.[inspectKey] || null

  return (
    <div className="space-y-6">
      <PageGuide
        title="How to use Adversarial Red Team Arena"
        steps={[
          { title: 'Upload dataset(s)', desc: 'Single mode: 1 file. Multi mode: up to 6 datasets for cross-domain analysis.' },
          { title: 'Select model(s)', desc: 'Multi-select models to compare robustness across architectures.' },
          { title: 'Choose attacks & epsilon', desc: 'Pick attack vectors and perturbation strength.' },
          { title: 'Launch arena', desc: 'View robustness heatmap, evasion matrix, epsilon profiles, and confidence erosion.' },
        ]}
        tip="Multi-mode reveals which model+dataset combinations are most vulnerable — critical intel for red team assessments."
      />

      {/* Header */}
      <div className="flex items-center gap-3">
        <Swords className="w-7 h-7 text-accent-red" />
        <div className="flex-1">
          <h1 className="text-xl md:text-2xl font-display font-bold">Adversarial Red Team Arena</h1>
          <p className="text-sm text-text-secondary mt-0.5">Multi-model, multi-dataset adversarial robustness analysis</p>
        </div>
        <ExportMenu filename="red-team" />
      </div>

      {/* Mode toggle */}
      <div className="flex gap-2">
        <button
          onClick={() => setMode('single')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            mode === 'single' ? 'bg-accent-red text-white' : 'bg-bg-secondary text-text-secondary border border-bg-card hover:text-text-primary'
          }`}
        >
          <Swords className="w-4 h-4 inline mr-1.5" />Single Arena
        </button>
        <button
          onClick={() => setMode('multi')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            mode === 'multi' ? 'bg-accent-red text-white' : 'bg-bg-secondary text-text-secondary border border-bg-card hover:text-text-primary'
          }`}
        >
          <Layers className="w-4 h-4 inline mr-1.5" />Multi-Dataset / Multi-Model
        </button>
      </div>

      {/* ═══════════════════ SINGLE MODE ═══════════════════ */}
      {mode === 'single' && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-3">
              <FileUpload onFile={handleFileSelect} label="Upload traffic dataset" accept=".csv,.parquet,.pcap,.pcapng" fileName={fileName} fileLoading={fileLoading} />
              <button
                onClick={async () => {
                  try { setFileLoading(true); setFileReady(false); const f = await fetchSampleData(); handleFileSelect(f) }
                  catch { setFileLoading(false); setError('Failed to load demo data') }
                }}
                className="text-xs text-accent-blue hover:text-accent-blue/80 underline"
              >or use built-in demo data (1000 flows)</button>
              <ModelSelector value={selectedModel} onChange={setSelectedModel} />
            </div>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-text-secondary block mb-1">Epsilon (perturbation strength)</label>
                <input type="range" min={0.01} max={0.5} step={0.01} value={epsilon}
                  onChange={e => setEpsilon(parseFloat(e.target.value))} className="w-full accent-accent-red" />
                <div className="flex justify-between text-xs text-text-secondary mt-0.5">
                  <span>Subtle (0.01)</span>
                  <span className="font-mono text-accent-red font-semibold">{epsilon.toFixed(2)}</span>
                  <span>Aggressive (0.50)</span>
                </div>
              </div>
              <div>
                <label className="text-xs text-text-secondary block mb-1">Max samples</label>
                <input type="number" min={50} max={5000} step={50} value={nSamples}
                  onChange={e => setNSamples(parseInt(e.target.value) || 500)}
                  className="w-24 px-2 py-1 bg-bg-primary border border-bg-card rounded text-sm text-text-primary" />
              </div>
            </div>
          </div>

          {/* Attack selection */}
          <div>
            <label className="text-xs text-text-secondary block mb-2">Attacks</label>
            <div className="flex flex-wrap gap-2">
              {ATTACK_OPTS.map(a => (
                <button key={a.id} onClick={() => toggleAttack(a.id)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                    selectedAttacks.includes(a.id)
                      ? 'bg-accent-red/15 border-accent-red/40 text-accent-red'
                      : 'bg-bg-primary border-bg-card text-text-secondary hover:text-text-primary'
                  }`} title={a.desc}>{a.label}</button>
              ))}
            </div>
          </div>

          <button onClick={handleRunSingle}
            disabled={!file || !fileReady || running || fileLoading || selectedAttacks.length === 0}
            className="px-5 py-2.5 bg-accent-red text-white rounded-lg text-sm font-medium hover:bg-accent-red/80 transition-colors disabled:opacity-40 flex items-center gap-2">
            {running ? <><Loader2 className="w-4 h-4 animate-spin" />Running attacks...</> : <><Swords className="w-4 h-4" />Launch Arena</>}
          </button>

          {error && <div className="px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">{error}</div>}
        </div>
      )}

      {/* ═══════════════════ MULTI MODE ═══════════════════ */}
      {mode === 'multi' && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-5">
          {/* File slots */}
          <div>
            <h3 className="text-sm font-medium text-text-secondary flex items-center gap-2 mb-3">
              <Upload className="w-4 h-4" /> Upload Datasets (up to 3)
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {slots.map((slot, idx) => (
                <div key={idx} className={`rounded-lg border p-3 ${
                  slot.fileReady ? 'border-accent-green/40 bg-accent-green/5' : 'border-bg-card bg-bg-primary'
                }`}>
                  <div className="text-xs text-text-secondary mb-1.5 font-medium">
                    Dataset {idx + 1} {idx === 0 && <span className="text-accent-red">*</span>}
                  </div>
                  <FileUpload
                    onFile={(f) => handleSlotFileSelect(idx, f)}
                    label={`Dataset ${idx + 1}`}
                    accept=".csv,.parquet,.pcap,.pcapng"
                    fileName={slot.fileName}
                    fileLoading={slot.fileLoading}
                  />
                  {idx === 0 && !slot.file && (
                    <button
                      onClick={async () => {
                        try {
                          updateSlot(idx, { fileLoading: true, fileReady: false })
                          const f = await fetchSampleData()
                          handleSlotFileSelect(idx, f)
                        } catch { updateSlot(idx, { fileLoading: false }); setError('Failed to load demo data') }
                      }}
                      className="text-xs text-accent-blue hover:text-accent-blue/80 underline mt-1"
                    >demo data</button>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Model multi-select */}
          <div>
            <h3 className="text-sm font-medium text-text-secondary flex items-center gap-2 mb-2">
              <Brain className="w-4 h-4" /> Select Models (multi-select)
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {availableModels.map(m => (
                <button key={m.id} onClick={() => toggleModel(m.id)}
                  className={`text-left px-3 py-2.5 rounded-lg border transition-all ${
                    selectedModels.includes(m.id)
                      ? 'border-accent-red bg-accent-red/10'
                      : 'border-bg-card bg-bg-primary hover:border-bg-card/80'
                  }`}>
                  <div className="flex items-center gap-2">
                    <div className={`w-4 h-4 rounded border flex items-center justify-center text-xs ${
                      selectedModels.includes(m.id) ? 'bg-accent-red border-accent-red text-white' : 'border-text-secondary'
                    }`}>{selectedModels.includes(m.id) && '✓'}</div>
                    <span className="text-sm font-medium truncate">{m.name}</span>
                  </div>
                  <p className="text-xs text-text-secondary mt-0.5 line-clamp-1 ml-6">{m.description}</p>
                </button>
              ))}
            </div>
            <div className="text-xs text-text-secondary mt-1">{selectedModels.length} models selected</div>
          </div>

          {/* Attack & params */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-text-secondary block mb-2">Attacks</label>
              <div className="flex flex-wrap gap-2">
                {ATTACK_OPTS.map(a => (
                  <button key={a.id} onClick={() => toggleAttack(a.id)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                      selectedAttacks.includes(a.id)
                        ? 'bg-accent-red/15 border-accent-red/40 text-accent-red'
                        : 'bg-bg-primary border-bg-card text-text-secondary hover:text-text-primary'
                    }`} title={a.desc}>{a.label}</button>
                ))}
              </div>
            </div>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-text-secondary block mb-1">Epsilon (perturbation strength)</label>
                <input type="range" min={0.01} max={0.5} step={0.01} value={epsilon}
                  onChange={e => setEpsilon(parseFloat(e.target.value))} className="w-full accent-accent-red" />
                <div className="flex justify-between text-xs text-text-secondary mt-0.5">
                  <span>Subtle</span>
                  <span className="font-mono text-accent-red font-semibold">{epsilon.toFixed(2)}</span>
                  <span>Aggressive</span>
                </div>
              </div>
              <div>
                <label className="text-xs text-text-secondary block mb-1">Max samples per dataset</label>
                <input type="number" min={50} max={5000} step={50} value={nSamples}
                  onChange={e => setNSamples(parseInt(e.target.value) || 500)}
                  className="w-24 px-2 py-1 bg-bg-primary border border-bg-card rounded text-sm text-text-primary" />
              </div>
            </div>
          </div>

          {/* Run button */}
          <button onClick={handleRunMulti}
            disabled={!slots.some(s => s.file && s.fileReady) || selectedModels.length === 0 || running || selectedAttacks.length === 0}
            className="px-5 py-2.5 bg-accent-red text-white rounded-lg text-sm font-medium hover:bg-accent-red/80 transition-colors disabled:opacity-40 flex items-center gap-2">
            {running ? <><Loader2 className="w-4 h-4 animate-spin" />Running multi-arena...</> : <><Swords className="w-4 h-4" />Launch Multi-Arena</>}
          </button>

          {error && <div className="px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">{error}</div>}
        </div>
      )}

      {/* ═══════════════════ SINGLE MODE RESULTS ═══════════════════ */}
      {mode === 'single' && result && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1"><ShieldCheck className="w-3.5 h-3.5" /> Clean Accuracy</div>
              <div className="text-xl font-mono font-bold text-accent-green">{(result.clean_accuracy * 100).toFixed(1)}%</div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1"><ShieldAlert className="w-3.5 h-3.5" /> Robustness Score</div>
              <div className={`text-xl font-mono font-bold ${result.robustness_score > 0.7 ? 'text-accent-green' : result.robustness_score > 0.4 ? 'text-accent-amber' : 'text-accent-red'}`}>
                {(result.robustness_score * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1"><Target className="w-3.5 h-3.5" /> Samples</div>
              <div className="text-xl font-mono font-bold text-text-primary">{result.n_samples.toLocaleString()}</div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1"><Brain className="w-3.5 h-3.5" /> Model</div>
              <div className="text-sm font-mono font-bold text-accent-blue truncate">{result.model_used}</div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h3 className="text-sm font-semibold mb-3">Robustness Radar</h3>
              <ResponsiveContainer width="100%" height={280}>
                <RadarChart data={radarData}>
                  <PolarGrid stroke="#334155" />
                  <PolarAngleAxis dataKey="attack" tick={{ fill: '#94A3B8', fontSize: 11 }} />
                  <PolarRadiusAxis domain={[0, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} />
                  <Radar name="Accuracy %" dataKey="Accuracy Retained" stroke="#22C55E" fill="#22C55E" fillOpacity={0.2} />
                  <Radar name="Confidence %" dataKey="Confidence Retained" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.15} />
                  <Legend wrapperStyle={{ fontSize: 11, color: '#94A3B8' }} />
                </RadarChart>
              </ResponsiveContainer>
            </div>
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h3 className="text-sm font-semibold mb-3">Impact per Attack</h3>
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={barData} barGap={4}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="name" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" />
                  <Tooltip contentStyle={TT} />
                  <Bar dataKey="Accuracy Drop" fill="#EF4444" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="Flip Rate" fill="#F59E0B" radius={[4, 4, 0, 0]} />
                  <Legend wrapperStyle={{ fontSize: 11, color: '#94A3B8' }} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Per-attack detail cards */}
          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-text-secondary">Attack Details</h3>
            {result.attacks.map(atk => (
              <div key={atk.attack} className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
                <button onClick={() => setExpandedAttack(expandedAttack === atk.attack ? null : atk.attack)}
                  className="w-full px-4 py-3 flex items-center gap-3 hover:bg-bg-card/30 transition-colors">
                  <Zap className="w-4 h-4" style={{ color: SEV_COLORS[atk.attack] || '#94A3B8' }} />
                  <span className="font-medium text-sm flex-1 text-left">{atk.label}</span>
                  {atk.error ? <span className="text-xs text-accent-red">Error</span> : (
                    <>
                      <span className="text-xs text-text-secondary">Drop: <span className="font-mono text-accent-red">{(atk.accuracy_drop * 100).toFixed(1)}%</span></span>
                      <span className="text-xs text-text-secondary ml-3">Flip: <span className="font-mono text-accent-amber">{(atk.flip_rate * 100).toFixed(1)}%</span></span>
                      <span className="text-xs text-text-secondary ml-3">L2: <span className="font-mono">{atk.perturbation_l2.toFixed(3)}</span></span>
                      <span className="text-xs text-text-secondary ml-3">{atk.time_ms.toFixed(0)}ms</span>
                    </>
                  )}
                  {expandedAttack === atk.attack ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
                {expandedAttack === atk.attack && !atk.error && atk.per_class && (
                  <div className="px-4 pb-4 border-t border-bg-card">
                    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2 mt-3">
                      {Object.entries(atk.per_class).slice(0, 12).map(([cls, data]) => (
                        <div key={cls} className="bg-bg-primary rounded-lg p-2 text-xs">
                          <div className="text-text-secondary truncate mb-1" title={cls}>{cls}</div>
                          <div className="flex justify-between">
                            <span className="text-accent-green">{(data.clean_acc * 100).toFixed(0)}%</span>
                            <span className="text-text-secondary">→</span>
                            <span className={data.adv_acc < data.clean_acc * 0.5 ? 'text-accent-red' : 'text-accent-amber'}>{(data.adv_acc * 100).toFixed(0)}%</span>
                          </div>
                          <div className="text-text-secondary mt-0.5">n={data.count}</div>
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

      {/* ═══════════════════ MULTI MODE RESULTS ═══════════════════ */}
      {mode === 'multi' && multiResult && (
        <>
          {/* View tabs */}
          <div className="flex flex-wrap gap-2">
            {[
              { id: 'overview', label: 'Overview', icon: BarChart3 },
              { id: 'evasion', label: 'Evasion Matrix', icon: Crosshair },
              { id: 'epsilon', label: 'Epsilon Profiles', icon: Activity },
              { id: 'erosion', label: 'Confidence Erosion', icon: TrendingDown },
              { id: 'transferability', label: 'Attack Transferability', icon: GitCompare },
              { id: 'inspect', label: 'Inspect Arena', icon: Target },
            ].map(tab => (
              <button key={tab.id} onClick={() => setActiveView(tab.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors flex items-center gap-1.5 ${
                  activeView === tab.id
                    ? 'bg-accent-red/15 border-accent-red/40 text-accent-red'
                    : 'bg-bg-secondary border-bg-card text-text-secondary hover:text-text-primary'
                }`}>
                <tab.icon className="w-3.5 h-3.5" />{tab.label}
              </button>
            ))}
          </div>

          {/* Summary cards */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1"><Layers className="w-3.5 h-3.5" /> Datasets</div>
              <div className="text-xl font-mono font-bold text-accent-blue">{multiResult.n_datasets}</div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1"><Brain className="w-3.5 h-3.5" /> Models</div>
              <div className="text-xl font-mono font-bold text-accent-purple">{multiResult.n_models}</div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1"><Zap className="w-3.5 h-3.5" /> Attacks</div>
              <div className="text-xl font-mono font-bold text-accent-red">{multiResult.attacks_used.length}</div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1"><Target className="w-3.5 h-3.5" /> Epsilon</div>
              <div className="text-xl font-mono font-bold text-accent-amber">{multiResult.epsilon.toFixed(2)}</div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1"><Activity className="w-3.5 h-3.5" /> Time</div>
              <div className="text-xl font-mono font-bold text-text-primary">{(multiResult.time_ms / 1000).toFixed(1)}s</div>
            </div>
          </div>

          {/* ── OVERVIEW TAB ── */}
          {activeView === 'overview' && (
            <>
              {/* Robustness Heatmap */}
              <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                <h3 className="text-sm font-semibold mb-3 flex items-center gap-2"><Shield className="w-4 h-4 text-accent-red" /> Robustness Heatmap (Model × Dataset)</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr>
                        <th className="text-left px-3 py-2 text-text-secondary">Model</th>
                        {datasetNames.map(ds => (
                          <th key={ds} className="text-center px-3 py-2 text-text-secondary truncate max-w-[140px]" title={ds}>
                            {ds.length > 18 ? ds.slice(0, 16) + '…' : ds}
                          </th>
                        ))}
                        <th className="text-center px-3 py-2 text-text-secondary">Risk Score</th>
                      </tr>
                    </thead>
                    <tbody>
                      {modelNames.map((m, mi) => {
                        const firstDs = datasetNames[0]
                        const cmp = firstDs ? multiResult.cross_model_comparison?.[firstDs] : null
                        const risk = cmp?.risk_scores?.[m] ?? 0
                        return (
                          <tr key={m} className="border-t border-bg-card">
                            <td className="px-3 py-2.5 font-medium text-text-primary">{m}</td>
                            {datasetNames.map(ds => {
                              const key = `${m}|${ds}`
                              const arena = multiResult.arena_matrix?.[key]
                              const score = arena?.robustness_score ?? 0
                              const bg = score > 0.7 ? 'bg-accent-green/20 text-accent-green' :
                                         score > 0.4 ? 'bg-accent-amber/20 text-accent-amber' :
                                         'bg-accent-red/20 text-accent-red'
                              return (
                                <td key={ds} className="text-center px-3 py-2.5">
                                  <button onClick={() => { setInspectKey(key); setActiveView('inspect') }}
                                    className={`inline-block px-2.5 py-1 rounded-lg font-mono font-bold ${bg} hover:opacity-80 transition-opacity cursor-pointer`}>
                                    {(score * 100).toFixed(1)}%
                                  </button>
                                </td>
                              )
                            })}
                            <td className="text-center px-3 py-2.5">
                              <span className={`font-mono font-bold ${risk > 0.3 ? 'text-accent-red' : risk > 0.15 ? 'text-accent-amber' : 'text-accent-green'}`}>
                                {(risk * 100).toFixed(1)}%
                              </span>
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Robustness comparison bar chart */}
              {comparisonBarData.length > 0 && (
                <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                  <h3 className="text-sm font-semibold mb-3">Robustness Score Comparison</h3>
                  <ResponsiveContainer width="100%" height={280}>
                    <BarChart data={comparisonBarData} barGap={4}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis dataKey="dataset" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                      <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" domain={[0, 100]} />
                      <Tooltip contentStyle={TT} />
                      {modelNames.map((m, i) => (
                        <Bar key={m} dataKey={m} fill={MODEL_COLORS[i % MODEL_COLORS.length]} radius={[4, 4, 0, 0]} />
                      ))}
                      <Legend wrapperStyle={{ fontSize: 11, color: '#94A3B8' }} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}

              {/* Robustness ranking */}
              {datasetNames[0] && multiResult.cross_model_comparison?.[datasetNames[0]] && (
                <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                  <h3 className="text-sm font-semibold mb-3 flex items-center gap-2"><ShieldCheck className="w-4 h-4 text-accent-green" /> Model Robustness Ranking</h3>
                  <div className="space-y-2">
                    {multiResult.cross_model_comparison[datasetNames[0]].robustness_ranking.map((m, idx) => {
                      const arena = multiResult.arena_matrix?.[`${m}|${datasetNames[0]}`]
                      const score = arena?.robustness_score ?? 0
                      return (
                        <div key={m} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-bg-primary">
                          <span className={`text-lg font-bold w-8 text-center ${idx === 0 ? 'text-accent-green' : idx === modelNames.length - 1 ? 'text-accent-red' : 'text-text-secondary'}`}>
                            #{idx + 1}
                          </span>
                          <span className="text-sm font-medium flex-1">{m}</span>
                          <div className="w-32 bg-bg-card rounded-full h-2 overflow-hidden">
                            <div className={`h-full rounded-full ${score > 0.7 ? 'bg-accent-green' : score > 0.4 ? 'bg-accent-amber' : 'bg-accent-red'}`}
                              style={{ width: `${score * 100}%` }} />
                          </div>
                          <span className="font-mono text-sm w-16 text-right">{(score * 100).toFixed(1)}%</span>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}
            </>
          )}

          {/* ── EVASION MATRIX TAB ── */}
          {activeView === 'evasion' && datasetNames[0] && multiResult.cross_model_comparison?.[datasetNames[0]] && (
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h3 className="text-sm font-semibold mb-1 flex items-center gap-2"><Crosshair className="w-4 h-4 text-accent-red" /> Evasion Success Matrix</h3>
              <p className="text-xs text-text-secondary mb-4">Flip rate per attack × model — higher = more easily evaded</p>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr>
                      <th className="text-left px-3 py-2 text-text-secondary">Attack</th>
                      {modelNames.map(m => (
                        <th key={m} className="text-center px-3 py-2 text-text-secondary">{m}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(multiResult.cross_model_comparison[datasetNames[0]].evasion_matrix).map(([atk, row]) => (
                      <tr key={atk} className="border-t border-bg-card">
                        <td className="px-3 py-2.5 font-medium flex items-center gap-2">
                          <Zap className="w-3.5 h-3.5" style={{ color: SEV_COLORS[atk] || '#94A3B8' }} />
                          {ATTACK_OPTS.find(a => a.id === atk)?.label || atk}
                        </td>
                        {modelNames.map(m => {
                          const val = row[m]
                          if (val == null) return <td key={m} className="text-center px-3 py-2.5 text-text-secondary">—</td>
                          const bg = val > 0.3 ? 'bg-accent-red/20 text-accent-red' :
                                     val > 0.1 ? 'bg-accent-amber/20 text-accent-amber' :
                                     'bg-accent-green/20 text-accent-green'
                          return (
                            <td key={m} className="text-center px-3 py-2.5">
                              <span className={`inline-block px-2 py-0.5 rounded font-mono font-bold ${bg}`}>
                                {(val * 100).toFixed(1)}%
                              </span>
                            </td>
                          )
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── EPSILON PROFILES TAB ── */}
          {activeView === 'epsilon' && (
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <div className="flex items-center justify-between mb-1">
                <h3 className="text-sm font-semibold flex items-center gap-2">
                  <Activity className="w-4 h-4 text-accent-amber" /> Epsilon Sensitivity Profiles
                </h3>
                {/* Attack selector pills */}
                <div className="flex gap-1.5 flex-wrap">
                  {availableEpsilonAttacks.map(atk => {
                    const opt = ATTACK_OPTS.find(a => a.id === atk)
                    return (
                      <button key={atk} onClick={() => setEpsilonAttack(atk)}
                        className={`px-2.5 py-1 rounded-md text-[10px] font-semibold transition-all border ${
                          epsilonAttack === atk
                            ? 'border-accent-amber/60 bg-accent-amber/15 text-accent-amber'
                            : 'border-bg-card bg-bg-primary text-text-secondary hover:text-text-primary hover:border-text-secondary'
                        }`}
                      >
                        {opt?.label || atk}
                      </button>
                    )
                  })}
                </div>
              </div>
              <p className="text-xs text-text-secondary mb-4">
                Accuracy vs. perturbation strength — find each model's breaking point
                <span className="ml-2 text-accent-amber font-medium">({ATTACK_OPTS.find(a => a.id === epsilonAttack)?.label || epsilonAttack})</span>
              </p>
              {epsilonChartData.length > 0 ? (
                <>
                  <ResponsiveContainer width="100%" height={320}>
                    <LineChart data={epsilonChartData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis dataKey="epsilon" tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'ε', position: 'insideBottomRight', offset: -5, fill: '#94A3B8', fontSize: 11 }} />
                      <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" domain={[0, 100]} />
                      <Tooltip contentStyle={TT} />
                      {modelNames.map((m, i) => (
                        <Line key={m} type="monotone" dataKey={m} stroke={MODEL_COLORS[i % MODEL_COLORS.length]}
                          strokeWidth={2} dot={{ r: 3 }} />
                      ))}
                      <Legend wrapperStyle={{ fontSize: 11, color: '#94A3B8' }} />
                    </LineChart>
                  </ResponsiveContainer>
                  {/* Breaking point badges */}
                  <div className="flex flex-wrap gap-3 mt-4">
                    {modelNames.map((m, i) => {
                      const profile = multiResult.epsilon_profiles?.[m]?.per_attack?.[epsilonAttack]
                      const bp = profile?.breaking_epsilon
                      return (
                        <div key={m} className="flex items-center gap-2 text-xs px-3 py-1.5 bg-bg-primary rounded-lg border border-bg-card">
                          <div className="w-3 h-3 rounded-full" style={{ background: MODEL_COLORS[i % MODEL_COLORS.length] }} />
                          <span className="font-medium">{m}</span>
                          <span className="text-text-secondary">breaks at ε =</span>
                          <span className={`font-mono font-bold ${bp != null ? 'text-accent-red' : 'text-accent-green'}`}>
                            {bp != null ? bp.toFixed(2) : '> 0.50'}
                          </span>
                        </div>
                      )
                    })}
                  </div>
                  {/* Worst-attack summary */}
                  <div className="flex flex-wrap gap-3 mt-3 pt-3 border-t border-bg-card">
                    {modelNames.map((m, i) => {
                      const ep = multiResult.epsilon_profiles?.[m]
                      const worst = ep?.worst_attack
                      const worstEps = ep?.worst_breaking_epsilon
                      return worst ? (
                        <div key={m} className="flex items-center gap-2 text-xs px-3 py-1.5 bg-accent-red/5 rounded-lg border border-accent-red/20">
                          <div className="w-3 h-3 rounded-full" style={{ background: MODEL_COLORS[i % MODEL_COLORS.length] }} />
                          <span className="font-medium">{m}</span>
                          <span className="text-text-secondary">most vulnerable to</span>
                          <span className="font-semibold text-accent-red">{ATTACK_OPTS.find(a => a.id === worst)?.label || worst}</span>
                          <span className="text-text-secondary">at ε =</span>
                          <span className="font-mono font-bold text-accent-red">{worstEps != null ? worstEps.toFixed(2) : '?'}</span>
                        </div>
                      ) : null
                    })}
                  </div>
                </>
              ) : (
                <p className="text-xs text-text-secondary italic">No data for this attack. Try selecting a different one.</p>
              )}
            </div>
          )}

          {/* ── CONFIDENCE EROSION TAB ── */}
          {activeView === 'erosion' && (
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <div className="flex items-center justify-between mb-1">
                <h3 className="text-sm font-semibold flex items-center gap-2">
                  <TrendingDown className="w-4 h-4 text-accent-red" /> Detection Confidence Erosion
                </h3>
                {/* Attack selector pills */}
                <div className="flex gap-1.5 flex-wrap">
                  {availableErosionAttacks.map(atk => {
                    const opt = ATTACK_OPTS.find(a => a.id === atk)
                    return (
                      <button key={atk} onClick={() => setErosionAttack(atk)}
                        className={`px-2.5 py-1 rounded-md text-[10px] font-semibold transition-all border ${
                          erosionAttack === atk
                            ? 'border-accent-red/60 bg-accent-red/15 text-accent-red'
                            : 'border-bg-card bg-bg-primary text-text-secondary hover:text-text-primary hover:border-text-secondary'
                        }`}
                      >
                        {opt?.label || atk}
                      </button>
                    )
                  })}
                </div>
              </div>
              <p className="text-xs text-text-secondary mb-4">
                How quickly models lose confidence under increasing perturbation
                <span className="ml-2 text-accent-red font-medium">({ATTACK_OPTS.find(a => a.id === erosionAttack)?.label || erosionAttack})</span>
              </p>
              {erosionChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={320}>
                <AreaChart data={erosionChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="epsilon" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" domain={[0, 100]} />
                  <Tooltip contentStyle={TT} />
                  {modelNames.map((m, i) => (
                    <Area key={m} type="monotone" dataKey={m} stroke={MODEL_COLORS[i % MODEL_COLORS.length]}
                      fill={MODEL_COLORS[i % MODEL_COLORS.length]} fillOpacity={0.1} strokeWidth={2} />
                  ))}
                  <Legend wrapperStyle={{ fontSize: 11, color: '#94A3B8' }} />
                </AreaChart>
              </ResponsiveContainer>
              ) : (
                <p className="text-xs text-text-secondary italic">No data for this attack. Try selecting a different one.</p>
              )}
            </div>
          )}

          {/* ── ATTACK TRANSFERABILITY TAB ── */}
          {activeView === 'transferability' && Object.keys(multiResult.cross_dataset_transferability || {}).length > 0 && (
            <div className="space-y-4">
              {Object.entries(multiResult.cross_dataset_transferability).map(([mname, trans]) => (
                <div key={mname} className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                  <h3 className="text-sm font-semibold mb-1 flex items-center gap-2">
                    <GitCompare className="w-4 h-4 text-accent-blue" /> Attack Transferability — {mname}
                  </h3>
                  <p className="text-xs text-text-secondary mb-4">Adversarial examples from source dataset applied to target — FGSM at ε={trans.epsilon}</p>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr>
                          <th className="text-left px-3 py-2 text-text-secondary">Source → Target</th>
                          {trans.dataset_names.map(ds => (
                            <th key={ds} className="text-center px-3 py-2 text-text-secondary truncate max-w-[120px]" title={ds}>
                              {ds.length > 15 ? ds.slice(0, 13) + '…' : ds}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {trans.dataset_names.map(src => (
                          <tr key={src} className="border-t border-bg-card">
                            <td className="px-3 py-2.5 font-medium truncate max-w-[120px]" title={src}>
                              {src.length > 15 ? src.slice(0, 13) + '…' : src}
                            </td>
                            {trans.dataset_names.map(tgt => {
                              const key = `${src}|${tgt}`
                              const cell = trans.transfer_matrix?.[key]
                              if (!cell) return <td key={tgt} className="text-center px-3 py-2.5 text-text-secondary">—</td>
                              const drop = cell.accuracy_drop
                              const bg = cell.is_self ? 'bg-accent-blue/10 border border-accent-blue/30' :
                                         drop > 0.2 ? 'bg-accent-red/20 text-accent-red' :
                                         drop > 0.1 ? 'bg-accent-amber/20 text-accent-amber' :
                                         'bg-accent-green/20 text-accent-green'
                              return (
                                <td key={tgt} className="text-center px-3 py-2.5">
                                  <div className={`inline-block px-2 py-1 rounded ${bg}`}>
                                    <div className="font-mono font-bold">{(cell.transferred_accuracy * 100).toFixed(1)}%</div>
                                    <div className="text-[10px] mt-0.5 opacity-70">flip: {(cell.flip_rate * 100).toFixed(0)}%</div>
                                  </div>
                                </td>
                              )
                            })}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ))}
            </div>
          )}

          {activeView === 'transferability' && Object.keys(multiResult.cross_dataset_transferability || {}).length === 0 && (
            <div className="bg-bg-secondary rounded-xl p-8 border border-bg-card text-center text-text-secondary text-sm">
              <GitCompare className="w-8 h-8 mx-auto mb-2 opacity-40" />
              Upload at least 2 datasets to see cross-dataset attack transferability analysis.
            </div>
          )}

          {/* ── INSPECT ARENA TAB ── */}
          {activeView === 'inspect' && (
            <div className="space-y-4">
              {/* Arena selector */}
              <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                <h3 className="text-sm font-semibold mb-3 flex items-center gap-2"><Target className="w-4 h-4 text-accent-blue" /> Select Arena to Inspect</h3>
                <div className="flex flex-wrap gap-2">
                  {Object.keys(multiResult.arena_matrix || {}).map(key => {
                    const [m, ds] = key.split('|')
                    return (
                      <button key={key} onClick={() => setInspectKey(key)}
                        className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                          inspectKey === key
                            ? 'bg-accent-red/15 border-accent-red/40 text-accent-red'
                            : 'bg-bg-primary border-bg-card text-text-secondary hover:text-text-primary'
                        }`}>
                        {m} × {ds && ds.length > 20 ? ds.slice(0, 18) + '…' : ds}
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* Inspected arena details */}
              {inspectArena && (
                <>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                      <div className="text-xs text-text-secondary mb-1">Clean Accuracy</div>
                      <div className="text-xl font-mono font-bold text-accent-green">{(inspectArena.clean_accuracy * 100).toFixed(1)}%</div>
                    </div>
                    <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                      <div className="text-xs text-text-secondary mb-1">Robustness</div>
                      <div className={`text-xl font-mono font-bold ${inspectArena.robustness_score > 0.7 ? 'text-accent-green' : inspectArena.robustness_score > 0.4 ? 'text-accent-amber' : 'text-accent-red'}`}>
                        {(inspectArena.robustness_score * 100).toFixed(1)}%
                      </div>
                    </div>
                    <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                      <div className="text-xs text-text-secondary mb-1">Samples</div>
                      <div className="text-xl font-mono font-bold text-text-primary">{inspectArena.n_samples}</div>
                    </div>
                    <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                      <div className="text-xs text-text-secondary mb-1">Epsilon</div>
                      <div className="text-xl font-mono font-bold text-accent-amber">{inspectArena.epsilon.toFixed(2)}</div>
                    </div>
                  </div>

                  {/* Radar + Bar for inspected arena */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                      <h3 className="text-sm font-semibold mb-3">Robustness Radar</h3>
                      <ResponsiveContainer width="100%" height={260}>
                        <RadarChart data={inspectArena.attacks.filter(a => !a.error).map(a => ({
                          attack: a.label,
                          'Accuracy %': Math.round(a.accuracy_adversarial * 100),
                          'Confidence %': Math.round(a.confidence_adversarial * 100),
                        }))}>
                          <PolarGrid stroke="#334155" />
                          <PolarAngleAxis dataKey="attack" tick={{ fill: '#94A3B8', fontSize: 11 }} />
                          <PolarRadiusAxis domain={[0, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} />
                          <Radar name="Accuracy %" dataKey="Accuracy %" stroke="#22C55E" fill="#22C55E" fillOpacity={0.2} />
                          <Radar name="Confidence %" dataKey="Confidence %" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.15} />
                          <Legend wrapperStyle={{ fontSize: 11, color: '#94A3B8' }} />
                        </RadarChart>
                      </ResponsiveContainer>
                    </div>
                    <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                      <h3 className="text-sm font-semibold mb-3">Impact per Attack</h3>
                      <ResponsiveContainer width="100%" height={260}>
                        <BarChart data={inspectArena.attacks.filter(a => !a.error).map(a => ({
                          name: a.label,
                          'Accuracy Drop': Math.round(a.accuracy_drop * 1000) / 10,
                          'Flip Rate': Math.round(a.flip_rate * 1000) / 10,
                        }))} barGap={4}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                          <XAxis dataKey="name" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                          <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" />
                          <Tooltip contentStyle={TT} />
                          <Bar dataKey="Accuracy Drop" fill="#EF4444" radius={[4, 4, 0, 0]} />
                          <Bar dataKey="Flip Rate" fill="#F59E0B" radius={[4, 4, 0, 0]} />
                          <Legend wrapperStyle={{ fontSize: 11, color: '#94A3B8' }} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  {/* Attack detail cards for inspected arena */}
                  <div className="space-y-2">
                    {inspectArena.attacks.map(atk => (
                      <div key={atk.attack} className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
                        <button onClick={() => setExpandedAttack(expandedAttack === `${inspectKey}-${atk.attack}` ? null : `${inspectKey}-${atk.attack}`)}
                          className="w-full px-4 py-3 flex items-center gap-3 hover:bg-bg-card/30 transition-colors">
                          <Zap className="w-4 h-4" style={{ color: SEV_COLORS[atk.attack] || '#94A3B8' }} />
                          <span className="font-medium text-sm flex-1 text-left">{atk.label}</span>
                          {atk.error ? <span className="text-xs text-accent-red">Error</span> : (
                            <>
                              <span className="text-xs text-text-secondary">Drop: <span className="font-mono text-accent-red">{(atk.accuracy_drop * 100).toFixed(1)}%</span></span>
                              <span className="text-xs text-text-secondary ml-3">Flip: <span className="font-mono text-accent-amber">{(atk.flip_rate * 100).toFixed(1)}%</span></span>
                              <span className="text-xs text-text-secondary ml-3">L2: <span className="font-mono">{atk.perturbation_l2.toFixed(3)}</span></span>
                            </>
                          )}
                          {expandedAttack === `${inspectKey}-${atk.attack}` ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </button>
                        {expandedAttack === `${inspectKey}-${atk.attack}` && !atk.error && atk.per_class && (
                          <div className="px-4 pb-4 border-t border-bg-card">
                            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2 mt-3">
                              {Object.entries(atk.per_class).slice(0, 12).map(([cls, data]) => (
                                <div key={cls} className="bg-bg-primary rounded-lg p-2 text-xs">
                                  <div className="text-text-secondary truncate mb-1" title={cls}>{cls}</div>
                                  <div className="flex justify-between">
                                    <span className="text-accent-green">{(data.clean_acc * 100).toFixed(0)}%</span>
                                    <span className="text-text-secondary">→</span>
                                    <span className={data.adv_acc < data.clean_acc * 0.5 ? 'text-accent-red' : 'text-accent-amber'}>{(data.adv_acc * 100).toFixed(0)}%</span>
                                  </div>
                                  <div className="text-text-secondary mt-0.5">n={data.count}</div>
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

              {!inspectArena && (
                <div className="bg-bg-secondary rounded-xl p-8 border border-bg-card text-center text-text-secondary text-sm">
                  Select a model × dataset combination above to inspect detailed arena results.
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}
