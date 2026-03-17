import { useEffect, useState, useRef, useCallback } from 'react'
import {
  Loader2, AlertTriangle, Zap,
  Target, CheckCircle2, XCircle, Upload, FileText, X,
  Layers, BarChart3, ArrowRightLeft, TrendingDown,
  FlaskConical,
} from 'lucide-react'
import { runAdversarialEval, runAdversarialMulti, fetchModels, createExperiment } from '../utils/api'
import ExportMenu from '../components/ExportMenu'
import { registerSessionReset } from '../utils/sessionReset'

const ATTACK_COLORS: Record<string, string> = {
  fgsm: '#EF4444',
  pgd: '#F59E0B',
  cw: '#A855F7',
  deepfool: '#3B82F6',
  gaussian: '#22C55E',
  label_masking: '#EC4899',
}

const DATASET_COLORS = ['#3B82F6', '#A855F7', '#22C55E']
const DATASET_LABELS = ['Dataset A', 'Dataset B', 'Dataset C']

type Mode = 'single' | 'multi'

interface SlotState {
  fileName: string | null
  fileReady: boolean
}

const _store: {
  file: File | null
  modelId: string
  result: any
  mode: Mode
  multiResult: any
  selectedModels: string[]
  slots: SlotState[]
  savedExperiment: boolean
} = {
  file: null,
  modelId: 'surrogate',
  result: null,
  mode: 'single',
  multiResult: null,
  selectedModels: ['surrogate'],
  slots: [{ fileName: null, fileReady: false }, { fileName: null, fileReady: false }, { fileName: null, fileReady: false }],
  savedExperiment: false,
}

registerSessionReset(() => {
  _store.file = null
  _store.modelId = 'surrogate'
  _store.result = null
  _store.mode = 'single'
  _store.multiResult = null
  _store.selectedModels = ['surrogate']
  _store.slots = [{ fileName: null, fileReady: false }, { fileName: null, fileReady: false }, { fileName: null, fileReady: false }]
  _store.savedExperiment = false
})

// ── Drag-drop file slot ──────────────────────────────────────────────────
function FileSlot({ index, slot, onFile, onClear }: {
  index: number
  slot: SlotState
  onFile: (index: number, file: File) => void
  onClear: (index: number) => void
}) {
  const [drag, setDrag] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDrag(false)
    const f = e.dataTransfer.files[0]
    if (f) onFile(index, f)
  }, [index, onFile])

  const handleChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (f) onFile(index, f)
  }, [index, onFile])

  return (
    <div className="relative">
      <div className="text-[10px] text-text-secondary mb-1 flex items-center gap-1">
        <div className="w-2 h-2 rounded-full" style={{ background: DATASET_COLORS[index] }} />
        {DATASET_LABELS[index]}
      </div>
      {slot.fileReady ? (
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-accent-green/30 bg-accent-green/5">
          <FileText className="w-4 h-4 text-accent-green shrink-0" />
          <span className="text-xs font-mono truncate flex-1">{slot.fileName}</span>
          <button onClick={() => onClear(index)} className="text-text-secondary hover:text-text-primary">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      ) : (
        <label
          onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
          onDragLeave={() => setDrag(false)}
          onDrop={handleDrop}
          className={`flex flex-col items-center justify-center gap-1 px-3 py-4 rounded-lg border-2 border-dashed cursor-pointer transition-colors ${
            drag ? 'border-accent-blue bg-accent-blue/10' : 'border-bg-card hover:border-text-secondary'
          }`}
        >
          <Upload className="w-5 h-5 text-text-secondary" />
          <span className="text-[10px] text-text-secondary">Drop or click</span>
          <span className="text-[9px] text-text-secondary/60">.csv .pcap .pcapng</span>
          <input ref={inputRef} type="file" accept=".csv,.pcap,.pcapng" className="hidden" onChange={handleChange} />
        </label>
      )}
    </div>
  )
}

// ── Attack result card ───────────────────────────────────────────────────
function AttackCard({ name, data }: { name: string; data: any }) {
  const color = ATTACK_COLORS[name] || '#9CA3AF'
  const drop = data.accuracy_drop ?? 0
  const ratio = data.robustness_ratio ?? 0
  return (
    <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-medium" style={{ color }}>{data.label || name}</span>
        {ratio >= 0.9 ? (
          <CheckCircle2 className="w-4 h-4 text-accent-green" />
        ) : ratio >= 0.7 ? (
          <AlertTriangle className="w-4 h-4 text-accent-amber" />
        ) : (
          <XCircle className="w-4 h-4 text-accent-red" />
        )}
      </div>
      {data.error ? (
        <div className="text-xs text-accent-red">{data.error}</div>
      ) : (
        <>
          <div className="text-2xl font-display font-bold">{data.accuracy?.toFixed(1)}%</div>
          <div className="flex items-center gap-2 mt-1">
            <span className={`text-[10px] ${drop > 0 ? 'text-accent-red' : 'text-accent-green'}`}>
              {drop > 0 ? '-' : '+'}{Math.abs(drop).toFixed(1)}%
            </span>
            <span className="text-[10px] text-text-secondary">
              Robustness: {(ratio * 100).toFixed(1)}%
            </span>
          </div>
          <div className="mt-2 h-1.5 bg-bg-card rounded-full overflow-hidden">
            <div className="h-full rounded-full transition-all" style={{ width: `${data.accuracy}%`, background: color }} />
          </div>
        </>
      )}
    </div>
  )
}

// ── Main Component ───────────────────────────────────────────────────────
export default function AdversarialRobustness() {
  // Mode
  const [mode, _setMode] = useState<Mode>(_store.mode)
  const setMode = (v: Mode) => { _store.mode = v; _setMode(v) }

  // Single mode state
  const [file, _setFile] = useState<File | null>(_store.file)
  const [modelId, _setModelId] = useState(_store.modelId)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')
  const [result, _setResult] = useState<any>(_store.result)
  const [models, setModels] = useState<any[]>([])
  const fileRef = useRef<HTMLInputElement>(null)

  const setFile = (f: File | null) => { _store.file = f; _setFile(f) }
  const setModelId = (v: string) => { _store.modelId = v; _setModelId(v) }
  const setResult = (v: any) => { _store.result = v; _store.savedExperiment = false; _setResult(v); _setSavedExperiment(false) }

  // Multi mode state
  const [slots, _setSlots] = useState<SlotState[]>(_store.slots)
  const [selectedModels, _setSelectedModels] = useState<string[]>(_store.selectedModels)
  const [multiRunning, setMultiRunning] = useState(false)
  const [multiError, setMultiError] = useState('')
  const [multiResult, _setMultiResult] = useState<any>(_store.multiResult)
  const filesRef = useRef<(File | null)[]>([null, null, null])

  const setSlots = (s: SlotState[]) => { _store.slots = s; _setSlots(s) }
  const setSelectedModels = (m: string[]) => { _store.selectedModels = m; _setSelectedModels(m) }
  const setMultiResult = (v: any) => { _store.multiResult = v; _store.savedExperiment = false; _setMultiResult(v); _setSavedExperiment(false) }

  // Multi-mode selected cell for detail view
  const [selectedCell, setSelectedCell] = useState<string | null>(null)

  // Save as experiment
  const [savedExperiment, _setSavedExperiment] = useState(_store.savedExperiment)
  const [saving, setSaving] = useState(false)
  const setSavedExperiment = (v: boolean) => { _store.savedExperiment = v; _setSavedExperiment(v) }

  useEffect(() => {
    fetchModels()
      .then((data) => setModels((data.models ?? []).filter((m: any) => m.enabled)))
      .catch(() => {})
  }, [])

  // Single-mode run
  const handleRun = async () => {
    if (!file) return
    setRunning(true)
    setError('')
    try {
      const data = await runAdversarialEval(file, modelId)
      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Evaluation failed')
    }
    setRunning(false)
  }

  // Multi-mode file management
  const handleSlotFile = useCallback((index: number, f: File) => {
    filesRef.current[index] = f
    _setSlots((prev) => {
      const next = [...prev]
      next[index] = { fileName: f.name, fileReady: true }
      _store.slots = next
      return next
    })
  }, [])

  const handleSlotClear = useCallback((index: number) => {
    filesRef.current[index] = null
    _setSlots((prev) => {
      const next = [...prev]
      next[index] = { fileName: null, fileReady: false }
      _store.slots = next
      return next
    })
  }, [])

  const toggleModel = (id: string) => {
    if (selectedModels.includes(id)) {
      if (selectedModels.length > 1) setSelectedModels(selectedModels.filter((v) => v !== id))
    } else {
      setSelectedModels([...selectedModels, id])
    }
  }

  // Multi-mode run
  const handleMultiRun = async () => {
    const activeFiles = filesRef.current.filter(Boolean)
    if (activeFiles.length === 0 || selectedModels.length === 0) return
    setMultiRunning(true)
    setMultiError('')
    try {
      const data = await runAdversarialMulti(filesRef.current, selectedModels)
      setMultiResult(data)
      setSelectedCell(null)
    } catch (err) {
      setMultiError(err instanceof Error ? err.message : 'Multi evaluation failed')
    }
    setMultiRunning(false)
  }

  const handleSaveExperiment = async () => {
    const activeResult = mode === 'single' ? result : multiResult
    if (!activeResult || saving) return
    setSaving(true)
    try {
      const isMulti = mode === 'multi'
      const metrics: Record<string, any> = {}
      if (!isMulti && result) {
        metrics.clean_accuracy = result.clean_accuracy
        const attacks = result.attacks || {}
        const ratios = Object.values(attacks).map((a: any) => a?.robustness_ratio ?? 0).filter((v: number) => v > 0)
        if (ratios.length) metrics.avg_robustness = ratios.reduce((a: number, b: number) => a + b, 0) / ratios.length
        metrics.n_samples = result.n_samples
      } else if (isMulti && multiResult) {
        metrics.n_models = multiResult.n_models
        metrics.n_datasets = multiResult.n_datasets
        const heatmap = multiResult.robustness_heatmap || []
        if (heatmap.length) {
          metrics.avg_robustness = heatmap.reduce((s: number, h: any) => s + (h.avg_robustness || 0), 0) / heatmap.length / 100
        }
      }
      await createExperiment({
        name: isMulti
          ? `Adversarial Multi — ${multiResult.n_datasets} datasets × ${multiResult.n_models} models`
          : `Adversarial Robustness — ${result.model_name || modelId}`,
        task_type: 'adversarial',
        tags: ['adversarial', 'robustness', ...(isMulti ? ['multi-dataset'] : [])],
        params: isMulti
          ? { model_names: multiResult.model_names, dataset_names: multiResult.dataset_names }
          : { model_id: modelId, dataset_format: result.dataset_format },
        results: activeResult,
        metrics,
      })
      setSavedExperiment(true)
    } catch (err: any) {
      setError(err.message || 'Failed to save experiment')
    }
    setSaving(false)
  }

  const activeSlotCount = slots.filter((s) => s.fileReady).length
  const attacks = result?.attacks ? Object.entries(result.attacks) : []

  return (
    <div className="space-y-6 max-w-6xl">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Target className="w-6 h-6 text-accent-red" />
        <div className="flex-1">
          <h1 className="text-2xl font-display font-bold">Adversarial Robustness</h1>
          <p className="text-sm text-text-secondary mt-1">
            Evaluate model resilience against 6 adversarial attack methods: FGSM, PGD, C&amp;W, DeepFool, Gaussian noise, and Label masking.
          </p>
        </div>
        <ExportMenu filename="adversarial-robustness" />
      </div>

      {/* Mode Toggle */}
      <div className="flex gap-2">
        <button
          onClick={() => setMode('single')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
            mode === 'single'
              ? 'bg-accent-red text-white'
              : 'bg-bg-secondary border border-bg-card text-text-secondary hover:text-text-primary'
          }`}
        >
          <Target className="w-4 h-4" /> Single Dataset
        </button>
        <button
          onClick={() => setMode('multi')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
            mode === 'multi'
              ? 'bg-accent-red text-white'
              : 'bg-bg-secondary border border-bg-card text-text-secondary hover:text-text-primary'
          }`}
        >
          <Layers className="w-4 h-4" /> Multi-Dataset Comparison
        </button>
      </div>

      {/* Error display */}
      {(error || multiError) && (
        <div className="px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {error || multiError}
          <button onClick={() => { setError(''); setMultiError('') }} className="ml-auto text-xs hover:underline">dismiss</button>
        </div>
      )}

      {/* ═══════════════════════════════ SINGLE MODE ═══════════════════════════════ */}
      {mode === 'single' && (
        <>
          <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
            <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">
              <Zap className="w-5 h-5 text-accent-amber" />
              Robustness Evaluation
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div>
                <label className="text-xs text-text-secondary block mb-1">Traffic Data (.csv)</label>
                <input
                  ref={fileRef}
                  type="file"
                  accept=".csv,.pcap,.pcapng"
                  onChange={(e) => setFile(e.target.files?.[0] || null)}
                  className="w-full text-sm text-text-secondary file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-medium file:bg-accent-blue/15 file:text-accent-blue hover:file:bg-accent-blue/25 cursor-pointer"
                />
              </div>
              <div>
                <label className="text-xs text-text-secondary block mb-1">Target Model</label>
                <select
                  value={modelId}
                  onChange={(e) => setModelId(e.target.value)}
                  className="w-full px-2 py-1.5 bg-bg-primary border border-bg-card rounded text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent-blue/50"
                >
                  {models.map((m) => (
                    <option key={m.id} value={m.id}>{m.name}</option>
                  ))}
                </select>
              </div>
              <div className="flex items-end">
                <button
                  onClick={handleRun}
                  disabled={!file || running}
                  className="w-full px-4 py-2 bg-accent-red text-white rounded-lg text-xs font-medium hover:bg-accent-red/80 disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  {running ? (
                    <><Loader2 className="w-4 h-4 animate-spin" /> Attacking...</>
                  ) : (
                    <><Target className="w-4 h-4" /> Run All Attacks</>
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Single results */}
          {result && (
            <>
              <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-xs text-text-secondary">Clean Accuracy (no attack)</div>
                    <div className="text-3xl font-display font-bold text-accent-green">{result.clean_accuracy?.toFixed(1)}%</div>
                  </div>
                  <div className="text-right">
                    <div className="text-xs text-text-secondary">Model</div>
                    <div className="text-sm font-medium">{result.model_name}</div>
                    <div className="text-[10px] text-text-secondary">{result.n_samples} samples · {result.dataset_format}</div>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                {attacks.map(([name, data]: [string, any]) => (
                  <AttackCard key={name} name={name} data={data} />
                ))}
              </div>

              <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                <h2 className="text-lg font-display font-semibold mb-3">Attack Comparison</h2>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-text-secondary text-xs">
                        <th className="px-3 py-2 text-left">Attack</th>
                        <th className="px-3 py-2 text-right">Accuracy Under Attack</th>
                        <th className="px-3 py-2 text-right">Accuracy Drop</th>
                        <th className="px-3 py-2 text-right">Robustness Ratio</th>
                        <th className="px-3 py-2 text-center">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {attacks.map(([name, data]: [string, any]) => (
                        <tr key={name} className="border-t border-bg-card/50">
                          <td className="px-3 py-2 font-medium" style={{ color: ATTACK_COLORS[name] }}>{data.label || name}</td>
                          <td className="px-3 py-2 text-right font-mono">{data.accuracy?.toFixed(1)}%</td>
                          <td className="px-3 py-2 text-right font-mono text-accent-red">-{data.accuracy_drop?.toFixed(1)}%</td>
                          <td className="px-3 py-2 text-right font-mono">{((data.robustness_ratio ?? 0) * 100).toFixed(1)}%</td>
                          <td className="px-3 py-2 text-center">
                            {(data.robustness_ratio ?? 0) >= 0.9 ? (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-accent-green/15 text-accent-green">Robust</span>
                            ) : (data.robustness_ratio ?? 0) >= 0.7 ? (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-accent-amber/15 text-accent-amber">Moderate</span>
                            ) : (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-accent-red/15 text-accent-red">Vulnerable</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Save as Experiment (single mode) */}
              <div className="flex gap-2">
                <button
                  onClick={handleSaveExperiment}
                  disabled={saving || savedExperiment}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-colors ${
                    savedExperiment
                      ? 'bg-accent-green/15 text-accent-green'
                      : 'bg-accent-blue/15 text-accent-blue hover:bg-accent-blue/25'
                  } disabled:opacity-60`}
                >
                  {saving ? (
                    <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Saving...</>
                  ) : savedExperiment ? (
                    <><CheckCircle2 className="w-3.5 h-3.5" /> Saved to Research Hub</>
                  ) : (
                    <><FlaskConical className="w-3.5 h-3.5" /> Save as Experiment</>
                  )}
                </button>
              </div>
            </>
          )}

          {!result && !running && (
            <div className="text-center py-12 text-text-secondary">
              <Target className="w-10 h-10 mx-auto mb-3 opacity-20" />
              <p className="text-sm">Upload labelled traffic data and select a model to evaluate adversarial robustness.</p>
            </div>
          )}
        </>
      )}

      {/* ═══════════════════════════════ MULTI MODE ═══════════════════════════════ */}
      {mode === 'multi' && (
        <>
          {/* Dataset slots */}
          <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
            <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-1">
              <Layers className="w-5 h-5 text-accent-purple" />
              Datasets (up to 3)
            </h2>
            <p className="text-[11px] text-text-secondary mb-4">
              Load multiple datasets to compare robustness across different traffic distributions. Supports CSV, PCAP, and PCAPNG formats.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {slots.map((slot, i) => (
                <FileSlot key={i} index={i} slot={slot} onFile={handleSlotFile} onClear={handleSlotClear} />
              ))}
            </div>
          </div>

          {/* Model selection */}
          <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
            <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-1">
              <BarChart3 className="w-5 h-5 text-accent-blue" />
              Models ({selectedModels.length} selected)
            </h2>
            <p className="text-[11px] text-text-secondary mb-3">
              Select multiple models to compare their adversarial robustness side-by-side.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
              {models.map((m) => {
                const selected = selectedModels.includes(m.id)
                return (
                  <button
                    key={m.id}
                    onClick={() => toggleModel(m.id)}
                    className={`text-left px-3 py-2.5 rounded-lg border transition-all text-xs ${
                      selected
                        ? 'border-accent-blue bg-accent-blue/10'
                        : 'border-bg-card bg-bg-card/30 hover:border-bg-card/80'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="font-medium truncate">{m.name}</span>
                      </div>
                      {selected && <CheckCircle2 className="w-3.5 h-3.5 text-accent-blue shrink-0" />}
                    </div>
                    <div className="text-[10px] text-text-secondary mt-0.5 truncate">{m.category}</div>
                  </button>
                )
              })}
            </div>
          </div>

          {/* Run button */}
          <button
            onClick={handleMultiRun}
            disabled={activeSlotCount === 0 || selectedModels.length === 0 || multiRunning}
            className="w-full px-4 py-3 bg-accent-red text-white rounded-xl text-sm font-medium hover:bg-accent-red/80 disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {multiRunning ? (
              <><Loader2 className="w-5 h-5 animate-spin" /> Running adversarial evaluation across {activeSlotCount} dataset(s) × {selectedModels.length} model(s)...</>
            ) : (
              <><Target className="w-5 h-5" /> Run Multi-Dataset Robustness Evaluation ({activeSlotCount} dataset{activeSlotCount !== 1 ? 's' : ''} × {selectedModels.length} model{selectedModels.length !== 1 ? 's' : ''})</>
            )}
          </button>

          {/* Multi results */}
          {multiResult && (
            <>
              {/* Robustness Heatmap */}
              <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-4">
                  <BarChart3 className="w-5 h-5 text-accent-amber" />
                  Robustness Heatmap
                </h2>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-text-secondary text-xs">
                        <th className="px-3 py-2 text-left">Model</th>
                        {(multiResult.dataset_names ?? []).map((ds: string, i: number) => (
                          <th key={ds} className="px-3 py-2 text-center">
                            <div className="flex items-center justify-center gap-1">
                              <div className="w-2 h-2 rounded-full" style={{ background: DATASET_COLORS[i] || '#9CA3AF' }} />
                              <span className="truncate max-w-[120px]" title={ds}>{ds}</span>
                            </div>
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {(multiResult.model_names ?? []).map((mn: string) => (
                        <tr key={mn} className="border-t border-bg-card/50">
                          <td className="px-3 py-2 font-medium text-xs">
                            {multiResult.eval_matrix?.[`${mn}|${(multiResult.dataset_names ?? [])[0]}`]?.model_name || mn}
                          </td>
                          {(multiResult.dataset_names ?? []).map((ds: string) => {
                            const cellKey = `${mn}|${ds}`
                            const cell = multiResult.eval_matrix?.[cellKey]
                            const hm = (multiResult.robustness_heatmap ?? []).find(
                              (h: any) => h.model === mn && h.dataset === ds,
                            )
                            const robustness = hm?.avg_robustness ?? 0
                            const bgOpacity = Math.min(robustness / 100, 1)
                            const color = robustness >= 80 ? 'accent-green' : robustness >= 60 ? 'accent-amber' : 'accent-red'
                            return (
                              <td
                                key={ds}
                                className="px-3 py-2 text-center cursor-pointer hover:ring-1 hover:ring-accent-blue/30 rounded"
                                onClick={() => setSelectedCell(cellKey)}
                                title="Click to view details"
                              >
                                {cell?.error && !cell?.attacks ? (
                                  <span className="text-[10px] text-accent-red">Error</span>
                                ) : (
                                  <div className="space-y-0.5">
                                    <div
                                      className={`text-sm font-mono font-bold text-${color}`}
                                      style={{ opacity: 0.6 + bgOpacity * 0.4 }}
                                    >
                                      {robustness.toFixed(1)}%
                                    </div>
                                    <div className="text-[9px] text-text-secondary">
                                      Clean: {cell?.clean_accuracy?.toFixed(1) ?? '—'}%
                                    </div>
                                  </div>
                                )}
                              </td>
                            )
                          })}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p className="text-[10px] text-text-secondary mt-2">Click any cell to view detailed attack breakdown below.</p>
              </div>

              {/* Cross-Model Comparison */}
              {multiResult.cross_model_comparison && Object.keys(multiResult.cross_model_comparison).length > 0 && (
                <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                  <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-4">
                    <ArrowRightLeft className="w-5 h-5 text-accent-blue" />
                    Cross-Model Robustness Comparison
                  </h2>
                  {Object.entries(multiResult.cross_model_comparison).map(([dsName, cmp]: [string, any]) => (
                    <div key={dsName} className="mb-4 last:mb-0">
                      <div className="text-xs font-medium mb-2 text-text-secondary">{dsName}</div>
                      <div className="overflow-x-auto">
                        <table className="w-full text-xs">
                          <thead>
                            <tr className="text-text-secondary">
                              <th className="px-2 py-1.5 text-left">Rank</th>
                              <th className="px-2 py-1.5 text-left">Model</th>
                              <th className="px-2 py-1.5 text-right">Clean Acc</th>
                              <th className="px-2 py-1.5 text-right">Avg Robustness</th>
                              <th className="px-2 py-1.5 text-right">Min Robustness</th>
                              <th className="px-2 py-1.5 text-right">Max Drop</th>
                            </tr>
                          </thead>
                          <tbody>
                            {(cmp.ranking ?? []).map((mn: string, rank: number) => {
                              const ms = cmp.models?.[mn]
                              if (!ms) return null
                              return (
                                <tr key={mn} className="border-t border-bg-card/50">
                                  <td className="px-2 py-1.5">
                                    <span className={`inline-flex items-center justify-center w-5 h-5 rounded-full text-[10px] font-bold ${
                                      rank === 0 ? 'bg-accent-amber/20 text-accent-amber' : 'bg-bg-card text-text-secondary'
                                    }`}>{rank + 1}</span>
                                  </td>
                                  <td className="px-2 py-1.5 font-medium">{mn}</td>
                                  <td className="px-2 py-1.5 text-right font-mono">{ms.clean_accuracy?.toFixed(1)}%</td>
                                  <td className="px-2 py-1.5 text-right font-mono font-bold">
                                    <span className={ms.avg_robustness >= 80 ? 'text-accent-green' : ms.avg_robustness >= 60 ? 'text-accent-amber' : 'text-accent-red'}>
                                      {ms.avg_robustness?.toFixed(1)}%
                                    </span>
                                  </td>
                                  <td className="px-2 py-1.5 text-right font-mono">{ms.min_robustness?.toFixed(1)}%</td>
                                  <td className="px-2 py-1.5 text-right font-mono text-accent-red">-{ms.max_drop?.toFixed(1)}%</td>
                                </tr>
                              )
                            })}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Cross-Dataset Comparison */}
              {multiResult.cross_dataset_comparison && Object.keys(multiResult.cross_dataset_comparison).length > 0 && (multiResult.dataset_names ?? []).length > 1 && (
                <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                  <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-4">
                    <TrendingDown className="w-5 h-5 text-accent-purple" />
                    Cross-Dataset Robustness Stability
                  </h2>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="text-text-secondary">
                          <th className="px-2 py-1.5 text-left">Model</th>
                          {(multiResult.dataset_names ?? []).map((ds: string, i: number) => (
                            <th key={ds} className="px-2 py-1.5 text-center">
                              <div className="flex items-center justify-center gap-1">
                                <div className="w-1.5 h-1.5 rounded-full" style={{ background: DATASET_COLORS[i] }} />
                                <span className="truncate max-w-[90px]">{ds}</span>
                              </div>
                            </th>
                          ))}
                          <th className="px-2 py-1.5 text-center">Variance</th>
                          <th className="px-2 py-1.5 text-center">Stability</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(multiResult.model_names ?? []).map((mn: string) => {
                          const dsData = multiResult.cross_dataset_comparison?.[mn] ?? {}
                          const values = Object.values(dsData).map((d: any) => d.avg_robustness ?? 0)
                          const mean = values.length > 0 ? values.reduce((a: number, b: number) => a + b, 0) / values.length : 0
                          const variance = values.length > 1
                            ? values.reduce((a: number, b: number) => a + (b - mean) ** 2, 0) / values.length
                            : 0
                          const stable = variance < 25
                          return (
                            <tr key={mn} className="border-t border-bg-card/50">
                              <td className="px-2 py-1.5 font-medium">{mn}</td>
                              {(multiResult.dataset_names ?? []).map((ds: string) => {
                                const d = dsData[ds]
                                return (
                                  <td key={ds} className="px-2 py-1.5 text-center font-mono">
                                    {d ? `${d.avg_robustness?.toFixed(1)}%` : '—'}
                                  </td>
                                )
                              })}
                              <td className="px-2 py-1.5 text-center font-mono text-text-secondary">
                                {variance.toFixed(2)}
                              </td>
                              <td className="px-2 py-1.5 text-center">
                                <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                                  stable ? 'bg-accent-green/15 text-accent-green' : 'bg-accent-amber/15 text-accent-amber'
                                }`}>
                                  {stable ? 'Stable' : 'Variable'}
                                </span>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Selected Cell Detail */}
              {selectedCell && multiResult.eval_matrix?.[selectedCell] && (() => {
                const cell = multiResult.eval_matrix[selectedCell]
                const cellAttacks = cell.attacks ? Object.entries(cell.attacks) : []
                return (
                  <div className="bg-bg-secondary rounded-xl p-5 border border-accent-blue/30">
                    <div className="flex items-center justify-between mb-4">
                      <h2 className="text-lg font-display font-semibold flex items-center gap-2">
                        <Target className="w-5 h-5 text-accent-red" />
                        Detail: {cell.model_name} on {cell.dataset_name}
                      </h2>
                      <button onClick={() => setSelectedCell(null)} className="text-xs text-text-secondary hover:text-text-primary flex items-center gap-1">
                        <X className="w-3.5 h-3.5" /> Close
                      </button>
                    </div>

                    {/* Clean accuracy */}
                    <div className="flex items-center gap-4 mb-4 px-3 py-2 bg-bg-primary rounded-lg">
                      <div>
                        <div className="text-[10px] text-text-secondary">Clean Accuracy</div>
                        <div className="text-xl font-display font-bold text-accent-green">{cell.clean_accuracy?.toFixed(1)}%</div>
                      </div>
                      <div>
                        <div className="text-[10px] text-text-secondary">Samples</div>
                        <div className="text-sm font-mono">{cell.n_samples}</div>
                      </div>
                      <div>
                        <div className="text-[10px] text-text-secondary">Format</div>
                        <div className="text-sm font-mono">{cell.dataset_format}</div>
                      </div>
                    </div>

                    {/* Attack cards */}
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mb-4">
                      {cellAttacks.map(([name, data]: [string, any]) => (
                        <AttackCard key={name} name={name} data={data} />
                      ))}
                    </div>

                    {/* Attack comparison table */}
                    {cellAttacks.length > 0 && (
                      <div className="overflow-x-auto">
                        <table className="w-full text-xs">
                          <thead>
                            <tr className="text-text-secondary">
                              <th className="px-2 py-1.5 text-left">Attack</th>
                              <th className="px-2 py-1.5 text-right">Accuracy</th>
                              <th className="px-2 py-1.5 text-right">Drop</th>
                              <th className="px-2 py-1.5 text-right">Robustness</th>
                              <th className="px-2 py-1.5 text-center">Status</th>
                            </tr>
                          </thead>
                          <tbody>
                            {cellAttacks.map(([name, data]: [string, any]) => (
                              <tr key={name} className="border-t border-bg-card/50">
                                <td className="px-2 py-1.5 font-medium" style={{ color: ATTACK_COLORS[name] }}>{data.label || name}</td>
                                <td className="px-2 py-1.5 text-right font-mono">{data.accuracy?.toFixed(1)}%</td>
                                <td className="px-2 py-1.5 text-right font-mono text-accent-red">-{data.accuracy_drop?.toFixed(1)}%</td>
                                <td className="px-2 py-1.5 text-right font-mono">{((data.robustness_ratio ?? 0) * 100).toFixed(1)}%</td>
                                <td className="px-2 py-1.5 text-center">
                                  {(data.robustness_ratio ?? 0) >= 0.9 ? (
                                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-accent-green/15 text-accent-green">Robust</span>
                                  ) : (data.robustness_ratio ?? 0) >= 0.7 ? (
                                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-accent-amber/15 text-accent-amber">Moderate</span>
                                  ) : (
                                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-accent-red/15 text-accent-red">Vulnerable</span>
                                  )}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )
              })()}

              {!selectedCell && (
                <div className="text-center py-4 text-text-secondary text-xs">
                  Click any cell in the heatmap to view the detailed per-attack breakdown.
                </div>
              )}

              {/* Save as Experiment (multi mode) */}
              <div className="flex gap-2">
                <button
                  onClick={handleSaveExperiment}
                  disabled={saving || savedExperiment}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-colors ${
                    savedExperiment
                      ? 'bg-accent-green/15 text-accent-green'
                      : 'bg-accent-blue/15 text-accent-blue hover:bg-accent-blue/25'
                  } disabled:opacity-60`}
                >
                  {saving ? (
                    <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Saving...</>
                  ) : savedExperiment ? (
                    <><CheckCircle2 className="w-3.5 h-3.5" /> Saved to Research Hub</>
                  ) : (
                    <><FlaskConical className="w-3.5 h-3.5" /> Save as Experiment</>
                  )}
                </button>
              </div>
            </>
          )}

          {!multiResult && !multiRunning && (
            <div className="text-center py-12 text-text-secondary">
              <Layers className="w-10 h-10 mx-auto mb-3 opacity-20" />
              <p className="text-sm">Load up to 6 datasets, select multiple models, and run comparative adversarial robustness evaluation.</p>
            </div>
          )}
        </>
      )}

      {/* Attack Descriptions — always visible */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold mb-3">Attack Methods (CL-RL Paper Section V-E)</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs text-text-secondary">
          {[
            ['FGSM', 'Fast Gradient Sign Method — single-step perturbation along gradient sign: x_adv = x + ε·sign(∇L)', '#EF4444'],
            ['PGD', 'Projected Gradient Descent — iterative FGSM within ε-ball (40 steps, α=0.01)', '#F59E0B'],
            ['C&W', 'Carlini-Wagner L2 — optimisation-based attack minimising ‖δ‖₂ + c·f(x+δ)', '#A855F7'],
            ['DeepFool', 'Minimal perturbation to cross nearest decision boundary iteratively', '#3B82F6'],
            ['Gaussian', 'Random Gaussian noise injection: x_adv = x + N(0, σ²) with σ=0.1', '#22C55E'],
            ['Label Masking', 'Training-time poisoning simulation — flips 10% of labels to test robustness', '#EC4899'],
          ].map(([name, desc, color]) => (
            <div key={name} className="flex gap-2 p-2 bg-bg-primary rounded-lg">
              <div className="w-2 h-2 rounded-full shrink-0 mt-1" style={{ background: color }} />
              <div>
                <span className="font-medium text-text-primary">{name}:</span> {desc}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
