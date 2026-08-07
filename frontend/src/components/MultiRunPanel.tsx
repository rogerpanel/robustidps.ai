import { useCallback, useEffect, useState } from 'react'
import { Loader2, Upload as UploadIcon, FileText, X, Layers, BarChart3 } from 'lucide-react'

import ModelMultiSelector from './ModelMultiSelector'
import { uploadAndPredictMulti, cachePageResult, fetchModels } from '../utils/api'
import { useNoticeBoard } from '../hooks/useNoticeBoard'

/* ── Types kept in sync with backend/main.py multi-run response ────── */

export interface MultiPredictionEntry {
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
  model_used: string
}

export interface MultiRunResult {
  results_matrix: Record<string, MultiPredictionEntry>
  models: string[]
  datasets: string[]
}

interface ModelInfo {
  id: string
  name: string
  enabled?: boolean
  weights_available: boolean
  parent_model?: string
}

interface SlotState {
  file: File | null
  fileName: string | null
}

interface Props {
  /** Which page is mounting the panel (drives cache key + notice title). */
  pageKey: string
  /** Default model that should be pre-selected when the panel mounts. */
  defaultModel: string
  /** Accent colour for the run button. Pass a tailwind colour key
   *  (e.g. 'orange', 'blue', 'green'). */
  accent?: 'orange' | 'blue' | 'green' | 'purple' | 'red'
  /** Number of dataset slots (default 3). */
  maxSlots?: number
  /** Number of Monte Carlo dropout passes per inference (default 5 for speed). */
  mcPasses?: number
}

const ACCENT_BG: Record<NonNullable<Props['accent']>, string> = {
  orange: 'bg-accent-orange hover:bg-accent-orange/80',
  blue:   'bg-accent-blue hover:bg-accent-blue/80',
  green:  'bg-accent-green hover:bg-accent-green/80',
  purple: 'bg-accent-purple hover:bg-accent-purple/80',
  red:    'bg-accent-red hover:bg-accent-red/80',
}

const ACCENT_TXT: Record<NonNullable<Props['accent']>, string> = {
  orange: 'text-accent-orange',
  blue:   'text-accent-blue',
  green:  'text-accent-green',
  purple: 'text-accent-purple',
  red:    'text-accent-red',
}

/**
 * Multi-dataset × multi-model comparison panel.
 *
 * Mobile-friendly: slot uploads stack on phones (`grid-cols-1`), expand to
 * two columns on `sm` and three on `lg`. The results matrix uses
 * `overflow-x-auto` so it scrolls horizontally rather than overflowing.
 */
export default function MultiRunPanel({
  pageKey,
  defaultModel,
  accent = 'blue',
  maxSlots = 3,
  mcPasses = 5,
}: Props) {
  const [slots, setSlots] = useState<SlotState[]>(
    Array.from({ length: maxSlots }, () => ({ file: null, fileName: null })),
  )
  const [availableModels, setAvailableModels] = useState<ModelInfo[]>([])
  const [selectedModels, setSelectedModels] = useState<string[]>([defaultModel])
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<MultiRunResult | null>(null)
  const { addNotice, updateNotice } = useNoticeBoard()

  useEffect(() => {
    fetchModels()
      .then((data) => {
        const enabled = (data.models ?? []).filter(
          (m: ModelInfo) => m.enabled !== false && m.weights_available,
        )
        setAvailableModels(enabled)
      })
      .catch(() => {})
  }, [])

  const setSlot = useCallback((idx: number, file: File | null) => {
    setSlots((prev) => prev.map((s, i) => (i === idx ? { file, fileName: file?.name ?? null } : s)))
  }, [])

  const activeSlotCount = slots.filter((s) => s.file).length

  const handleRun = async () => {
    const files = slots.map((s) => s.file)
    const activeFiles = files.filter(Boolean) as File[]
    if (activeFiles.length === 0 || selectedModels.length === 0) return

    setRunning(true)
    setError(null)
    setResult(null)
    const nid = addNotice({
      title: `${pageKey} multi-run`,
      description: `${selectedModels.length} model(s) × ${activeFiles.length} dataset(s)`,
      status: 'running',
      page: `/${pageKey.replace(/_/g, '-')}`,
    })

    try {
      const data = (await uploadAndPredictMulti(files, selectedModels, mcPasses)) as unknown as MultiRunResult
      setResult(data)
      const matrixSize = Object.keys(data.results_matrix ?? {}).length
      cachePageResult(`${pageKey}_multi`, {
        n_runs: matrixSize,
        models: selectedModels,
        n_datasets: activeFiles.length,
        per_run_summary: Object.entries(data.results_matrix ?? {}).map(([k, v]) => ({
          key: k,
          model: v.model,
          dataset: v.dataset,
          n_flows: v.n_flows,
          n_threats: v.n_threats,
          accuracy: v.accuracy,
          ece: v.ece,
        })),
      }).catch(() => {})
      updateNotice(nid, {
        status: 'completed',
        description: `${matrixSize} runs complete`,
      })
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Multi-run failed'
      setError(msg)
      updateNotice(nid, { status: 'error', description: msg })
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 text-sm text-text-secondary">
        <Layers className={`w-4 h-4 ${ACCENT_TXT[accent]}`} />
        <span>
          Compare {selectedModels.length} model{selectedModels.length === 1 ? '' : 's'} across {activeSlotCount}{' '}
          dataset{activeSlotCount === 1 ? '' : 's'} — results matrix below shows accuracy / ECE per (model × dataset).
        </span>
      </div>

      <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
        <h4 className="text-sm font-semibold mb-2">Dataset slots (up to {maxSlots})</h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {slots.map((slot, idx) => (
            <SlotCard key={idx} idx={idx} slot={slot} accent={accent} onPick={(f) => setSlot(idx, f)} />
          ))}
        </div>
      </div>

      <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
        <h4 className="text-sm font-semibold mb-2">
          Models to compare ({selectedModels.length} selected)
        </h4>
        <ModelMultiSelector value={selectedModels} onChange={setSelectedModels} />
        <p className="text-[11px] text-text-secondary mt-2">
          All {availableModels.length} registered models are eligible; pick any subset to compare side-by-side.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <button
          onClick={handleRun}
          disabled={running || activeSlotCount === 0 || selectedModels.length === 0}
          className={`px-4 py-2.5 ${ACCENT_BG[accent]} text-white rounded-lg text-sm font-semibold disabled:opacity-50 flex items-center gap-2 min-h-10`}
        >
          {running ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" /> Running {activeSlotCount * selectedModels.length} analyses…
            </>
          ) : (
            <>
              <BarChart3 className="w-4 h-4" /> Run multi-dataset comparison
              {' '}({activeSlotCount} dataset{activeSlotCount === 1 ? '' : 's'} × {selectedModels.length} model{selectedModels.length === 1 ? '' : 's'} = {activeSlotCount * selectedModels.length} runs)
            </>
          )}
        </button>
        {error && (
          <div className="px-3 py-1.5 bg-red-500/10 border border-red-500/30 rounded-lg text-xs text-red-400">
            {error}
          </div>
        )}
      </div>

      {result && <ResultsMatrix result={result} accent={accent} />}
    </div>
  )
}

/* ── Sub-components ─────────────────────────────────────────────────── */

function SlotCard({
  idx,
  slot,
  accent,
  onPick,
}: {
  idx: number
  slot: SlotState
  accent: NonNullable<Props['accent']>
  onPick: (f: File | null) => void
}) {
  return (
    <div className="bg-bg-card/40 rounded-lg p-3 border border-bg-card">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] text-text-secondary uppercase tracking-wider font-semibold">
          Slot {idx + 1}
        </span>
        {slot.file && (
          <span className="text-[10px] text-accent-green">Ready</span>
        )}
      </div>
      {slot.file ? (
        <div className="flex items-center gap-2 px-2.5 py-2 rounded-lg border border-accent-green/30 bg-accent-green/5">
          <FileText className="w-4 h-4 text-accent-green shrink-0" />
          <span className="text-xs font-mono truncate flex-1">{slot.fileName}</span>
          <button
            onClick={() => onPick(null)}
            className="text-text-secondary hover:text-text-primary min-h-10 min-w-10 flex items-center justify-center"
            title="Remove file"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      ) : (
        <label
          onDragOver={(e) => {
            e.preventDefault()
            e.currentTarget.classList.add(`border-accent-${accent}`, `bg-accent-${accent}/10`)
          }}
          onDragLeave={(e) =>
            e.currentTarget.classList.remove(`border-accent-${accent}`, `bg-accent-${accent}/10`)
          }
          onDrop={(e) => {
            e.preventDefault()
            e.currentTarget.classList.remove(`border-accent-${accent}`, `bg-accent-${accent}/10`)
            const f = e.dataTransfer.files[0]
            if (f) onPick(f)
          }}
          className="flex flex-col items-center gap-1 px-2 py-4 rounded-lg border-2 border-dashed border-bg-card hover:border-text-secondary cursor-pointer transition-colors min-h-20"
        >
          <UploadIcon className="w-4 h-4 text-text-secondary" />
          <span className="text-[10px] text-text-secondary">Drop or click</span>
          <span className="text-[9px] text-text-secondary/60">.csv .pcap .pcapng</span>
          <input
            type="file"
            accept=".csv,.pcap,.pcapng"
            className="hidden"
            onChange={(e) => onPick(e.target.files?.[0] ?? null)}
          />
        </label>
      )}
    </div>
  )
}

function ResultsMatrix({ result, accent }: { result: MultiRunResult; accent: NonNullable<Props['accent']> }) {
  const entries = Object.entries(result.results_matrix ?? {})
  if (entries.length === 0) {
    return (
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card text-xs text-text-secondary">
        No results returned from the multi-run.
      </div>
    )
  }
  return (
    <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
      <h4 className={`text-sm font-semibold mb-3 ${ACCENT_TXT[accent]}`}>
        Comparison matrix — {entries.length} run{entries.length === 1 ? '' : 's'}
      </h4>
      <div className="overflow-x-auto">
        <table className="w-full text-xs min-w-[640px]">
          <thead>
            <tr className="border-b border-bg-card text-text-secondary">
              <th className="text-left px-3 py-2 font-semibold">Model</th>
              <th className="text-left px-3 py-2 font-semibold">Dataset</th>
              <th className="text-right px-3 py-2 font-semibold">Flows</th>
              <th className="text-right px-3 py-2 font-semibold">Threats</th>
              <th className="text-right px-3 py-2 font-semibold">Threat %</th>
              <th className="text-right px-3 py-2 font-semibold">Accuracy</th>
              <th className="text-right px-3 py-2 font-semibold">ECE</th>
              <th className="text-right px-3 py-2 font-semibold">Mean Conf.</th>
            </tr>
          </thead>
          <tbody>
            {entries.map(([key, r]) => (
              <tr key={key} className="border-b border-bg-card/60 hover:bg-bg-card/30 transition-colors">
                <td className="px-3 py-2 font-mono text-text-primary">{r.model}</td>
                <td className="px-3 py-2 text-text-secondary">{r.dataset}</td>
                <td className="px-3 py-2 text-right font-mono">{r.n_flows.toLocaleString()}</td>
                <td className="px-3 py-2 text-right font-mono text-accent-red">{r.n_threats.toLocaleString()}</td>
                <td className="px-3 py-2 text-right">{(r.threat_rate * 100).toFixed(1)}%</td>
                <td className="px-3 py-2 text-right">
                  <span className={r.accuracy > 0.95 ? 'text-accent-green' : r.accuracy > 0.85 ? 'text-accent-amber' : 'text-accent-red'}>
                    {(r.accuracy * 100).toFixed(1)}%
                  </span>
                </td>
                <td className="px-3 py-2 text-right">{r.ece.toFixed(3)}</td>
                <td className="px-3 py-2 text-right">{(r.mean_confidence * 100).toFixed(1)}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-[10px] text-text-secondary/70 mt-3">
        Lower ECE = better-calibrated probabilities. Results also cached for the SOC Copilot under the
        <code className="px-1 mx-1 bg-bg-card rounded">_multi</code> page key suffix.
      </p>
    </div>
  )
}
