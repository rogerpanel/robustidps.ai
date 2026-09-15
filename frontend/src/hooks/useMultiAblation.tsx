import { createContext, useContext, useState, useCallback, useRef, type ReactNode } from 'react'
import { runAblationMulti } from '../utils/api'
import { getUser } from '../utils/auth'
import type { AblationEntry, PairwiseEntry, IncrementalEntry } from './useAblation'

function _storageKey(): string {
  const u = getUser()
  return u ? `robustidps_multi_ablation::${u.email}` : 'robustidps_multi_ablation'
}

/* ── Types ──────────────────────────────────────────────────────────── */

export interface SingleRunResult {
  ablation: Record<string, AblationEntry>
  pairwise: Record<string, PairwiseEntry>
  incremental: IncrementalEntry[]
  branch_names: string[]
  model_used: string
  dataset_name: string
}

export interface BranchStability {
  drops_per_dataset: Record<string, number>
  mean_drop: number
  variance: number
  stability_score: number
}

export interface CrossDatasetStability {
  branches: Record<string, BranchStability>
  most_stable: string | null
  least_stable: string | null
  dataset_names: string[]
}

export interface ModelMetrics {
  full_accuracy: number
  full_precision: number
  full_recall: number
  full_f1: number
  avg_branch_drop: number
  max_branch_drop: number
  robustness_score: number
}

export interface CrossModelComparison {
  models: Record<string, ModelMetrics>
  ranking: string[]
}

export interface DatasetSensitivity {
  model_accuracies: Record<string, number>
  mean_accuracy: number
  variance: number
  sensitivity_score: number
}

export interface RobustnessHeatmapEntry {
  model: string
  dataset: string
  full_accuracy: number
  avg_drop: number
  robustness_score: number
}

export interface MultiAblationData {
  multi_ablation_id: string
  n_models: number
  n_datasets: number
  model_names: string[]
  dataset_names: string[]
  ablation_matrix: Record<string, SingleRunResult>
  cross_dataset_stability: Record<string, CrossDatasetStability>
  cross_model_comparison: Record<string, CrossModelComparison>
  dataset_sensitivity: Record<string, DatasetSensitivity>
  robustness_heatmap: RobustnessHeatmapEntry[]
  branch_names_map: Record<string, string[]>
}

export interface SlotState {
  file: File | null
  fileName: string | null
  fileReady: boolean
  fileLoading: boolean
}

interface MultiAblationState {
  loading: boolean
  data: MultiAblationData | null
  error: string | null
  selectedModels: string[]
  slots: SlotState[]
}

interface MultiAblationContextType extends MultiAblationState {
  setSelectedModels: (models: string[]) => void
  setSlotFile: (index: number, file: File | null) => void
  run: () => void
  clear: () => void
}

const defaultSlot = (): SlotState => ({
  file: null,
  fileName: null,
  fileReady: false,
  fileLoading: false,
})

const MultiAblationContext = createContext<MultiAblationContextType | null>(null)

function loadCached(): Partial<MultiAblationState> {
  try {
    const raw = localStorage.getItem(_storageKey())
    if (!raw) return {}
    return JSON.parse(raw)
  } catch {
    return {}
  }
}

function saveCache(state: Partial<MultiAblationState>) {
  try {
    localStorage.setItem(
      _storageKey(),
      JSON.stringify({
        data: state.data,
        selectedModels: state.selectedModels,
        slots: state.slots?.map((s) => ({ fileName: s.fileName, fileReady: s.fileReady })),
      }),
    )
  } catch {
    /* quota exceeded */
  }
}

export function MultiAblationProvider({ children }: { children: ReactNode }) {
  const cached = loadCached()

  const [state, setState] = useState<MultiAblationState>({
    loading: false,
    data: (cached.data as MultiAblationData) ?? null,
    error: null,
    selectedModels: (cached.selectedModels as string[]) ?? ['surrogate'],
    slots: cached.slots
      ? (cached.slots as SlotState[]).map((s) => ({
          ...defaultSlot(),
          fileName: s.fileName,
          fileReady: s.fileReady,
        }))
      : [defaultSlot(), defaultSlot(), defaultSlot()],
  })

  const requestId = useRef(0)
  // Store files outside state since File objects are not serializable
  const filesRef = useRef<(File | null)[]>([null, null, null])

  const setSelectedModels = useCallback((selectedModels: string[]) => {
    setState((prev) => {
      const updated = { ...prev, selectedModels }
      saveCache(updated)
      return updated
    })
  }, [])

  const setSlotFile = useCallback((index: number, file: File | null) => {
    filesRef.current[index] = file
    setState((prev) => {
      const slots = [...prev.slots]
      slots[index] = {
        file: null, // not stored in state (non-serializable)
        fileName: file?.name ?? null,
        fileReady: !!file,
        fileLoading: false,
      }
      const updated = { ...prev, slots }
      saveCache(updated)
      return updated
    })
  }, [])

  const run = useCallback(() => {
    const activeFiles = filesRef.current.filter(Boolean) as File[]
    if (activeFiles.length === 0) return

    const thisRequest = ++requestId.current
    setState((prev) => ({ ...prev, loading: true, error: null }))

    runAblationMulti(filesRef.current, state.selectedModels)
      .then((res) => {
        if (thisRequest !== requestId.current) return
        const data = res as MultiAblationData
        setState((prev) => {
          const updated = { ...prev, loading: false, data, error: null }
          saveCache(updated)
          return updated
        })
      })
      .catch((err) => {
        if (thisRequest !== requestId.current) return
        setState((prev) => ({
          ...prev,
          loading: false,
          error: err?.message || 'Multi-ablation failed. Is the backend running?',
        }))
      })
  }, [state.selectedModels])

  const clear = useCallback(() => {
    localStorage.removeItem(_storageKey())
    filesRef.current = [null, null, null]
    setState({
      loading: false,
      data: null,
      error: null,
      selectedModels: ['surrogate'],
      slots: [defaultSlot(), defaultSlot(), defaultSlot()],
    })
  }, [])

  return (
    <MultiAblationContext.Provider
      value={{ ...state, setSelectedModels, setSlotFile, run, clear }}
    >
      {children}
    </MultiAblationContext.Provider>
  )
}

export function useMultiAblation() {
  const ctx = useContext(MultiAblationContext)
  if (!ctx) throw new Error('useMultiAblation must be used within MultiAblationProvider')
  return ctx
}
