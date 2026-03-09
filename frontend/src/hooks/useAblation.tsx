import { createContext, useContext, useState, useCallback, useRef, type ReactNode } from 'react'
import { runAblation } from '../utils/api'
import { getUser } from '../utils/auth'

function _storageKey(): string {
  const u = getUser()
  return u ? `robustidps_ablation::${u.email}` : 'robustidps_ablation'
}

export interface AblationEntry {
  accuracy: number
  precision: number
  recall: number
  f1: number
  accuracy_drop: number
  disabled: number[]
}

export interface PairwiseEntry {
  branch_i: number
  branch_j: number
  name_i: string
  name_j: string
  pair_accuracy: number
  pair_drop: number
  interaction: number
}

export interface IncrementalEntry {
  step: number
  label: string
  added: string | null
  added_idx?: number
  accuracy: number
  gain: number
}

export interface AblationData {
  ablation: Record<string, AblationEntry>
  pairwise: Record<string, PairwiseEntry>
  incremental: IncrementalEntry[]
  branch_names: string[]
  model_used: string
}

interface AblationState {
  loading: boolean
  data: AblationData | null
  error: string | null
  enabled: boolean[]
  selectedModel: string
  fileName: string | null
}

interface AblationContextType extends AblationState {
  toggle: (i: number) => void
  setEnabled: (enabled: boolean[]) => void
  setSelectedModel: (model: string) => void
  run: (file: File) => void
  clear: () => void
  setFileName: (name: string | null) => void
}

const AblationContext = createContext<AblationContextType | null>(null)

function loadCached(): Partial<AblationState> {
  try {
    const raw = localStorage.getItem(_storageKey())
    if (!raw) return {}
    return JSON.parse(raw)
  } catch {
    return {}
  }
}

function saveCache(state: Partial<AblationState>) {
  try {
    localStorage.setItem(_storageKey(), JSON.stringify({
      data: state.data,
      enabled: state.enabled,
      selectedModel: state.selectedModel,
      fileName: state.fileName,
    }))
  } catch { /* quota exceeded — ignore */ }
}

export function AblationProvider({ children }: { children: ReactNode }) {
  const cached = loadCached()

  const [state, setState] = useState<AblationState>({
    loading: false,
    data: (cached.data as AblationData) ?? null,
    error: null,
    enabled: (cached.enabled as boolean[]) ?? new Array(7).fill(true),
    selectedModel: (cached.selectedModel as string) ?? 'surrogate',
    fileName: (cached.fileName as string) ?? null,
  })

  const requestId = useRef(0)

  const toggle = useCallback((i: number) => {
    setState((prev) => {
      const next = [...prev.enabled]
      next[i] = !next[i]
      const updated = { ...prev, enabled: next }
      saveCache(updated)
      return updated
    })
  }, [])

  const setEnabled = useCallback((enabled: boolean[]) => {
    setState((prev) => {
      const updated = { ...prev, enabled }
      saveCache(updated)
      return updated
    })
  }, [])

  const setSelectedModel = useCallback((selectedModel: string) => {
    setState((prev) => {
      const updated = { ...prev, selectedModel }
      saveCache(updated)
      return updated
    })
  }, [])

  const setFileName = useCallback((fileName: string | null) => {
    setState((prev) => ({ ...prev, fileName }))
  }, [])

  const run = useCallback((file: File) => {
    const thisRequest = ++requestId.current
    setState((prev) => ({ ...prev, loading: true, error: null, fileName: file.name }))

    const disabled = state.enabled
      .map((v, i) => (v ? -1 : i))
      .filter((i) => i >= 0)

    runAblation(file, disabled, state.selectedModel)
      .then((res) => {
        if (thisRequest !== requestId.current) return
        const data: AblationData = {
          ablation: res.ablation,
          pairwise: res.pairwise ?? {},
          incremental: res.incremental ?? [],
          branch_names: res.branch_names ?? [],
          model_used: res.model_used ?? '',
        }
        setState((prev) => {
          const updated = { ...prev, loading: false, data, error: null }
          saveCache(updated)
          return updated
        })
      })
      .catch(() => {
        if (thisRequest !== requestId.current) return
        setState((prev) => ({
          ...prev,
          loading: false,
          error: 'Failed to run ablation. Is the backend running?',
        }))
      })
  }, [state.enabled, state.selectedModel])

  const clear = useCallback(() => {
    localStorage.removeItem(_storageKey())
    setState({
      loading: false,
      data: null,
      error: null,
      enabled: new Array(7).fill(true),
      selectedModel: 'surrogate',
      fileName: null,
    })
  }, [])

  return (
    <AblationContext.Provider value={{
      ...state,
      toggle,
      setEnabled,
      setSelectedModel,
      run,
      clear,
      setFileName,
    }}>
      {children}
    </AblationContext.Provider>
  )
}

export function useAblation() {
  const ctx = useContext(AblationContext)
  if (!ctx) throw new Error('useAblation must be used within AblationProvider')
  return ctx
}
