import { createContext, useContext, useState, useCallback, useRef, type ReactNode } from 'react'
import { uploadAndPredict } from '../utils/api'

interface AnalysisState {
  loading: boolean
  results: Record<string, unknown> | null
  error: string | null
  fileName: string | null
}

interface AnalysisContextType extends AnalysisState {
  runAnalysis: (file: File, mcPasses: number, modelName: string) => void
  clearResults: () => void
}

const AnalysisContext = createContext<AnalysisContextType | null>(null)

export function AnalysisProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AnalysisState>(() => {
    // Restore previous results from localStorage on mount
    const cached = localStorage.getItem('robustidps_results')
    return {
      loading: false,
      results: cached ? JSON.parse(cached) : null,
      error: null,
      fileName: null,
    }
  })

  // Track the latest request so we can ignore stale responses
  const requestId = useRef(0)

  const runAnalysis = useCallback((file: File, mcPasses: number, modelName: string) => {
    const thisRequest = ++requestId.current
    setState((prev) => ({ ...prev, loading: true, error: null, fileName: file.name }))

    uploadAndPredict(file, mcPasses, modelName)
      .then((data) => {
        // Ignore if a newer request was started
        if (thisRequest !== requestId.current) return
        localStorage.setItem('robustidps_results', JSON.stringify(data))
        setState({ loading: false, results: data, error: null, fileName: file.name })
      })
      .catch((err) => {
        if (thisRequest !== requestId.current) return
        const msg = err instanceof Error && err.message
          ? err.message
          : 'Failed to analyse file. Is the backend running?'
        setState((prev) => ({
          ...prev,
          loading: false,
          error: msg,
        }))
      })
  }, [])

  const clearResults = useCallback(() => {
    localStorage.removeItem('robustidps_results')
    setState({ loading: false, results: null, error: null, fileName: null })
  }, [])

  return (
    <AnalysisContext.Provider value={{ ...state, runAnalysis, clearResults }}>
      {children}
    </AnalysisContext.Provider>
  )
}

export function useAnalysis() {
  const ctx = useContext(AnalysisContext)
  if (!ctx) throw new Error('useAnalysis must be used within AnalysisProvider')
  return ctx
}
