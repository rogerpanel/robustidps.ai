import { createContext, useContext, useState, useCallback, useRef, type ReactNode } from 'react'
import { uploadAndPredict } from '../utils/api'
import { authHeaders } from '../utils/auth'

const API = import.meta.env.VITE_API_URL || ''

interface AnalysisState {
  loading: boolean
  results: Record<string, unknown> | null
  error: string | null
  fileName: string | null
  jobId: string | null
}

interface AnalysisContextType extends AnalysisState {
  runAnalysis: (file: File, mcPasses: number, modelName: string) => void
  clearResults: () => void
  deleteJob: () => Promise<void>
}

const AnalysisContext = createContext<AnalysisContextType | null>(null)

export function AnalysisProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AnalysisState>(() => {
    // Restore previous results from localStorage on mount
    const cached = localStorage.getItem('robustidps_results')
    const cachedJobId = localStorage.getItem('robustidps_job_id')
    const cachedFileName = localStorage.getItem('robustidps_file_name')
    return {
      loading: false,
      results: cached ? JSON.parse(cached) : null,
      error: null,
      fileName: cachedFileName || null,
      jobId: cachedJobId || null,
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
        const jobId = (data as Record<string, unknown>).job_id as string || null
        // Cache summary only (exclude large predictions array) to avoid localStorage quota
        try {
          const { predictions, confusion_matrix, ...summary } = data as Record<string, unknown>
          localStorage.setItem('robustidps_results', JSON.stringify(summary))
          if (jobId) localStorage.setItem('robustidps_job_id', jobId)
          localStorage.setItem('robustidps_file_name', file.name)
        } catch { /* quota exceeded — keep results in memory only */ }
        setState({ loading: false, results: data, error: null, fileName: file.name, jobId })
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
    localStorage.removeItem('robustidps_job_id')
    localStorage.removeItem('robustidps_file_name')
    setState({ loading: false, results: null, error: null, fileName: null, jobId: null })
  }, [])

  const deleteJob = useCallback(async () => {
    const jobId = state.jobId
    if (jobId) {
      try {
        await fetch(`${API}/api/jobs/${jobId}`, {
          method: 'DELETE',
          headers: authHeaders(),
        })
      } catch {
        // Server may be unavailable — still clear locally
      }
    }
    clearResults()
  }, [state.jobId, clearResults])

  return (
    <AnalysisContext.Provider value={{ ...state, runAnalysis, clearResults, deleteJob }}>
      {children}
    </AnalysisContext.Provider>
  )
}

export function useAnalysis() {
  const ctx = useContext(AnalysisContext)
  if (!ctx) throw new Error('useAnalysis must be used within AnalysisProvider')
  return ctx
}
