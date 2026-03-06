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
  source: 'upload' | 'live-monitor' | null
}

interface AnalysisContextType extends AnalysisState {
  runAnalysis: (file: File, mcPasses: number, modelName: string) => void
  setLiveResults: (results: Record<string, unknown>, fileName: string) => void
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
    const cachedSource = localStorage.getItem('robustidps_source') as AnalysisState['source']
    return {
      loading: false,
      results: cached ? JSON.parse(cached) : null,
      error: null,
      fileName: cachedFileName || null,
      jobId: cachedJobId || null,
      source: cachedSource || null,
    }
  })

  // Track the latest request so we can ignore stale responses
  const requestId = useRef(0)

  const runAnalysis = useCallback((file: File, mcPasses: number, modelName: string) => {
    const thisRequest = ++requestId.current
    setState((prev) => ({ ...prev, loading: true, error: null, fileName: file.name, source: 'upload' }))

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
          localStorage.setItem('robustidps_source', 'upload')
        } catch { /* quota exceeded — keep results in memory only */ }
        setState({ loading: false, results: data, error: null, fileName: file.name, jobId, source: 'upload' })
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

  const setLiveResults = useCallback((results: Record<string, unknown>, fileName: string) => {
    try {
      const { predictions, confusion_matrix, ...summary } = results
      localStorage.setItem('robustidps_results', JSON.stringify(summary))
      localStorage.setItem('robustidps_file_name', fileName)
      localStorage.setItem('robustidps_source', 'live-monitor')
      localStorage.removeItem('robustidps_job_id')
    } catch { /* quota exceeded */ }
    setState({
      loading: false,
      results,
      error: null,
      fileName,
      jobId: null,
      source: 'live-monitor',
    })
  }, [])

  const clearResults = useCallback(() => {
    localStorage.removeItem('robustidps_results')
    localStorage.removeItem('robustidps_job_id')
    localStorage.removeItem('robustidps_file_name')
    localStorage.removeItem('robustidps_source')
    setState({ loading: false, results: null, error: null, fileName: null, jobId: null, source: null })
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
    <AnalysisContext.Provider value={{ ...state, runAnalysis, setLiveResults, clearResults, deleteJob }}>
      {children}
    </AnalysisContext.Provider>
  )
}

export function useAnalysis() {
  const ctx = useContext(AnalysisContext)
  if (!ctx) throw new Error('useAnalysis must be used within AnalysisProvider')
  return ctx
}
