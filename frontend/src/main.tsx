import { StrictMode, Component, type ReactNode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { AnalysisProvider } from './hooks/useAnalysis'
import { AblationProvider } from './hooks/useAblation'
import { MultiAblationProvider } from './hooks/useMultiAblation'
import { NoticeBoardProvider } from './hooks/useNoticeBoard'
import { LLMAttackResultsProvider } from './hooks/useLLMAttackResults'
import App from './App'
import './index.css'

class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null }

  static getDerivedStateFromError(error: Error) {
    return { error }
  }

  handleReset = () => {
    // Clear potentially corrupted localStorage (both legacy and user-scoped keys)
    try {
      const bases = ['robustidps_results', 'robustidps_job_id', 'robustidps_file_name', 'robustidps_source']
      for (const b of bases) localStorage.removeItem(b)
      // Also clear email-scoped variants
      const toRemove: string[] = []
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i)
        if (k && bases.some(base => k.startsWith(base + '::'))) toRemove.push(k)
      }
      for (const k of toRemove) localStorage.removeItem(k)
    } catch { /* ignore */ }
    this.setState({ error: null })
    window.location.reload()
  }

  render() {
    if (this.state.error) {
      return (
        <div style={{
          minHeight: '100vh',
          background: '#0f172a',
          color: '#f8fafc',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontFamily: 'Inter, system-ui, sans-serif',
        }}>
          <div style={{ textAlign: 'center', maxWidth: 480, padding: 24 }}>
            <div style={{ fontSize: 48, marginBottom: 16 }}>!</div>
            <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 8 }}>Something went wrong</h1>
            <p style={{ fontSize: 14, color: '#94a3b8', marginBottom: 24 }}>
              {this.state.error.message || 'An unexpected error occurred.'}
            </p>
            <button
              onClick={this.handleReset}
              style={{
                padding: '10px 24px',
                background: '#3b82f6',
                color: 'white',
                border: 'none',
                borderRadius: 8,
                fontSize: 14,
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Reload Application
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      <BrowserRouter>
        <AnalysisProvider>
          <AblationProvider>
            <MultiAblationProvider>
              <NoticeBoardProvider>
                <LLMAttackResultsProvider>
                  <App />
                </LLMAttackResultsProvider>
              </NoticeBoardProvider>
            </MultiAblationProvider>
          </AblationProvider>
        </AnalysisProvider>
      </BrowserRouter>
    </ErrorBoundary>
  </StrictMode>,
)
