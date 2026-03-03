import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { AnalysisProvider } from './hooks/useAnalysis'
import { AblationProvider } from './hooks/useAblation'
import App from './App'
import './index.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <AnalysisProvider>
        <AblationProvider>
          <App />
        </AblationProvider>
      </AnalysisProvider>
    </BrowserRouter>
  </StrictMode>,
)
