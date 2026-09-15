import { createContext, useContext, useState, useCallback, type ReactNode } from 'react'
import { getUser } from '../utils/auth'

/** Per-user localStorage key. */
function _key(base: string): string {
  const u = getUser()
  return u ? `${base}::${u.email}` : base
}

const STORAGE_KEY = 'robustidps_llm_attacks'

/* ── Result types for each LLM Attack Surface page ───────────────────── */

export interface PromptInjectionResult {
  timestamp: number
  template: string
  severity: string
  defense: string
  blocked: boolean
  confidence: number
  latency: number
  payload: string
}

export interface JailbreakFinding {
  timestamp: number
  technique: string
  category: string
  severity: string
  effectiveness: number
  detectionDifficulty: number
  mitigations: string[]
}

export interface RAGPoisoningResult {
  timestamp: number
  attackType: string
  severity: string
  riskLevel: string
  confidence: number
  defensesActive: string[]
  poisonedDocuments: number
  cleanResponse: string
  poisonedResponse: string
}

export interface MultiAgentResult {
  timestamp: number
  attackScenario: string
  severity: string
  compromisedAgents: string[]
  totalAgents: number
  attackSteps: number
  defensesEnabled: boolean
  mitigations: string[]
}

export interface LLMAttackResultsState {
  promptInjection: PromptInjectionResult[]
  jailbreakFindings: JailbreakFinding[]
  ragPoisoning: RAGPoisoningResult[]
  multiAgent: MultiAgentResult[]
  lastUpdated: number | null
}

interface LLMAttackResultsContextType extends LLMAttackResultsState {
  addPromptInjectionResult: (r: PromptInjectionResult) => void
  addJailbreakFinding: (f: JailbreakFinding) => void
  addRAGPoisoningResult: (r: RAGPoisoningResult) => void
  addMultiAgentResult: (r: MultiAgentResult) => void
  clearAll: () => void
  getCondensedSummary: () => Record<string, unknown>
}

const INITIAL: LLMAttackResultsState = {
  promptInjection: [],
  jailbreakFindings: [],
  ragPoisoning: [],
  multiAgent: [],
  lastUpdated: null,
}

const LLMAttackResultsContext = createContext<LLMAttackResultsContextType | null>(null)

function loadFromStorage(): LLMAttackResultsState {
  try {
    const raw = localStorage.getItem(_key(STORAGE_KEY))
    if (!raw) return INITIAL
    return JSON.parse(raw) as LLMAttackResultsState
  } catch {
    return INITIAL
  }
}

function saveToStorage(state: LLMAttackResultsState) {
  try {
    // Keep last 50 results per category to avoid bloat
    const trimmed: LLMAttackResultsState = {
      promptInjection: state.promptInjection.slice(-50),
      jailbreakFindings: state.jailbreakFindings.slice(-50),
      ragPoisoning: state.ragPoisoning.slice(-50),
      multiAgent: state.multiAgent.slice(-50),
      lastUpdated: state.lastUpdated,
    }
    localStorage.setItem(_key(STORAGE_KEY), JSON.stringify(trimmed))
  } catch {
    // quota exceeded — skip
  }
}

export function LLMAttackResultsProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<LLMAttackResultsState>(loadFromStorage)

  const update = useCallback((updater: (prev: LLMAttackResultsState) => LLMAttackResultsState) => {
    setState((prev) => {
      const next = updater(prev)
      next.lastUpdated = Date.now()
      saveToStorage(next)
      return next
    })
  }, [])

  const addPromptInjectionResult = useCallback((r: PromptInjectionResult) => {
    update((prev) => ({ ...prev, promptInjection: [...prev.promptInjection, r] }))
  }, [update])

  const addJailbreakFinding = useCallback((f: JailbreakFinding) => {
    update((prev) => ({ ...prev, jailbreakFindings: [...prev.jailbreakFindings, f] }))
  }, [update])

  const addRAGPoisoningResult = useCallback((r: RAGPoisoningResult) => {
    update((prev) => ({ ...prev, ragPoisoning: [...prev.ragPoisoning, r] }))
  }, [update])

  const addMultiAgentResult = useCallback((r: MultiAgentResult) => {
    update((prev) => ({ ...prev, multiAgent: [...prev.multiAgent, r] }))
  }, [update])

  const clearAll = useCallback(() => {
    localStorage.removeItem(_key(STORAGE_KEY))
    setState(INITIAL)
  }, [])

  const getCondensedSummary = useCallback((): Record<string, unknown> => {
    const s = state
    const piResults = s.promptInjection
    const piBlocked = piResults.filter((r) => r.blocked).length
    const piBypass = piResults.filter((r) => !r.blocked).length
    const criticalInjections = piResults.filter((r) => r.severity === 'critical')

    const jbFindings = s.jailbreakFindings
    const jbBySeverity = { critical: 0, high: 0, medium: 0, low: 0 }
    jbFindings.forEach((f) => { jbBySeverity[f.severity as keyof typeof jbBySeverity]++ })

    const ragResults = s.ragPoisoning
    const ragHighRisk = ragResults.filter((r) => r.riskLevel === 'High').length

    const maResults = s.multiAgent
    const maCompromised = maResults.reduce((acc, r) => acc + r.compromisedAgents.length, 0)
    const maTotalAgents = maResults.reduce((acc, r) => acc + r.totalAgents, 0)

    return {
      prompt_injection: {
        total_tests: piResults.length,
        blocked: piBlocked,
        bypassed: piBypass,
        block_rate: piResults.length ? Math.round((piBlocked / piResults.length) * 100) : 0,
        critical_bypasses: criticalInjections.filter((r) => !r.blocked).length,
        avg_confidence: piResults.length
          ? Math.round(piResults.reduce((a, r) => a + r.confidence, 0) / piResults.length)
          : 0,
        defenses_tested: [...new Set(piResults.map((r) => r.defense))],
      },
      jailbreak_taxonomy: {
        techniques_analyzed: jbFindings.length,
        severity_distribution: jbBySeverity,
        categories: [...new Set(jbFindings.map((f) => f.category))],
        avg_effectiveness: jbFindings.length
          ? Math.round(jbFindings.reduce((a, f) => a + f.effectiveness, 0) / jbFindings.length)
          : 0,
        avg_detection_difficulty: jbFindings.length
          ? Math.round(jbFindings.reduce((a, f) => a + f.detectionDifficulty, 0) / jbFindings.length)
          : 0,
      },
      rag_poisoning: {
        total_simulations: ragResults.length,
        high_risk: ragHighRisk,
        mitigated: ragResults.filter((r) => r.riskLevel === 'Mitigated').length,
        attack_types: [...new Set(ragResults.map((r) => r.attackType))],
        defenses_active: [...new Set(ragResults.flatMap((r) => r.defensesActive))],
      },
      multi_agent: {
        total_scenarios: maResults.length,
        agents_compromised: maCompromised,
        agents_total: maTotalAgents,
        compromise_rate: maTotalAgents ? Math.round((maCompromised / maTotalAgents) * 100) : 0,
        critical_scenarios: maResults.filter((r) => r.severity === 'critical').length,
        attack_scenarios: [...new Set(maResults.map((r) => r.attackScenario))],
      },
      last_updated: s.lastUpdated ? new Date(s.lastUpdated).toISOString() : null,
    }
  }, [state])

  return (
    <LLMAttackResultsContext.Provider
      value={{
        ...state,
        addPromptInjectionResult,
        addJailbreakFinding,
        addRAGPoisoningResult,
        addMultiAgentResult,
        clearAll,
        getCondensedSummary,
      }}
    >
      {children}
    </LLMAttackResultsContext.Provider>
  )
}

export function useLLMAttackResults() {
  const ctx = useContext(LLMAttackResultsContext)
  if (!ctx) throw new Error('useLLMAttackResults must be used within LLMAttackResultsProvider')
  return ctx
}
