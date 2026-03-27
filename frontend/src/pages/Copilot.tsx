import { useState, useRef, useEffect, useCallback } from 'react'
import { Send, Bot, User, Key, Loader2, Sparkles, X, Settings, Trash2, ChevronDown, Cpu, ToggleLeft, ToggleRight, ChevronLeft, ChevronRight } from 'lucide-react'
import DOMPurify from 'dompurify'
import { authHeaders } from '../utils/auth'
import PageGuide from '../components/PageGuide'
import { syncLLMAttackResults } from '../utils/api'
import { useLLMAttackResults } from '../hooks/useLLMAttackResults'

interface Message {
  role: 'user' | 'assistant'
  content: string
  provider?: string
  timestamp?: number
}

interface IDSModel {
  id: string
  name: string
  category: string
  description: string
  branch_index?: number
  weights_available?: boolean
}

interface ProviderConfig {
  id: string
  name: string
  keyPrefix: string
  placeholder: string
  color: string
  models: string[]
}

const API = import.meta.env.VITE_API_URL || ''

const STORAGE_KEYS = {
  messages: 'robustidps_copilot_messages',
  apiKey: 'robustidps_copilot_api_key',
  provider: 'robustidps_copilot_provider',
  model: 'robustidps_copilot_model',
  activeIdsModels: 'robustidps_copilot_ids_models',
}

// Migrate any API key from localStorage to sessionStorage (one-time cleanup)
;(() => {
  const legacy = localStorage.getItem(STORAGE_KEYS.apiKey)
  if (legacy) {
    sessionStorage.setItem(STORAGE_KEYS.apiKey, legacy)
    localStorage.removeItem(STORAGE_KEYS.apiKey)
  }
})()

const PROVIDERS: ProviderConfig[] = [
  {
    id: 'anthropic',
    name: 'Anthropic (Claude)',
    keyPrefix: 'sk-ant-',
    placeholder: 'sk-ant-...',
    color: 'accent-amber',
    models: ['claude-sonnet-4-20250514', 'claude-haiku-4-5-20251001', 'claude-opus-4-20250514'],
  },
  {
    id: 'openai',
    name: 'OpenAI',
    keyPrefix: 'sk-',
    placeholder: 'sk-...',
    color: 'accent-green',
    models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'o3-mini'],
  },
  {
    id: 'google',
    name: 'Google (Gemini)',
    keyPrefix: 'AIza',
    placeholder: 'AIza...',
    color: 'accent-blue',
    models: ['gemini-2.0-flash', 'gemini-2.5-pro', 'gemini-2.5-flash'],
  },
  {
    id: 'deepseek',
    name: 'DeepSeek',
    keyPrefix: 'dsk-',
    placeholder: 'dsk-...',
    color: 'accent-purple',
    models: ['deepseek-chat', 'deepseek-reasoner'],
  },
]

const SUGGESTIONS = [
  'Show me the threat summary',
  'What are the recent scan jobs?',
  'What active operations are running?',
  'What can you do?',
]

const PAGE_CONTEXTS = [
  { id: 'active_ops', label: 'Active Operations', query: 'Show me all active operations across pages. What analyses are currently running or completed?', icon: 'activity' },
  { id: 'upload', label: 'Upload Results', query: 'Get the latest upload analysis results. Summarise the threats found, severity distribution, and key findings.', icon: 'upload' },
  { id: 'redteam', label: 'Red Team', query: 'Get the red team arena results. What adversarial attacks were tested and what was the model robustness?', icon: 'shield' },
  { id: 'xai', label: 'Explainability', query: 'Get the XAI analysis results. What features are most important for detection? Explain the model decisions.', icon: 'eye' },
  { id: 'federated', label: 'Federated', query: 'Get the federated learning simulation results. What was the convergence, accuracy, and privacy metrics?', icon: 'network' },
  { id: 'ablation', label: 'Ablation Studio', query: 'Get the ablation study results. Which branches are most important? What is the accuracy drop when each branch is disabled? Show pairwise interactions and incremental gains.', icon: 'layers' },
  { id: 'pq_crypto', label: 'PQ Crypto', query: 'Get the post-quantum cryptography status. What algorithms are recommended and what are the risks?', icon: 'lock' },
  { id: 'zero_trust', label: 'Zero-Trust', query: 'Get the zero-trust governance status. What is the current trust score and policy compliance?', icon: 'shield-check' },
  { id: 'supply_chain', label: 'Supply Chain', query: 'Get the supply chain security status. Are there any vulnerabilities in our model pipeline?', icon: 'package' },
  { id: 'threat_resp', label: 'Threat Response', query: 'Get the threat response status. What playbooks are active and what incidents have been handled?', icon: 'zap' },
  { id: 'rl_response', label: 'RL Response Agent', query: 'Get the RL response agent simulation results. What was the threat mitigation rate, false positive blocking rate, action distribution, and constraint violations? Summarise the CPO agent performance.', icon: 'shield' },
  { id: 'adversarial_robustness', label: 'Adversarial Robustness', query: 'Get the adversarial robustness evaluation results. What attacks were tested (FGSM, PGD, C&W, DeepFool, Gaussian, Label masking), what was the clean accuracy, and how robust is the model? Report per-attack accuracy and robustness ratios.', icon: 'target' },
  { id: 'live_monitor', label: 'Live Monitor', query: 'Get the live monitor results. What threats were detected in the latest capture session? Show attack distribution, severity breakdown, top threat source IPs, confidence statistics, auto-block actions, and any active capture cycles.', icon: 'radio' },
  { id: 'prompt_injection', label: 'Prompt Injection', query: 'Get the LLM prompt injection testing results. How many injection attacks were tested, what was the block rate, which defenses were most effective, and were any critical attacks able to bypass defenses? Show the defense effectiveness breakdown.', icon: 'syringe' },
  { id: 'jailbreak_taxonomy', label: 'Jailbreak Taxonomy', query: 'Get the jailbreak taxonomy analysis results. What jailbreak techniques have been catalogued, what is the severity distribution, average effectiveness vs detection difficulty, and which categories pose the highest risk?', icon: 'book-open' },
  { id: 'rag_poisoning', label: 'RAG Poisoning', query: 'Get the RAG poisoning simulation results. How many poisoning scenarios were tested, what was the risk level distribution, which attack types were most dangerous, and which defenses were active during testing?', icon: 'database' },
  { id: 'multi_agent', label: 'Multi-Agent Chain', query: 'Get the multi-agent chain attack simulation results. How many attack scenarios were tested, what was the agent compromise rate, which scenarios were critical, and how effective were the defenses at containing propagation?', icon: 'git-merge' },
] as const

// Safely parse JSON from localStorage
function safeJsonParse<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key)
    if (!raw) return fallback
    return JSON.parse(raw) as T
  } catch {
    return fallback
  }
}

export default function Copilot() {
  const { getCondensedSummary, lastUpdated: llmAttackLastUpdated } = useLLMAttackResults()

  // Sync LLM attack results to backend on mount and when results change
  const syncedRef = useRef<number | null>(null)
  const [llmSyncStatus, setLlmSyncStatus] = useState<'idle' | 'syncing' | 'synced' | 'error'>('idle')
  useEffect(() => {
    if (llmAttackLastUpdated && llmAttackLastUpdated !== syncedRef.current) {
      syncedRef.current = llmAttackLastUpdated
      setLlmSyncStatus('syncing')
      syncLLMAttackResults(getCondensedSummary())
        .then(() => {
          setLlmSyncStatus('synced')
          setTimeout(() => setLlmSyncStatus('idle'), 3000)
        })
        .catch(() => {
          setLlmSyncStatus('error')
          setTimeout(() => setLlmSyncStatus('idle'), 5000)
        })
    }
  }, [llmAttackLastUpdated, getCondensedSummary])

  // Persist messages across navigation
  const [messages, setMessages] = useState<Message[]>(() => safeJsonParse(STORAGE_KEYS.messages, []))
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)

  // Settings
  const [apiKey, setApiKey] = useState(() => sessionStorage.getItem(STORAGE_KEYS.apiKey) || '')
  const [provider, setProvider] = useState(() => localStorage.getItem(STORAGE_KEYS.provider) || 'auto')
  const [selectedModel, setSelectedModel] = useState(() => localStorage.getItem(STORAGE_KEYS.model) || '')
  const [showSettings, setShowSettings] = useState(false)
  const [showModelPanel, setShowModelPanel] = useState(false)

  // Server-side provider status
  const [serverProviders, setServerProviders] = useState<Record<string, boolean>>({})

  // IDS model selector
  const [idsModels, setIdsModels] = useState<IDSModel[]>([])
  const [activeIdsModels, setActiveIdsModels] = useState<string[]>(() => safeJsonParse(STORAGE_KEYS.activeIdsModels, []))

  const scrollRef = useRef<HTMLDivElement>(null)

  // Persist messages to localStorage whenever they change
  useEffect(() => {
    try {
      if (messages.length > 0) {
        // Keep last 100 messages to avoid localStorage bloat
        const toStore = messages.slice(-100)
        localStorage.setItem(STORAGE_KEYS.messages, JSON.stringify(toStore))
      } else {
        localStorage.removeItem(STORAGE_KEYS.messages)
      }
    } catch {
      // localStorage full — clear old messages
      localStorage.removeItem(STORAGE_KEYS.messages)
    }
  }, [messages])

  // Persist API key in sessionStorage (cleared on tab close for security)
  useEffect(() => {
    if (apiKey) sessionStorage.setItem(STORAGE_KEYS.apiKey, apiKey)
    else sessionStorage.removeItem(STORAGE_KEYS.apiKey)
  }, [apiKey])

  useEffect(() => {
    localStorage.setItem(STORAGE_KEYS.provider, provider)
  }, [provider])

  useEffect(() => {
    localStorage.setItem(STORAGE_KEYS.model, selectedModel)
  }, [selectedModel])

  useEffect(() => {
    localStorage.setItem(STORAGE_KEYS.activeIdsModels, JSON.stringify(activeIdsModels))
  }, [activeIdsModels])

  // Fetch server status + IDS models on mount
  useEffect(() => {
    fetch(`${API}/api/copilot/status`, { headers: authHeaders() })
      .then((r) => r.json())
      .then((d) => setServerProviders(d.providers_configured || {}))
      .catch(() => {})

    fetch(`${API}/api/copilot/models`, { headers: authHeaders() })
      .then((r) => r.json())
      .then((d) => {
        setIdsModels(d.models || [])
        // If no active models are set, activate all by default
        if (!localStorage.getItem(STORAGE_KEYS.activeIdsModels)) {
          setActiveIdsModels((d.models || []).map((m: IDSModel) => m.id))
        }
      })
      .catch(() => {})
  }, [])

  // Auto-scroll
  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [messages])

  const clearKey = () => {
    setApiKey('')
    sessionStorage.removeItem(STORAGE_KEYS.apiKey)
  }

  const clearHistory = () => {
    setMessages([])
    localStorage.removeItem(STORAGE_KEYS.messages)
  }

  const toggleIdsModel = (modelId: string) => {
    setActiveIdsModels((prev) =>
      prev.includes(modelId) ? prev.filter((id) => id !== modelId) : [...prev, modelId]
    )
  }

  const selectAllModels = () => setActiveIdsModels(idsModels.map((m) => m.id))
  const deselectAllModels = () => setActiveIdsModels([])

  // Determine active provider for display
  const getActiveProvider = (): string => {
    if (provider !== 'auto') return provider
    if (apiKey) {
      if (apiKey.startsWith('sk-ant-')) return 'anthropic'
      if (apiKey.startsWith('AIza')) return 'google'
      if (apiKey.startsWith('dsk-')) return 'deepseek'
      if (apiKey.startsWith('sk-')) return 'openai'
    }
    // Check server-side
    for (const p of ['anthropic', 'openai', 'google', 'deepseek']) {
      if (serverProviders[p]) return p
    }
    return 'local'
  }

  const activeProv = getActiveProvider()
  const activeProviderInfo = PROVIDERS.find((p) => p.id === activeProv)
  const usingAI = activeProv !== 'local'

  const sendMessage = useCallback(async (text?: string) => {
    const msg = text || input.trim()
    if (!msg || loading) return
    setInput('')

    const userMsg: Message = { role: 'user', content: msg, timestamp: Date.now() }
    const newMessages = [...messages, userMsg]
    setMessages(newMessages)
    setLoading(true)

    try {
      const payload = {
        messages: newMessages.map((m) => ({ role: m.role, content: m.content })),
        api_key: apiKey,
        provider,
        model: selectedModel,
        active_ids_models: activeIdsModels,
      }

      const res = await fetch(`${API}/api/copilot/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify(payload),
      })

      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        throw new Error(err.detail || `Error ${res.status}`)
      }

      const contentType = res.headers.get('content-type') || ''

      if (contentType.includes('text/event-stream')) {
        const reader = res.body?.getReader()
        const decoder = new TextDecoder()
        let fullContent = ''
        let detectedProvider = activeProv

        setMessages((prev) => [...prev, { role: 'assistant', content: '', provider: detectedProvider, timestamp: Date.now() }])

        if (reader) {
          while (true) {
            const { done, value } = await reader.read()
            if (done) break
            const text = decoder.decode(value, { stream: true })
            const lines = text.split('\n')
            for (const line of lines) {
              if (line.startsWith('data: ')) {
                try {
                  const data = JSON.parse(line.slice(6))
                  if (data.provider) detectedProvider = data.provider
                  if (data.error) {
                    fullContent += `\n\n**Error:** ${data.error}`
                  } else if (data.content) {
                    fullContent += data.content
                  }
                  setMessages((prev) => {
                    const updated = [...prev]
                    updated[updated.length - 1] = { role: 'assistant', content: fullContent, provider: detectedProvider, timestamp: Date.now() }
                    return updated
                  })
                } catch {}
              }
            }
          }
        }
      } else {
        const data = await res.json()
        setMessages((prev) => [...prev, { role: 'assistant', content: data.content, provider: data.provider, timestamp: Date.now() }])
      }
    } catch (err) {
      setMessages((prev) => [...prev, { role: 'assistant', content: `**Error:** ${err instanceof Error ? err.message : 'Request failed'}`, provider: 'error', timestamp: Date.now() }])
    } finally {
      setLoading(false)
    }
  }, [input, loading, messages, apiKey, provider, selectedModel, activeIdsModels, activeProv])

  const providerLabel = (prov: string) => {
    const p = PROVIDERS.find((x) => x.id === prov)
    return p ? p.name : prov === 'local' ? 'Local Mode' : prov
  }

  const surrogateModels = idsModels.filter((m) => m.category === 'surrogate')
  const independentModels = idsModels.filter((m) => m.category !== 'surrogate')

  return (
    <div className="flex flex-col h-[calc(100vh-6rem)] md:h-[calc(100vh-4rem)]">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <h1 className="text-xl md:text-2xl font-display font-bold">SOC Copilot</h1>
          <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${
            usingAI ? 'bg-accent-blue/15 text-accent-blue' : 'bg-bg-card text-text-secondary'
          }`}>
            {usingAI ? (activeProviderInfo?.name || activeProv) : 'Local Mode'}
          </span>
        </div>
        <div className="flex items-center gap-1">
          {messages.length > 0 && (
            <button
              onClick={clearHistory}
              title="Clear chat history"
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs text-text-secondary hover:text-accent-red hover:bg-accent-red/10 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
          <button
            onClick={() => { setShowModelPanel(!showModelPanel); setShowSettings(false) }}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition-colors ${
              showModelPanel ? 'text-accent-blue bg-accent-blue/10' : 'text-text-secondary hover:text-text-primary hover:bg-bg-card/50'
            }`}
          >
            <Cpu className="w-3.5 h-3.5" /> Models ({activeIdsModels.length})
          </button>
          <button
            onClick={() => { setShowSettings(!showSettings); setShowModelPanel(false) }}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition-colors ${
              showSettings ? 'text-accent-blue bg-accent-blue/10' : 'text-text-secondary hover:text-text-primary hover:bg-bg-card/50'
            }`}
          >
            <Settings className="w-3.5 h-3.5" /> Settings
          </button>
        </div>
      </div>

      <PageGuide
        title="How to use SOC Copilot"
        steps={[
          { title: 'Configure LLM provider', desc: 'Open Settings to enter your API key for Claude, GPT-4o, Gemini, or DeepSeek. Leave empty to use the server\'s configured key. Local mode works without any key.' },
          { title: 'Select context', desc: 'Click any context chip (Active Operations, Upload Results, Red Team, etc.) to pre-fill a relevant query. The copilot fetches real data from that page.' },
          { title: 'Ask questions', desc: 'Type any security question. The copilot uses tool-calling to look up threat summaries, job details, firewall rules, model info, and LLM attack results.' },
          { title: 'Investigate LLM attacks', desc: 'Click the Prompt Injection, Jailbreak, RAG Poisoning, or Multi-Agent context chips to query findings from the LLM Attack Surface pages.' },
        ]}
        tip="Tip: Start with 'Show me all active operations' to see what data is available for the copilot to analyze."
      />

      {/* Settings Panel */}
      {showSettings && (
        <div className="mb-4 p-4 bg-bg-secondary rounded-xl border border-bg-card space-y-4 max-h-[320px] overflow-y-auto">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Key className="w-4 h-4 text-accent-amber" />
              <span className="text-sm font-medium text-text-primary">LLM Provider Settings</span>
            </div>
            <button onClick={() => setShowSettings(false)} className="text-text-secondary hover:text-text-primary"><X className="w-4 h-4" /></button>
          </div>

          <p className="text-xs text-text-secondary">
            Add your API key from any supported provider. The copilot auto-detects the provider from the key prefix, or you can choose manually.
            {Object.keys(serverProviders).length > 0 && (
              <span className="text-accent-green"> Server-side configured: {Object.keys(serverProviders).join(', ')}.</span>
            )}
          </p>

          {/* Provider selector */}
          <div className="space-y-2">
            <label className="text-xs text-text-secondary font-medium">Provider</label>
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => setProvider('auto')}
                className={`px-3 py-1.5 rounded-lg text-xs border transition-colors ${
                  provider === 'auto' ? 'border-accent-blue bg-accent-blue/10 text-accent-blue' : 'border-bg-card text-text-secondary hover:border-text-secondary'
                }`}
              >
                Auto-detect
              </button>
              {PROVIDERS.map((p) => (
                <button
                  key={p.id}
                  onClick={() => setProvider(p.id)}
                  className={`px-3 py-1.5 rounded-lg text-xs border transition-colors ${
                    provider === p.id ? 'border-accent-blue bg-accent-blue/10 text-accent-blue' : 'border-bg-card text-text-secondary hover:border-text-secondary'
                  }`}
                >
                  {p.name}
                  {serverProviders[p.id] && <span className="ml-1 text-accent-green">*</span>}
                </button>
              ))}
            </div>
          </div>

          {/* API key input */}
          <div className="space-y-2">
            <label className="text-xs text-text-secondary font-medium">API Key</label>
            <div className="flex gap-2">
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={activeProviderInfo?.placeholder || 'Enter your API key...'}
                className="flex-1 px-3 py-2 bg-bg-primary border border-bg-card rounded-lg text-text-primary text-sm focus:outline-none focus:ring-2 focus:ring-accent-blue/50"
              />
              {apiKey && (
                <button onClick={clearKey} className="px-3 py-2 text-xs text-accent-red hover:bg-accent-red/10 rounded-lg transition-colors">Clear</button>
              )}
            </div>
            <p className="text-[10px] text-text-secondary opacity-60">
              Your key is stored in your browser session only — it is automatically cleared when you close the tab and is never sent to our servers.
            </p>
          </div>

          {/* Model selector */}
          {(provider !== 'auto' || apiKey) && (
            <div className="space-y-2">
              <label className="text-xs text-text-secondary font-medium">LLM Model (optional)</label>
              <div className="relative">
                <select
                  value={selectedModel}
                  onChange={(e) => setSelectedModel(e.target.value)}
                  className="w-full px-3 py-2 bg-bg-primary border border-bg-card rounded-lg text-text-primary text-sm focus:outline-none focus:ring-2 focus:ring-accent-blue/50 appearance-none cursor-pointer"
                >
                  <option value="">Default</option>
                  {(activeProviderInfo?.models || []).map((m) => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
                <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-secondary pointer-events-none" />
              </div>
            </div>
          )}
        </div>
      )}

      {/* IDS Model Panel */}
      {showModelPanel && (
        <div className="mb-4 p-4 bg-bg-secondary rounded-xl border border-bg-card max-h-[360px] overflow-y-auto">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-accent-blue" />
              <span className="text-sm font-medium text-text-primary">Active IDS Models</span>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={selectAllModels} className="px-2 py-1 text-[10px] text-accent-blue hover:bg-accent-blue/10 rounded transition-colors">All</button>
              <button onClick={deselectAllModels} className="px-2 py-1 text-[10px] text-text-secondary hover:bg-bg-card rounded transition-colors">None</button>
              <button onClick={() => setShowModelPanel(false)} className="text-text-secondary hover:text-text-primary"><X className="w-4 h-4" /></button>
            </div>
          </div>

          <p className="text-xs text-text-secondary mb-3">
            Select which IDS models the copilot should consider when analysing threats. Active models are included in the AI context.
          </p>

          {/* Surrogate branches */}
          {surrogateModels.length > 0 && (
            <div className="mb-3">
              <h3 className="text-[10px] uppercase tracking-wider text-text-secondary font-medium mb-2">Surrogate Ensemble (7 Branches)</h3>
              <div className="space-y-1">
                {surrogateModels.map((m) => (
                  <button
                    key={m.id}
                    onClick={() => toggleIdsModel(m.id)}
                    className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-left text-xs transition-colors ${
                      activeIdsModels.includes(m.id)
                        ? 'bg-accent-blue/10 border border-accent-blue/30 text-text-primary'
                        : 'bg-bg-primary border border-bg-card text-text-secondary hover:border-text-secondary'
                    }`}
                  >
                    {activeIdsModels.includes(m.id)
                      ? <ToggleRight className="w-4 h-4 text-accent-blue shrink-0" />
                      : <ToggleLeft className="w-4 h-4 text-text-secondary shrink-0" />
                    }
                    <span className="font-medium">{m.name}</span>
                    <span className="ml-auto text-[10px] opacity-50">B{m.branch_index}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Independent models */}
          {independentModels.length > 0 && (
            <div>
              <h3 className="text-[10px] uppercase tracking-wider text-text-secondary font-medium mb-2">Independent Research Models</h3>
              <div className="space-y-1">
                {independentModels.map((m) => (
                  <button
                    key={m.id}
                    onClick={() => toggleIdsModel(m.id)}
                    className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-left text-xs transition-colors ${
                      activeIdsModels.includes(m.id)
                        ? 'bg-accent-green/10 border border-accent-green/30 text-text-primary'
                        : 'bg-bg-primary border border-bg-card text-text-secondary hover:border-text-secondary'
                    }`}
                  >
                    {activeIdsModels.includes(m.id)
                      ? <ToggleRight className="w-4 h-4 text-accent-green shrink-0" />
                      : <ToggleLeft className="w-4 h-4 text-text-secondary shrink-0" />
                    }
                    <div className="min-w-0">
                      <div className="font-medium truncate">{m.name}</div>
                      <div className="text-[10px] opacity-50 truncate">{m.description}</div>
                    </div>
                    {m.weights_available === false && (
                      <span className="ml-auto text-[10px] text-accent-amber shrink-0">no weights</span>
                    )}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Page Context Selector — two-row wrapped grid */}
      <div className="mb-3">
        <div className="flex flex-wrap gap-1.5">
          {PAGE_CONTEXTS.map((ctx) => (
            <button
              key={ctx.id}
              onClick={() => sendMessage(ctx.query)}
              disabled={loading}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] border border-bg-card bg-bg-secondary hover:border-accent-blue/40 hover:bg-accent-blue/5 text-text-secondary hover:text-accent-blue transition-colors disabled:opacity-50"
            >
              {ctx.label}
            </button>
          ))}
          {llmSyncStatus === 'syncing' && (
            <span className="flex items-center text-[9px] text-accent-blue animate-pulse px-2">syncing results...</span>
          )}
          {llmSyncStatus === 'synced' && (
            <span className="flex items-center text-[9px] text-accent-green px-2">results synced</span>
          )}
          {llmSyncStatus === 'error' && (
            <span className="flex items-center text-[9px] text-accent-red px-2">sync failed</span>
          )}
        </div>
      </div>

      {/* Messages */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto space-y-4 pb-4">
        {messages.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-center px-4">
            <Bot className="w-12 h-12 text-accent-blue/30 mb-4" />
            <h2 className="text-lg font-semibold text-text-primary mb-2">RobustIDPS.ai SOC Copilot</h2>
            <p className="text-sm text-text-secondary mb-6 max-w-md">
              Your AI security analyst. Ask about threats, investigate scan results, generate reports, or get remediation advice.
            </p>
            <div className="flex flex-wrap justify-center gap-2">
              {SUGGESTIONS.map((s) => (
                <button key={s} onClick={() => sendMessage(s)} className="px-3 py-1.5 bg-bg-card/50 border border-bg-card rounded-lg text-xs text-text-secondary hover:text-accent-blue hover:border-accent-blue/30 transition-colors">
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : ''}`}>
            {msg.role === 'assistant' && (
              <div className="shrink-0 w-7 h-7 rounded-full bg-accent-blue/15 flex items-center justify-center">
                {msg.provider && msg.provider !== 'local' && msg.provider !== 'error'
                  ? <Sparkles className="w-3.5 h-3.5 text-accent-blue" />
                  : <Bot className="w-3.5 h-3.5 text-accent-blue" />
                }
              </div>
            )}
            <div className={`max-w-[80%] px-4 py-3 rounded-xl text-sm leading-relaxed ${
              msg.role === 'user'
                ? 'bg-accent-blue text-white rounded-br-sm'
                : 'bg-bg-secondary border border-bg-card text-text-primary rounded-bl-sm'
            }`}>
              {msg.role === 'assistant' ? (
                <div className="prose prose-sm prose-invert max-w-none [&_strong]:text-text-primary [&_code]:text-accent-blue [&_code]:bg-bg-card/50 [&_code]:px-1 [&_code]:rounded" dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(msg.content.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>').replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\n/g, '<br/>').replace(/- (.*?)(<br\/>|$)/g, '<li>$1</li>').replace(/(<li>.*<\/li>)/g, '<ul class="list-disc list-inside space-y-0.5 my-1">$1</ul>'), { ALLOWED_TAGS: ['strong', 'em', 'code', 'br', 'ul', 'ol', 'li', 'p', 'span', 'div', 'pre'], ALLOWED_ATTR: ['class'] }) }} />
              ) : (
                msg.content
              )}
              {msg.provider && msg.role === 'assistant' && (
                <div className="mt-2 text-[10px] text-text-secondary opacity-60">
                  via {providerLabel(msg.provider)}
                </div>
              )}
            </div>
            {msg.role === 'user' && (
              <div className="shrink-0 w-7 h-7 rounded-full bg-accent-blue/30 flex items-center justify-center">
                <User className="w-3.5 h-3.5 text-accent-blue" />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex gap-3">
            <div className="shrink-0 w-7 h-7 rounded-full bg-accent-blue/15 flex items-center justify-center">
              <Loader2 className="w-3.5 h-3.5 text-accent-blue animate-spin" />
            </div>
            <div className="px-4 py-3 bg-bg-secondary border border-bg-card rounded-xl rounded-bl-sm">
              <div className="flex gap-1">
                <div className="w-2 h-2 bg-accent-blue/40 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                <div className="w-2 h-2 bg-accent-blue/40 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                <div className="w-2 h-2 bg-accent-blue/40 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Input */}
      <div className="pt-3 border-t border-bg-card">
        <form onSubmit={(e) => { e.preventDefault(); sendMessage() }} className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about threats, scan results, or security advice..."
            className="flex-1 px-4 py-3 bg-bg-secondary border border-bg-card rounded-xl text-sm text-text-primary placeholder-text-secondary focus:outline-none focus:ring-2 focus:ring-accent-blue/50"
            disabled={loading}
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="px-4 py-3 bg-accent-blue text-white rounded-xl hover:bg-accent-blue/90 disabled:opacity-50 transition-colors"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  )
}
