import { useState, useEffect } from 'react'
import { Key, ChevronDown, ChevronUp, CheckCircle2, AlertCircle } from 'lucide-react'

const PROVIDERS = [
  { id: 'local', name: 'Local Defense Only', desc: 'Run defense pipeline without LLM (no API key needed)', color: 'text-text-secondary' },
  { id: 'anthropic', name: 'Claude (Anthropic)', desc: 'Test against Claude models', prefix: 'sk-ant-', placeholder: 'sk-ant-...', color: 'text-accent-amber' },
  { id: 'openai', name: 'GPT-4o (OpenAI)', desc: 'Test against OpenAI models', prefix: 'sk-', placeholder: 'sk-...', color: 'text-accent-green' },
  { id: 'google', name: 'Gemini (Google)', desc: 'Test against Google Gemini', prefix: 'AIza', placeholder: 'AIza...', color: 'text-accent-blue' },
  { id: 'deepseek', name: 'DeepSeek', desc: 'Test against DeepSeek', prefix: 'dsk-', placeholder: 'dsk-...', color: 'text-accent-purple' },
]

interface Props {
  provider: string
  apiKey: string
  onProviderChange: (provider: string) => void
  onApiKeyChange: (key: string) => void
  compact?: boolean  // If true, show inline instead of expandable panel
}

export default function LLMProviderConfig({ provider, apiKey, onProviderChange, onApiKeyChange, compact }: Props) {
  const [expanded, setExpanded] = useState(false)

  // Auto-detect provider from key prefix
  const detectedProvider = apiKey
    ? apiKey.startsWith('sk-ant-') ? 'anthropic'
      : apiKey.startsWith('AIza') ? 'google'
      : apiKey.startsWith('dsk-') ? 'deepseek'
      : apiKey.startsWith('sk-') ? 'openai'
      : provider
    : provider

  const activeProvider = PROVIDERS.find(p => p.id === (provider === 'auto' ? detectedProvider : provider)) || PROVIDERS[0]
  const needsKey = provider !== 'local'
  const hasValidKey = !needsKey || apiKey.length > 10

  if (compact) {
    return (
      <div className="flex items-center gap-2 text-xs">
        <select
          value={provider}
          onChange={e => onProviderChange(e.target.value)}
          className="bg-bg-secondary border border-bg-card rounded px-2 py-1 text-text-primary text-xs"
        >
          {PROVIDERS.map(p => (
            <option key={p.id} value={p.id}>{p.name}</option>
          ))}
        </select>
        {needsKey && (
          <input
            type="password"
            value={apiKey}
            onChange={e => onApiKeyChange(e.target.value)}
            placeholder={activeProvider.placeholder || 'API key...'}
            className="bg-bg-secondary border border-bg-card rounded px-2 py-1 text-text-primary text-xs w-40"
          />
        )}
        {hasValidKey ? (
          <CheckCircle2 className="w-3.5 h-3.5 text-accent-green shrink-0" />
        ) : (
          <AlertCircle className="w-3.5 h-3.5 text-accent-amber shrink-0" />
        )}
      </div>
    )
  }

  return (
    <div className="bg-bg-card/50 rounded-xl border border-bg-card">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between p-3 text-xs"
      >
        <div className="flex items-center gap-2">
          <Key className="w-3.5 h-3.5 text-accent-orange" />
          <span className="font-medium text-text-primary">LLM Provider:</span>
          <span className={activeProvider.color}>{activeProvider.name}</span>
          {provider !== 'local' && (
            hasValidKey
              ? <span className="text-accent-green text-[10px]">(key set)</span>
              : <span className="text-accent-amber text-[10px]">(no key)</span>
          )}
        </div>
        {expanded ? <ChevronUp className="w-3.5 h-3.5 text-text-secondary" /> : <ChevronDown className="w-3.5 h-3.5 text-text-secondary" />}
      </button>

      {expanded && (
        <div className="px-3 pb-3 space-y-3">
          {/* Provider selector */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5">
            {PROVIDERS.map(p => (
              <button
                key={p.id}
                onClick={() => onProviderChange(p.id)}
                className={`p-2 rounded-lg border text-left transition-all ${
                  provider === p.id
                    ? 'border-accent-orange/50 bg-accent-orange/10'
                    : 'border-bg-card hover:border-bg-card/80 bg-bg-secondary'
                }`}
              >
                <div className={`text-[11px] font-medium ${p.color}`}>{p.name}</div>
                <div className="text-[9px] text-text-secondary mt-0.5">{p.desc}</div>
              </button>
            ))}
          </div>

          {/* API Key input */}
          {needsKey && (
            <div>
              <label className="text-[10px] text-text-secondary block mb-1">
                API Key {apiKey ? '(set)' : '— uses Copilot key if available'}
              </label>
              <input
                type="password"
                value={apiKey}
                onChange={e => onApiKeyChange(e.target.value)}
                placeholder={activeProvider.placeholder || 'Enter API key...'}
                className="w-full bg-bg-secondary border border-bg-card rounded-lg px-3 py-2 text-xs text-text-primary placeholder:text-text-secondary/50 focus:outline-none focus:border-accent-orange/50"
              />
              <p className="text-[9px] text-text-secondary mt-1">
                Leave empty to use the API key configured in the SOC Copilot page. Your key is stored in session memory only — never persisted to disk.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/** Helper: get Copilot's stored API key and provider as defaults */
export function getCopilotDefaults(): { apiKey: string; provider: string } {
  const apiKey = sessionStorage.getItem('robustidps_copilot_api_key') || ''
  const provider = localStorage.getItem('robustidps_copilot_provider') || 'local'
  return { apiKey, provider: provider === 'auto' ? 'local' : provider }
}
