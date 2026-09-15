import { useEffect, useState } from 'react'
import { fetchModels } from '../utils/api'
import { Brain, Check, ChevronRight, Shield, Zap } from 'lucide-react'

interface ModelInfo {
  id: string
  name: string
  description: string
  paper: string
  has_ablation: boolean
  category: string
  weights_available: boolean
  enabled?: boolean
  custom?: boolean
  sub_models?: string[]
  parent_model?: string
}

interface Props {
  value: string[]
  onChange: (modelIds: string[]) => void
  disabled?: boolean
}

const CATEGORY_COLORS: Record<string, string> = {
  ensemble: 'bg-accent-blue/15 text-accent-blue',
  temporal: 'bg-accent-purple/15 text-accent-purple',
  federated: 'bg-accent-green/15 text-accent-green',
  foundation: 'bg-accent-amber/15 text-accent-amber',
  clrl: 'bg-accent-red/15 text-accent-red',
  custom: 'bg-accent-red/15 text-accent-red',
}

const CATEGORY_ICONS: Record<string, string> = {
  ensemble: '🛡️',
  temporal: '⏱️',
  federated: '🌐',
  foundation: '🧠',
  clrl: '🔄',
  custom: '⚙️',
}

export default function LiveCaptureModelSelector({ value, onChange, disabled }: Props) {
  const [models, setModels] = useState<ModelInfo[]>([])

  useEffect(() => {
    fetchModels()
      .then((data) => {
        const enabled = (data.models ?? []).filter(
          (m: ModelInfo) => m.enabled !== false && m.weights_available,
        )
        setModels(enabled)
      })
      .catch(() => {})
  }, [])

  if (models.length === 0) return null

  const toggleModel = (id: string) => {
    if (disabled) return
    if (value.includes(id)) {
      // Allow deselecting all — capture-only mode
      onChange(value.filter((v) => v !== id))
    } else {
      onChange([...value, id])
    }
  }

  const selectAll = () => {
    if (disabled) return
    const allIds = topModels.map((m) => m.id)
    onChange(allIds)
  }

  const clearAll = () => {
    if (disabled) return
    onChange([])
  }

  // Separate top-level models from sub-models
  const topModels = models.filter((m) => !m.parent_model)
  const subModelsMap = models.reduce<Record<string, ModelInfo[]>>((acc, m) => {
    if (m.parent_model) {
      if (!acc[m.parent_model]) acc[m.parent_model] = []
      acc[m.parent_model].push(m)
    }
    return acc
  }, {})

  const captureOnlyMode = value.length === 0

  return (
    <div className={`space-y-3 ${disabled ? 'opacity-60 pointer-events-none' : ''}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <label className="text-xs font-semibold text-text-secondary flex items-center gap-1.5 uppercase tracking-wider">
          <Brain className="w-3.5 h-3.5" />
          Detection Models
        </label>
        <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded-full ${
          captureOnlyMode
            ? 'bg-accent-amber/15 text-accent-amber'
            : 'bg-accent-green/15 text-accent-green'
        }`}>
          {captureOnlyMode ? 'Capture Only' : `${value.length} active`}
        </span>
      </div>

      {/* Quick actions */}
      <div className="flex items-center gap-2">
        <button
          onClick={selectAll}
          className="text-[10px] px-2 py-0.5 rounded border border-bg-card text-text-secondary hover:text-accent-blue hover:border-accent-blue/30 transition-colors"
        >
          Select All
        </button>
        <button
          onClick={clearAll}
          className="text-[10px] px-2 py-0.5 rounded border border-bg-card text-text-secondary hover:text-accent-amber hover:border-accent-amber/30 transition-colors"
        >
          Capture Only
        </button>
      </div>

      {/* Capture-only info banner */}
      {captureOnlyMode && (
        <div className="px-3 py-2 bg-accent-amber/10 border border-accent-amber/20 rounded-lg">
          <p className="text-[10px] text-accent-amber leading-relaxed">
            <Zap className="w-3 h-3 inline mr-1" />
            No models selected — traffic will be captured and recorded without real-time inference. You can analyse the captured data later on Upload &amp; Analyse.
          </p>
        </div>
      )}

      {/* Default recommendation */}
      {value.length > 0 && value.includes('surrogate') && (
        <div className="px-3 py-1.5 bg-accent-blue/5 border border-accent-blue/15 rounded-lg">
          <p className="text-[10px] text-accent-blue/80 leading-relaxed">
            <Shield className="w-3 h-3 inline mr-1" />
            Surrogate ensemble (default) — 7-branch ML model for comprehensive threat detection.
          </p>
        </div>
      )}

      {/* Model list */}
      <div className="space-y-1.5 max-h-[320px] overflow-y-auto pr-1">
        {topModels.map((m) => {
          const selected = value.includes(m.id)
          const subs = subModelsMap[m.id]
          const isDefault = m.id === 'surrogate'
          return (
            <div key={m.id}>
              <button
                onClick={() => toggleModel(m.id)}
                className={`w-full text-left px-3 py-2.5 rounded-lg border transition-all text-xs group ${
                  selected
                    ? 'border-accent-blue bg-accent-blue/10 shadow-sm shadow-accent-blue/5'
                    : 'border-bg-card bg-bg-card/30 hover:border-bg-card/80 hover:bg-bg-card/50'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-sm shrink-0">{CATEGORY_ICONS[m.category] || '🔧'}</span>
                    <span className="font-medium truncate">{m.name}</span>
                    {isDefault && (
                      <span className="text-[8px] px-1 py-0.5 rounded bg-accent-green/15 text-accent-green font-semibold shrink-0">
                        DEFAULT
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0 ml-2">
                    <span
                      className={`text-[9px] px-1 py-0.5 rounded-full font-medium ${
                        CATEGORY_COLORS[m.category] || 'bg-bg-card text-text-secondary'
                      }`}
                    >
                      {m.custom ? 'Custom' : m.category}
                    </span>
                    {selected && <Check className="w-3.5 h-3.5 text-accent-blue shrink-0" />}
                  </div>
                </div>
                <p className="text-[10px] text-text-secondary mt-1 line-clamp-1 pl-6">{m.description}</p>
              </button>
              {/* Sub-models indented */}
              {subs && subs.length > 0 && selected && (
                <div className="ml-4 mt-1 space-y-1 border-l-2 border-bg-card/50 pl-2">
                  {subs.map((sub) => {
                    const subSelected = value.includes(sub.id)
                    return (
                      <button
                        key={sub.id}
                        onClick={() => toggleModel(sub.id)}
                        className={`w-full text-left px-2.5 py-1.5 rounded-lg border transition-all text-[11px] ${
                          subSelected
                            ? 'border-accent-blue/50 bg-accent-blue/5'
                            : 'border-bg-card/30 bg-bg-card/10 hover:border-bg-card/50'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-1.5">
                            <ChevronRight className="w-3 h-3 text-text-secondary" />
                            <span className="font-medium">{sub.name}</span>
                          </div>
                          {subSelected && <Check className="w-3 h-3 text-accent-blue shrink-0" />}
                        </div>
                      </button>
                    )
                  })}
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* Footer info */}
      <p className="text-[9px] text-text-secondary/60 leading-relaxed">
        Selected models run inference on each captured flow in real time. More models = richer detection but higher compute. Deselect all for raw traffic capture.
      </p>
    </div>
  )
}
