import { useEffect, useState } from 'react'
import { fetchModels } from '../utils/api'
import { Brain, Check } from 'lucide-react'

interface ModelInfo {
  id: string
  name: string
  description: string
  paper: string
  has_ablation: boolean
  category: string
  weights_available: boolean
}

interface Props {
  value: string
  onChange: (modelId: string) => void
  compact?: boolean
}

const CATEGORY_COLORS: Record<string, string> = {
  ensemble: 'bg-accent-blue/15 text-accent-blue',
  temporal: 'bg-accent-purple/15 text-accent-purple',
  federated: 'bg-accent-green/15 text-accent-green',
}

export default function ModelSelector({ value, onChange, compact }: Props) {
  const [models, setModels] = useState<ModelInfo[]>([])

  useEffect(() => {
    fetchModels()
      .then((data) => setModels(data.models ?? []))
      .catch(() => {})
  }, [])

  if (models.length === 0) return null

  if (compact) {
    return (
      <div>
        <label className="text-xs text-text-secondary block mb-1">
          <Brain className="w-3.5 h-3.5 inline mr-1" />
          Model
        </label>
        <select
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="w-full bg-bg-card border border-bg-card rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-accent-blue"
        >
          {models.map((m) => (
            <option key={m.id} value={m.id} disabled={!m.weights_available}>
              {m.name}{!m.weights_available ? ' (no weights)' : ''}
            </option>
          ))}
        </select>
      </div>
    )
  }

  return (
    <div className="space-y-2">
      <h3 className="text-sm font-medium text-text-secondary flex items-center gap-2">
        <Brain className="w-4 h-4" />
        Select Model
      </h3>
      <div className="grid grid-cols-1 gap-2">
        {models.map((m) => (
          <button
            key={m.id}
            onClick={() => m.weights_available && onChange(m.id)}
            disabled={!m.weights_available}
            className={`text-left px-4 py-3 rounded-lg border transition-all ${
              value === m.id
                ? 'border-accent-blue bg-accent-blue/10'
                : 'border-bg-card bg-bg-secondary hover:border-bg-card/80'
            } ${!m.weights_available ? 'opacity-40 cursor-not-allowed' : 'cursor-pointer'}`}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">{m.name}</span>
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded-full font-medium ${
                    CATEGORY_COLORS[m.category] || 'bg-bg-card text-text-secondary'
                  }`}
                >
                  {m.category}
                </span>
              </div>
              {value === m.id && (
                <Check className="w-4 h-4 text-accent-blue shrink-0" />
              )}
            </div>
            <p className="text-xs text-text-secondary mt-1 line-clamp-1">
              {m.description}
            </p>
          </button>
        ))}
      </div>
    </div>
  )
}
