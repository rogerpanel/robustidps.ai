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
  enabled?: boolean
  custom?: boolean
}

interface Props {
  value: string[]
  onChange: (modelIds: string[]) => void
}

const CATEGORY_COLORS: Record<string, string> = {
  ensemble: 'bg-accent-blue/15 text-accent-blue',
  temporal: 'bg-accent-purple/15 text-accent-purple',
  federated: 'bg-accent-green/15 text-accent-green',
  foundation: 'bg-accent-amber/15 text-accent-amber',
  custom: 'bg-accent-red/15 text-accent-red',
}

export default function ModelMultiSelector({ value, onChange }: Props) {
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
    if (value.includes(id)) {
      if (value.length > 1) onChange(value.filter((v) => v !== id))
    } else {
      onChange([...value, id])
    }
  }

  return (
    <div>
      <label className="text-xs text-text-secondary flex items-center gap-1 mb-2">
        <Brain className="w-3.5 h-3.5" />
        Models ({value.length} selected)
      </label>
      <div className="space-y-1.5">
        {models.map((m) => {
          const selected = value.includes(m.id)
          return (
            <button
              key={m.id}
              onClick={() => toggleModel(m.id)}
              className={`w-full text-left px-3 py-2 rounded-lg border transition-all text-xs ${
                selected
                  ? 'border-accent-blue bg-accent-blue/10'
                  : 'border-bg-card bg-bg-card/30 hover:border-bg-card/80'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-medium">{m.name}</span>
                  <span
                    className={`text-[9px] px-1 py-0.5 rounded-full font-medium ${
                      CATEGORY_COLORS[m.category] || 'bg-bg-card text-text-secondary'
                    }`}
                  >
                    {m.custom ? 'Custom' : m.category}
                  </span>
                </div>
                {selected && <Check className="w-3.5 h-3.5 text-accent-blue shrink-0" />}
              </div>
            </button>
          )
        })}
      </div>
    </div>
  )
}
