import { useEffect, useState } from 'react'
import { fetchModels, activateModel } from '../utils/api'
import { Brain, Check, FlaskConical, Clock, Network, Loader2 } from 'lucide-react'

interface ModelInfo {
  id: string
  name: string
  description: string
  paper: string
  has_ablation: boolean
  category: string
  weights_available: boolean
}

const CATEGORY_META: Record<string, { icon: typeof Brain; color: string; label: string }> = {
  ensemble: { icon: FlaskConical, color: 'accent-blue', label: 'Ensemble' },
  temporal: { icon: Clock, color: 'accent-purple', label: 'Temporal' },
  federated: { icon: Network, color: 'accent-green', label: 'Federated' },
}

export default function Models() {
  const [models, setModels] = useState<ModelInfo[]>([])
  const [activeModel, setActiveModel] = useState('surrogate')
  const [activating, setActivating] = useState<string | null>(null)

  useEffect(() => {
    fetchModels()
      .then((data) => {
        setModels(data.models ?? [])
        setActiveModel(data.active_model ?? 'surrogate')
      })
      .catch(() => {})
  }, [])

  const handleActivate = async (modelId: string) => {
    setActivating(modelId)
    try {
      const data = await activateModel(modelId)
      setActiveModel(data.active_model)
    } catch {
      // ignore
    } finally {
      setActivating(null)
    }
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-2xl font-display font-bold">Models</h1>
        <p className="text-sm text-text-secondary mt-1">
          Browse and activate alternative detection models. Each model implements a different
          approach from the dissertation research.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {models.map((m) => {
          const meta = CATEGORY_META[m.category] || CATEGORY_META.ensemble
          const Icon = meta.icon
          const isActive = activeModel === m.id
          const isLoading = activating === m.id

          return (
            <div
              key={m.id}
              className={`bg-bg-secondary rounded-xl p-5 border transition-all ${
                isActive
                  ? `border-${meta.color} ring-1 ring-${meta.color}/30`
                  : 'border-bg-card'
              }`}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div className={`p-1.5 rounded-lg bg-${meta.color}/15`}>
                    <Icon className={`w-4 h-4 text-${meta.color}`} />
                  </div>
                  <div>
                    <h3 className="text-sm font-display font-semibold">{m.name}</h3>
                    <span
                      className={`text-[10px] px-1.5 py-0.5 rounded-full font-medium bg-${meta.color}/15 text-${meta.color}`}
                    >
                      {meta.label}
                    </span>
                  </div>
                </div>
                {isActive && (
                  <span className="flex items-center gap-1 text-xs text-accent-green bg-accent-green/10 px-2 py-1 rounded-full">
                    <Check className="w-3 h-3" /> Active
                  </span>
                )}
              </div>

              <p className="text-xs text-text-secondary mb-2">{m.description}</p>

              <div className="text-[11px] font-mono text-text-secondary bg-bg-card/50 px-2 py-1 rounded mb-3">
                {m.paper}
              </div>

              <div className="flex items-center justify-between">
                <div className="flex gap-2">
                  {m.has_ablation && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-accent-amber/15 text-accent-amber">
                      Ablation
                    </span>
                  )}
                  <span
                    className={`text-[10px] px-1.5 py-0.5 rounded ${
                      m.weights_available
                        ? 'bg-accent-green/15 text-accent-green'
                        : 'bg-accent-red/15 text-accent-red'
                    }`}
                  >
                    {m.weights_available ? 'Weights ready' : 'No weights'}
                  </span>
                </div>

                {!isActive && m.weights_available && (
                  <button
                    onClick={() => handleActivate(m.id)}
                    disabled={isLoading}
                    className="px-3 py-1.5 bg-accent-blue text-white rounded-lg text-xs font-medium hover:bg-accent-blue/80 disabled:opacity-50 flex items-center gap-1.5"
                  >
                    {isLoading ? (
                      <>
                        <Loader2 className="w-3 h-3 animate-spin" /> Loading...
                      </>
                    ) : (
                      'Activate'
                    )}
                  </button>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {models.length === 0 && (
        <div className="text-center py-12 text-text-secondary">
          <Brain className="w-10 h-10 mx-auto mb-3 opacity-30" />
          <p className="text-sm">No models loaded. Is the backend running?</p>
        </div>
      )}

      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold mb-3">Model Architecture Comparison</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-text-secondary text-xs">
                <th className="px-3 py-2 text-left">Model</th>
                <th className="px-3 py-2 text-left">Approach</th>
                <th className="px-3 py-2 text-left">Key Innovation</th>
                <th className="px-3 py-2 text-left">Best For</th>
              </tr>
            </thead>
            <tbody>
              {[
                ['SurrogateIDS', '7-branch MLP ensemble', 'Ablation support for all 7 methods', 'Demo & ablation studies'],
                ['Neural ODE', 'Continuous-time ODE + point process', 'Temporal Adaptive Batch Norm', 'Non-stationary attack dynamics'],
                ['Optimal Transport', 'Wasserstein domain adaptation', 'DP-preserving multi-cloud transfer', 'Cross-cloud deployment'],
                ['FedGTD', 'Graph + federated + game-theoretic', 'Byzantine-resilient aggregation', 'Distributed multi-org IDS'],
                ['SDE-TGNN', 'Stochastic DE + temporal GNN', 'Drift-diffusion uncertainty', 'Noisy network environments'],
              ].map(([name, approach, innovation, best]) => (
                <tr key={name} className="border-t border-bg-card/50">
                  <td className="px-3 py-2 font-medium text-accent-blue">{name}</td>
                  <td className="px-3 py-2 text-text-secondary text-xs">{approach}</td>
                  <td className="px-3 py-2 text-text-secondary text-xs">{innovation}</td>
                  <td className="px-3 py-2 text-text-secondary text-xs">{best}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
