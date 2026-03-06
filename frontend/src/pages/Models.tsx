import { useEffect, useState, useRef } from 'react'
import { fetchModels, activateModel, enableModel, disableModel, uploadCustomModel, deleteCustomModel } from '../utils/api'
import { Brain, Check, FlaskConical, Clock, Network, Loader2, ToggleLeft, ToggleRight, Upload, Trash2, X, AlertTriangle, Sparkles, Info } from 'lucide-react'

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
  uploaded_by?: string
}

const CATEGORY_META: Record<string, { icon: typeof Brain; color: string; label: string }> = {
  ensemble: { icon: FlaskConical, color: 'accent-blue', label: 'Ensemble' },
  temporal: { icon: Clock, color: 'accent-purple', label: 'Temporal' },
  federated: { icon: Network, color: 'accent-green', label: 'Federated' },
  foundation: { icon: Sparkles, color: 'accent-amber', label: 'Foundation' },
  custom: { icon: Upload, color: 'accent-red', label: 'Custom' },
}

export default function Models() {
  const [models, setModels] = useState<ModelInfo[]>([])
  const [activeModel, setActiveModel] = useState('surrogate')
  const [enabledModels, setEnabledModels] = useState<string[]>(['surrogate'])
  const [activating, setActivating] = useState<string | null>(null)
  const [toggling, setToggling] = useState<string | null>(null)

  // Custom model upload
  const [showUpload, setShowUpload] = useState(false)
  const [customName, setCustomName] = useState('')
  const [customFile, setCustomFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadError, setUploadError] = useState('')
  const [uploadSuccess, setUploadSuccess] = useState('')
  const [deletingCustom, setDeletingCustom] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const loadModels = () => {
    fetchModels()
      .then((data) => {
        setModels(data.models ?? [])
        setActiveModel(data.active_model ?? 'surrogate')
        setEnabledModels(data.enabled_models ?? ['surrogate'])
      })
      .catch(() => {})
  }

  useEffect(() => { loadModels() }, [])

  const handleActivate = async (modelId: string) => {
    setActivating(modelId)
    try {
      const data = await activateModel(modelId)
      setActiveModel(data.active_model)
    } catch {}
    setActivating(null)
  }

  const handleToggle = async (modelId: string, currentlyEnabled: boolean) => {
    setToggling(modelId)
    try {
      if (currentlyEnabled) {
        const data = await disableModel(modelId)
        setEnabledModels(data.enabled_models)
      } else {
        const data = await enableModel(modelId)
        setEnabledModels(data.enabled_models)
      }
    } catch {}
    setToggling(null)
  }

  const handleCustomUpload = async () => {
    if (!customFile) return
    setUploading(true)
    setUploadError('')
    setUploadSuccess('')
    try {
      const data = await uploadCustomModel(customFile, customName)
      setUploadSuccess(data.message || 'Model uploaded successfully')
      setCustomFile(null)
      setCustomName('')
      if (fileRef.current) fileRef.current.value = ''
      loadModels()
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : 'Upload failed')
    }
    setUploading(false)
  }

  const handleDeleteCustom = async (modelId: string) => {
    setDeletingCustom(modelId)
    try {
      await deleteCustomModel(modelId)
      loadModels()
    } catch {}
    setDeletingCustom(null)
  }

  const builtInModels = models.filter((m) => !m.custom)
  const customModels = models.filter((m) => m.custom)

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-2xl font-display font-bold">Models</h1>
        <p className="text-sm text-text-secondary mt-1">
          Enable models for analysis, activate a default, or upload your own custom model for testing.
        </p>
      </div>

      {/* Info: Where models apply */}
      <div className="flex items-start gap-3 px-4 py-3 bg-accent-blue/5 border border-accent-blue/20 rounded-xl">
        <Info className="w-5 h-5 text-accent-blue shrink-0 mt-0.5" />
        <div className="text-xs text-text-secondary space-y-1">
          <p><strong className="text-text-primary">Where selected models apply:</strong></p>
          <p><span className="text-accent-blue font-medium">Upload & Analyse</span> — uses the model you select in its Settings panel. Only <strong>enabled</strong> models appear in that dropdown.</p>
          <p><span className="text-accent-blue font-medium">Default model</span> (star icon) — pre-selected when you open Upload & Analyse. Click "Set Default" to change it.</p>
          <p><span className="text-accent-blue font-medium">Ablation Studio</span> — only works with the SurrogateIDS (7-branch) model.</p>
          <p><span className="text-accent-blue font-medium">SOC Copilot</span> — reads results from completed analysis jobs (whichever model was used).</p>
        </div>
      </div>

      {/* Built-in models */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {builtInModels.map((m) => {
          const meta = CATEGORY_META[m.category] || CATEGORY_META.ensemble
          const Icon = meta.icon
          const isActive = activeModel === m.id
          const isEnabled = enabledModels.includes(m.id)
          const isLoading = activating === m.id
          const isToggling = toggling === m.id
          const isSurrogate = m.id === 'surrogate'

          return (
            <div
              key={m.id}
              className={`bg-bg-secondary rounded-xl p-5 border transition-all ${
                isActive
                  ? `border-${meta.color} ring-1 ring-${meta.color}/30`
                  : isEnabled
                  ? 'border-accent-green/30'
                  : 'border-bg-card opacity-60'
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
                <div className="flex items-center gap-1.5">
                  {isActive && (
                    <span className="flex items-center gap-1 text-xs text-accent-green bg-accent-green/10 px-2 py-1 rounded-full">
                      <Check className="w-3 h-3" /> Default
                    </span>
                  )}
                </div>
              </div>

              <p className="text-xs text-text-secondary mb-2">{m.description}</p>

              <div className="text-[11px] font-mono text-text-secondary bg-bg-card/50 px-2 py-1 rounded mb-3">
                {m.paper}
              </div>

              <div className="flex items-center justify-between">
                <div className="flex gap-2 items-center">
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

                <div className="flex items-center gap-2">
                  {/* Enable/Disable toggle */}
                  {!isSurrogate && m.weights_available && (
                    <button
                      onClick={() => handleToggle(m.id, isEnabled)}
                      disabled={isToggling}
                      className={`flex items-center gap-1 px-2 py-1 rounded-lg text-[10px] font-medium transition-colors ${
                        isEnabled
                          ? 'text-accent-green hover:bg-accent-green/10'
                          : 'text-text-secondary hover:bg-bg-card'
                      }`}
                      title={isEnabled ? 'Disable (hide from Upload selector)' : 'Enable (show in Upload selector)'}
                    >
                      {isToggling ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : isEnabled ? (
                        <ToggleRight className="w-4 h-4" />
                      ) : (
                        <ToggleLeft className="w-4 h-4" />
                      )}
                      {isEnabled ? 'Enabled' : 'Disabled'}
                    </button>
                  )}

                  {/* Set as default */}
                  {!isActive && isEnabled && m.weights_available && (
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
                        'Set Default'
                      )}
                    </button>
                  )}
                </div>
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

      {/* Custom Models Section */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-display font-semibold flex items-center gap-2">
              <Upload className="w-5 h-5 text-accent-amber" />
              Custom Models
            </h2>
            <p className="text-xs text-text-secondary mt-1">
              Upload your own trained PyTorch model (.pt/.pth) to test on your datasets. Models are temporary and can be discarded after use.
            </p>
          </div>
          <button
            onClick={() => setShowUpload(!showUpload)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              showUpload
                ? 'bg-bg-card text-text-secondary'
                : 'bg-accent-blue text-white hover:bg-accent-blue/80'
            }`}
          >
            {showUpload ? 'Cancel' : 'Upload Model'}
          </button>
        </div>

        {/* Upload form */}
        {showUpload && (
          <div className="mb-4 p-4 bg-bg-primary rounded-lg border border-bg-card space-y-3">
            <div className="flex items-start gap-2 text-xs text-accent-amber">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <p>
                Model must be a PyTorch <code className="bg-bg-card px-1 rounded">state_dict</code> saved
                with <code className="bg-bg-card px-1 rounded">torch.save(model.state_dict(), path)</code>.
                Expected input: <strong>[batch, 83]</strong> features, output: <strong>[batch, 34]</strong> class logits.
              </p>
            </div>

            <div>
              <label className="text-xs text-text-secondary block mb-1">Model Name</label>
              <input
                type="text"
                value={customName}
                onChange={(e) => setCustomName(e.target.value)}
                placeholder="e.g. My Custom IDS v2"
                className="w-full px-3 py-2 bg-bg-secondary border border-bg-card rounded-lg text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-blue/50"
              />
            </div>

            <div>
              <label className="text-xs text-text-secondary block mb-1">Model File (.pt / .pth)</label>
              <input
                ref={fileRef}
                type="file"
                accept=".pt,.pth"
                onChange={(e) => setCustomFile(e.target.files?.[0] || null)}
                className="w-full text-sm text-text-secondary file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-medium file:bg-accent-blue/15 file:text-accent-blue hover:file:bg-accent-blue/25 cursor-pointer"
              />
            </div>

            {uploadError && (
              <div className="px-3 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-xs">
                {uploadError}
              </div>
            )}

            {uploadSuccess && (
              <div className="px-3 py-2 bg-accent-green/10 border border-accent-green/30 rounded-lg text-accent-green text-xs">
                {uploadSuccess}
              </div>
            )}

            <button
              onClick={handleCustomUpload}
              disabled={!customFile || uploading}
              className="px-4 py-2 bg-accent-blue text-white rounded-lg text-xs font-medium hover:bg-accent-blue/80 disabled:opacity-50 flex items-center gap-2"
            >
              {uploading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" /> Validating & Uploading...
                </>
              ) : (
                <>
                  <Upload className="w-3.5 h-3.5" /> Upload & Validate
                </>
              )}
            </button>
          </div>
        )}

        {/* Custom models list */}
        {customModels.length > 0 ? (
          <div className="space-y-2">
            {customModels.map((m) => (
              <div key={m.id} className="flex items-center justify-between px-4 py-3 bg-bg-primary rounded-lg border border-bg-card">
                <div className="flex items-center gap-3">
                  <div className="p-1.5 rounded-lg bg-accent-amber/15">
                    <Upload className="w-4 h-4 text-accent-amber" />
                  </div>
                  <div>
                    <div className="text-sm font-medium text-text-primary">{m.name}</div>
                    <div className="text-[10px] text-text-secondary">
                      {m.uploaded_by && `Uploaded by ${m.uploaded_by}`}
                      {m.id && <span className="ml-2 opacity-50">ID: {m.id}</span>}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {enabledModels.includes(m.id) && (
                    <span className="text-[10px] text-accent-green px-1.5 py-0.5 rounded bg-accent-green/10">
                      Enabled
                    </span>
                  )}
                  {activeModel === m.id && (
                    <span className="text-[10px] text-accent-blue px-1.5 py-0.5 rounded bg-accent-blue/10">
                      Default
                    </span>
                  )}
                  {!enabledModels.includes(m.id) && (
                    <button
                      onClick={() => handleToggle(m.id, false)}
                      className="px-2 py-1 text-[10px] text-accent-green hover:bg-accent-green/10 rounded transition-colors"
                    >
                      Enable
                    </button>
                  )}
                  <button
                    onClick={() => handleDeleteCustom(m.id)}
                    disabled={deletingCustom === m.id}
                    className="flex items-center gap-1 px-2.5 py-1.5 text-xs text-accent-red hover:bg-accent-red/10 rounded-lg transition-colors"
                  >
                    {deletingCustom === m.id ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Trash2 className="w-3.5 h-3.5" />
                    )}
                    Discard
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-6 text-text-secondary">
            <Upload className="w-8 h-8 mx-auto mb-2 opacity-20" />
            <p className="text-xs">No custom models uploaded yet</p>
          </div>
        )}
      </div>

      {/* Architecture comparison table */}
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
                ['CyberSecLLM', 'Mamba SSM + CrossAttn + MoE', 'Foundation model on all 6 datasets', 'Maximum accuracy & transfer'],
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
