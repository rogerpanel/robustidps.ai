import { useEffect, useState, useRef } from 'react'
import { fetchModels, activateModel, enableModel, disableModel, uploadCustomModel, deleteCustomModel, benchmarkModels } from '../utils/api'
import { Brain, Check, FlaskConical, Clock, Network, Loader2, ToggleLeft, ToggleRight, Upload, Trash2, X, AlertTriangle, Sparkles, Info, Zap, BarChart3, Trophy, Cpu, ArrowRight } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

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

interface BenchmarkResult {
  model_id: string
  model_name: string
  category: string
  inference_ms?: number
  throughput?: number
  mean_confidence?: number
  std_confidence?: number
  threat_rate?: number
  n_classes_predicted?: number
  top_predictions?: Array<{ label: string; count: number }>
  class_distribution?: Record<string, number>
  error?: string
}

interface BenchmarkData {
  n_samples: number
  device: string
  results: BenchmarkResult[]
  active_model: string
}

const CATEGORY_META: Record<string, { icon: typeof Brain; color: string; label: string }> = {
  ensemble: { icon: FlaskConical, color: 'accent-blue', label: 'Ensemble' },
  temporal: { icon: Clock, color: 'accent-purple', label: 'Temporal' },
  federated: { icon: Network, color: 'accent-green', label: 'Federated' },
  foundation: { icon: Sparkles, color: 'accent-amber', label: 'Foundation' },
  clrl: { icon: Zap, color: 'accent-red', label: 'CL-RL' },
  custom: { icon: Upload, color: 'accent-red', label: 'Custom' },
}

const CAT_COLORS: Record<string, string> = {
  ensemble: '#3B82F6',
  temporal: '#A855F7',
  federated: '#22C55E',
  foundation: '#F59E0B',
  clrl: '#EF4444',
  custom: '#9CA3AF',
}

export default function Models() {
  const navigate = useNavigate()
  const [models, setModels] = useState<ModelInfo[]>([])
  const [activeModel, setActiveModel] = useState('surrogate')
  const [enabledModels, setEnabledModels] = useState<string[]>(['surrogate'])
  const [activating, setActivating] = useState<string | null>(null)
  const [toggling, setToggling] = useState<string | null>(null)

  // Benchmark
  const [benchmark, setBenchmark] = useState<BenchmarkData | null>(null)
  const [benchmarking, setBenchmarking] = useState(false)
  const [benchmarkError, setBenchmarkError] = useState('')

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

  const handleBenchmark = async () => {
    setBenchmarking(true)
    setBenchmarkError('')
    setBenchmark(null)
    try {
      const data = await benchmarkModels()
      setBenchmark(data)
    } catch (err) {
      setBenchmarkError(err instanceof Error ? err.message : 'Benchmark failed')
    }
    setBenchmarking(false)
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

  // Find fastest and highest-confidence models from benchmark
  const fastestModel = benchmark?.results?.filter(r => !r.error).sort((a, b) => (a.inference_ms ?? 999) - (b.inference_ms ?? 999))[0]
  const mostConfident = benchmark?.results?.filter(r => !r.error).sort((a, b) => (b.mean_confidence ?? 0) - (a.mean_confidence ?? 0))[0]

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-2xl font-display font-bold">Models</h1>
        <p className="text-sm text-text-secondary mt-1">
          Enable models for analysis, benchmark their performance, or upload your own custom model.
        </p>
      </div>

      {/* Info: Where models apply */}
      <div className="flex items-start gap-3 px-4 py-3 bg-accent-blue/5 border border-accent-blue/20 rounded-xl">
        <Info className="w-5 h-5 text-accent-blue shrink-0 mt-0.5" />
        <div className="text-xs text-text-secondary space-y-1">
          <p><strong className="text-text-primary">Where selected models apply:</strong></p>
          <p><span className="text-accent-blue font-medium">Upload & Analyse</span> — uses the model you select in its Settings panel. Only <strong>enabled</strong> models appear in that dropdown.</p>
          <p><span className="text-accent-blue font-medium">Live Monitor</span> — streams predictions using the active default model. Enable additional models here to compare.</p>
          <p><span className="text-accent-blue font-medium">Ablation Studio</span> — only works with the SurrogateIDS (7-branch) model.</p>
          <p><span className="text-accent-blue font-medium">Quick Benchmark</span> — runs all <strong>enabled</strong> models on synthetic data to compare speed, confidence, and threat distribution. No dataset needed.</p>
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
          const bResult = benchmark?.results?.find(r => r.model_id === m.id)

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

              {/* Benchmark inline results for this model */}
              {bResult && !bResult.error && (
                <div className="grid grid-cols-3 gap-2 mb-3 py-2 px-2 bg-bg-card/30 rounded-lg">
                  <div className="text-center">
                    <div className="text-[10px] text-text-secondary">Speed</div>
                    <div className="text-xs font-mono font-semibold text-accent-blue">
                      {bResult.inference_ms}ms
                    </div>
                  </div>
                  <div className="text-center">
                    <div className="text-[10px] text-text-secondary">Confidence</div>
                    <div className="text-xs font-mono font-semibold text-accent-green">
                      {((bResult.mean_confidence ?? 0) * 100).toFixed(1)}%
                    </div>
                  </div>
                  <div className="text-center">
                    <div className="text-[10px] text-text-secondary">Threat Rate</div>
                    <div className="text-xs font-mono font-semibold text-accent-red">
                      {((bResult.threat_rate ?? 0) * 100).toFixed(1)}%
                    </div>
                  </div>
                </div>
              )}
              {bResult?.error && (
                <div className="text-[10px] text-accent-red mb-3 px-2 py-1 bg-accent-red/5 rounded">
                  Benchmark error: {bResult.error}
                </div>
              )}

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

      {/* ═══════════════════════════════════════════════════════════════════════
          Quick Benchmark Section
          ═══════════════════════════════════════════════════════════════════════ */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-display font-semibold flex items-center gap-2">
              <Zap className="w-5 h-5 text-accent-amber" />
              Quick Benchmark
            </h2>
            <p className="text-xs text-text-secondary mt-1">
              Run all enabled models on 200 synthetic samples — compare inference speed, confidence, and threat distribution. No dataset upload needed.
            </p>
          </div>
          <button
            onClick={handleBenchmark}
            disabled={benchmarking}
            className="px-4 py-2 bg-accent-amber text-white rounded-lg text-xs font-medium hover:bg-accent-amber/80 disabled:opacity-50 flex items-center gap-2"
          >
            {benchmarking ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" /> Running...
              </>
            ) : (
              <>
                <Zap className="w-3.5 h-3.5" /> Run Benchmark
              </>
            )}
          </button>
        </div>

        {benchmarkError && (
          <div className="px-3 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-xs mb-4">
            {benchmarkError}
          </div>
        )}

        {benchmark && (
          <div className="space-y-4">
            {/* Summary cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="bg-bg-primary rounded-lg p-3 border border-bg-card text-center">
                <Cpu className="w-4 h-4 text-accent-blue mx-auto mb-1" />
                <div className="text-[10px] text-text-secondary">Device</div>
                <div className="text-sm font-mono font-semibold text-accent-blue">{benchmark.device}</div>
              </div>
              <div className="bg-bg-primary rounded-lg p-3 border border-bg-card text-center">
                <BarChart3 className="w-4 h-4 text-accent-purple mx-auto mb-1" />
                <div className="text-[10px] text-text-secondary">Models Tested</div>
                <div className="text-sm font-mono font-semibold text-accent-purple">{benchmark.results.length}</div>
              </div>
              {fastestModel && (
                <div className="bg-bg-primary rounded-lg p-3 border border-bg-card text-center">
                  <Zap className="w-4 h-4 text-accent-green mx-auto mb-1" />
                  <div className="text-[10px] text-text-secondary">Fastest</div>
                  <div className="text-xs font-semibold text-accent-green truncate">{fastestModel.model_name?.split('(')[0].trim()}</div>
                  <div className="text-[10px] font-mono text-text-secondary">{fastestModel.inference_ms}ms</div>
                </div>
              )}
              {mostConfident && (
                <div className="bg-bg-primary rounded-lg p-3 border border-bg-card text-center">
                  <Trophy className="w-4 h-4 text-accent-amber mx-auto mb-1" />
                  <div className="text-[10px] text-text-secondary">Most Confident</div>
                  <div className="text-xs font-semibold text-accent-amber truncate">{mostConfident.model_name?.split('(')[0].trim()}</div>
                  <div className="text-[10px] font-mono text-text-secondary">{((mostConfident.mean_confidence ?? 0) * 100).toFixed(1)}%</div>
                </div>
              )}
            </div>

            {/* Comparison table */}
            <div className="overflow-x-auto rounded-lg border border-bg-card">
              <table className="w-full text-sm">
                <thead className="bg-bg-card/40">
                  <tr className="text-text-secondary text-xs">
                    <th className="px-3 py-2 text-left">Model</th>
                    <th className="px-3 py-2 text-left">Category</th>
                    <th className="px-3 py-2 text-right">Inference</th>
                    <th className="px-3 py-2 text-right">Throughput</th>
                    <th className="px-3 py-2 text-right">Confidence</th>
                    <th className="px-3 py-2 text-right">Threat Rate</th>
                    <th className="px-3 py-2 text-right">Classes</th>
                    <th className="px-3 py-2 text-left">Top Predictions</th>
                  </tr>
                </thead>
                <tbody>
                  {benchmark.results.map((r) => {
                    const catColor = CAT_COLORS[r.category] || CAT_COLORS.custom
                    const isFastest = r.model_id === fastestModel?.model_id
                    const isMostConf = r.model_id === mostConfident?.model_id
                    return (
                      <tr key={r.model_id} className="border-t border-bg-card/50 hover:bg-bg-card/20">
                        <td className="px-3 py-2">
                          <div className="flex items-center gap-1.5">
                            <div className="w-2 h-2 rounded-full" style={{ background: catColor }} />
                            <span className="font-medium text-xs">{r.model_name?.split('(')[0].trim()}</span>
                            {isFastest && <Zap className="w-3 h-3 text-accent-green" title="Fastest" />}
                            {isMostConf && <Trophy className="w-3 h-3 text-accent-amber" title="Most confident" />}
                          </div>
                        </td>
                        <td className="px-3 py-2">
                          <span className="text-[10px] px-1.5 py-0.5 rounded-full font-medium" style={{ background: `${catColor}20`, color: catColor }}>
                            {r.category}
                          </span>
                        </td>
                        {r.error ? (
                          <td colSpan={6} className="px-3 py-2 text-xs text-accent-red">{r.error}</td>
                        ) : (
                          <>
                            <td className="px-3 py-2 text-right font-mono text-xs">{r.inference_ms}ms</td>
                            <td className="px-3 py-2 text-right font-mono text-xs">{r.throughput?.toLocaleString()}/s</td>
                            <td className="px-3 py-2 text-right font-mono text-xs">
                              {((r.mean_confidence ?? 0) * 100).toFixed(1)}%
                              <span className="text-text-secondary ml-1">±{((r.std_confidence ?? 0) * 100).toFixed(1)}</span>
                            </td>
                            <td className="px-3 py-2 text-right font-mono text-xs">
                              <span className={(r.threat_rate ?? 0) > 0.5 ? 'text-accent-red' : 'text-accent-green'}>
                                {((r.threat_rate ?? 0) * 100).toFixed(1)}%
                              </span>
                            </td>
                            <td className="px-3 py-2 text-right font-mono text-xs">{r.n_classes_predicted}</td>
                            <td className="px-3 py-2 text-xs text-text-secondary">
                              {r.top_predictions?.slice(0, 3).map((p) => (
                                <span key={p.label} className="inline-block mr-1.5 px-1 py-0.5 bg-bg-card rounded text-[10px]">
                                  {p.label.length > 15 ? p.label.slice(0, 13) + '..' : p.label} ({p.count})
                                </span>
                              ))}
                            </td>
                          </>
                        )}
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>

            {/* Quick actions */}
            <div className="flex flex-wrap gap-2 pt-1">
              <button
                onClick={() => navigate('/upload')}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-accent-blue bg-accent-blue/10 rounded-lg hover:bg-accent-blue/20 transition-colors"
              >
                <ArrowRight className="w-3 h-3" /> Test with real data in Upload & Analyse
              </button>
              <button
                onClick={() => navigate('/ablation')}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-accent-purple bg-accent-purple/10 rounded-lg hover:bg-accent-purple/20 transition-colors"
              >
                <FlaskConical className="w-3 h-3" /> Deep-dive in Ablation Studio
              </button>
            </div>
          </div>
        )}

        {!benchmark && !benchmarking && (
          <div className="text-center py-8 text-text-secondary">
            <Zap className="w-8 h-8 mx-auto mb-2 opacity-20" />
            <p className="text-xs">Click "Run Benchmark" to compare all enabled models. No dataset upload needed.</p>
            <p className="text-[10px] mt-1 opacity-50">
              Enable more models above to include them in the comparison.
              Currently {enabledModels.length} model{enabledModels.length !== 1 ? 's' : ''} enabled.
            </p>
          </div>
        )}
      </div>

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
                ['CL-RL Unified', '7-branch + MC Dropout + RL state', 'Unified FIM + continual adaptation', 'Live adaptive IDS with RL response'],
                ['CPO Policy', 'Constrained Policy Optimisation', '5 graduated actions + FP constraint', 'Autonomous threat response'],
                ['Value Network', 'MLP reward estimator', 'GAE advantage computation', 'RL training & evaluation'],
                ['Cost Value Net', 'MLP cost estimator', 'Lagrangian FP constraint', 'Safety-constrained response'],
                ['Unified FIM', 'Fisher Information regularisation', 'β-weighted detection + policy FIM', 'Robust continual updates'],
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
