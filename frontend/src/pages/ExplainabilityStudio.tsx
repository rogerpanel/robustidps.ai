import {
  Eye, Upload, Loader2, BarChart3, Layers, Zap, Brain,
  ChevronDown, ChevronUp, Target, TrendingUp,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid, Legend, Cell,
} from 'recharts'
import FileUpload from '../components/FileUpload'
import ModelSelector from '../components/ModelSelector'
import PageGuide from '../components/PageGuide'
import { runXai, fetchSampleData } from '../utils/api'
import { usePageState } from '../hooks/usePageState'

const PAGE = 'xai'

const TT = { background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }

const METHOD_OPTS = [
  { id: 'all', label: 'All Methods', desc: 'Run saliency, integrated gradients, and sensitivity analysis' },
  { id: 'saliency', label: 'Gradient Saliency', desc: 'Gradient-based feature importance' },
  { id: 'integrated_gradients', label: 'Integrated Gradients', desc: 'Path-integrated attribution' },
  { id: 'sensitivity', label: 'Sensitivity Analysis', desc: 'Feature perturbation impact' },
]

const GRADIENT_COLORS = [
  '#EF4444', '#F97316', '#F59E0B', '#EAB308', '#84CC16',
  '#22C55E', '#14B8A6', '#06B6D4', '#3B82F6', '#6366F1',
  '#8B5CF6', '#A855F7', '#D946EF', '#EC4899', '#F43F5E',
  '#64748B', '#475569', '#334155', '#1E293B', '#0F172A',
]

interface FeatureEntry {
  index: number
  name: string
  importance?: number
  attribution?: number
  max_flip_rate?: number
  detail?: { epsilon: number; flip_rate: number }[]
}

interface XaiResult {
  xai_id: string
  n_samples: number
  method: string
  feature_names: string[]
  class_names: string[]
  prediction_summary: { accuracy: number; mean_confidence: number }
  saliency?: {
    global_importance: FeatureEntry[]
    per_class_importance: Record<string, FeatureEntry[]>
    heatmap: number[]
  }
  integrated_gradients?: {
    global_attribution: FeatureEntry[]
    heatmap: number[]
  }
  sensitivity?: {
    top_sensitive_features: FeatureEntry[]
  }
  model_used: string
  time_ms: number
}

export default function ExplainabilityStudio() {
  const [file, setFile] = usePageState<File | null>(PAGE, 'file', null)
  const [selectedModel, setSelectedModel] = usePageState(PAGE, 'selectedModel', 'surrogate')
  const [method, setMethod] = usePageState(PAGE, 'method', 'all')
  const [nSamples, setNSamples] = usePageState(PAGE, 'nSamples', 200)
  const [running, setRunning] = usePageState(PAGE, 'running', false)
  const [result, setResult] = usePageState<XaiResult | null>(PAGE, 'result', null)
  const [error, setError] = usePageState(PAGE, 'error', '')
  const [activeTab, setActiveTab] = usePageState<'saliency' | 'ig' | 'sensitivity'>(PAGE, 'activeTab', 'saliency')
  const [expandedClass, setExpandedClass] = usePageState<string | null>(PAGE, 'expandedClass', null)

  const handleRun = async () => {
    if (!file) return
    setRunning(true)
    setError('')
    setResult(null)
    try {
      const data = await runXai(file, method, nSamples, selectedModel)
      setResult(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'XAI analysis failed')
    } finally {
      setRunning(false)
    }
  }

  const saliencyData = result?.saliency?.global_importance?.slice(0, 15).map(f => ({
    name: f.name.length > 18 ? f.name.slice(0, 16) + '…' : f.name,
    fullName: f.name,
    importance: Math.round((f.importance || 0) * 1000) / 10,
  })) || []

  const igData = result?.integrated_gradients?.global_attribution?.slice(0, 15).map(f => ({
    name: f.name.length > 18 ? f.name.slice(0, 16) + '…' : f.name,
    fullName: f.name,
    attribution: Math.round((f.attribution || 0) * 1000) / 10,
  })) || []

  const sensData = result?.sensitivity?.top_sensitive_features?.slice(0, 15).map(f => ({
    name: f.name.length > 18 ? f.name.slice(0, 16) + '…' : f.name,
    fullName: f.name,
    max_flip: Math.round((f.max_flip_rate || 0) * 1000) / 10,
  })) || []

  return (
    <div className="space-y-6">
      <PageGuide
        title="How to use Explainability Studio"
        steps={[
          { title: 'Upload a dataset', desc: 'Drop a network traffic CSV for analysis.' },
          { title: 'Choose method', desc: 'Select gradient saliency, integrated gradients, sensitivity, or all.' },
          { title: 'Run analysis', desc: 'The XAI engine computes feature attributions and sensitivity.' },
          { title: 'Explore results', desc: 'View global and per-class feature importance rankings.' },
        ]}
        tip="Explainability helps you understand WHY the model flags traffic as malicious — critical for SOC trust and compliance."
      />

      {/* Header */}
      <div className="flex items-center gap-3">
        <Eye className="w-7 h-7 text-accent-purple" />
        <div>
          <h1 className="text-xl md:text-2xl font-display font-bold">Explainability Studio</h1>
          <p className="text-sm text-text-secondary mt-0.5">Understand why the model makes its decisions</p>
        </div>
      </div>

      {/* Config Panel */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-3">
            <FileUpload
              onFile={(f) => setFile(f)}
              label="Upload traffic dataset"
              accept=".csv,.parquet"
            />
            <button
              onClick={async () => {
                try {
                  const f = await fetchSampleData()
                  setFile(f)
                } catch { setError('Failed to load demo data') }
              }}
              className="text-xs text-accent-purple hover:text-accent-purple/80 underline"
            >
              or use built-in demo data (1000 flows)
            </button>
            {file && (
              <div className="text-xs text-text-secondary flex items-center gap-1">
                <Upload className="w-3 h-3" /> {file.name}
              </div>
            )}
            <ModelSelector value={selectedModel} onChange={setSelectedModel} />
          </div>

          <div className="space-y-3">
            <div>
              <label className="text-xs text-text-secondary block mb-2">XAI Method</label>
              <div className="flex flex-wrap gap-2">
                {METHOD_OPTS.map(m => (
                  <button
                    key={m.id}
                    onClick={() => setMethod(m.id)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                      method === m.id
                        ? 'bg-accent-purple/15 border-accent-purple/40 text-accent-purple'
                        : 'bg-bg-primary border-bg-card text-text-secondary hover:text-text-primary'
                    }`}
                    title={m.desc}
                  >
                    {m.label}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="text-xs text-text-secondary block mb-1">Max samples</label>
              <input
                type="number" min={50} max={2000} step={50}
                value={nSamples}
                onChange={e => setNSamples(parseInt(e.target.value) || 200)}
                className="w-24 px-2 py-1 bg-bg-primary border border-bg-card rounded text-sm text-text-primary"
              />
            </div>
          </div>
        </div>

        <button
          onClick={handleRun}
          disabled={!file || running}
          className="px-5 py-2.5 bg-accent-purple text-white rounded-lg text-sm font-medium hover:bg-accent-purple/80 transition-colors disabled:opacity-40 flex items-center gap-2"
        >
          {running ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Analysing...
            </>
          ) : (
            <>
              <Eye className="w-4 h-4" />
              Run XAI Analysis
            </>
          )}
        </button>

        {error && (
          <div className="px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">
            {error}
          </div>
        )}
      </div>

      {/* Results */}
      {result && (
        <>
          {/* Summary */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Target className="w-3.5 h-3.5" /> Accuracy
              </div>
              <div className="text-xl font-mono font-bold text-accent-green">
                {(result.prediction_summary.accuracy * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <TrendingUp className="w-3.5 h-3.5" /> Confidence
              </div>
              <div className="text-xl font-mono font-bold text-accent-blue">
                {(result.prediction_summary.mean_confidence * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Layers className="w-3.5 h-3.5" /> Features
              </div>
              <div className="text-xl font-mono font-bold text-text-primary">
                {result.feature_names.length}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Zap className="w-3.5 h-3.5" /> Time
              </div>
              <div className="text-xl font-mono font-bold text-accent-amber">
                {(result.time_ms / 1000).toFixed(1)}s
              </div>
            </div>
          </div>

          {/* Tab selector */}
          <div className="flex gap-1 bg-bg-secondary rounded-lg p-1 border border-bg-card w-fit">
            {[
              { key: 'saliency' as const, label: 'Gradient Saliency', icon: BarChart3, show: !!result.saliency },
              { key: 'ig' as const, label: 'Integrated Gradients', icon: Layers, show: !!result.integrated_gradients },
              { key: 'sensitivity' as const, label: 'Sensitivity', icon: Zap, show: !!result.sensitivity },
            ].filter(t => t.show).map(t => (
              <button
                key={t.key}
                onClick={() => setActiveTab(t.key)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  activeTab === t.key
                    ? 'bg-accent-purple/15 text-accent-purple'
                    : 'text-text-secondary hover:text-text-primary'
                }`}
              >
                <t.icon className="w-3.5 h-3.5" />
                {t.label}
              </button>
            ))}
          </div>

          {/* Saliency Tab */}
          {activeTab === 'saliency' && result.saliency && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                <h3 className="text-sm font-semibold mb-3">Top Features (Gradient Saliency)</h3>
                <ResponsiveContainer width="100%" height={400}>
                  <BarChart data={saliencyData} layout="vertical" margin={{ left: 10 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis type="number" tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" />
                    <YAxis dataKey="name" type="category" tick={{ fill: '#94A3B8', fontSize: 10 }} width={120} />
                    <Tooltip contentStyle={TT} formatter={(v: number) => `${v}%`} />
                    <Bar dataKey="importance" radius={[0, 4, 4, 0]}>
                      {saliencyData.map((_, i) => (
                        <Cell key={i} fill={GRADIENT_COLORS[i % GRADIENT_COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>

              {/* Per-class breakdown */}
              <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                <h3 className="text-sm font-semibold mb-3">Per-Class Feature Importance</h3>
                <div className="space-y-1 max-h-[420px] overflow-y-auto">
                  {Object.entries(result.saliency.per_class_importance || {}).slice(0, 15).map(([cls, features]) => (
                    <div key={cls} className="border border-bg-card rounded-lg overflow-hidden">
                      <button
                        onClick={() => setExpandedClass(expandedClass === cls ? null : cls)}
                        className="w-full px-3 py-2 flex items-center gap-2 text-xs hover:bg-bg-card/30 transition-colors"
                      >
                        <span className="flex-1 text-left font-medium truncate">{cls}</span>
                        {expandedClass === cls ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                      </button>
                      {expandedClass === cls && (
                        <div className="px-3 pb-2 space-y-1">
                          {features.slice(0, 8).map((f, i) => (
                            <div key={f.index} className="flex items-center gap-2 text-xs">
                              <span className="w-4 text-text-secondary">{i + 1}</span>
                              <span className="flex-1 truncate text-text-secondary">{f.name}</span>
                              <div className="w-20 bg-bg-primary rounded-full h-1.5">
                                <div
                                  className="h-1.5 rounded-full bg-accent-purple"
                                  style={{ width: `${(f.importance || 0) * 100}%` }}
                                />
                              </div>
                              <span className="font-mono text-accent-purple w-12 text-right">
                                {((f.importance || 0) * 100).toFixed(0)}%
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Integrated Gradients Tab */}
          {activeTab === 'ig' && result.integrated_gradients && (
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h3 className="text-sm font-semibold mb-3">Top Features (Integrated Gradients)</h3>
              <ResponsiveContainer width="100%" height={400}>
                <BarChart data={igData} layout="vertical" margin={{ left: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis type="number" tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" />
                  <YAxis dataKey="name" type="category" tick={{ fill: '#94A3B8', fontSize: 10 }} width={120} />
                  <Tooltip contentStyle={TT} formatter={(v: number) => `${v}%`} />
                  <Bar dataKey="attribution" radius={[0, 4, 4, 0]}>
                    {igData.map((_, i) => (
                      <Cell key={i} fill={GRADIENT_COLORS[i % GRADIENT_COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Sensitivity Tab */}
          {activeTab === 'sensitivity' && result.sensitivity && (
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h3 className="text-sm font-semibold mb-3">Most Sensitive Features</h3>
              <ResponsiveContainer width="100%" height={400}>
                <BarChart data={sensData} layout="vertical" margin={{ left: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis type="number" tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" domain={[0, 'auto']} />
                  <YAxis dataKey="name" type="category" tick={{ fill: '#94A3B8', fontSize: 10 }} width={120} />
                  <Tooltip contentStyle={TT} formatter={(v: number) => `${v}%`} />
                  <Bar dataKey="max_flip" name="Max Flip Rate" radius={[0, 4, 4, 0]}>
                    {sensData.map((_, i) => (
                      <Cell key={i} fill={i < 5 ? '#EF4444' : i < 10 ? '#F59E0B' : '#22C55E'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
              <p className="text-xs text-text-secondary mt-2">
                Features with high flip rate are decision-critical — small perturbations change predictions.
              </p>
            </div>
          )}

          {/* Feature heatmap strip */}
          {result.saliency?.heatmap && (
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h3 className="text-sm font-semibold mb-3">Feature Importance Heatmap</h3>
              <div className="flex gap-px rounded overflow-hidden h-6">
                {result.saliency.heatmap.map((val, i) => {
                  const max = Math.max(...result.saliency!.heatmap)
                  const intensity = max > 0 ? val / max : 0
                  return (
                    <div
                      key={i}
                      className="flex-1 min-w-[2px]"
                      style={{
                        backgroundColor: `rgba(168, 85, 247, ${0.05 + intensity * 0.95})`,
                      }}
                      title={`${result.feature_names[i] || `f${i}`}: ${(intensity * 100).toFixed(0)}%`}
                    />
                  )
                })}
              </div>
              <div className="flex justify-between text-[10px] text-text-secondary mt-1">
                <span>Feature 0</span>
                <span>Low → High importance</span>
                <span>Feature {result.saliency.heatmap.length - 1}</span>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
