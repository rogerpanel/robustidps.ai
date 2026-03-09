import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import FileUpload from '../components/FileUpload'
import ThreatTable from '../components/ThreatTable'
import UncertaintyChart from '../components/UncertaintyChart'
import ConfusionMatrix from '../components/ConfusionMatrix'
import ModelSelector from '../components/ModelSelector'
import ModelAnalyticsPanel from '../components/ModelAnalyticsPanel'
import { useAnalysis } from '../hooks/useAnalysis'
import { useAblation } from '../hooks/useAblation'
import PageGuide from '../components/PageGuide'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { Loader2, Database, AlertTriangle, Trash2, X, Radio, Upload as UploadIcon, ChevronDown, ChevronUp, TrendingUp, FlaskConical, ToggleRight, ToggleLeft, TrendingDown, Brain, Shield, FolderOpen } from 'lucide-react'
import { fetchDatasets, fetchSampleData, type DatasetMeta } from '../utils/api'

interface DatasetInfo {
  total_rows: number
  analysed_rows: number
  sampled: boolean
  format: string
  columns: string[]
}

function DatasetSummary({ info, fileName }: { info: DatasetInfo; fileName: string | null }) {
  return (
    <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
      <h3 className="text-sm font-medium text-text-secondary mb-3 flex items-center gap-2">
        <Database className="w-4 h-4" /> Dataset Summary
      </h3>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 md:gap-4">
        <div>
          <div className="text-xs text-text-secondary">File</div>
          <div className="text-sm font-mono text-text-primary truncate">
            {fileName || 'Unknown'}
          </div>
        </div>
        <div>
          <div className="text-xs text-text-secondary">Format Detected</div>
          <div className="text-sm font-medium text-accent-blue">{info.format}</div>
        </div>
        <div>
          <div className="text-xs text-text-secondary">Total Rows</div>
          <div className="text-sm font-mono text-text-primary">
            {info.total_rows.toLocaleString()}
          </div>
        </div>
        <div>
          <div className="text-xs text-text-secondary">Rows Analysed</div>
          <div className="text-sm font-mono text-text-primary">
            {info.analysed_rows.toLocaleString()}
            {info.sampled && (
              <span className="ml-1 text-xs text-accent-yellow">(sampled)</span>
            )}
          </div>
        </div>
      </div>
      {info.sampled && (
        <div className="mt-3 flex items-center gap-2 text-xs text-accent-yellow">
          <AlertTriangle className="w-3.5 h-3.5" />
          Large dataset: {info.analysed_rows.toLocaleString()} rows randomly sampled from {info.total_rows.toLocaleString()} for analysis
        </div>
      )}
    </div>
  )
}

const BRANCH_NAMES = [
  'CT-TGNN (Neural ODE)',
  'TripleE-TGNN (Multi-scale)',
  'FedLLM-API (Zero-shot)',
  'PQ-IDPS (Post-quantum)',
  'MambaShield (State-space)',
  'Stochastic Transformer',
  'Game-Theoretic Defence',
]

export default function UploadPage() {
  const navigate = useNavigate()
  const ablation = useAblation()
  const [mcPasses, setMcPasses] = useState(20)
  const [selectedModel, setSelectedModel] = useState(ablation.selectedModel || 'surrogate')
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [showModelAnalytics, setShowModelAnalytics] = useState(true)
  const [showAblation, setShowAblation] = useState(true)
  const [showDatasets, setShowDatasets] = useState(true)
  const [datasets, setDatasets] = useState<DatasetMeta[]>([])
  const [loadingDataset, setLoadingDataset] = useState<string | null>(null)
  const { loading, results, error, fileName, jobId, source, runAnalysis, deleteJob } = useAnalysis()

  // Sync model selection from Ablation Studio
  useEffect(() => {
    if (ablation.selectedModel && ablation.selectedModel !== selectedModel) {
      setSelectedModel(ablation.selectedModel)
    }
  }, [ablation.selectedModel]) // eslint-disable-line react-hooks/exhaustive-deps

  // Fetch available datasets on mount
  useEffect(() => {
    fetchDatasets()
      .then((data) => setDatasets(data.datasets || []))
      .catch(() => {})
  }, [])

  const handleUpload = (file: File) => {
    runAnalysis(file, mcPasses, selectedModel)
  }

  const handleDelete = async () => {
    setDeleting(true)
    await deleteJob()
    setDeleting(false)
    setShowDeleteConfirm(false)
  }

  const predictions = (results?.predictions ?? []) as Array<Record<string, unknown>>
  const datasetInfo = results?.dataset_info as DatasetInfo | undefined
  const perClass = (results?.per_class_metrics ?? {}) as Record<
    string,
    { precision: number; recall: number; f1: number }
  >
  const perClassData = Object.entries(perClass)
    .filter(([, m]) => m != null)
    .map(([label, m]) => ({
      label: label.length > 18 ? label.slice(0, 16) + '..' : label,
      precision: +((m.precision ?? 0) * 100).toFixed(1),
      recall: +((m.recall ?? 0) * 100).toFixed(1),
      f1: +((m.f1 ?? 0) * 100).toFixed(1),
    }))

  return (
    <div className="space-y-6">
      <h1 className="text-xl md:text-2xl font-display font-bold">Upload & Analyse</h1>

      <PageGuide
        title="How to use Upload & Analyse"
        steps={[
          { title: 'Choose a dataset', desc: 'Drag & drop a CSV (CIC-IoT-2023, CSE-CIC-IDS2018, UNSW-NB15) or PCAP file. The format is auto-detected.' },
          { title: 'Adjust settings', desc: 'Select a model and set MC Dropout passes (fewer = faster, more = more precise uncertainty). Default: 20 passes.' },
          { title: 'Wait for analysis', desc: 'The backend runs multiple forward passes for uncertainty quantification. Large datasets (>10K rows) are automatically sampled.' },
          { title: 'Review results', desc: 'See the Dataset Summary, Threat Table, Uncertainty Chart, Confusion Matrix (if ground-truth labels exist), and Per-Class Metrics.' },
        ]}
        tip="Supported benchmarks: CIC-IoT-2023 (46 features), CSE-CIC-IDS2018 (79 features), UNSW-NB15 (49 features). Any CSV with numeric columns will also work as generic format."
      />

      {/* Sample Datasets Panel */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <button
          onClick={() => setShowDatasets(!showDatasets)}
          className="w-full flex items-center justify-between text-sm font-medium text-text-primary"
        >
          <span className="flex items-center gap-2">
            <FolderOpen className="w-4 h-4 text-accent-purple" />
            Sample Datasets
            {datasets.length > 0 && (
              <span className="text-xs bg-accent-purple/15 text-accent-purple px-2 py-0.5 rounded-full">
                {datasets.length}
              </span>
            )}
          </span>
          {showDatasets ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>
        {showDatasets && (
          <div className="mt-4 space-y-3">
            {/* Quick-load buttons */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <button
                onClick={async () => {
                  setLoadingDataset('pqc');
                  try {
                    const file = await fetchSampleData('pqc');
                    handleUpload(file);
                  } catch { /* ignore */ }
                  setLoadingDataset(null);
                }}
                disabled={loading || loadingDataset !== null}
                className="flex items-center gap-2 px-3 py-2.5 rounded-lg border border-accent-purple/30 bg-accent-purple/5 hover:bg-accent-purple/15 text-sm transition-colors disabled:opacity-50"
              >
                {loadingDataset === 'pqc' ? <Loader2 className="w-4 h-4 animate-spin text-accent-purple" /> : <Shield className="w-4 h-4 text-accent-purple" />}
                <div className="text-left">
                  <div className="font-medium text-text-primary">PQC Test Dataset</div>
                  <div className="text-[10px] text-text-secondary">5K flows | Kyber + attacks | ~4 MB</div>
                </div>
              </button>
              <button
                onClick={async () => {
                  setLoadingDataset('ciciot');
                  try {
                    const file = await fetchSampleData('ciciot');
                    handleUpload(file);
                  } catch { /* ignore */ }
                  setLoadingDataset(null);
                }}
                disabled={loading || loadingDataset !== null}
                className="flex items-center gap-2 px-3 py-2.5 rounded-lg border border-accent-blue/30 bg-accent-blue/5 hover:bg-accent-blue/15 text-sm transition-colors disabled:opacity-50"
              >
                {loadingDataset === 'ciciot' ? <Loader2 className="w-4 h-4 animate-spin text-accent-blue" /> : <Database className="w-4 h-4 text-accent-blue" />}
                <div className="text-left">
                  <div className="font-medium text-text-primary">CIC-IoT-2023 Sample</div>
                  <div className="text-[10px] text-text-secondary">1K flows | Standard IDS | 0.9 MB</div>
                </div>
              </button>
            </div>

            {/* Server-side datasets */}
            {datasets.length > 0 && (
              <div className="border-t border-bg-card pt-3">
                <div className="text-xs text-text-secondary mb-2">Server Datasets ({datasets.length})</div>
                <div className="space-y-1.5 max-h-40 overflow-y-auto">
                  {datasets.map((ds) => (
                    <div
                      key={ds.name}
                      className="flex items-center justify-between px-2 py-1.5 rounded bg-bg-card/50 text-xs"
                    >
                      <div className="flex items-center gap-2">
                        {ds.has_pq_metadata ? <Shield className="w-3 h-3 text-accent-purple" /> : <Database className="w-3 h-3 text-accent-blue" />}
                        <span className="font-mono text-text-primary">{ds.name}</span>
                        <span className="text-text-secondary">{ds.n_rows.toLocaleString()} rows | {ds.size_mb} MB</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 md:gap-6">
        <div className="lg:col-span-2">
          <FileUpload onFileSelect={handleUpload} loading={loading} fileLoading={loading} />
        </div>

        <div className="space-y-4">
          <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-4">
            <h3 className="text-sm font-medium text-text-secondary">Settings</h3>
            <ModelSelector value={selectedModel} onChange={(v) => { setSelectedModel(v); ablation.setSelectedModel(v) }} compact />
            <div>
              <label className="text-xs text-text-secondary block mb-1">
                MC Dropout Passes: {mcPasses}
              </label>
              <input
                type="range"
                min={5}
                max={100}
                value={mcPasses}
                onChange={(e) => setMcPasses(+e.target.value)}
                className="w-full accent-accent-blue"
              />
              <div className="flex justify-between text-xs text-text-secondary">
                <span>5 (fast)</span>
                <span>100 (precise)</span>
              </div>
            </div>
          </div>

          {/* Ablation Configuration Card */}
          {ablation.data && (
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <button
                onClick={() => setShowAblation(!showAblation)}
                className="w-full flex items-center justify-between text-xs font-medium text-text-secondary"
              >
                <span className="flex items-center gap-1.5">
                  <FlaskConical className="w-3.5 h-3.5 text-accent-blue" />
                  Ablation Configuration
                </span>
                {showAblation ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              </button>
              {showAblation && (
                <div className="mt-3 space-y-2">
                  {/* Branch toggles compact */}
                  <div className="grid grid-cols-1 gap-1">
                    {BRANCH_NAMES.map((name, i) => (
                      <div key={i} className={`flex items-center gap-2 px-2 py-1 rounded text-[10px] ${
                        ablation.enabled[i]
                          ? 'text-accent-green bg-accent-green/5'
                          : 'text-accent-red/60 bg-accent-red/5 line-through'
                      }`}>
                        {ablation.enabled[i] ? <ToggleRight className="w-3 h-3 shrink-0" /> : <ToggleLeft className="w-3 h-3 shrink-0" />}
                        <span className="font-mono opacity-60">M{i + 1}</span>
                        <span className="truncate">{name}</span>
                      </div>
                    ))}
                  </div>
                  {/* Key stats */}
                  {ablation.data.ablation?.['Full System'] && (
                    <div className="pt-2 border-t border-bg-card space-y-1.5">
                      <div className="flex justify-between text-[10px]">
                        <span className="text-text-secondary">Full Ensemble</span>
                        <span className="font-mono text-accent-blue font-semibold">
                          {(ablation.data.ablation['Full System'].accuracy * 100).toFixed(2)}%
                        </span>
                      </div>
                      {(() => {
                        const entries = Object.entries(ablation.data.ablation)
                          .filter(([k]) => k !== 'Full System' && k !== 'Custom')
                        const most = entries.sort((a, b) => b[1].accuracy_drop - a[1].accuracy_drop)[0]
                        if (!most) return null
                        return (
                          <div className="flex justify-between text-[10px]">
                            <span className="text-text-secondary flex items-center gap-1">
                              <TrendingDown className="w-2.5 h-2.5 text-accent-red" />
                              Most impactful
                            </span>
                            <span className="font-mono text-accent-red">
                              {most[0].split('(')[0].trim()} (-{(most[1].accuracy_drop * 100).toFixed(1)}%)
                            </span>
                          </div>
                        )
                      })()}
                      <div className="text-[9px] text-text-secondary/50">
                        {ablation.enabled.filter(v => !v).length > 0
                          ? `${ablation.enabled.filter(v => !v).length} branch(es) disabled`
                          : 'All branches active'}
                        {' · '}
                        <span className="text-accent-blue cursor-pointer hover:underline" onClick={() => navigate('/ablation')}>
                          Edit in Ablation Studio
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {loading && (
        <div className="flex items-center gap-3 text-accent-blue">
          <Loader2 className="w-5 h-5 animate-spin" />
          <span>Analysing traffic flows with {mcPasses} MC passes...</span>
        </div>
      )}

      {error && (
        <div className="px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">
          {error}
        </div>
      )}

      {results && (
        <>
          {/* Dataset header with delete button */}
          <div className="flex items-center justify-between">
            {datasetInfo && (
              <div className="flex-1">
                <DatasetSummary info={datasetInfo} fileName={fileName} />
              </div>
            )}
          </div>

          {/* Delete dataset bar */}
          <div className="flex items-center justify-between px-4 py-2.5 bg-bg-secondary rounded-lg border border-bg-card">
            <div className="text-xs text-text-secondary flex items-center gap-2">
              {source === 'live-monitor' ? (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-accent-green/15 text-accent-green text-[10px] font-semibold uppercase">
                  <Radio className="w-3 h-3" /> Live Monitor
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-accent-blue/15 text-accent-blue text-[10px] font-semibold uppercase">
                  <UploadIcon className="w-3 h-3" /> Upload &amp; Analyse
                </span>
              )}
              <span className="font-medium text-text-primary">{fileName}</span>
              {jobId && <span className="ml-2 opacity-50">Job: {jobId}</span>}
              {results?.model_used && (
                <span className="flex items-center gap-1 ml-2 text-[10px] text-accent-purple bg-accent-purple/10 px-2 py-0.5 rounded-full">
                  <Brain className="w-3 h-3" /> {String(results.model_used)}
                </span>
              )}
            </div>
            {!showDeleteConfirm ? (
              <button
                onClick={() => setShowDeleteConfirm(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-accent-red hover:bg-accent-red/10 rounded-lg transition-colors"
              >
                <Trash2 className="w-3.5 h-3.5" /> Remove Dataset
              </button>
            ) : (
              <div className="flex items-center gap-2">
                <span className="text-xs text-accent-red">Delete this analysis?</span>
                <button
                  onClick={handleDelete}
                  disabled={deleting}
                  className="px-3 py-1.5 text-xs font-medium bg-accent-red text-white rounded-lg hover:bg-accent-red/90 disabled:opacity-50 transition-colors"
                >
                  {deleting ? 'Deleting...' : 'Confirm Delete'}
                </button>
                <button
                  onClick={() => setShowDeleteConfirm(false)}
                  className="p-1.5 text-text-secondary hover:text-text-primary rounded transition-colors"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>

          <ThreatTable predictions={predictions as never} />

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <UncertaintyChart predictions={predictions as never} />
            <ConfusionMatrix
              matrix={results.confusion_matrix as number[][] | null}
              labels={
                results.per_class_metrics
                  ? Object.keys(results.per_class_metrics as Record<string, unknown>)
                  : undefined
              }
              source={source}
            />
          </div>

          {perClassData.length > 0 && (
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h3 className="text-sm font-medium text-text-secondary mb-4">Per-Class Metrics</h3>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={perClassData} layout="vertical" margin={{ left: 120 }}>
                  <XAxis
                    type="number"
                    domain={[0, 100]}
                    tick={{ fill: '#94A3B8', fontSize: 10 }}
                    axisLine={{ stroke: '#334155' }}
                    tickFormatter={(v) => `${v}%`}
                  />
                  <YAxis
                    type="category"
                    dataKey="label"
                    tick={{ fill: '#94A3B8', fontSize: 10 }}
                    axisLine={{ stroke: '#334155' }}
                    width={115}
                  />
                  <Tooltip
                    contentStyle={{
                      background: '#1E293B',
                      border: '1px solid #334155',
                      borderRadius: '8px',
                      color: '#F8FAFC',
                      fontSize: '12px',
                    }}
                  />
                  <Bar dataKey="precision" fill="#3B82F6" name="Precision" />
                  <Bar dataKey="recall" fill="#22C55E" name="Recall" />
                  <Bar dataKey="f1" fill="#A855F7" name="F1" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </>
      )}

      {/* Model Analytics — always available */}
      <div className="space-y-3">
        <button
          onClick={() => setShowModelAnalytics(!showModelAnalytics)}
          className="flex items-center gap-2 text-sm font-semibold text-text-primary hover:text-accent-blue transition-colors"
        >
          <TrendingUp className="w-4 h-4 text-accent-blue" />
          Model Analytics & Evaluation
          {showModelAnalytics ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>
        {!results && !loading && (
          <p className="text-xs text-text-secondary">
            Pre-computed benchmark metrics for all dissertation models. Upload a dataset above or send results from Live Monitor to see per-dataset analysis alongside these model evaluations.
          </p>
        )}
        {showModelAnalytics && <ModelAnalyticsPanel />}
      </div>
    </div>
  )
}
