import { useState } from 'react'
import FileUpload from '../components/FileUpload'
import ThreatTable from '../components/ThreatTable'
import UncertaintyChart from '../components/UncertaintyChart'
import ConfusionMatrix from '../components/ConfusionMatrix'
import ModelSelector from '../components/ModelSelector'
import { useAnalysis } from '../hooks/useAnalysis'
import PageGuide from '../components/PageGuide'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { Loader2, Database, AlertTriangle, Trash2, X, Radio, Upload as UploadIcon } from 'lucide-react'

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

export default function UploadPage() {
  const [mcPasses, setMcPasses] = useState(20)
  const [selectedModel, setSelectedModel] = useState('surrogate')
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const { loading, results, error, fileName, jobId, source, runAnalysis, deleteJob } = useAnalysis()

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

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 md:gap-6">
        <div className="lg:col-span-2">
          <FileUpload onFileSelect={handleUpload} loading={loading} />
        </div>

        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-4">
          <h3 className="text-sm font-medium text-text-secondary">Settings</h3>
          <ModelSelector value={selectedModel} onChange={setSelectedModel} compact />
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
    </div>
  )
}
