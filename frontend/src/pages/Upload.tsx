import { useState } from 'react'
import FileUpload from '../components/FileUpload'
import ThreatTable from '../components/ThreatTable'
import UncertaintyChart from '../components/UncertaintyChart'
import ConfusionMatrix from '../components/ConfusionMatrix'
import ModelSelector from '../components/ModelSelector'
import { useAnalysis } from '../hooks/useAnalysis'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { Loader2 } from 'lucide-react'

export default function UploadPage() {
  const [mcPasses, setMcPasses] = useState(50)
  const [selectedModel, setSelectedModel] = useState('surrogate')
  const { loading, results, error, runAnalysis } = useAnalysis()

  const handleUpload = (file: File) => {
    runAnalysis(file, mcPasses, selectedModel)
  }

  const predictions = (results?.predictions ?? []) as Array<Record<string, unknown>>
  const perClass = (results?.per_class_metrics ?? {}) as Record<
    string,
    { precision: number; recall: number; f1: number }
  >
  const perClassData = Object.entries(perClass).map(([label, m]) => ({
    label: label.length > 18 ? label.slice(0, 16) + '..' : label,
    precision: +(m.precision * 100).toFixed(1),
    recall: +(m.recall * 100).toFixed(1),
    f1: +(m.f1 * 100).toFixed(1),
  }))

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-display font-bold">Upload & Analyse</h1>

      <div className="grid grid-cols-3 gap-6">
        <div className="col-span-2">
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
          <ThreatTable predictions={predictions as never} />

          <div className="grid grid-cols-2 gap-4">
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
