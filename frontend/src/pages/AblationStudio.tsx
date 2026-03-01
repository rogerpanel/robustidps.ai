import { useState } from 'react'
import FileUpload from '../components/FileUpload'
import AblationChart from '../components/AblationChart'
import { runAblation } from '../utils/api'
import { Loader2 } from 'lucide-react'

const BRANCH_NAMES = [
  'CT-TGNN (Neural ODE)',
  'TripleE-TGNN (Multi-scale)',
  'FedLLM-API (Zero-shot)',
  'PQ-IDPS (Post-quantum)',
  'MambaShield (State-space)',
  'Stochastic Transformer',
  'Game-Theoretic Defence',
]

export default function AblationStudio() {
  const [file, setFile] = useState<File | null>(null)
  const [enabled, setEnabled] = useState<boolean[]>(new Array(7).fill(true))
  const [loading, setLoading] = useState(false)
  const [data, setData] = useState<Record<string, { accuracy: number; accuracy_drop: number; disabled: number[] }> | null>(null)
  const [error, setError] = useState<string | null>(null)

  const toggle = (i: number) => {
    const next = [...enabled]
    next[i] = !next[i]
    setEnabled(next)
  }

  const handleRun = async () => {
    if (!file) return
    setLoading(true)
    setError(null)
    try {
      const disabled = enabled
        .map((v, i) => (v ? -1 : i))
        .filter((i) => i >= 0)
      const res = await runAblation(file, disabled)
      setData(res.ablation)
    } catch {
      setError('Failed to run ablation. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-display font-bold">Ablation Studio</h1>
        <p className="text-sm text-text-secondary mt-1">
          Toggle dissertation methods on/off to measure each contribution's impact on accuracy.
        </p>
      </div>

      {/* Branch toggles */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h3 className="text-sm font-medium text-text-secondary mb-4">Dissertation Methods</h3>
        <div className="flex flex-wrap gap-3">
          {BRANCH_NAMES.map((name, i) => (
            <button
              key={i}
              onClick={() => toggle(i)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all border ${
                enabled[i]
                  ? 'bg-accent-blue/15 border-accent-blue text-accent-blue'
                  : 'bg-accent-red/10 border-accent-red/30 text-accent-red line-through'
              }`}
            >
              <span className="font-mono text-xs mr-2">M{i + 1}</span>
              {name}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-3 gap-6">
        <div className="col-span-2">
          {!file ? (
            <FileUpload onFileSelect={(f) => setFile(f)} />
          ) : (
            <div className="flex items-center gap-4">
              <span className="text-sm font-mono text-text-secondary">
                File: {file.name}
              </span>
              <button
                onClick={handleRun}
                disabled={loading}
                className="px-6 py-2 bg-accent-blue text-white rounded-lg text-sm font-medium hover:bg-accent-blue/80 disabled:opacity-50"
              >
                {loading ? (
                  <span className="flex items-center gap-2">
                    <Loader2 className="w-4 h-4 animate-spin" /> Running...
                  </span>
                ) : (
                  'Run Ablation Study'
                )}
              </button>
              <button
                onClick={() => {
                  setFile(null)
                  setData(null)
                }}
                className="px-4 py-2 border border-bg-card rounded-lg text-sm text-text-secondary hover:text-text-primary"
              >
                Change File
              </button>
            </div>
          )}
        </div>
      </div>

      {error && (
        <div className="px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">
          {error}
        </div>
      )}

      {data && <AblationChart data={data} />}

      {data && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Ablation Results Table</h3>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-text-secondary text-xs">
                <th className="px-3 py-2 text-left">Configuration</th>
                <th className="px-3 py-2 text-right">Accuracy</th>
                <th className="px-3 py-2 text-right">Drop</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(data).map(([name, v]) => (
                <tr key={name} className="border-t border-bg-card/50">
                  <td className="px-3 py-2 font-medium">
                    {name === 'Full System' ? (
                      <span className="text-accent-blue">{name}</span>
                    ) : (
                      name
                    )}
                  </td>
                  <td className="px-3 py-2 text-right font-mono">
                    {(v.accuracy * 100).toFixed(2)}%
                  </td>
                  <td
                    className={`px-3 py-2 text-right font-mono ${
                      v.accuracy_drop > 0 ? 'text-accent-red' : 'text-accent-green'
                    }`}
                  >
                    {v.accuracy_drop > 0 ? `-${(v.accuracy_drop * 100).toFixed(2)}%` : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
