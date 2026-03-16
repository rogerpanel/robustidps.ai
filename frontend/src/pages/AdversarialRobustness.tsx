import { useEffect, useState, useRef } from 'react'
import {
  Shield, Loader2, AlertTriangle, Zap, BarChart3,
  Target, CheckCircle2, XCircle, Brain,
} from 'lucide-react'
import { runAdversarialEval, fetchModels, fetchAttackConfigs } from '../utils/api'
import ExportMenu from '../components/ExportMenu'
import { registerSessionReset } from '../utils/sessionReset'

const ATTACK_COLORS: Record<string, string> = {
  fgsm: '#EF4444',
  pgd: '#F59E0B',
  cw: '#A855F7',
  deepfool: '#3B82F6',
  gaussian: '#22C55E',
  label_masking: '#EC4899',
}

const _store: {
  file: File | null
  modelId: string
  result: any
} = {
  file: null,
  modelId: 'surrogate',
  result: null,
}

registerSessionReset(() => {
  _store.file = null
  _store.modelId = 'surrogate'
  _store.result = null
})

export default function AdversarialRobustness() {
  const [file, _setFile] = useState<File | null>(_store.file)
  const [modelId, _setModelId] = useState(_store.modelId)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')
  const [result, _setResult] = useState<any>(_store.result)
  const [models, setModels] = useState<any[]>([])
  const fileRef = useRef<HTMLInputElement>(null)

  const setFile = (f: File | null) => { _store.file = f; _setFile(f) }
  const setModelId = (v: string) => { _store.modelId = v; _setModelId(v) }
  const setResult = (v: any) => { _store.result = v; _setResult(v) }

  useEffect(() => {
    fetchModels()
      .then((data) => setModels((data.models ?? []).filter((m: any) => m.enabled)))
      .catch(() => {})
  }, [])

  const handleRun = async () => {
    if (!file) return
    setRunning(true)
    setError('')
    try {
      const data = await runAdversarialEval(file, modelId)
      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Evaluation failed')
    }
    setRunning(false)
  }

  const attacks = result?.attacks ? Object.entries(result.attacks) : []

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex items-center gap-3">
        <Target className="w-6 h-6 text-accent-red" />
        <div className="flex-1">
          <h1 className="text-2xl font-display font-bold">Adversarial Robustness</h1>
          <p className="text-sm text-text-secondary mt-1">
            Evaluate model resilience against 6 adversarial attack methods: FGSM, PGD, C&amp;W, DeepFool, Gaussian noise, and Label masking.
          </p>
        </div>
        <ExportMenu filename="adversarial-robustness" />
      </div>

      {error && (
        <div className="px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {error}
          <button onClick={() => setError('')} className="ml-auto text-xs hover:underline">dismiss</button>
        </div>
      )}

      {/* Controls */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">
          <Zap className="w-5 h-5 text-accent-amber" />
          Robustness Evaluation
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <label className="text-xs text-text-secondary block mb-1">Traffic Data (.csv)</label>
            <input
              ref={fileRef}
              type="file"
              accept=".csv,.pcap,.pcapng"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              className="w-full text-sm text-text-secondary file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-medium file:bg-accent-blue/15 file:text-accent-blue hover:file:bg-accent-blue/25 cursor-pointer"
            />
          </div>
          <div>
            <label className="text-xs text-text-secondary block mb-1">Target Model</label>
            <select
              value={modelId}
              onChange={(e) => setModelId(e.target.value)}
              className="w-full px-2 py-1.5 bg-bg-primary border border-bg-card rounded text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent-blue/50"
            >
              {models.map((m) => (
                <option key={m.id} value={m.id}>{m.name}</option>
              ))}
            </select>
          </div>
          <div className="flex items-end">
            <button
              onClick={handleRun}
              disabled={!file || running}
              className="w-full px-4 py-2 bg-accent-red text-white rounded-lg text-xs font-medium hover:bg-accent-red/80 disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {running ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> Attacking...</>
              ) : (
                <><Target className="w-4 h-4" /> Run All Attacks</>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Results */}
      {result && (
        <>
          {/* Clean accuracy banner */}
          <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs text-text-secondary">Clean Accuracy (no attack)</div>
                <div className="text-3xl font-display font-bold text-accent-green">
                  {result.clean_accuracy?.toFixed(1)}%
                </div>
              </div>
              <div className="text-right">
                <div className="text-xs text-text-secondary">Model</div>
                <div className="text-sm font-medium">{result.model_name}</div>
                <div className="text-[10px] text-text-secondary">{result.n_samples} samples · {result.dataset_format}</div>
              </div>
            </div>
          </div>

          {/* Attack results grid */}
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {attacks.map(([name, data]: [string, any]) => {
              const color = ATTACK_COLORS[name] || '#9CA3AF'
              const drop = data.accuracy_drop ?? 0
              const ratio = data.robustness_ratio ?? 0
              return (
                <div key={name} className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-medium" style={{ color }}>{data.label || name}</span>
                    {ratio >= 0.9 ? (
                      <CheckCircle2 className="w-4 h-4 text-accent-green" />
                    ) : ratio >= 0.7 ? (
                      <AlertTriangle className="w-4 h-4 text-accent-amber" />
                    ) : (
                      <XCircle className="w-4 h-4 text-accent-red" />
                    )}
                  </div>
                  {data.error ? (
                    <div className="text-xs text-accent-red">{data.error}</div>
                  ) : (
                    <>
                      <div className="text-2xl font-display font-bold">{data.accuracy?.toFixed(1)}%</div>
                      <div className="flex items-center gap-2 mt-1">
                        <span className={`text-[10px] ${drop > 0 ? 'text-accent-red' : 'text-accent-green'}`}>
                          {drop > 0 ? '-' : '+'}{Math.abs(drop).toFixed(1)}%
                        </span>
                        <span className="text-[10px] text-text-secondary">
                          Robustness: {(ratio * 100).toFixed(1)}%
                        </span>
                      </div>
                      {/* Mini bar */}
                      <div className="mt-2 h-1.5 bg-bg-card rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all"
                          style={{ width: `${data.accuracy}%`, background: color }}
                        />
                      </div>
                    </>
                  )}
                </div>
              )
            })}
          </div>

          {/* Comparison Table */}
          <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
            <h2 className="text-lg font-display font-semibold mb-3">Attack Comparison</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-text-secondary text-xs">
                    <th className="px-3 py-2 text-left">Attack</th>
                    <th className="px-3 py-2 text-right">Accuracy Under Attack</th>
                    <th className="px-3 py-2 text-right">Accuracy Drop</th>
                    <th className="px-3 py-2 text-right">Robustness Ratio</th>
                    <th className="px-3 py-2 text-center">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {attacks.map(([name, data]: [string, any]) => (
                    <tr key={name} className="border-t border-bg-card/50">
                      <td className="px-3 py-2 font-medium" style={{ color: ATTACK_COLORS[name] }}>
                        {data.label || name}
                      </td>
                      <td className="px-3 py-2 text-right font-mono">{data.accuracy?.toFixed(1)}%</td>
                      <td className="px-3 py-2 text-right font-mono text-accent-red">
                        -{data.accuracy_drop?.toFixed(1)}%
                      </td>
                      <td className="px-3 py-2 text-right font-mono">
                        {((data.robustness_ratio ?? 0) * 100).toFixed(1)}%
                      </td>
                      <td className="px-3 py-2 text-center">
                        {(data.robustness_ratio ?? 0) >= 0.9 ? (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-accent-green/15 text-accent-green">Robust</span>
                        ) : (data.robustness_ratio ?? 0) >= 0.7 ? (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-accent-amber/15 text-accent-amber">Moderate</span>
                        ) : (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-accent-red/15 text-accent-red">Vulnerable</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {!result && !running && (
        <div className="text-center py-12 text-text-secondary">
          <Target className="w-10 h-10 mx-auto mb-3 opacity-20" />
          <p className="text-sm">Upload labelled traffic data and select a model to evaluate adversarial robustness.</p>
        </div>
      )}

      {/* Attack Descriptions */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold mb-3">Attack Methods (CL-RL Paper Section V-E)</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs text-text-secondary">
          {[
            ['FGSM', 'Fast Gradient Sign Method — single-step perturbation along gradient sign: x_adv = x + ε·sign(∇L)', '#EF4444'],
            ['PGD', 'Projected Gradient Descent — iterative FGSM within ε-ball (40 steps, α=0.01)', '#F59E0B'],
            ['C&W', 'Carlini-Wagner L2 — optimisation-based attack minimising ‖δ‖₂ + c·f(x+δ)', '#A855F7'],
            ['DeepFool', 'Minimal perturbation to cross nearest decision boundary iteratively', '#3B82F6'],
            ['Gaussian', 'Random Gaussian noise injection: x_adv = x + N(0, σ²) with σ=0.1', '#22C55E'],
            ['Label Masking', 'Training-time poisoning simulation — flips 10% of labels to test robustness', '#EC4899'],
          ].map(([name, desc, color]) => (
            <div key={name} className="flex gap-2 p-2 bg-bg-primary rounded-lg">
              <div className="w-2 h-2 rounded-full shrink-0 mt-1" style={{ background: color }} />
              <div>
                <span className="font-medium text-text-primary">{name}:</span> {desc}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
