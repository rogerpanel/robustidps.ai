import { useEffect, useState } from 'react'
import {
  BarChart, Bar, LineChart, Line, XAxis, YAxis, Tooltip, Legend,
  ResponsiveContainer, RadarChart, Radar, PolarGrid, PolarAngleAxis,
  PolarRadiusAxis, CartesianGrid,
} from 'recharts'
import { Loader2, Download, TrendingUp, Shield, GitBranch, Target } from 'lucide-react'
import { fetchAnalytics } from '../utils/api'

const MODEL_COLORS: Record<string, string> = {
  surrogate: '#3B82F6',
  neural_ode: '#A855F7',
  optimal_transport: '#22C55E',
  fedgtd: '#F59E0B',
  sde_tgnn: '#EF4444',
}

type Tab = 'performance' | 'convergence' | 'robustness' | 'transfer' | 'calibration' | 'roc'

const TABS: { key: Tab; label: string; icon: typeof TrendingUp }[] = [
  { key: 'performance', label: 'Performance', icon: TrendingUp },
  { key: 'convergence', label: 'Convergence', icon: TrendingUp },
  { key: 'robustness', label: 'Robustness', icon: Shield },
  { key: 'transfer', label: 'Transfer Learning', icon: GitBranch },
  { key: 'calibration', label: 'Calibration', icon: Target },
  { key: 'roc', label: 'ROC / AUC', icon: TrendingUp },
]

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export default function Analytics() {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [data, setData] = useState<Record<string, any> | null>(null)
  const [tab, setTab] = useState<Tab>('performance')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchAnalytics()
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false))
  }, [])

  if (loading)
    return (
      <div className="flex items-center gap-3 text-accent-blue mt-20 justify-center">
        <Loader2 className="w-5 h-5 animate-spin" />
        Loading analytics...
      </div>
    )
  if (!data)
    return (
      <div className="text-accent-red text-center mt-20">
        Failed to load analytics. Is the backend running?
      </div>
    )

  const models: string[] = data.models
  const names: Record<string, string> = data.model_names

  const downloadJSON = () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'robustidps_analytics.json'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-display font-bold">Analytics & Evaluation</h1>
        <button
          onClick={downloadJSON}
          className="flex items-center gap-2 px-3 py-1.5 text-xs bg-accent-blue/15 text-accent-blue rounded-lg hover:bg-accent-blue/25 transition-colors"
        >
          <Download className="w-3.5 h-3.5" />
          Export All Metrics (JSON)
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-bg-secondary rounded-lg p-1 border border-bg-card">
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`flex items-center gap-2 px-3 py-2 rounded-md text-xs font-medium transition-colors ${
              tab === t.key
                ? 'bg-accent-blue/15 text-accent-blue'
                : 'text-text-secondary hover:text-text-primary hover:bg-bg-card/50'
            }`}
          >
            <t.icon className="w-3.5 h-3.5" />
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'performance' && <PerformanceTab data={data} models={models} names={names} />}
      {tab === 'convergence' && <ConvergenceTab data={data} models={models} names={names} />}
      {tab === 'robustness' && <RobustnessTab data={data} models={models} names={names} />}
      {tab === 'transfer' && <TransferTab data={data} models={models} names={names} />}
      {tab === 'calibration' && <CalibrationTab data={data} models={models} names={names} />}
      {tab === 'roc' && <ROCTab data={data} models={models} names={names} />}
    </div>
  )
}

/* ═══════════════════════ 1. Performance Comparison ═══════════════════════ */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function PerformanceTab({ data, models, names }: { data: any; models: string[]; names: Record<string, string> }) {
  const perf = data.performance
  const metrics = ['accuracy', 'precision', 'recall', 'f1', 'auc_roc']
  const barData = metrics.map((m) => {
    const row: Record<string, unknown> = { metric: m.toUpperCase().replace('_', ' ') }
    models.forEach((mid) => {
      row[mid] = +(perf[mid][m] * 100).toFixed(2)
    })
    return row
  })

  // Radar chart data
  const radarData = metrics.map((m) => {
    const row: Record<string, unknown> = { metric: m === 'auc_roc' ? 'AUC-ROC' : m.charAt(0).toUpperCase() + m.slice(1) }
    models.forEach((mid) => {
      row[mid] = +(perf[mid][m] * 100).toFixed(1)
    })
    return row
  })

  // Summary table
  const tableMetrics = ['accuracy', 'precision', 'recall', 'f1', 'auc_roc', 'ece', 'inference_ms', 'params_k']
  const tableHeaders = ['Model', 'Accuracy', 'Precision', 'Recall', 'F1', 'AUC-ROC', 'ECE', 'Inference (ms)', 'Params (K)']

  // Per-class F1 heatmap data
  const pcf1 = data.per_class_f1
  const classes: string[] = pcf1.classes

  return (
    <div className="space-y-6">
      {/* Bar chart comparison */}
      <div className="grid grid-cols-2 gap-4">
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Model Comparison (% Score)</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={barData} layout="vertical" margin={{ left: 80 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis type="number" domain={[85, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} />
              <YAxis type="category" dataKey="metric" tick={{ fill: '#94A3B8', fontSize: 10 }} width={75} />
              <Tooltip contentStyle={{ background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 10 }} />
              {models.map((mid) => (
                <Bar key={mid} dataKey={mid} fill={MODEL_COLORS[mid]} name={names[mid].split('(')[0].trim()} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Radar */}
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Radar — Multi-Metric Overview</h3>
          <ResponsiveContainer width="100%" height={300}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="#334155" />
              <PolarAngleAxis dataKey="metric" tick={{ fill: '#94A3B8', fontSize: 10 }} />
              <PolarRadiusAxis domain={[88, 100]} tick={{ fill: '#64748B', fontSize: 9 }} />
              {models.map((mid) => (
                <Radar key={mid} dataKey={mid} stroke={MODEL_COLORS[mid]} fill={MODEL_COLORS[mid]} fillOpacity={0.08} name={names[mid].split('(')[0].trim()} />
              ))}
              <Legend wrapperStyle={{ fontSize: 10 }} />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Summary table */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h3 className="text-sm font-medium text-text-secondary mb-4">Detailed Comparison Table</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-text-secondary text-xs">
                {tableHeaders.map((h) => (
                  <th key={h} className="px-3 py-2 text-left">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {models.map((mid) => (
                <tr key={mid} className="border-t border-bg-card/50 hover:bg-bg-card/20">
                  <td className="px-3 py-2 font-medium" style={{ color: MODEL_COLORS[mid] }}>
                    {names[mid].split('(')[0].trim()}
                  </td>
                  {tableMetrics.map((m) => {
                    const val = perf[mid][m]
                    const display = m === 'inference_ms' ? `${val}` : m === 'params_k' ? `${val}` : m === 'ece' ? val.toFixed(4) : `${(val * 100).toFixed(2)}%`
                    // Highlight best value
                    const allVals = models.map((m2) => perf[m2][m])
                    const isBest = m === 'ece' || m === 'inference_ms'
                      ? val === Math.min(...allVals)
                      : val === Math.max(...allVals)
                    return (
                      <td key={m} className={`px-3 py-2 font-mono text-xs ${isBest ? 'text-accent-green font-bold' : ''}`}>
                        {display}
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Per-class F1 heatmap */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h3 className="text-sm font-medium text-text-secondary mb-4">Per-Class F1 Scores (Selected Attack Families)</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr>
                <th className="px-2 py-1 text-left text-text-secondary">Model</th>
                {classes.map((c) => (
                  <th key={c} className="px-1 py-1 text-center text-text-secondary" style={{ writingMode: 'vertical-lr', height: 80 }}>
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {models.map((mid) => (
                <tr key={mid} className="border-t border-bg-card/30">
                  <td className="px-2 py-1 font-medium whitespace-nowrap" style={{ color: MODEL_COLORS[mid] }}>
                    {names[mid].split('(')[0].trim()}
                  </td>
                  {(pcf1[mid] as number[]).map((v, i) => {
                    const intensity = Math.round((v - 0.85) / 0.15 * 255)
                    const bg = `rgba(34, 197, 94, ${Math.max(0, intensity) / 255 * 0.6})`
                    return (
                      <td key={i} className="px-1 py-1 text-center font-mono" style={{ background: bg }}>
                        {(v * 100).toFixed(0)}
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

/* ═══════════════════════ 2. Convergence Curves ═══════════════════════════ */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function ConvergenceTab({ data, models, names }: { data: any; models: string[]; names: Record<string, string> }) {
  const conv = data.convergence

  // Build line data: [{epoch:1, surrogate_loss:..., surrogate_acc:...}, ...]
  const epochs = conv[models[0]].epochs
  const lossData = Array.from({ length: epochs }, (_, i) => {
    const row: Record<string, unknown> = { epoch: i + 1 }
    models.forEach((mid) => { row[`${mid}`] = conv[mid].loss[i] })
    return row
  })
  const accData = Array.from({ length: epochs }, (_, i) => {
    const row: Record<string, unknown> = { epoch: i + 1 }
    models.forEach((mid) => { row[`${mid}`] = +(conv[mid].accuracy[i] * 100).toFixed(2) })
    return row
  })

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4">
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Training Loss (Cross-Entropy)</h3>
          <ResponsiveContainer width="100%" height={350}>
            <LineChart data={lossData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="epoch" tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Epoch', position: 'insideBottom', offset: -5, fill: '#94A3B8', fontSize: 11 }} />
              <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Loss', angle: -90, position: 'insideLeft', fill: '#94A3B8', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 10 }} />
              {models.map((mid) => (
                <Line key={mid} type="monotone" dataKey={mid} stroke={MODEL_COLORS[mid]} dot={false} strokeWidth={2} name={names[mid].split('(')[0].trim()} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Validation Accuracy (%)</h3>
          <ResponsiveContainer width="100%" height={350}>
            <LineChart data={accData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="epoch" tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Epoch', position: 'insideBottom', offset: -5, fill: '#94A3B8', fontSize: 11 }} />
              <YAxis domain={[0, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Accuracy %', angle: -90, position: 'insideLeft', fill: '#94A3B8', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }} formatter={(v: number) => `${v.toFixed(2)}%`} />
              <Legend wrapperStyle={{ fontSize: 10 }} />
              {models.map((mid) => (
                <Line key={mid} type="monotone" dataKey={mid} stroke={MODEL_COLORS[mid]} dot={false} strokeWidth={2} name={names[mid].split('(')[0].trim()} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Convergence speed table */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h3 className="text-sm font-medium text-text-secondary mb-4">Convergence Speed (Epochs to Reach Threshold)</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-text-secondary text-xs">
                <th className="px-3 py-2 text-left">Model</th>
                <th className="px-3 py-2 text-left">90% Accuracy</th>
                <th className="px-3 py-2 text-left">95% Accuracy</th>
                <th className="px-3 py-2 text-left">Final Accuracy</th>
                <th className="px-3 py-2 text-left">Final Loss</th>
              </tr>
            </thead>
            <tbody>
              {models.map((mid) => {
                const accArr: number[] = conv[mid].accuracy
                const ep90 = accArr.findIndex((a: number) => a >= 0.90) + 1 || '> 100'
                const ep95 = accArr.findIndex((a: number) => a >= 0.95) + 1 || '> 100'
                return (
                  <tr key={mid} className="border-t border-bg-card/50 hover:bg-bg-card/20">
                    <td className="px-3 py-2 font-medium" style={{ color: MODEL_COLORS[mid] }}>
                      {names[mid].split('(')[0].trim()}
                    </td>
                    <td className="px-3 py-2 font-mono">{ep90}</td>
                    <td className="px-3 py-2 font-mono">{ep95}</td>
                    <td className="px-3 py-2 font-mono">{(accArr[accArr.length - 1] * 100).toFixed(2)}%</td>
                    <td className="px-3 py-2 font-mono">{conv[mid].loss[conv[mid].loss.length - 1].toFixed(4)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

/* ═══════════════════════ 3. Robustness Under Perturbation ════════════════ */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function RobustnessTab({ data, models, names }: { data: any; models: string[]; names: Record<string, string> }) {
  const rob = data.robustness
  const eps: number[] = rob.epsilons

  const lineData = eps.map((e, i) => {
    const row: Record<string, unknown> = { epsilon: e }
    models.forEach((mid) => { row[mid] = +(rob[mid][i] * 100).toFixed(2) })
    return row
  })

  // Robustness score: area under accuracy-vs-epsilon curve (higher = more robust)
  const robScores = models.map((mid) => {
    const vals: number[] = rob[mid]
    let area = 0
    for (let i = 1; i < eps.length; i++) {
      area += (eps[i] - eps[i - 1]) * (vals[i] + vals[i - 1]) / 2
    }
    return { model: names[mid].split('(')[0].trim(), score: +(area / eps[eps.length - 1] * 100).toFixed(2), mid }
  }).sort((a, b) => b.score - a.score)

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2 bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">
            Accuracy Under FGSM Adversarial Perturbation
          </h3>
          <ResponsiveContainer width="100%" height={350}>
            <LineChart data={lineData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="epsilon" tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Perturbation \u03B5', position: 'insideBottom', offset: -5, fill: '#94A3B8', fontSize: 11 }} />
              <YAxis domain={[60, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Accuracy %', angle: -90, position: 'insideLeft', fill: '#94A3B8', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }} formatter={(v: number) => `${v.toFixed(2)}%`} />
              <Legend wrapperStyle={{ fontSize: 10 }} />
              {models.map((mid) => (
                <Line key={mid} type="monotone" dataKey={mid} stroke={MODEL_COLORS[mid]} strokeWidth={2} dot={{ r: 3 }} name={names[mid].split('(')[0].trim()} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Robustness ranking */}
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Robustness Score (AUC)</h3>
          <div className="space-y-3">
            {robScores.map((r, i) => (
              <div key={r.mid} className="flex items-center gap-3">
                <span className={`text-lg font-bold ${i === 0 ? 'text-accent-green' : 'text-text-secondary'}`}>
                  #{i + 1}
                </span>
                <div className="flex-1">
                  <div className="text-sm font-medium" style={{ color: MODEL_COLORS[r.mid] }}>{r.model}</div>
                  <div className="w-full bg-bg-card rounded-full h-2 mt-1">
                    <div
                      className="h-2 rounded-full"
                      style={{ width: `${r.score}%`, background: MODEL_COLORS[r.mid] }}
                    />
                  </div>
                </div>
                <span className="text-xs font-mono text-text-secondary">{r.score}%</span>
              </div>
            ))}
          </div>
          <p className="text-xs text-text-secondary mt-4">
            Robustness Score = normalized AUC of accuracy across all perturbation levels.
            Higher is more resilient to adversarial attacks.
          </p>
        </div>
      </div>

      {/* Drop table */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h3 className="text-sm font-medium text-text-secondary mb-4">Accuracy Drop at Key Perturbation Levels</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-text-secondary text-xs">
                <th className="px-3 py-2 text-left">Model</th>
                <th className="px-3 py-2 text-left">{'\u03B5'}=0 (Clean)</th>
                <th className="px-3 py-2 text-left">{'\u03B5'}=0.05</th>
                <th className="px-3 py-2 text-left">{'\u03B5'}=0.10</th>
                <th className="px-3 py-2 text-left">{'\u03B5'}=0.20</th>
                <th className="px-3 py-2 text-left">{'\u03B5'}=0.30</th>
                <th className="px-3 py-2 text-left">Max Drop</th>
              </tr>
            </thead>
            <tbody>
              {models.map((mid) => {
                const vals: number[] = rob[mid]
                const clean = vals[0]
                const maxDrop = clean - vals[vals.length - 1]
                return (
                  <tr key={mid} className="border-t border-bg-card/50 hover:bg-bg-card/20">
                    <td className="px-3 py-2 font-medium" style={{ color: MODEL_COLORS[mid] }}>
                      {names[mid].split('(')[0].trim()}
                    </td>
                    <td className="px-3 py-2 font-mono">{(clean * 100).toFixed(1)}%</td>
                    <td className="px-3 py-2 font-mono">{(vals[3] * 100).toFixed(1)}%</td>
                    <td className="px-3 py-2 font-mono">{(vals[5] * 100).toFixed(1)}%</td>
                    <td className="px-3 py-2 font-mono">{(vals[7] * 100).toFixed(1)}%</td>
                    <td className="px-3 py-2 font-mono">{(vals[9] * 100).toFixed(1)}%</td>
                    <td className="px-3 py-2 font-mono text-accent-red">-{(maxDrop * 100).toFixed(1)}%</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

/* ═══════════════════════ 4. Transfer Learning Matrix ═════════════════════ */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function TransferTab({ data, models, names }: { data: any; models: string[]; names: Record<string, string> }) {
  const tl = data.transfer_learning
  const datasets: string[] = tl.datasets
  const [selectedModel, setSelectedModel] = useState(models[0])

  const matrix: number[][] = tl[selectedModel]

  return (
    <div className="space-y-6">
      {/* Model selector */}
      <div className="flex gap-2">
        {models.map((mid) => (
          <button
            key={mid}
            onClick={() => setSelectedModel(mid)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              selectedModel === mid
                ? 'text-white'
                : 'bg-bg-card/50 text-text-secondary hover:text-text-primary'
            }`}
            style={selectedModel === mid ? { background: MODEL_COLORS[mid] } : {}}
          >
            {names[mid].split('(')[0].trim()}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-4">
        {/* Heatmap */}
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">
            Cross-Dataset Transfer Matrix — {names[selectedModel].split('(')[0].trim()}
          </h3>
          <table className="w-full text-sm">
            <thead>
              <tr>
                <th className="px-3 py-2 text-left text-xs text-text-secondary">Train \ Test</th>
                {datasets.map((d) => (
                  <th key={d} className="px-3 py-2 text-center text-xs text-text-secondary">{d}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {datasets.map((d, i) => (
                <tr key={d} className="border-t border-bg-card/50">
                  <td className="px-3 py-3 text-xs font-medium">{d}</td>
                  {matrix[i].map((v, j) => {
                    const isDiag = i === j
                    const pct = (v * 100).toFixed(1)
                    const opacity = Math.max(0.1, (v - 0.8) / 0.2)
                    return (
                      <td
                        key={j}
                        className={`px-3 py-3 text-center font-mono text-xs ${isDiag ? 'font-bold' : ''}`}
                        style={{
                          background: isDiag
                            ? `rgba(59, 130, 246, ${opacity * 0.4})`
                            : `rgba(168, 85, 247, ${opacity * 0.3})`,
                        }}
                      >
                        {pct}%
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
          <p className="text-xs text-text-secondary mt-3">
            Diagonal = same-dataset accuracy. Off-diagonal = transfer performance.
            Higher off-diagonal values indicate better generalization.
          </p>
        </div>

        {/* Transfer gap comparison */}
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">
            Transfer Gap (Avg Off-Diagonal vs Diagonal)
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart
              data={models.map((mid) => {
                const m: number[][] = tl[mid]
                let diagSum = 0, offSum = 0, offCount = 0
                m.forEach((row, i) =>
                  row.forEach((v, j) => {
                    if (i === j) diagSum += v
                    else { offSum += v; offCount++ }
                  }),
                )
                return {
                  model: names[mid].split('(')[0].trim(),
                  diagonal: +((diagSum / datasets.length) * 100).toFixed(1),
                  transfer: +((offSum / offCount) * 100).toFixed(1),
                  gap: +(((diagSum / datasets.length) - (offSum / offCount)) * 100).toFixed(1),
                  mid,
                }
              })}
              margin={{ left: 10 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="model" tick={{ fill: '#94A3B8', fontSize: 9 }} />
              <YAxis domain={[80, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} />
              <Tooltip contentStyle={{ background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 10 }} />
              <Bar dataKey="diagonal" fill="#3B82F6" name="Same-Dataset" />
              <Bar dataKey="transfer" fill="#A855F7" name="Cross-Dataset" />
            </BarChart>
          </ResponsiveContainer>
          <p className="text-xs text-text-secondary mt-2">
            Smaller gap between same-dataset and cross-dataset = better transfer learning.
            Optimal Transport excels here due to domain adaptation.
          </p>
        </div>
      </div>
    </div>
  )
}

/* ═══════════════════════ 5. Calibration (Reliability Diagram) ════════════ */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function CalibrationTab({ data, models, names }: { data: any; models: string[]; names: Record<string, string> }) {
  const cal = data.calibration
  const bins: number[] = cal.bins

  const lineData = bins.map((b, i) => {
    const row: Record<string, unknown> = { predicted: +(b * 100).toFixed(0), perfect: +(b * 100).toFixed(0) }
    models.forEach((mid) => {
      row[mid] = +(cal[mid][i] * 100).toFixed(1)
    })
    return row
  })

  const perf = data.performance

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2 bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Reliability Diagram (Calibration Plot)</h3>
          <ResponsiveContainer width="100%" height={400}>
            <LineChart data={lineData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="predicted" tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Mean Predicted Confidence (%)', position: 'insideBottom', offset: -5, fill: '#94A3B8', fontSize: 11 }} />
              <YAxis domain={[0, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Observed Accuracy (%)', angle: -90, position: 'insideLeft', fill: '#94A3B8', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 10 }} />
              <Line type="monotone" dataKey="perfect" stroke="#475569" strokeDasharray="5 5" strokeWidth={2} dot={false} name="Perfect calibration" />
              {models.map((mid) => (
                <Line key={mid} type="monotone" dataKey={mid} stroke={MODEL_COLORS[mid]} strokeWidth={2} dot={{ r: 4 }} name={names[mid].split('(')[0].trim()} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* ECE ranking */}
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">ECE Ranking (Lower = Better)</h3>
          <div className="space-y-4 mt-6">
            {models
              .slice()
              .sort((a, b) => perf[a].ece - perf[b].ece)
              .map((mid, i) => (
                <div key={mid}>
                  <div className="flex items-center justify-between text-sm mb-1">
                    <span className="font-medium" style={{ color: MODEL_COLORS[mid] }}>
                      {i === 0 && <span className="text-accent-green mr-1">Best</span>}
                      {names[mid].split('(')[0].trim()}
                    </span>
                    <span className="font-mono text-xs">{perf[mid].ece.toFixed(4)}</span>
                  </div>
                  <div className="w-full bg-bg-card rounded-full h-2">
                    <div
                      className="h-2 rounded-full"
                      style={{
                        width: `${(perf[mid].ece / 0.06) * 100}%`,
                        background: MODEL_COLORS[mid],
                      }}
                    />
                  </div>
                </div>
              ))}
          </div>
          <p className="text-xs text-text-secondary mt-6">
            ECE (Expected Calibration Error) measures how well predicted confidence
            matches actual accuracy. A perfectly calibrated model has ECE = 0.
          </p>
        </div>
      </div>
    </div>
  )
}

/* ═══════════════════════ 6. ROC / AUC ═══════════════════════════════════ */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function ROCTab({ data, models, names }: { data: any; models: string[]; names: Record<string, string> }) {
  const roc = data.roc_auc
  const families: string[] = roc.families

  const barData = families.map((f, i) => {
    const row: Record<string, unknown> = { family: f }
    models.forEach((mid) => {
      row[mid] = +(roc[mid][i] * 100).toFixed(2)
    })
    return row
  })

  return (
    <div className="space-y-6">
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h3 className="text-sm font-medium text-text-secondary mb-4">AUC-ROC by Attack Family</h3>
        <ResponsiveContainer width="100%" height={400}>
          <BarChart data={barData} layout="vertical" margin={{ left: 90 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis type="number" domain={[97, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} tickFormatter={(v) => `${v}%`} />
            <YAxis type="category" dataKey="family" tick={{ fill: '#94A3B8', fontSize: 10 }} width={85} />
            <Tooltip contentStyle={{ background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }} formatter={(v: number) => `${v.toFixed(2)}%`} />
            <Legend wrapperStyle={{ fontSize: 10 }} />
            {models.map((mid) => (
              <Bar key={mid} dataKey={mid} fill={MODEL_COLORS[mid]} name={names[mid].split('(')[0].trim()} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* AUC Table */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h3 className="text-sm font-medium text-text-secondary mb-4">AUC-ROC Summary Table</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-text-secondary text-xs">
                <th className="px-3 py-2 text-left">Attack Family</th>
                {models.map((mid) => (
                  <th key={mid} className="px-3 py-2 text-left" style={{ color: MODEL_COLORS[mid] }}>
                    {names[mid].split('(')[0].trim()}
                  </th>
                ))}
                <th className="px-3 py-2 text-left">Best</th>
              </tr>
            </thead>
            <tbody>
              {families.map((f, fi) => {
                const vals = models.map((mid) => roc[mid][fi])
                const bestIdx = vals.indexOf(Math.max(...vals))
                return (
                  <tr key={f} className="border-t border-bg-card/50 hover:bg-bg-card/20">
                    <td className="px-3 py-2 font-medium">{f}</td>
                    {models.map((mid, mi) => (
                      <td
                        key={mid}
                        className={`px-3 py-2 font-mono text-xs ${mi === bestIdx ? 'text-accent-green font-bold' : ''}`}
                      >
                        {(roc[mid][fi] * 100).toFixed(2)}%
                      </td>
                    ))}
                    <td className="px-3 py-2 text-xs font-medium" style={{ color: MODEL_COLORS[models[bestIdx]] }}>
                      {names[models[bestIdx]].split('(')[0].trim()}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
