import { useEffect, useState } from 'react'
import {
  BarChart, Bar, LineChart, Line, XAxis, YAxis, Tooltip, Legend,
  ResponsiveContainer, RadarChart, Radar, PolarGrid, PolarAngleAxis,
  PolarRadiusAxis, CartesianGrid,
} from 'recharts'
import { Loader2, TrendingUp, Shield, Target, ScatterChart as ScatterIcon } from 'lucide-react'
import { fetchAnalytics } from '../utils/api'

const MODEL_COLORS: Record<string, string> = {
  surrogate: '#3B82F6',
  neural_ode: '#A855F7',
  optimal_transport: '#22C55E',
  fedgtd: '#F59E0B',
  sde_tgnn: '#EF4444',
  cybersec_llm: '#06B6D4',
}

const ATTACK_COLORS: Record<string, string> = {
  fgsm: '#3B82F6', pgd: '#A855F7', deepfool: '#F59E0B', cw: '#EF4444',
}

const TT = { background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }

type Tab = 'performance' | 'robustness' | 'calibration' | 'roc'

const TABS: { key: Tab; label: string; icon: typeof TrendingUp }[] = [
  { key: 'performance', label: 'Performance', icon: TrendingUp },
  { key: 'robustness', label: 'Robustness', icon: Shield },
  { key: 'calibration', label: 'Calibration', icon: Target },
  { key: 'roc', label: 'ROC / AUC', icon: ScatterIcon },
]

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _cachedData: Record<string, any> | null = null

export default function ModelAnalyticsPanel({ compact }: { compact?: boolean }) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [data, setData] = useState<Record<string, any> | null>(_cachedData)
  const [tab, setTab] = useState<Tab>('performance')
  const [loading, setLoading] = useState(!_cachedData)
  const [selectedAttack, setSelectedAttack] = useState('fgsm')
  const [selectedModel, setSelectedModel] = useState('surrogate')

  useEffect(() => {
    if (_cachedData) return
    fetchAnalytics()
      .then((d) => { _cachedData = d; setData(d) })
      .catch(() => setData(null))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return (
    <div className="flex items-center gap-2 text-accent-blue text-sm py-8 justify-center">
      <Loader2 className="w-4 h-4 animate-spin" /> Loading model analytics...
    </div>
  )
  if (!data) return (
    <div className="text-text-secondary text-sm text-center py-4">
      Model analytics unavailable. Is the backend running?
    </div>
  )

  const models: string[] = data.models
  const names: Record<string, string> = data.model_names

  return (
    <div className={`space-y-4 ${compact ? '' : 'mt-2'}`}>
      {/* Tab bar */}
      <div className="overflow-x-auto -mx-1 px-1">
        <div className="flex gap-1 bg-bg-secondary rounded-lg p-1 border border-bg-card min-w-max">
          {TABS.map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
                tab === t.key
                  ? 'bg-accent-blue/15 text-accent-blue'
                  : 'text-text-secondary hover:text-text-primary hover:bg-bg-card/50'
              }`}
            >
              <t.icon className="w-3 h-3" />
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {tab === 'performance' && <PerformanceSection data={data} models={models} names={names} />}
      {tab === 'robustness' && (
        <RobustnessSection data={data} models={models} names={names}
          selectedAttack={selectedAttack} setSelectedAttack={setSelectedAttack}
          selectedModel={selectedModel} setSelectedModel={setSelectedModel} />
      )}
      {tab === 'calibration' && <CalibrationSection data={data} models={models} names={names} />}
      {tab === 'roc' && <ROCSection data={data} models={models} names={names} />}
    </div>
  )
}

/* ─── Performance ──────────────────────────────────────────────────────── */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function PerformanceSection({ data, models, names }: { data: any; models: string[]; names: Record<string, string> }) {
  const perf = data.performance
  const metrics = ['accuracy', 'precision', 'recall', 'f1', 'auc_roc']

  const barData = metrics.map((m) => {
    const row: Record<string, unknown> = { metric: m.toUpperCase().replace('_', ' ') }
    models.forEach((mid) => { row[mid] = +(perf[mid][m] * 100).toFixed(2) })
    return row
  })

  const radarData = metrics.map((m) => {
    const row: Record<string, unknown> = { metric: m === 'auc_roc' ? 'AUC-ROC' : m.charAt(0).toUpperCase() + m.slice(1) }
    models.forEach((mid) => { row[mid] = +(perf[mid][m] * 100).toFixed(1) })
    return row
  })

  const tableMetrics = ['accuracy', 'precision', 'recall', 'f1', 'auc_roc', 'ece', 'inference_ms', 'params_k']
  const tableHeaders = ['Model', 'Accuracy', 'Precision', 'Recall', 'F1', 'AUC-ROC', 'ECE', 'Inf. (ms)', 'Params (K)']

  const pcf1 = data.per_class_f1
  const classes: string[] = pcf1?.classes || []

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Model Comparison (% Score)</h3>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={barData} layout="vertical" margin={{ left: 80 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis type="number" domain={[85, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} />
              <YAxis type="category" dataKey="metric" tick={{ fill: '#94A3B8', fontSize: 10 }} width={75} />
              <Tooltip contentStyle={TT} />
              <Legend wrapperStyle={{ fontSize: 10 }} />
              {models.map((mid) => (
                <Bar key={mid} dataKey={mid} fill={MODEL_COLORS[mid]} name={names[mid].split('(')[0].trim()} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Radar — Multi-Metric Overview</h3>
          <ResponsiveContainer width="100%" height={280}>
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
                {tableHeaders.map((h) => <th key={h} className="px-3 py-2 text-left">{h}</th>)}
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
                    const allVals = models.map((m2) => perf[m2][m])
                    const isBest = m === 'ece' || m === 'inference_ms'
                      ? val === Math.min(...allVals)
                      : val === Math.max(...allVals)
                    return <td key={m} className={`px-3 py-2 font-mono text-xs ${isBest ? 'text-accent-green font-bold' : ''}`}>{display}</td>
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Per-class F1 heatmap */}
      {classes.length > 0 && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Per-Class F1 Scores (Attack Families)</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr>
                  <th className="px-2 py-1 text-left text-text-secondary">Model</th>
                  {classes.map((c) => (
                    <th key={c} className="px-1 py-1 text-center text-text-secondary" style={{ writingMode: 'vertical-lr', height: 80 }}>{c}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {models.map((mid) => (
                  <tr key={mid} className="border-t border-bg-card/30">
                    <td className="px-2 py-1 font-medium whitespace-nowrap" style={{ color: MODEL_COLORS[mid] }}>
                      {names[mid].split('(')[0].trim()}
                    </td>
                    {(pcf1[mid] as number[]).map((v: number, i: number) => {
                      const intensity = Math.round((v - 0.85) / 0.15 * 255)
                      const bg = `rgba(34, 197, 94, ${Math.max(0, intensity) / 255 * 0.6})`
                      return <td key={i} className="px-1 py-1 text-center font-mono" style={{ background: bg }}>{(v * 100).toFixed(0)}</td>
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

/* ─── Robustness ───────────────────────────────────────────────────────── */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function RobustnessSection({ data, models, names, selectedAttack, setSelectedAttack, selectedModel, setSelectedModel }: {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any; models: string[]; names: Record<string, string>
  selectedAttack: string; setSelectedAttack: (v: string) => void
  selectedModel: string; setSelectedModel: (v: string) => void
}) {
  const rob = data.robustness
  const eps: number[] = rob.epsilons
  const attacks: string[] = rob.attacks
  const attackNames: Record<string, string> = rob.attack_names

  const perAttackData = eps.map((e, i) => {
    const row: Record<string, unknown> = { epsilon: e }
    models.forEach((mid) => { row[mid] = +(rob[selectedAttack][mid][i] * 100).toFixed(2) })
    return row
  })

  const perModelData = eps.map((e, i) => {
    const row: Record<string, unknown> = { epsilon: e }
    attacks.forEach((atk) => { row[atk] = +(rob[atk][selectedModel][i] * 100).toFixed(2) })
    return row
  })

  const aucScores = (atk: string, mid: string) => {
    const vals: number[] = rob[atk][mid]
    let area = 0
    for (let i = 1; i < eps.length; i++) area += (eps[i] - eps[i - 1]) * (vals[i] + vals[i - 1]) / 2
    return +(area / eps[eps.length - 1] * 100).toFixed(2)
  }

  const ranking = models
    .map((mid) => ({ mid, model: names[mid].split('(')[0].trim(), score: aucScores(selectedAttack, mid) }))
    .sort((a, b) => b.score - a.score)

  return (
    <div className="space-y-4">
      {/* Attack selector */}
      <div className="flex gap-2 flex-wrap">
        {attacks.map((atk) => (
          <button key={atk} onClick={() => setSelectedAttack(atk)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors border ${
              selectedAttack === atk ? 'text-white border-transparent' : 'bg-bg-card/50 text-text-secondary hover:text-text-primary border-bg-card'
            }`}
            style={selectedAttack === atk ? { background: ATTACK_COLORS[atk] } : {}}
          >{attackNames[atk]}</button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Accuracy Under {attackNames[selectedAttack]}</h3>
          <ResponsiveContainer width="100%" height={320}>
            <LineChart data={perAttackData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="epsilon" tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Perturbation ε', position: 'insideBottom', offset: -5, fill: '#94A3B8', fontSize: 11 }} />
              <YAxis domain={[55, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Accuracy %', angle: -90, position: 'insideLeft', fill: '#94A3B8', fontSize: 11 }} />
              <Tooltip contentStyle={TT} formatter={(v: number) => `${v.toFixed(2)}%`} />
              <Legend wrapperStyle={{ fontSize: 10 }} />
              {models.map((mid) => (
                <Line key={mid} type="monotone" dataKey={mid} stroke={MODEL_COLORS[mid]} strokeWidth={2} dot={{ r: 3 }} name={names[mid].split('(')[0].trim()} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Robustness Ranking — {selectedAttack.toUpperCase()}</h3>
          <div className="space-y-3">
            {ranking.map((r, i) => (
              <div key={r.mid} className="flex items-center gap-3">
                <span className={`text-lg font-bold ${i === 0 ? 'text-accent-green' : 'text-text-secondary'}`}>#{i + 1}</span>
                <div className="flex-1">
                  <div className="text-sm font-medium" style={{ color: MODEL_COLORS[r.mid] }}>{r.model}</div>
                  <div className="w-full bg-bg-card rounded-full h-2 mt-1">
                    <div className="h-2 rounded-full" style={{ width: `${r.score}%`, background: MODEL_COLORS[r.mid] }} />
                  </div>
                </div>
                <span className="text-xs font-mono text-text-secondary">{r.score}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Per-model multi-attack overlay */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
            <h3 className="text-sm font-medium text-text-secondary">All Attacks on {names[selectedModel]?.split('(')[0].trim()}</h3>
            <div className="flex gap-1 flex-wrap">
              {models.map((mid) => (
                <button key={mid} onClick={() => setSelectedModel(mid)}
                  className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                    selectedModel === mid ? 'text-white' : 'bg-bg-card/50 text-text-secondary hover:text-text-primary'
                  }`}
                  style={selectedModel === mid ? { background: MODEL_COLORS[mid] } : {}}
                >{names[mid].split('(')[0].trim().split(' ')[0]}</button>
              ))}
            </div>
          </div>
          <ResponsiveContainer width="100%" height={320}>
            <LineChart data={perModelData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="epsilon" tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Perturbation ε', position: 'insideBottom', offset: -5, fill: '#94A3B8', fontSize: 11 }} />
              <YAxis domain={[55, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Accuracy %', angle: -90, position: 'insideLeft', fill: '#94A3B8', fontSize: 11 }} />
              <Tooltip contentStyle={TT} formatter={(v: number) => `${v.toFixed(2)}%`} />
              <Legend wrapperStyle={{ fontSize: 10 }} />
              {attacks.map((atk) => (
                <Line key={atk} type="monotone" dataKey={atk} stroke={ATTACK_COLORS[atk]} strokeWidth={2} dot={{ r: 3 }} name={attackNames[atk].split('(')[0].trim()} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Attack Severity (Accuracy at ε=0.30)</h3>
          <div className="space-y-4">
            {attacks
              .map((atk) => {
                const vals: number[] = rob[atk][selectedModel]
                return { atk, name: attackNames[atk], final: vals[vals.length - 1], drop: vals[0] - vals[vals.length - 1] }
              })
              .sort((a, b) => a.final - b.final)
              .map((a, i) => (
                <div key={a.atk}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="font-medium" style={{ color: ATTACK_COLORS[a.atk] }}>
                      {i === 0 && <span className="text-accent-red mr-1">Hardest</span>}
                      {a.name.split('(')[0].trim()}
                    </span>
                    <span className="font-mono text-accent-red">-{(a.drop * 100).toFixed(1)}%</span>
                  </div>
                  <div className="w-full bg-bg-card rounded-full h-2">
                    <div className="h-2 rounded-full" style={{ width: `${a.final * 100}%`, background: ATTACK_COLORS[a.atk] }} />
                  </div>
                  <div className="text-right text-xs font-mono text-text-secondary mt-0.5">{(a.final * 100).toFixed(1)}%</div>
                </div>
              ))}
          </div>
        </div>
      </div>

      {/* Cross-attack table */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h3 className="text-sm font-medium text-text-secondary mb-4">Cross-Attack Accuracy at Key ε Levels</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-text-secondary">
                <th className="px-2 py-2 text-left">Model</th>
                <th className="px-2 py-2 text-left">Attack</th>
                <th className="px-2 py-2 text-center">ε=0</th>
                <th className="px-2 py-2 text-center">ε=0.10</th>
                <th className="px-2 py-2 text-center">ε=0.20</th>
                <th className="px-2 py-2 text-center">ε=0.30</th>
                <th className="px-2 py-2 text-center">AUC</th>
              </tr>
            </thead>
            <tbody>
              {models.map((mid) =>
                attacks.map((atk, ai) => {
                  const vals: number[] = rob[atk][mid]
                  const auc = aucScores(atk, mid)
                  const bestAuc = Math.max(...attacks.map((a) => aucScores(a, mid)))
                  const worstAuc = Math.min(...attacks.map((a) => aucScores(a, mid)))
                  return (
                    <tr key={`${mid}-${atk}`} className={`border-t border-bg-card/30 hover:bg-bg-card/20 ${ai === 0 ? 'border-t-bg-card' : ''}`}>
                      {ai === 0 && (
                        <td className="px-2 py-1.5 font-medium" style={{ color: MODEL_COLORS[mid] }} rowSpan={attacks.length}>
                          {names[mid].split('(')[0].trim()}
                        </td>
                      )}
                      <td className="px-2 py-1.5 font-medium" style={{ color: ATTACK_COLORS[atk] }}>{atk.toUpperCase()}</td>
                      <td className="px-2 py-1.5 text-center font-mono">{(vals[0] * 100).toFixed(1)}%</td>
                      <td className="px-2 py-1.5 text-center font-mono">{(vals[5] * 100).toFixed(1)}%</td>
                      <td className="px-2 py-1.5 text-center font-mono">{(vals[7] * 100).toFixed(1)}%</td>
                      <td className="px-2 py-1.5 text-center font-mono">{(vals[9] * 100).toFixed(1)}%</td>
                      <td className={`px-2 py-1.5 text-center font-mono font-bold ${auc === bestAuc ? 'text-accent-green' : auc === worstAuc ? 'text-accent-red' : ''}`}>{auc}</td>
                    </tr>
                  )
                }),
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

/* ─── Calibration ──────────────────────────────────────────────────────── */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function CalibrationSection({ data, models, names }: { data: any; models: string[]; names: Record<string, string> }) {
  const cal = data.calibration
  const bins: number[] = cal.bins
  const perf = data.performance

  const calData = bins.map((b, i) => {
    const row: Record<string, unknown> = { confidence: +b.toFixed(2), perfect: +b.toFixed(2) }
    models.forEach((mid) => { row[mid] = +((cal[mid]?.[i] ?? 0) * 100).toFixed(1) })
    return row
  })

  const eceRanking = models
    .map((mid) => ({ mid, model: names[mid].split('(')[0].trim(), ece: perf[mid].ece }))
    .sort((a, b) => a.ece - b.ece)

  // Privacy-accuracy data if available
  const privAcc = data.privacy_accuracy
  const dpLabels: string[] = privAcc?.dp_labels || []

  const privData = dpLabels.map((label, i) => {
    const row: Record<string, unknown> = { budget: label }
    models.forEach((mid) => { row[mid] = +((privAcc[mid]?.[i] ?? 0) * 100).toFixed(2) })
    return row
  })

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Reliability Diagram (Calibration)</h3>
          <ResponsiveContainer width="100%" height={320}>
            <LineChart data={calData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="confidence" tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Confidence', position: 'insideBottom', offset: -5, fill: '#94A3B8', fontSize: 11 }} />
              <YAxis domain={[0, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Accuracy %', angle: -90, position: 'insideLeft', fill: '#94A3B8', fontSize: 11 }} />
              <Tooltip contentStyle={TT} />
              <Legend wrapperStyle={{ fontSize: 10 }} />
              <Line type="linear" dataKey="perfect" stroke="#475569" strokeDasharray="5 5" dot={false} name="Perfect Calibration" strokeWidth={1} />
              {models.map((mid) => (
                <Line key={mid} type="monotone" dataKey={mid} stroke={MODEL_COLORS[mid]} strokeWidth={2} dot={{ r: 2 }} name={names[mid].split('(')[0].trim()} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">ECE Ranking (Lower is Better)</h3>
          <div className="space-y-4">
            {eceRanking.map((r, i) => (
              <div key={r.mid}>
                <div className="flex justify-between text-xs mb-1">
                  <span className="font-medium" style={{ color: MODEL_COLORS[r.mid] }}>
                    {i === 0 && <span className="text-accent-green mr-1">Best</span>}
                    {r.model}
                  </span>
                  <span className="font-mono">{r.ece.toFixed(4)}</span>
                </div>
                <div className="w-full bg-bg-card rounded-full h-2">
                  <div className="h-2 rounded-full" style={{
                    width: `${Math.min(100, r.ece / 0.08 * 100)}%`,
                    background: MODEL_COLORS[r.mid],
                  }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Privacy-Accuracy Trade-off */}
      {dpLabels.length > 0 && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Privacy-Accuracy Trade-off (Differential Privacy)</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={privData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="budget" tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Privacy Budget', position: 'insideBottom', offset: -5, fill: '#94A3B8', fontSize: 11 }} />
              <YAxis domain={[70, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Accuracy %', angle: -90, position: 'insideLeft', fill: '#94A3B8', fontSize: 11 }} />
              <Tooltip contentStyle={TT} formatter={(v: number) => `${v.toFixed(2)}%`} />
              <Legend wrapperStyle={{ fontSize: 10 }} />
              {models.map((mid) => (
                <Line key={mid} type="monotone" dataKey={mid} stroke={MODEL_COLORS[mid]} strokeWidth={2} dot={{ r: 3 }} name={names[mid].split('(')[0].trim()} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  )
}

/* ─── ROC / AUC ────────────────────────────────────────────────────────── */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function ROCSection({ data, models, names }: { data: any; models: string[]; names: Record<string, string> }) {
  const roc = data.roc_auc
  const families: string[] = roc.families

  const barData = families.map((f, fi) => {
    const row: Record<string, unknown> = { family: f }
    models.forEach((mid) => { row[mid] = +((roc[mid]?.[fi] ?? 0) * 100).toFixed(2) })
    return row
  })

  // Transfer learning data if available
  const tl = data.transfer_learning
  const datasets: string[] = tl?.datasets || []

  return (
    <div className="space-y-4">
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h3 className="text-sm font-medium text-text-secondary mb-4">AUC-ROC by Attack Family</h3>
        <ResponsiveContainer width="100%" height={350}>
          <BarChart data={barData} layout="vertical" margin={{ left: 100 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis type="number" domain={[90, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} tickFormatter={(v) => `${v}%`} />
            <YAxis type="category" dataKey="family" tick={{ fill: '#94A3B8', fontSize: 10 }} width={95} />
            <Tooltip contentStyle={TT} formatter={(v: number) => `${v.toFixed(2)}%`} />
            <Legend wrapperStyle={{ fontSize: 10 }} />
            {models.map((mid) => (
              <Bar key={mid} dataKey={mid} fill={MODEL_COLORS[mid]} name={names[mid].split('(')[0].trim()} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* AUC Summary Table */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h3 className="text-sm font-medium text-text-secondary mb-4">AUC-ROC Summary Table</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-text-secondary text-xs">
                <th className="px-3 py-2 text-left">Model</th>
                {families.map((f) => <th key={f} className="px-3 py-2 text-center">{f}</th>)}
                <th className="px-3 py-2 text-center">Average</th>
              </tr>
            </thead>
            <tbody>
              {models.map((mid) => {
                const vals = families.map((_, fi) => (roc[mid]?.[fi] ?? 0))
                const avg = vals.reduce((a, b) => a + b, 0) / vals.length
                return (
                  <tr key={mid} className="border-t border-bg-card/50 hover:bg-bg-card/20">
                    <td className="px-3 py-2 font-medium" style={{ color: MODEL_COLORS[mid] }}>{names[mid].split('(')[0].trim()}</td>
                    {vals.map((v, i) => {
                      const allForFamily = models.map((m2) => roc[m2]?.[i] ?? 0)
                      const isBest = v === Math.max(...allForFamily)
                      return <td key={i} className={`px-3 py-2 text-center font-mono text-xs ${isBest ? 'text-accent-green font-bold' : ''}`}>{(v * 100).toFixed(2)}%</td>
                    })}
                    <td className="px-3 py-2 text-center font-mono text-xs font-bold">{(avg * 100).toFixed(2)}%</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Transfer Learning Matrix */}
      {datasets.length > 0 && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Cross-Dataset Transfer Learning</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr>
                  <th className="px-2 py-1 text-left text-text-secondary">Train → Test</th>
                  {datasets.map((d) => <th key={d} className="px-2 py-1 text-center text-text-secondary">{d}</th>)}
                </tr>
              </thead>
              <tbody>
                {models.slice(0, 3).map((mid) => (
                  (tl[mid] as number[][])?.map((row: number[], ri: number) => (
                    <tr key={`${mid}-${ri}`} className={`border-t border-bg-card/30 ${ri === 0 ? 'border-t-bg-card' : ''}`}>
                      {ri === 0 && (
                        <td className="px-2 py-1 font-medium" style={{ color: MODEL_COLORS[mid] }} rowSpan={datasets.length}>
                          {names[mid].split('(')[0].trim()}
                        </td>
                      )}
                      {row.map((v: number, ci: number) => {
                        const isDiag = ri === ci
                        const bg = isDiag ? `rgba(59, 130, 246, ${0.15 + v * 0.3})` : `rgba(168, 85, 247, ${0.05 + v * 0.2})`
                        return <td key={ci} className="px-2 py-1 text-center font-mono" style={{ background: bg }}>{(v * 100).toFixed(1)}%</td>
                      })}
                    </tr>
                  ))
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
