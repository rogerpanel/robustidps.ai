import { useEffect, useState, useRef } from 'react'
import {
  BarChart, Bar, LineChart, Line, XAxis, YAxis, Tooltip, Legend,
  ResponsiveContainer, RadarChart, Radar, PolarGrid, PolarAngleAxis,
  PolarRadiusAxis, CartesianGrid,
} from 'recharts'
import { Loader2, Download, TrendingUp, Shield, GitBranch, Target, Lock, ScatterChart as ScatterIcon, Image, FileText, Presentation, ChevronDown } from 'lucide-react'
import { fetchAnalytics } from '../utils/api'
import { exportAsPNG, exportAsPDF, exportAsSlides } from '../utils/exportUtils'
import PageGuide from '../components/PageGuide'

const MODEL_COLORS: Record<string, string> = {
  surrogate: '#3B82F6',
  neural_ode: '#A855F7',
  optimal_transport: '#22C55E',
  fedgtd: '#F59E0B',
  sde_tgnn: '#EF4444',
  cybersec_llm: '#06B6D4',
}

type Tab = 'performance' | 'convergence' | 'robustness' | 'transfer' | 'calibration' | 'roc' | 'tradeoffs'

const TABS: { key: Tab; label: string; icon: typeof TrendingUp }[] = [
  { key: 'performance', label: 'Performance', icon: TrendingUp },
  { key: 'convergence', label: 'Convergence', icon: TrendingUp },
  { key: 'robustness', label: 'Robustness', icon: Shield },
  { key: 'tradeoffs', label: 'Privacy & Trade-offs', icon: Lock },
  { key: 'transfer', label: 'Transfer Learning', icon: GitBranch },
  { key: 'calibration', label: 'Calibration', icon: Target },
  { key: 'roc', label: 'ROC / AUC', icon: ScatterIcon },
]

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export default function Analytics() {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [data, setData] = useState<Record<string, any> | null>(null)
  const [tab, setTab] = useState<Tab>('performance')
  const [loading, setLoading] = useState(true)
  const [exportOpen, setExportOpen] = useState(false)
  const [exporting, setExporting] = useState(false)
  const contentRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    fetchAnalytics()
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false))
  }, [])

  // Close export menu on outside click
  useEffect(() => {
    if (!exportOpen) return
    const handleClick = () => setExportOpen(false)
    document.addEventListener('click', handleClick)
    return () => document.removeEventListener('click', handleClick)
  }, [exportOpen])

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

  const handleExportPNG = async () => {
    if (!contentRef.current) return
    setExporting(true)
    setExportOpen(false)
    try {
      await exportAsPNG(contentRef.current, `robustidps_${tab}.png`)
    } catch { /* ignore */ }
    setExporting(false)
  }

  const handleExportPDF = async () => {
    if (!contentRef.current) return
    setExporting(true)
    setExportOpen(false)
    try {
      await exportAsPDF(contentRef.current, `robustidps_${tab}.pdf`)
    } catch { /* ignore */ }
    setExporting(false)
  }

  const handleExportSlides = async () => {
    setExporting(true)
    setExportOpen(false)
    try {
      // Collect all chart sections from the current tab content
      const container = contentRef.current
      if (!container) return
      const sections = Array.from(container.querySelectorAll<HTMLElement>('.bg-bg-secondary, .bg-accent-purple\\/10, .bg-bg-card\\/30'))
      if (sections.length === 0) sections.push(container)
      await exportAsSlides(sections, 'robustidps_analytics_slides.pdf', `RobustIDPS.AI — ${TABS.find(t => t.key === tab)?.label ?? 'Analytics'}`)
    } catch { /* ignore */ }
    setExporting(false)
  }

  return (
    <div className="space-y-6">
      <PageGuide
        title="How to use Analytics & Evaluation"
        steps={[
          { title: 'Browse tabs', desc: 'Use the 7 tabs to compare all 5 dissertation models: Performance, Convergence, Robustness, Privacy, Transfer Learning, Calibration, and ROC/AUC.' },
          { title: 'Compare models', desc: 'Each chart shows all models side by side. Hover for exact values. Models are color-coded consistently across all tabs.' },
          { title: 'Export results', desc: 'Click "Export" to download as PNG image, PDF document, or PDF slides presentation for papers and talks.' },
        ]}
        tip="These are pre-computed benchmark metrics from the dissertation research. No file upload needed — this page always works."
      />

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <h1 className="text-xl md:text-2xl font-display font-bold">Analytics & Evaluation</h1>
        <div className="flex items-center gap-2 self-start sm:self-auto">
          {exporting && (
            <span className="flex items-center gap-1.5 text-xs text-accent-blue">
              <Loader2 className="w-3.5 h-3.5 animate-spin" /> Generating...
            </span>
          )}
          {/* Export dropdown */}
          <div className="relative">
            <button
              onClick={(e) => { e.stopPropagation(); setExportOpen(!exportOpen) }}
              className="flex items-center gap-2 px-3 py-1.5 text-xs bg-accent-blue/15 text-accent-blue rounded-lg hover:bg-accent-blue/25 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              Export
              <ChevronDown className="w-3 h-3" />
            </button>
            {exportOpen && (
              <div className="absolute right-0 top-full mt-1 w-56 bg-bg-secondary border border-bg-card rounded-lg shadow-xl z-50 overflow-hidden" onClick={(e) => e.stopPropagation()}>
                <button onClick={handleExportPNG} className="w-full flex items-center gap-3 px-4 py-2.5 text-xs text-text-primary hover:bg-bg-card/50 transition-colors">
                  <Image className="w-4 h-4 text-accent-green" />
                  <div className="text-left">
                    <div className="font-medium">Export as PNG</div>
                    <div className="text-text-secondary text-[10px]">Current tab as image</div>
                  </div>
                </button>
                <button onClick={handleExportPDF} className="w-full flex items-center gap-3 px-4 py-2.5 text-xs text-text-primary hover:bg-bg-card/50 transition-colors">
                  <FileText className="w-4 h-4 text-accent-red" />
                  <div className="text-left">
                    <div className="font-medium">Export as PDF</div>
                    <div className="text-text-secondary text-[10px]">Current tab as document</div>
                  </div>
                </button>
                <button onClick={handleExportSlides} className="w-full flex items-center gap-3 px-4 py-2.5 text-xs text-text-primary hover:bg-bg-card/50 transition-colors">
                  <Presentation className="w-4 h-4 text-accent-purple" />
                  <div className="text-left">
                    <div className="font-medium">Export as PDF Slides</div>
                    <div className="text-text-secondary text-[10px]">Each chart section as a slide</div>
                  </div>
                </button>
                <div className="border-t border-bg-card" />
                <button onClick={() => { downloadJSON(); setExportOpen(false) }} className="w-full flex items-center gap-3 px-4 py-2.5 text-xs text-text-primary hover:bg-bg-card/50 transition-colors">
                  <Download className="w-4 h-4 text-accent-blue" />
                  <div className="text-left">
                    <div className="font-medium">Export Raw JSON</div>
                    <div className="text-text-secondary text-[10px]">Full metrics data for analysis</div>
                  </div>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Tabs — horizontally scrollable on mobile */}
      <div className="overflow-x-auto -mx-3 px-3 md:mx-0 md:px-0">
        <div className="flex gap-1 bg-bg-secondary rounded-lg p-1 border border-bg-card min-w-max">
          {TABS.map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`flex items-center gap-2 px-3 py-2 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
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
      </div>

      <div ref={contentRef}>
      {tab === 'performance' && <PerformanceTab data={data} models={models} names={names} />}
      {tab === 'convergence' && <ConvergenceTab data={data} models={models} names={names} />}
      {tab === 'robustness' && <RobustnessTab data={data} models={models} names={names} />}
      {tab === 'tradeoffs' && <TradeoffsTab data={data} models={models} names={names} />}
      {tab === 'transfer' && <TransferTab data={data} models={models} names={names} />}
      {tab === 'calibration' && <CalibrationTab data={data} models={models} names={names} />}
      {tab === 'roc' && <ROCTab data={data} models={models} names={names} />}
      </div>
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
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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

const ATTACK_COLORS: Record<string, string> = {
  fgsm: '#3B82F6',
  pgd: '#A855F7',
  deepfool: '#F59E0B',
  cw: '#EF4444',
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function RobustnessTab({ data, models, names }: { data: any; models: string[]; names: Record<string, string> }) {
  const rob = data.robustness
  const eps: number[] = rob.epsilons
  const attacks: string[] = rob.attacks
  const attackNames: Record<string, string> = rob.attack_names
  const [selectedAttack, setSelectedAttack] = useState(attacks[0])
  const [selectedModel, setSelectedModel] = useState(models[0])

  // ── Data for per-attack chart (all models on one attack) ────────────
  const perAttackData = eps.map((e, i) => {
    const row: Record<string, unknown> = { epsilon: e }
    models.forEach((mid) => { row[mid] = +(rob[selectedAttack][mid][i] * 100).toFixed(2) })
    return row
  })

  // ── Data for per-model chart (all attacks on one model) ─────────────
  const perModelData = eps.map((e, i) => {
    const row: Record<string, unknown> = { epsilon: e }
    attacks.forEach((atk) => { row[atk] = +(rob[atk][selectedModel][i] * 100).toFixed(2) })
    return row
  })

  // ── Robustness AUC scores per attack ────────────────────────────────
  const aucScores = (atk: string, mid: string) => {
    const vals: number[] = rob[atk][mid]
    let area = 0
    for (let i = 1; i < eps.length; i++) {
      area += (eps[i] - eps[i - 1]) * (vals[i] + vals[i - 1]) / 2
    }
    return +(area / eps[eps.length - 1] * 100).toFixed(2)
  }

  // ── Ranking for current attack ──────────────────────────────────────
  const ranking = models
    .map((mid) => ({ mid, model: names[mid].split('(')[0].trim(), score: aucScores(selectedAttack, mid) }))
    .sort((a, b) => b.score - a.score)

  const ttStyle = { background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }

  return (
    <div className="space-y-6">
      {/* Attack selector */}
      <div className="flex gap-2 flex-wrap">
        {attacks.map((atk) => (
          <button
            key={atk}
            onClick={() => setSelectedAttack(atk)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors border ${
              selectedAttack === atk
                ? 'text-white border-transparent'
                : 'bg-bg-card/50 text-text-secondary hover:text-text-primary border-bg-card'
            }`}
            style={selectedAttack === atk ? { background: ATTACK_COLORS[atk] } : {}}
          >
            {attackNames[atk]}
          </button>
        ))}
      </div>

      {/* Row 1: Per-attack curve + ranking */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">
            Accuracy Under {attackNames[selectedAttack]}
          </h3>
          <ResponsiveContainer width="100%" height={350}>
            <LineChart data={perAttackData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="epsilon" tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Perturbation \u03B5', position: 'insideBottom', offset: -5, fill: '#94A3B8', fontSize: 11 }} />
              <YAxis domain={[55, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Accuracy %', angle: -90, position: 'insideLeft', fill: '#94A3B8', fontSize: 11 }} />
              <Tooltip contentStyle={ttStyle} formatter={(v: number) => `${v.toFixed(2)}%`} />
              <Legend wrapperStyle={{ fontSize: 10 }} />
              {models.map((mid) => (
                <Line key={mid} type="monotone" dataKey={mid} stroke={MODEL_COLORS[mid]} strokeWidth={2} dot={{ r: 3 }} name={names[mid].split('(')[0].trim()} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">
            Robustness Ranking — {selectedAttack.toUpperCase()}
          </h3>
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

      {/* Row 2: Per-model multi-attack overlay */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
            <h3 className="text-sm font-medium text-text-secondary">
              All 4 Attacks on {names[selectedModel].split('(')[0].trim()}
            </h3>
            <div className="flex gap-1">
              {models.map((mid) => (
                <button
                  key={mid}
                  onClick={() => setSelectedModel(mid)}
                  className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                    selectedModel === mid ? 'text-white' : 'bg-bg-card/50 text-text-secondary hover:text-text-primary'
                  }`}
                  style={selectedModel === mid ? { background: MODEL_COLORS[mid] } : {}}
                >
                  {names[mid].split('(')[0].trim().split(' ')[0]}
                </button>
              ))}
            </div>
          </div>
          <ResponsiveContainer width="100%" height={350}>
            <LineChart data={perModelData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="epsilon" tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Perturbation \u03B5', position: 'insideBottom', offset: -5, fill: '#94A3B8', fontSize: 11 }} />
              <YAxis domain={[55, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Accuracy %', angle: -90, position: 'insideLeft', fill: '#94A3B8', fontSize: 11 }} />
              <Tooltip contentStyle={ttStyle} formatter={(v: number) => `${v.toFixed(2)}%`} />
              <Legend wrapperStyle={{ fontSize: 10 }} />
              {attacks.map((atk) => (
                <Line key={atk} type="monotone" dataKey={atk} stroke={ATTACK_COLORS[atk]} strokeWidth={2} dot={{ r: 3 }} name={attackNames[atk].split('(')[0].trim()} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Attack severity ranking for selected model */}
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Attack Severity (Accuracy at {'\u03B5'}=0.30)</h3>
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

      {/* Row 3: Cross-attack summary table */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h3 className="text-sm font-medium text-text-secondary mb-4">
          Cross-Attack Accuracy Comparison at Key {'\u03B5'} Levels
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-text-secondary">
                <th className="px-2 py-2 text-left">Model</th>
                <th className="px-2 py-2 text-left">Attack</th>
                <th className="px-2 py-2 text-center">{'\u03B5'}=0</th>
                <th className="px-2 py-2 text-center">{'\u03B5'}=0.05</th>
                <th className="px-2 py-2 text-center">{'\u03B5'}=0.10</th>
                <th className="px-2 py-2 text-center">{'\u03B5'}=0.20</th>
                <th className="px-2 py-2 text-center">{'\u03B5'}=0.30</th>
                <th className="px-2 py-2 text-center">Max Drop</th>
                <th className="px-2 py-2 text-center">AUC Score</th>
              </tr>
            </thead>
            <tbody>
              {models.map((mid) =>
                attacks.map((atk, ai) => {
                  const vals: number[] = rob[atk][mid]
                  const clean = vals[0]
                  const maxDrop = clean - vals[vals.length - 1]
                  const auc = aucScores(atk, mid)
                  // Best AUC across attacks for this model
                  const bestAuc = Math.max(...attacks.map((a) => aucScores(a, mid)))
                  const worstAuc = Math.min(...attacks.map((a) => aucScores(a, mid)))
                  return (
                    <tr
                      key={`${mid}-${atk}`}
                      className={`border-t border-bg-card/30 hover:bg-bg-card/20 ${ai === 0 ? 'border-t-bg-card' : ''}`}
                    >
                      {ai === 0 && (
                        <td className="px-2 py-1.5 font-medium" style={{ color: MODEL_COLORS[mid] }} rowSpan={attacks.length}>
                          {names[mid].split('(')[0].trim()}
                        </td>
                      )}
                      <td className="px-2 py-1.5 font-medium" style={{ color: ATTACK_COLORS[atk] }}>
                        {atk.toUpperCase()}
                      </td>
                      <td className="px-2 py-1.5 text-center font-mono">{(clean * 100).toFixed(1)}%</td>
                      <td className="px-2 py-1.5 text-center font-mono">{(vals[3] * 100).toFixed(1)}%</td>
                      <td className="px-2 py-1.5 text-center font-mono">{(vals[5] * 100).toFixed(1)}%</td>
                      <td className="px-2 py-1.5 text-center font-mono">{(vals[7] * 100).toFixed(1)}%</td>
                      <td className="px-2 py-1.5 text-center font-mono">{(vals[9] * 100).toFixed(1)}%</td>
                      <td className="px-2 py-1.5 text-center font-mono text-accent-red">-{(maxDrop * 100).toFixed(1)}%</td>
                      <td className={`px-2 py-1.5 text-center font-mono font-bold ${auc === bestAuc ? 'text-accent-green' : auc === worstAuc ? 'text-accent-red' : ''}`}>
                        {auc}
                      </td>
                    </tr>
                  )
                }),
              )}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-text-secondary mt-3">
          Green AUC = best resilience for that model. Red = most vulnerable attack vector.
          C&W consistently degrades accuracy the most, while FGSM is the least effective.
        </p>
      </div>
    </div>
  )
}

/* ═══════════════════════ 3b. Privacy & Trade-offs ════════════════════════ */
/*
 * Master Problem 2: Joint optimisation of robustness–accuracy–privacy.
 * This tab proves that these three are competing resources whose
 * allocation must be optimised jointly.
 */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function TradeoffsTab({ data, models, names }: { data: any; models: string[]; names: Record<string, string> }) {
  const pa = data.privacy_accuracy
  const pr = data.privacy_robustness
  const cost = data.computational_cost
  const pareto = data.pareto_frontier
  const dpLabels: string[] = pa.dp_labels

  // Attack selector for privacy-robustness chart
  const prAttacks: string[] = pr.attacks || ['fgsm']
  const prAttackNames: Record<string, string> = pr.attack_names || { fgsm: 'FGSM' }
  const [selectedAttack, setSelectedAttack] = useState(prAttacks[0])

  const ttStyle = { background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }

  // ── Privacy-Accuracy curve data ─────────────────────────────────────
  const paData = dpLabels.map((label, i) => {
    const row: Record<string, unknown> = { dp: label }
    models.forEach((mid) => { row[mid] = +(pa[mid][i] * 100).toFixed(2) })
    return row
  })

  // ── Privacy-Robustness curve data (selected attack) ────────────────
  const prAttackData = pr[selectedAttack] || pr
  const prData = dpLabels.map((label, i) => {
    const row: Record<string, unknown> = { dp: label }
    models.forEach((mid) => {
      const src = prAttackData[mid]
      row[mid] = src ? +(src[i] * 100).toFixed(2) : 0
    })
    return row
  })

  // ── Privacy utility loss (accuracy drop from no-DP to strongest DP) ─
  const utilityLoss = models.map((mid) => {
    const clean = pa[mid][0]
    const priv = pa[mid][pa[mid].length - 1]
    return {
      model: names[mid].split('(')[0].trim(),
      mid,
      clean: +(clean * 100).toFixed(1),
      private: +(priv * 100).toFixed(1),
      drop: +((clean - priv) * 100).toFixed(1),
    }
  }).sort((a, b) => a.drop - b.drop)

  // ── Pareto scatter data ─────────────────────────────────────────────
  const regimes: string[] = pareto.regimes

  // ── Computational cost bar data ─────────────────────────────────────
  const costMetrics = ['params_k', 'flops_m', 'train_time_min', 'inference_ms', 'memory_mb', 'energy_j']
  const costLabels = ['Params (K)', 'FLOPs (M)', 'Train (min)', 'Inference (ms)', 'Memory (MB)', 'Energy (J)']

  return (
    <div className="space-y-6">
      {/* Header callout */}
      <div className="bg-accent-purple/10 border border-accent-purple/30 rounded-xl p-4">
        <h3 className="text-sm font-bold text-accent-purple mb-1">
          Master Problem 2: Robustness–Accuracy–Privacy Trade-off
        </h3>
        <p className="text-xs text-text-secondary">
          No single model dominates all three axes simultaneously. Increasing differential privacy
          (lower ε<sub>dp</sub>) degrades both clean accuracy and adversarial robustness, but models
          with domain adaptation (Optimal Transport) and federated aggregation (FedGTD) are
          most resilient to the privacy-induced utility loss.
        </p>
      </div>

      {/* Row 1: Privacy-Accuracy + Privacy-Robustness */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Privacy–Accuracy Trade-off (DP-SGD)</h3>
          <ResponsiveContainer width="100%" height={320}>
            <LineChart data={paData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="dp" tick={{ fill: '#94A3B8', fontSize: 9 }} label={{ value: 'Privacy Budget ε_dp', position: 'insideBottom', offset: -5, fill: '#94A3B8', fontSize: 10 }} />
              <YAxis domain={[70, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Accuracy %', angle: -90, position: 'insideLeft', fill: '#94A3B8', fontSize: 10 }} />
              <Tooltip contentStyle={ttStyle} formatter={(v: number) => `${v.toFixed(2)}%`} />
              <Legend wrapperStyle={{ fontSize: 9 }} />
              {models.map((mid) => (
                <Line key={mid} type="monotone" dataKey={mid} stroke={MODEL_COLORS[mid]} strokeWidth={2} dot={{ r: 3 }} name={names[mid].split('(')[0].trim()} />
              ))}
            </LineChart>
          </ResponsiveContainer>
          <p className="text-xs text-text-secondary mt-2">
            Left = no privacy (ε=∞). Right = strong privacy (ε=1). Lower ε means more noise
            via DP-SGD, reducing accuracy. OT retains the most utility under strong DP.
          </p>
        </div>

        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-text-secondary">
              Privacy–Robustness Trade-off (ε<sub>adv</sub>=0.10)
            </h3>
          </div>
          {/* Attack selector tabs */}
          <div className="flex gap-1 mb-4 flex-wrap">
            {prAttacks.map((atk) => {
              const shortName = (prAttackNames[atk] || atk).split('(')[0].trim()
              return (
                <button
                  key={atk}
                  onClick={() => setSelectedAttack(atk)}
                  className={`px-2.5 py-1 rounded text-[10px] font-medium transition-colors ${
                    selectedAttack === atk
                      ? 'bg-accent-blue text-white'
                      : 'bg-bg-card/50 text-text-secondary hover:text-text-primary hover:bg-bg-card'
                  }`}
                >
                  {shortName}
                </button>
              )
            })}
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={prData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="dp" tick={{ fill: '#94A3B8', fontSize: 9 }} label={{ value: 'Privacy Budget ε_dp', position: 'insideBottom', offset: -5, fill: '#94A3B8', fontSize: 10 }} />
              <YAxis domain={[55, 95]} tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Adv. Accuracy %', angle: -90, position: 'insideLeft', fill: '#94A3B8', fontSize: 10 }} />
              <Tooltip contentStyle={ttStyle} formatter={(v: number) => `${v.toFixed(2)}%`} />
              <Legend wrapperStyle={{ fontSize: 9 }} />
              {models.map((mid) => (
                <Line key={mid} type="monotone" dataKey={mid} stroke={MODEL_COLORS[mid]} strokeWidth={2} dot={{ r: 3 }} name={names[mid].split('(')[0].trim()} />
              ))}
            </LineChart>
          </ResponsiveContainer>
          <p className="text-xs text-text-secondary mt-2">
            Adversarial accuracy under <strong>{(prAttackNames[selectedAttack] || selectedAttack).split('(')[0].trim()}</strong> (ε<sub>adv</sub>=0.10) at each DP level.
            {selectedAttack === 'cw' && ' C&W is the strongest attack — lowest accuracy across all DP levels.'}
            {selectedAttack === 'fgsm' && ' FGSM is the fastest but weakest attack.'}
            {selectedAttack === 'pgd' && ' PGD iterates 20 steps, consistently ~2-3% worse than FGSM.'}
            {selectedAttack === 'deepfool' && ' DeepFool finds minimal perturbations with outsized impact at low ε.'}
          </p>
        </div>
      </div>

      {/* Row 2: Privacy utility loss ranking + Pareto frontier */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Privacy Resilience Ranking</h3>
          <p className="text-xs text-text-secondary mb-3">Accuracy drop from ε=∞ to ε=1 (lower = more resilient)</p>
          <div className="space-y-3">
            {utilityLoss.map((u, i) => (
              <div key={u.mid}>
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="font-medium" style={{ color: MODEL_COLORS[u.mid] }}>
                    {i === 0 && <span className="text-accent-green mr-1">Best</span>}
                    {u.model}
                  </span>
                  <span className="font-mono">
                    {u.clean}% → {u.private}%
                    <span className="text-accent-red ml-1">(-{u.drop}%)</span>
                  </span>
                </div>
                <div className="w-full bg-bg-card rounded-full h-2">
                  <div className="h-2 rounded-full" style={{ width: `${(u.drop / 20) * 100}%`, background: MODEL_COLORS[u.mid] }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Pareto frontier table */}
        <div className="lg:col-span-2 bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">
            Pareto Frontier — Joint Robustness-Accuracy-Privacy Operating Points
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-text-secondary">
                  <th className="px-2 py-2 text-left">Model</th>
                  <th className="px-2 py-2 text-left">Regime</th>
                  <th className="px-2 py-2 text-center">Accuracy</th>
                  <th className="px-2 py-2 text-center">Adv. Robustness</th>
                  <th className="px-2 py-2 text-center">ε<sub>dp</sub></th>
                  <th className="px-2 py-2 text-center">Inference (ms)</th>
                  <th className="px-2 py-2 text-center">Trade-off Score</th>
                </tr>
              </thead>
              <tbody>
                {models.map((mid) =>
                  (pareto[mid] as Array<{accuracy: number; robustness: number; privacy_eps: number | null; cost_ms: number}>).map((pt, ri) => {
                    // Composite score: accuracy + robustness + privacy_reward - cost_penalty
                    const privReward = pt.privacy_eps == null ? 0 : (1 / pt.privacy_eps) * 100
                    const composite = +((pt.accuracy + pt.robustness) / 2 + privReward - pt.cost_ms * 0.5).toFixed(1)
                    return (
                      <tr
                        key={`${mid}-${ri}`}
                        className={`border-t border-bg-card/30 hover:bg-bg-card/20 ${ri === 0 ? 'border-t-bg-card' : ''}`}
                      >
                        {ri === 0 && (
                          <td className="px-2 py-1.5 font-medium" style={{ color: MODEL_COLORS[mid] }} rowSpan={regimes.length}>
                            {names[mid].split('(')[0].trim()}
                          </td>
                        )}
                        <td className="px-2 py-1.5">{regimes[ri]}</td>
                        <td className="px-2 py-1.5 text-center font-mono">{pt.accuracy.toFixed(1)}%</td>
                        <td className="px-2 py-1.5 text-center font-mono">{pt.robustness.toFixed(1)}%</td>
                        <td className="px-2 py-1.5 text-center font-mono">
                          {pt.privacy_eps == null ? '∞' : pt.privacy_eps.toFixed(1)}
                        </td>
                        <td className="px-2 py-1.5 text-center font-mono">{pt.cost_ms.toFixed(1)}</td>
                        <td className={`px-2 py-1.5 text-center font-mono font-bold ${
                          ri === regimes.length - 1 ? 'text-accent-purple' : ''
                        }`}>
                          {composite}
                        </td>
                      </tr>
                    )
                  }),
                )}
              </tbody>
            </table>
          </div>
          <p className="text-xs text-text-secondary mt-3">
            Trade-off Score = (Accuracy + Robustness)/2 + Privacy_Reward - Cost_Penalty.
            No model dominates at all operating points — this validates Master Problem 2.
          </p>
        </div>
      </div>

      {/* Row 3: Computational cost comparison */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h3 className="text-sm font-medium text-text-secondary mb-4">Computational Cost Comparison</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-text-secondary text-xs">
                <th className="px-3 py-2 text-left">Model</th>
                {costLabels.map((l) => (
                  <th key={l} className="px-3 py-2 text-center">{l}</th>
                ))}
                <th className="px-3 py-2 text-center">Accuracy / ms</th>
              </tr>
            </thead>
            <tbody>
              {models.map((mid) => {
                const c = cost[mid]
                const perf = data.performance[mid]
                const effRatio = (perf.accuracy * 100 / c.inference_ms).toFixed(1)
                return (
                  <tr key={mid} className="border-t border-bg-card/50 hover:bg-bg-card/20">
                    <td className="px-3 py-2 font-medium" style={{ color: MODEL_COLORS[mid] }}>
                      {names[mid].split('(')[0].trim()}
                    </td>
                    {costMetrics.map((m) => {
                      const val = c[m]
                      const allVals = models.map((m2) => cost[m2][m])
                      const isBest = val === Math.min(...allVals)
                      return (
                        <td key={m} className={`px-3 py-2 text-center font-mono text-xs ${isBest ? 'text-accent-green font-bold' : ''}`}>
                          {val}
                        </td>
                      )
                    })}
                    <td className="px-3 py-2 text-center font-mono text-xs font-bold text-accent-blue">
                      {effRatio}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-text-secondary mt-3">
          Green = lowest cost in category. Accuracy/ms = efficiency ratio (higher = better).
          SurrogateIDS achieves the best efficiency due to its lightweight MLP architecture.
        </p>
      </div>

      {/* Row 4: Master Problem summary */}
      <div className="bg-bg-card/30 rounded-xl p-5 border border-accent-purple/20">
        <h3 className="text-sm font-bold text-accent-purple mb-3">
          Dissertation Validation: Both Master Problems Covered
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs text-text-secondary">
          <div>
            <div className="font-semibold text-text-primary mb-1">Master Problem 1: Adversarial Resilience</div>
            <ul className="space-y-1 list-disc list-inside">
              <li>4 adversarial attacks evaluated (FGSM, PGD, DeepFool, C&W)</li>
              <li>Accuracy curves across 10 perturbation levels (ε=0 to 0.30)</li>
              <li>AUC-based robustness ranking per model per attack</li>
              <li>Cross-attack comparison table with max degradation</li>
            </ul>
          </div>
          <div>
            <div className="font-semibold text-text-primary mb-1">Master Problem 2: Joint Trade-off Optimisation</div>
            <ul className="space-y-1 list-disc list-inside">
              <li>Privacy–accuracy curves (DP-SGD at 8 privacy levels, ε=∞ to ε=1)</li>
              <li>Privacy–robustness compound degradation analysis</li>
              <li>Pareto frontier across 4 operating regimes per model</li>
              <li>Computational cost: params, FLOPs, latency, memory, energy</li>
              <li>No model dominates all axes — confirms trade-off is fundamental</li>
            </ul>
          </div>
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

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-bg-secondary rounded-xl p-5 border border-bg-card">
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
