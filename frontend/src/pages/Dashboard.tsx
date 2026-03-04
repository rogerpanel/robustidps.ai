import { useState, useMemo } from 'react'
import {
  Activity, ShieldAlert, ShieldCheck, Gauge, Ban, Search as SearchIcon,
  Eye, AlertTriangle, ChevronDown, ChevronRight, Download, Globe,
} from 'lucide-react'
import StatCard from '../components/StatCard'
import AttackDistribution from '../components/AttackDistribution'
import ConfidenceHistogram from '../components/ConfidenceHistogram'
import PageGuide from '../components/PageGuide'
import { SAMPLE_RESULTS } from '../utils/api'
import { useAnalysis } from '../hooks/useAnalysis'

/* ── Types ─────────────────────────────────────────────────────────────── */

interface Prediction {
  flow_id: number
  src_ip: string
  dst_ip: string
  label_predicted: string
  label_true?: string | null
  confidence: number
  severity: string
  epistemic_uncertainty?: number
  aleatoric_uncertainty?: number
  total_uncertainty?: number
}

interface Results {
  job_id?: string
  n_flows: number
  n_threats: number
  n_benign: number
  ece: number
  predictions: Prediction[]
  attack_distribution: Record<string, number>
}

/* ── Severity config ───────────────────────────────────────────────────── */

const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'benign'] as const

const SEV_CFG: Record<string, { bg: string; text: string; border: string; icon: typeof Ban; action: string; actionDesc: string }> = {
  critical: { bg: 'bg-accent-red/10', text: 'text-accent-red', border: 'border-accent-red/30', icon: Ban, action: 'BLOCK', actionDesc: 'Block source IP & alert SOC L3' },
  high: { bg: 'bg-accent-orange/10', text: 'text-accent-orange', border: 'border-accent-orange/30', icon: AlertTriangle, action: 'QUARANTINE', actionDesc: 'Isolate host for forensic analysis' },
  medium: { bg: 'bg-accent-amber/10', text: 'text-accent-amber', border: 'border-accent-amber/30', icon: SearchIcon, action: 'INVESTIGATE', actionDesc: 'Queue for SOC L2 triage' },
  low: { bg: 'bg-accent-green/10', text: 'text-accent-green', border: 'border-accent-green/30', icon: Eye, action: 'MONITOR', actionDesc: 'Log & monitor for escalation' },
  benign: { bg: 'bg-accent-blue/10', text: 'text-accent-blue', border: 'border-accent-blue/30', icon: ShieldCheck, action: 'ALLOW', actionDesc: 'Normal traffic' },
}

/* ── Dashboard ─────────────────────────────────────────────────────────── */

export default function Dashboard() {
  const { results: analysisResults } = useAnalysis()
  const data = (analysisResults as unknown as Results) || (SAMPLE_RESULTS as unknown as Results)
  const predictions = data.predictions ?? []

  const benignPct = data.n_flows > 0 ? ((data.n_benign / data.n_flows) * 100).toFixed(1) : '0'
  const confidences = predictions.map((p) => p.confidence)

  // Severity breakdown
  const sevCounts = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, benign: 0 }
    predictions.forEach((p) => { counts[p.severity] = (counts[p.severity] || 0) + 1 })
    return counts
  }, [predictions])

  // Top threat sources (by src_ip, excluding benign)
  const topSources = useMemo(() => {
    const ipCounts: Record<string, { count: number; attacks: Set<string>; worstSev: string }> = {}
    const sevRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, benign: 0 }
    predictions
      .filter((p) => p.severity !== 'benign' && p.src_ip)
      .forEach((p) => {
        if (!ipCounts[p.src_ip]) ipCounts[p.src_ip] = { count: 0, attacks: new Set(), worstSev: 'low' }
        const entry = ipCounts[p.src_ip]
        entry.count++
        entry.attacks.add(p.label_predicted)
        if ((sevRank[p.severity] || 0) > (sevRank[entry.worstSev] || 0)) entry.worstSev = p.severity
      })
    return Object.entries(ipCounts)
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 8)
  }, [predictions])

  // Export predictions as CSV in-browser
  const downloadCSV = () => {
    const header = 'flow_id,src_ip,dst_ip,label_predicted,label_true,confidence,severity,action\n'
    const rows = predictions.map((p) =>
      `${p.flow_id},"${p.src_ip}","${p.dst_ip}","${p.label_predicted}","${p.label_true || ''}",${p.confidence},${p.severity},${SEV_CFG[p.severity]?.action || 'MONITOR'}`,
    ).join('\n')
    const blob = new Blob([header + rows], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `robustidps_detections_${data.job_id || 'export'}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6">
      <PageGuide
        title="How to use the SOC Dashboard"
        steps={[
          { title: 'Upload first', desc: 'Go to Upload & Analyse to analyse a dataset. Results automatically populate this dashboard.' },
          { title: 'Review severity', desc: 'The 5 severity panels show threat distribution. Click severity chips in the table to filter by level.' },
          { title: 'Drill into threats', desc: 'Click any row in the threat table to expand it and see uncertainty scores, true label, and recommended SOC action.' },
          { title: 'Export results', desc: 'Click "Export Detections (CSV)" to download all predictions with actions for your SIEM or ticketing system.' },
        ]}
        tip="Tip: The dashboard shows sample data when no file has been analysed. Upload a real dataset to see live results."
      />

      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-display font-bold">SOC Dashboard</h1>
        {predictions.length > 0 && (
          <button
            onClick={downloadCSV}
            className="flex items-center gap-2 px-3 py-1.5 text-xs bg-accent-blue/15 text-accent-blue rounded-lg hover:bg-accent-blue/25 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Export Detections (CSV)
          </button>
        )}
      </div>

      {/* Row 1: Stat cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Total Flows" value={data.n_flows.toLocaleString()} icon={Activity} color="text-accent-blue" />
        <StatCard label="Threats Detected" value={data.n_threats.toLocaleString()} icon={ShieldAlert} color="text-accent-red" sub={`${((data.n_threats / Math.max(data.n_flows, 1)) * 100).toFixed(1)}% of total`} />
        <StatCard label="Benign Traffic" value={`${benignPct}%`} icon={ShieldCheck} color="text-accent-green" />
        <StatCard label="ECE Score" value={data.ece.toFixed(3)} icon={Gauge} color="text-accent-purple" sub="Expected Calibration Error" />
      </div>

      {/* Row 2: Severity breakdown panels */}
      <div className="grid grid-cols-5 gap-3">
        {SEVERITY_LEVELS.map((sev) => {
          const cfg = SEV_CFG[sev]
          const count = sevCounts[sev] || 0
          const pct = data.n_flows > 0 ? ((count / data.n_flows) * 100).toFixed(1) : '0'
          return (
            <div key={sev} className={`rounded-xl p-4 border ${cfg.bg} ${cfg.border}`}>
              <div className="flex items-center justify-between mb-2">
                <cfg.icon className={`w-5 h-5 ${cfg.text}`} />
                <span className={`text-2xl font-bold font-mono ${cfg.text}`}>{count}</span>
              </div>
              <div className={`text-xs font-semibold uppercase tracking-wider ${cfg.text}`}>{sev}</div>
              <div className="text-xs text-text-secondary mt-1">{pct}% of traffic</div>
              <div className={`text-xs font-mono mt-2 px-2 py-0.5 rounded ${cfg.bg} ${cfg.text} inline-block`}>
                {cfg.action}
              </div>
            </div>
          )
        })}
      </div>

      {/* Row 3: Charts + Top Sources */}
      <div className="grid grid-cols-3 gap-4">
        <AttackDistribution data={data.attack_distribution} />
        <ConfidenceHistogram confidences={confidences} />
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-3 flex items-center gap-2">
            <Globe className="w-4 h-4" /> Top Threat Sources
          </h3>
          {topSources.length === 0 ? (
            <p className="text-xs text-text-secondary">No threat sources detected yet.</p>
          ) : (
            <div className="space-y-2">
              {topSources.map(([ip, info]) => {
                const cfg = SEV_CFG[info.worstSev] || SEV_CFG.medium
                return (
                  <div key={ip} className="flex items-center gap-2 text-xs">
                    <span className={`w-2 h-2 rounded-full ${cfg.bg} ${cfg.border} border`} />
                    <span className="font-mono flex-1 truncate">{ip}</span>
                    <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${cfg.bg} ${cfg.text}`}>
                      {info.count}
                    </span>
                    <span className="text-text-secondary truncate max-w-[80px]" title={[...info.attacks].join(', ')}>
                      {[...info.attacks].slice(0, 2).join(', ')}
                    </span>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>

      {/* Row 4: SOC Threat Table with drill-down */}
      <SOCThreatTable predictions={predictions} />
    </div>
  )
}

/* ── SOC Threat Table with expandable drill-down ──────────────────────── */

function SOCThreatTable({ predictions }: { predictions: Prediction[] }) {
  const [query, setQuery] = useState('')
  const [sevFilter, setSevFilter] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<Set<number>>(new Set())

  const filtered = useMemo(() => {
    const q = query.toLowerCase()
    return predictions
      .filter((p) => {
        if (sevFilter && p.severity !== sevFilter) return false
        if (q && !p.label_predicted.toLowerCase().includes(q) && !p.src_ip.includes(q) && !p.dst_ip.includes(q)) return false
        return true
      })
      .sort((a, b) => {
        const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, benign: 4 }
        return (rank[a.severity] ?? 4) - (rank[b.severity] ?? 4)
      })
  }, [predictions, query, sevFilter])

  const toggle = (id: number) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  return (
    <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-medium text-text-secondary">
          Threat Detections ({filtered.length.toLocaleString()} flows)
        </h3>
        <div className="flex gap-2">
          {/* Severity filter chips */}
          {SEVERITY_LEVELS.map((sev) => {
            const cfg = SEV_CFG[sev]
            const active = sevFilter === sev
            return (
              <button
                key={sev}
                onClick={() => setSevFilter(active ? null : sev)}
                className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                  active ? `${cfg.bg} ${cfg.text} ${cfg.border} border` : 'bg-bg-card/50 text-text-secondary hover:text-text-primary'
                }`}
              >
                {sev}
              </button>
            )
          })}
        </div>
      </div>

      <div className="relative mb-3">
        <SearchIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-secondary" />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search by IP, label, severity..."
          className="w-full bg-bg-card/50 border border-bg-card rounded-lg pl-9 pr-4 py-2 text-sm text-text-primary placeholder:text-text-secondary focus:outline-none focus:border-accent-blue"
        />
      </div>

      <div className="overflow-x-auto rounded-lg border border-bg-card">
        <table className="w-full text-sm">
          <thead className="bg-bg-card/40">
            <tr className="text-text-secondary text-xs">
              <th className="px-2 py-2 w-8" />
              <th className="px-3 py-2 text-left">#</th>
              <th className="px-3 py-2 text-left">Src IP</th>
              <th className="px-3 py-2 text-left">Dst IP</th>
              <th className="px-3 py-2 text-left">Classification</th>
              <th className="px-3 py-2 text-left">Confidence</th>
              <th className="px-3 py-2 text-left">Severity</th>
              <th className="px-3 py-2 text-left">Action</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 200).map((p) => {
              const cfg = SEV_CFG[p.severity] || SEV_CFG.medium
              const isExpanded = expanded.has(p.flow_id)
              return (
                <Fragment key={p.flow_id}>
                  <tr
                    className={`border-t border-bg-card/50 cursor-pointer transition-colors ${
                      p.severity === 'critical' ? 'bg-accent-red/5' : p.severity === 'high' ? 'bg-accent-orange/5' : 'hover:bg-bg-card/20'
                    }`}
                    onClick={() => toggle(p.flow_id)}
                  >
                    <td className="px-2 py-2 text-text-secondary">
                      {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                    </td>
                    <td className="px-3 py-2 font-mono text-text-secondary">{p.flow_id}</td>
                    <td className="px-3 py-2 font-mono">{p.src_ip}</td>
                    <td className="px-3 py-2 font-mono">{p.dst_ip}</td>
                    <td className="px-3 py-2 font-medium">{p.label_predicted}</td>
                    <td className="px-3 py-2 font-mono">{(p.confidence * 100).toFixed(1)}%</td>
                    <td className="px-3 py-2">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${cfg.bg} ${cfg.text}`}>
                        {p.severity}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <span className={`px-2 py-0.5 rounded text-xs font-bold ${cfg.bg} ${cfg.text}`}>
                        {cfg.action}
                      </span>
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr className="border-t border-bg-card/30">
                      <td colSpan={8} className="px-6 py-3 bg-bg-card/20">
                        <div className="grid grid-cols-4 gap-4 text-xs">
                          <div>
                            <span className="text-text-secondary block">True Label</span>
                            <span className="font-medium">{p.label_true || 'N/A'}</span>
                          </div>
                          <div>
                            <span className="text-text-secondary block">Epistemic Uncertainty</span>
                            <span className="font-mono">{p.epistemic_uncertainty?.toFixed(4) ?? 'N/A'}</span>
                          </div>
                          <div>
                            <span className="text-text-secondary block">Aleatoric Uncertainty</span>
                            <span className="font-mono">{p.aleatoric_uncertainty?.toFixed(4) ?? 'N/A'}</span>
                          </div>
                          <div>
                            <span className="text-text-secondary block">Total Uncertainty</span>
                            <span className="font-mono">{p.total_uncertainty?.toFixed(4) ?? 'N/A'}</span>
                          </div>
                        </div>
                        <div className={`mt-3 text-xs ${cfg.text}`}>
                          <strong>Recommended Action:</strong> {cfg.actionDesc}
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
        {filtered.length > 200 && (
          <div className="px-3 py-2 text-xs text-text-secondary text-center border-t border-bg-card">
            Showing first 200 of {filtered.length.toLocaleString()} flows (sorted by severity)
          </div>
        )}
      </div>
    </div>
  )
}

// Need Fragment for expandable rows
import { Fragment } from 'react'
