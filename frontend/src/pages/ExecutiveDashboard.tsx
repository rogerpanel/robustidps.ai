import { useState, useCallback, useMemo } from 'react'
import { Shield, Loader2, Upload, FileText, X, BarChart3, AlertTriangle, CheckCircle2, Target, Zap, Search, Sparkles, Radio, ArrowRight, Activity } from 'lucide-react'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import ModelSelector from '../components/ModelSelector'
import { analyseFile, cachePageResult } from '../utils/api'
import { useNoticeBoard } from '../hooks/useNoticeBoard'
import { getLiveData, hasLiveData } from '../utils/liveDataStore'

// Module-level store: survives component unmount on navigation
const _store: {
  file: File | null
  analysisResult: any
  modelId: string
} = {
  file: null,
  analysisResult: null,
  modelId: 'surrogate',
}

/* ── Guide steps ── */
const GUIDE_STEPS = [
  { title: 'Upload Data', desc: 'Drag-and-drop a network capture file or use live monitor data for instant analysis.' },
  { title: 'View Security Posture', desc: 'Review your organization\'s overall health score, threat breakdown, and top risks at a glance.' },
  { title: 'Take Action', desc: 'Jump to incident reports, threat hunting, or the AI copilot for deeper investigation.' },
]

/* ── Severity colors ── */
const SEV_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  benign: '#22c55e',
}

const SEV_LABELS: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  benign: 'Safe',
}

export default function ExecutiveDashboard() {
  const [file, _setFile] = useState<File | null>(_store.file)
  const [modelId, _setModelId] = useState(_store.modelId)
  const [analysisResult, _setAnalysisResult] = useState<any>(_store.analysisResult)
  const [analyzing, setAnalyzing] = useState(false)

  const setFile = (f: File | null) => { _store.file = f; _setFile(f) }
  const setModelId = (v: string) => { _store.modelId = v; _setModelId(v) }
  const setAnalysisResult = (v: any) => { _store.analysisResult = v; _setAnalysisResult(v) }
  const [dragOver, setDragOver] = useState(false)
  const [liveDataLoaded, setLiveDataLoaded] = useState(false)
  const { addNotice, updateNotice } = useNoticeBoard()

  /* ── Load live data ── */
  const loadLiveData = useCallback(() => {
    const live = getLiveData()
    if (!live) return
    setAnalysisResult({
      predictions: live.predictions,
      n_flows: live.totalFlows,
      n_threats: live.threatCount,
      n_benign: live.benignCount,
    })
    setLiveDataLoaded(true)
  }, [])

  /* ── File upload ── */
  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const f = e.dataTransfer.files[0]
    if (f) setFile(f)
  }, [])

  const runAnalysis = async () => {
    if (!file) return
    setAnalyzing(true)
    const nid = addNotice({ title: 'Executive Dashboard Analysis', description: `Analyzing ${file.name}...`, status: 'running', page: '/executive-dashboard' })
    try {
      const data = await analyseFile(file, modelId, 'executive_dashboard', true)
      setAnalysisResult(data)
      updateNotice(nid, { status: 'completed', description: `${data.predictions?.length || 0} flows analyzed` })
    } catch (err) {
      updateNotice(nid, { status: 'error', description: err instanceof Error ? err.message : 'Analysis failed' })
    }
    setAnalyzing(false)
  }

  /* ── Derived metrics ── */
  const predictions = analysisResult?.predictions || []
  const totalFlows = predictions.length
  const threatCount = predictions.filter((p: any) => (p.severity || 'benign') !== 'benign').length
  const benignCount = totalFlows - threatCount
  const healthScore = totalFlows > 0 ? Math.round((benignCount / totalFlows) * 100) : 0

  const healthColor = healthScore > 80 ? '#22c55e' : healthScore >= 50 ? '#eab308' : '#ef4444'
  const healthLabel = healthScore > 80 ? 'Healthy' : healthScore >= 50 ? 'Caution' : 'At Risk'

  /* ── Severity distribution ── */
  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, benign: 0 }
    predictions.forEach((p: any) => {
      const sev = (p.severity || 'benign').toLowerCase()
      if (sev in counts) counts[sev]++
      else counts.benign++
    })
    return counts
  }, [predictions])

  /* ── Top 5 attack types ── */
  const topAttacks = useMemo(() => {
    const map: Record<string, number> = {}
    predictions.forEach((p: any) => {
      const label = p.label_predicted || p.label || 'Unknown'
      if (label.toLowerCase() !== 'benign') map[label] = (map[label] || 0) + 1
    })
    return Object.entries(map)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5)
  }, [predictions])

  /* ── Top 5 source IPs ── */
  const topIPs = useMemo(() => {
    const map: Record<string, number> = {}
    predictions.forEach((p: any) => {
      if ((p.severity || 'benign') === 'benign') return
      const ip = p.src_ip || p.source_ip || 'Unknown'
      map[ip] = (map[ip] || 0) + 1
    })
    return Object.entries(map)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5)
  }, [predictions])

  /* ── Auto-triage summary ── */
  const triageSummary = useMemo(() => {
    let confirmed = 0, falsePositive = 0, review = 0
    predictions.forEach((p: any) => {
      const conf = p.confidence ?? 0.5
      if (conf >= 0.95) confirmed++
      else if (conf <= 0.30) falsePositive++
      else review++
    })
    return { confirmed, falsePositive, review }
  }, [predictions])

  const maxAttackCount = topAttacks.length > 0 ? topAttacks[0][1] : 1

  const hasResults = totalFlows > 0

  return (
    <div className="space-y-6 max-w-7xl mx-auto" id="executive-dashboard">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-accent-blue/15 flex items-center justify-center">
            <BarChart3 className="w-5 h-5 text-accent-blue" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-text-primary">Executive Dashboard</h1>
            <p className="text-sm text-text-secondary">Security posture at a glance</p>
          </div>
        </div>
        <ExportMenu targetSelector="#executive-dashboard" filename="executive-dashboard" />
      </div>

      <PageGuide title="How to use this dashboard" steps={GUIDE_STEPS} tip="Designed for wall monitors and leadership briefings." />

      {/* Live Monitor Banner */}
      {hasLiveData() && !liveDataLoaded && (
        <button
          onClick={loadLiveData}
          className="w-full flex items-center gap-3 p-4 rounded-xl bg-accent-green/10 border border-accent-green/30 hover:bg-accent-green/20 transition-colors"
        >
          <Radio className="w-5 h-5 text-accent-green animate-pulse" />
          <span className="text-lg font-semibold text-accent-green">Live data available</span>
          <span className="text-sm text-text-secondary ml-2">Click to load captured network data</span>
          <ArrowRight className="w-4 h-4 text-accent-green ml-auto" />
        </button>
      )}

      {/* Upload + Model Selection */}
      {!hasResults && (
        <div className="glass-card p-6 space-y-4">
          <div className="flex items-center gap-4 flex-wrap">
            <ModelSelector value={modelId} onChange={setModelId} compact />
          </div>

          <div
            onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            className={`border-2 border-dashed rounded-xl p-10 text-center transition-colors ${
              dragOver ? 'border-accent-blue bg-accent-blue/5' : 'border-border-primary'
            }`}
          >
            {file ? (
              <div className="flex items-center justify-center gap-3">
                <FileText className="w-6 h-6 text-accent-blue" />
                <span className="text-lg text-text-primary font-medium">{file.name}</span>
                <button onClick={() => setFile(null)} className="text-text-secondary hover:text-accent-red">
                  <X className="w-5 h-5" />
                </button>
              </div>
            ) : (
              <label className="cursor-pointer flex flex-col items-center gap-3">
                <Upload className="w-10 h-10 text-text-secondary" />
                <span className="text-lg text-text-secondary">Drag and drop a network capture file here</span>
                <span className="text-sm text-text-secondary">or click to browse</span>
                <input type="file" className="hidden" accept=".csv,.pcap,.json" onChange={(e) => setFile(e.target.files?.[0] || null)} />
              </label>
            )}
          </div>

          {file && (
            <button
              onClick={runAnalysis}
              disabled={analyzing}
              className="w-full py-3 rounded-xl bg-accent-blue text-white font-semibold text-lg flex items-center justify-center gap-2 hover:bg-accent-blue/90 disabled:opacity-50 transition-colors"
            >
              {analyzing ? <><Loader2 className="w-5 h-5 animate-spin" /> Analyzing...</> : <><Sparkles className="w-5 h-5" /> Analyze Network Data</>}
            </button>
          )}
        </div>
      )}

      {/* ── Results ── */}
      {hasResults && (
        <div className="space-y-6">

          {/* Row 1: Health Score + Stat Cards */}
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
            {/* Health Score Circle */}
            <div className="lg:col-span-1 glass-card p-6 flex flex-col items-center justify-center">
              <div className="relative w-32 h-32">
                <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                  <circle cx="50" cy="50" r="42" fill="none" stroke="currentColor" strokeWidth="8" className="text-border-primary" />
                  <circle cx="50" cy="50" r="42" fill="none" stroke={healthColor} strokeWidth="8"
                    strokeDasharray={`${healthScore * 2.64} 264`} strokeLinecap="round" />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-3xl font-bold" style={{ color: healthColor }}>{healthScore}</span>
                  <span className="text-xs text-text-secondary">/ 100</span>
                </div>
              </div>
              <span className="mt-2 text-lg font-semibold" style={{ color: healthColor }}>{healthLabel}</span>
              <span className="text-xs text-text-secondary">Network Health</span>
            </div>

            {/* Stat Cards */}
            <StatCard icon={<Activity className="w-6 h-6" />} label="Total Flows" value={totalFlows.toLocaleString()} color="text-accent-blue" bg="bg-accent-blue/10" />
            <StatCard icon={<AlertTriangle className="w-6 h-6" />} label="Threats Detected" value={threatCount.toLocaleString()} color="text-accent-red" bg="bg-accent-red/10" />
            <StatCard icon={<CheckCircle2 className="w-6 h-6" />} label="Safe Traffic" value={benignCount.toLocaleString()} color="text-accent-green" bg="bg-accent-green/10" />
            <StatCard icon={<Shield className="w-6 h-6" />} label="Models Active" value="1" color="text-accent-purple" bg="bg-accent-purple/10" />
          </div>

          {/* Row 2: Severity Distribution Bar */}
          <div className="glass-card p-6">
            <h2 className="text-lg font-semibold text-text-primary mb-4">Threat Severity Breakdown</h2>
            <div className="w-full h-10 rounded-full overflow-hidden flex bg-bg-secondary">
              {['critical', 'high', 'medium', 'low', 'benign'].map((sev) => {
                const count = severityCounts[sev]
                const pct = totalFlows > 0 ? (count / totalFlows) * 100 : 0
                if (pct === 0) return null
                return (
                  <div key={sev} style={{ width: `${pct}%`, backgroundColor: SEV_COLORS[sev] }}
                    className="h-full flex items-center justify-center text-xs font-bold text-white min-w-[2rem]"
                    title={`${SEV_LABELS[sev]}: ${count}`}
                  >
                    {pct >= 5 ? `${Math.round(pct)}%` : ''}
                  </div>
                )
              })}
            </div>
            <div className="flex flex-wrap gap-4 mt-3">
              {['critical', 'high', 'medium', 'low', 'benign'].map((sev) => (
                <div key={sev} className="flex items-center gap-2 text-sm text-text-secondary">
                  <span className="w-3 h-3 rounded-full" style={{ backgroundColor: SEV_COLORS[sev] }} />
                  {SEV_LABELS[sev]}: <span className="font-semibold text-text-primary">{severityCounts[sev]}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Row 3: Top 5 Attack Types */}
          {topAttacks.length > 0 && (
            <div className="glass-card p-6">
              <h2 className="text-lg font-semibold text-text-primary mb-4 flex items-center gap-2">
                <Zap className="w-5 h-5 text-accent-amber" /> Top Attack Types
              </h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
                {topAttacks.map(([label, count]) => (
                  <div key={label} className="bg-bg-secondary rounded-xl p-4">
                    <div className="text-sm font-medium text-text-primary truncate mb-1">{label}</div>
                    <div className="text-2xl font-bold text-accent-red">{count}</div>
                    <div className="w-full h-2 bg-bg-tertiary rounded-full mt-2 overflow-hidden">
                      <div className="h-full bg-accent-red rounded-full" style={{ width: `${(count / maxAttackCount) * 100}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Row 4: Top 5 Threat Source IPs */}
          {topIPs.length > 0 && (
            <div className="glass-card p-6">
              <h2 className="text-lg font-semibold text-text-primary mb-4 flex items-center gap-2">
                <Target className="w-5 h-5 text-accent-orange" /> Top Threat Sources
              </h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
                {topIPs.map(([ip, count]) => (
                  <div key={ip} className="bg-bg-secondary rounded-xl p-4 flex items-center gap-3">
                    <Search className="w-5 h-5 text-text-secondary shrink-0" />
                    <div className="min-w-0">
                      <div className="text-sm font-mono text-text-primary truncate">{ip}</div>
                      <div className="text-lg font-bold text-accent-orange">{count} events</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Row 5: Auto-Triage Summary */}
          <div className="glass-card p-6">
            <h2 className="text-lg font-semibold text-text-primary mb-4 flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-accent-purple" /> Automated Triage Summary
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <TriageCard label="Confirmed Threats" count={triageSummary.confirmed} total={totalFlows} color="text-accent-red" bg="bg-accent-red/10" desc="High confidence (above 95%)" />
              <TriageCard label="Likely False Positives" count={triageSummary.falsePositive} total={totalFlows} color="text-accent-green" bg="bg-accent-green/10" desc="Low confidence (below 30%)" />
              <TriageCard label="Needs Review" count={triageSummary.review} total={totalFlows} color="text-accent-amber" bg="bg-accent-amber/10" desc="Requires analyst attention" />
            </div>
          </div>

          {/* Row 6: Action Buttons */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <ActionLink href="/incident-reports" icon={<FileText className="w-6 h-6" />} label="Incident Reports" desc="View full incident details" color="text-accent-blue" />
            <ActionLink href="/threat-hunt" icon={<Search className="w-6 h-6" />} label="Threat Hunting" desc="Investigate suspicious activity" color="text-accent-amber" />
            <ActionLink href="/copilot" icon={<Sparkles className="w-6 h-6" />} label="AI Security Copilot" desc="Ask questions in plain English" color="text-accent-purple" />
            <ActionLink href="/" icon={<Shield className="w-6 h-6" />} label="Main Dashboard" desc="Full technical overview" color="text-accent-green" />
          </div>
        </div>
      )}
    </div>
  )
}

/* ── Stat Card ── */
function StatCard({ icon, label, value, color, bg }: { icon: React.ReactNode; label: string; value: string; color: string; bg: string }) {
  return (
    <div className="glass-card p-6 flex flex-col items-center justify-center text-center">
      <div className={`w-12 h-12 rounded-xl ${bg} flex items-center justify-center ${color} mb-3`}>{icon}</div>
      <div className="text-3xl font-bold text-text-primary">{value}</div>
      <div className="text-sm text-text-secondary mt-1">{label}</div>
    </div>
  )
}

/* ── Triage Card ── */
function TriageCard({ label, count, total, color, bg, desc }: { label: string; count: number; total: number; color: string; bg: string; desc: string }) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0
  return (
    <div className={`${bg} rounded-xl p-5`}>
      <div className={`text-3xl font-bold ${color}`}>{count.toLocaleString()}</div>
      <div className="text-base font-semibold text-text-primary mt-1">{label}</div>
      <div className="text-sm text-text-secondary">{pct}% of total &mdash; {desc}</div>
    </div>
  )
}

/* ── Action Link ── */
function ActionLink({ href, icon, label, desc, color }: { href: string; icon: React.ReactNode; label: string; desc: string; color: string }) {
  return (
    <a href={href} className="glass-card p-5 flex items-center gap-4 hover:bg-bg-secondary transition-colors group">
      <div className={`${color}`}>{icon}</div>
      <div className="min-w-0">
        <div className="text-base font-semibold text-text-primary group-hover:text-accent-blue transition-colors">{label}</div>
        <div className="text-sm text-text-secondary">{desc}</div>
      </div>
      <ArrowRight className="w-5 h-5 text-text-secondary ml-auto shrink-0 group-hover:text-accent-blue transition-colors" />
    </a>
  )
}
