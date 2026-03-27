import { useState, useMemo, useCallback } from 'react'
import {
  GitBranch, AlertTriangle, Shield, ChevronDown, ChevronRight,
  Clock, ArrowRight, Zap, Search, Activity,
  Upload, FileText, X, Loader2, Radio,
} from 'lucide-react'
import { getLiveData, hasLiveData } from '../utils/liveDataStore'
import PageGuide from '../components/PageGuide'
import ModelSelector from '../components/ModelSelector'
import { analyseFile } from '../utils/api'
import { useNoticeBoard } from '../hooks/useNoticeBoard'

/* ── Types ── */
interface IncidentAlert {
  id: string
  time: string
  attack: string
  src: string
  dst: string
  confidence: number
  stage: string
}

interface Incident {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  alerts: IncidentAlert[]
  rootCause: string
  recommendation: string
}

/* ── Demo data ── */
const DEMO_INCIDENTS: Incident[] = [
  {
    id: 'INC-001',
    title: 'Multi-Stage Web Application Attack',
    severity: 'critical',
    alerts: [
      { id: 'A1', time: '14:22:03', attack: 'Recon-PortScan', src: '203.0.113.14', dst: '10.0.1.5', confidence: 0.92, stage: 'Reconnaissance' },
      { id: 'A2', time: '14:23:15', attack: 'Recon-OSScan', src: '203.0.113.14', dst: '10.0.1.5', confidence: 0.88, stage: 'Reconnaissance' },
      { id: 'A3', time: '14:25:41', attack: 'WebAttack-SQLi', src: '203.0.113.14', dst: '10.0.1.5', confidence: 0.96, stage: 'Initial Access' },
      { id: 'A4', time: '14:27:02', attack: 'WebAttack-CmdInjection', src: '203.0.113.14', dst: '10.0.1.5', confidence: 0.94, stage: 'Execution' },
      { id: 'A5', time: '14:28:33', attack: 'Malware-Backdoor', src: '10.0.1.5', dst: '198.51.100.7', confidence: 0.91, stage: 'Persistence' },
    ],
    rootCause: 'Unpatched web application (CVE-2024-XXXX)',
    recommendation: 'Patch web server, block 203.0.113.14, scan 10.0.1.5 for persistence',
  },
  {
    id: 'INC-002',
    title: 'Credential Stuffing to Lateral Movement',
    severity: 'high',
    alerts: [
      { id: 'B1', time: '09:15:22', attack: 'BruteForce-SSH', src: '198.51.100.50', dst: '10.0.2.10', confidence: 0.97, stage: 'Credential Access' },
      { id: 'B2', time: '09:17:45', attack: 'BruteForce-SSH', src: '198.51.100.50', dst: '10.0.2.11', confidence: 0.95, stage: 'Credential Access' },
      { id: 'B3', time: '09:19:01', attack: 'Spoofing-IP', src: '10.0.2.10', dst: '10.0.2.20', confidence: 0.82, stage: 'Lateral Movement' },
      { id: 'B4', time: '09:21:33', attack: 'Malware-Ransomware', src: '10.0.2.20', dst: '10.0.2.0/24', confidence: 0.98, stage: 'Impact' },
    ],
    rootCause: 'Weak SSH credentials on 10.0.2.10',
    recommendation: 'Enforce MFA, rotate SSH keys, isolate 10.0.2.0/24 subnet',
  },
  {
    id: 'INC-003',
    title: 'IoT Botnet Recruitment Campaign',
    severity: 'high',
    alerts: [
      { id: 'C1', time: '03:44:11', attack: 'Recon-PingSweep', src: '185.220.101.33', dst: '10.0.3.0/24', confidence: 0.89, stage: 'Reconnaissance' },
      { id: 'C2', time: '03:45:28', attack: 'BruteForce-HTTP', src: '185.220.101.33', dst: '10.0.3.15', confidence: 0.93, stage: 'Credential Access' },
      { id: 'C3', time: '03:46:02', attack: 'Mirai-greeth', src: '10.0.3.15', dst: '185.220.101.33', confidence: 0.96, stage: 'C2 Communication' },
      { id: 'C4', time: '03:48:55', attack: 'DDoS-UDP', src: '10.0.3.15', dst: '93.184.216.34', confidence: 0.99, stage: 'Impact' },
    ],
    rootCause: 'Default credentials on IoT device 10.0.3.15',
    recommendation: 'Change default credentials, segment IoT network, block C2 IP',
  },
]

const STAGE_COLORS: Record<string, string> = {
  'Reconnaissance': '#3B82F6',
  'Initial Access': '#F59E0B',
  'Credential Access': '#F97316',
  'Execution': '#EF4444',
  'Persistence': '#A855F7',
  'Lateral Movement': '#EC4899',
  'C2 Communication': '#8B5CF6',
  'Impact': '#EF4444',
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-accent-red/15 text-accent-red border-accent-red/30',
  high: 'bg-accent-orange/15 text-accent-orange border-accent-orange/30',
  medium: 'bg-accent-amber/15 text-accent-amber border-accent-amber/30',
  low: 'bg-accent-blue/15 text-accent-blue border-accent-blue/30',
}

/* ── Helpers for building incidents from analysis ── */

const mapAttackToStage = (label: string) => {
  if (label?.includes('Recon') || label?.includes('Ping') || label?.includes('Scan')) return 'Reconnaissance'
  if (label?.includes('BruteForce')) return 'Credential Access'
  if (label?.includes('SQLi') || label?.includes('XSS')) return 'Initial Access'
  if (label?.includes('CmdInjection')) return 'Execution'
  if (label?.includes('Backdoor')) return 'Persistence'
  if (label?.includes('Spoofing')) return 'Lateral Movement'
  if (label?.includes('DDoS') || label?.includes('Ransom')) return 'Impact'
  if (label?.includes('Mirai')) return 'C2 Communication'
  return 'Execution'
}

const buildIncidents = (predictions: any[]): Incident[] => {
  const groups: Record<string, any[]> = {}
  predictions.forEach((p: any, i: number) => {
    if (p.severity === 'benign') return
    const src = p.src_ip || 'unknown'
    if (!groups[src]) groups[src] = []
    groups[src].push({
      id: `A${i + 1}`,
      time: new Date(Date.now() - (predictions.length - i) * 60000).toTimeString().slice(0, 8),
      attack: p.label_predicted || 'Unknown',
      src: src,
      dst: p.dst_ip || '10.0.0.1',
      confidence: p.confidence || 0.5,
      stage: mapAttackToStage(p.label_predicted),
    })
  })

  return Object.entries(groups)
    .filter(([_, alerts]) => alerts.length >= 2)
    .slice(0, 5)
    .map(([src, alerts], i) => ({
      id: `INC-${String(i + 1).padStart(3, '0')}`,
      title: `Attack chain from ${src}`,
      severity: alerts.some((a: any) => a.attack.includes('Malware') || a.attack.includes('Ransom')) ? 'critical' as const : 'high' as const,
      alerts,
      rootCause: `Multiple attack stages detected from ${src}`,
      recommendation: `Investigate ${src}, check for lateral movement, review firewall rules`,
    }))
}

/* ── Component ── */
export default function AlertCausalityGraph() {
  const [expandedId, setExpandedId] = useState<string | null>('INC-001')
  const [searchTerm, setSearchTerm] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [modelId, setModelId] = useState('surrogate')
  const [analysisResult, setAnalysisResult] = useState<any>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [liveDataLoaded, setLiveDataLoaded] = useState(false)
  const { addNotice, updateNotice } = useNoticeBoard()

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

  const runAnalysis = async () => {
    if (!file) return
    setAnalyzing(true)
    const nid = addNotice({ title: 'Causality Graph Analysis', description: `Analyzing ${file.name}...`, status: 'running', page: '/alert-causality-graph' })
    try {
      const data = await analyseFile(file, modelId)
      setAnalysisResult(data)
      const incidents = data.predictions ? buildIncidents(data.predictions) : []
      updateNotice(nid, { status: 'completed', description: `${incidents.length} incident chain(s) built from ${data.predictions?.length || 0} predictions` })
    } catch (err) {
      updateNotice(nid, { status: 'error', description: err instanceof Error ? err.message : 'Analysis failed' })
    }
    setAnalyzing(false)
  }

  const realIncidents = analysisResult?.predictions ? buildIncidents(analysisResult.predictions) : []
  const activeIncidents = realIncidents.length > 0 ? realIncidents : DEMO_INCIDENTS

  const filteredIncidents = useMemo(() => {
    if (!searchTerm) return activeIncidents
    const q = searchTerm.toLowerCase()
    return activeIncidents.filter(
      (inc) =>
        inc.title.toLowerCase().includes(q) ||
        inc.id.toLowerCase().includes(q) ||
        inc.alerts.some(
          (a) =>
            a.attack.toLowerCase().includes(q) ||
            a.src.toLowerCase().includes(q) ||
            a.dst.toLowerCase().includes(q) ||
            a.stage.toLowerCase().includes(q),
        ),
    )
  }, [searchTerm, activeIncidents])

  /* ── Stats ── */
  const stats = useMemo(() => {
    const totalIncidents = activeIncidents.length
    const totalAlerts = activeIncidents.reduce((s, i) => s + i.alerts.length, 0)
    const avgAlerts = totalIncidents ? (totalAlerts / totalIncidents).toFixed(1) : '0'
    const rootCauses = activeIncidents.map((i) => i.rootCause)
    const causeWords = rootCauses.map((r) => r.split(' ').slice(0, 3).join(' '))
    const freq: Record<string, number> = {}
    causeWords.forEach((w) => { freq[w] = (freq[w] || 0) + 1 })
    const mostCommon = Object.entries(freq).sort((a, b) => b[1] - a[1])[0]?.[0] || 'N/A'
    const criticalCount = activeIncidents.filter((i) => i.severity === 'critical').length
    return { totalIncidents, totalAlerts, avgAlerts, mostCommon, criticalCount }
  }, [activeIncidents])

  const uniqueStages = useMemo(() => {
    const stages = new Set<string>()
    activeIncidents.forEach((inc) => inc.alerts.forEach((a) => stages.add(a.stage)))
    return Array.from(stages)
  }, [activeIncidents])

  const toggle = (id: string) => setExpandedId((prev) => (prev === id ? null : id))

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-start gap-4">
        <div className="flex-1">
          <h1 className="text-2xl font-display font-bold flex items-center gap-2">
            <GitBranch className="w-6 h-6 text-accent-blue" />
            Alert Causality Graph
          </h1>
          <p className="text-text-secondary text-sm mt-1">
            Groups related detections into incident chains with visual kill-chain progression.
            Inspired by Palo Alto XSIAM causality view.
          </p>
        </div>
      </div>

      {/* PageGuide */}
      <PageGuide
        steps={[
          'Review incident cards below -- each groups correlated alerts into a single attack narrative.',
          'Expand an incident to see the horizontal causality chain with kill-chain stage progression and alert details.',
          'Check the root cause analysis and recommended response actions at the bottom of each expanded incident.',
        ]}
      />

      {/* Upload + Model selector */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">Upload Traffic for Causality Analysis</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end">
          {/* Drag & drop file zone */}
          <div>
            {file ? (
              <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-accent-green/30 bg-accent-green/5">
                <FileText className="w-4 h-4 text-accent-green shrink-0" />
                <span className="text-xs font-mono truncate flex-1">{file.name}</span>
                <button onClick={() => { setFile(null); setAnalysisResult(null) }} className="text-text-secondary hover:text-text-primary"><X className="w-3.5 h-3.5" /></button>
              </div>
            ) : (
              <label onDragOver={e => { e.preventDefault(); e.currentTarget.classList.add('border-accent-blue','bg-accent-blue/10') }} onDragLeave={e => { e.currentTarget.classList.remove('border-accent-blue','bg-accent-blue/10') }} onDrop={e => { e.preventDefault(); e.currentTarget.classList.remove('border-accent-blue','bg-accent-blue/10'); const f = e.dataTransfer.files[0]; if(f) setFile(f) }} className="flex flex-col items-center gap-1 px-3 py-3 rounded-lg border-2 border-dashed border-bg-card hover:border-text-secondary cursor-pointer transition-colors">
                <Upload className="w-5 h-5 text-text-secondary" />
                <span className="text-[10px] text-text-secondary">Drop or click</span>
                <span className="text-[9px] text-text-secondary/60">.csv .pcap .pcapng</span>
                <input type="file" accept=".csv,.pcap,.pcapng" className="hidden" onChange={e => setFile(e.target.files?.[0] || null)} />
              </label>
            )}
          </div>
          <div>
            <label className="text-xs text-text-secondary block mb-1">Detection Model</label>
            <ModelSelector value={modelId} onChange={setModelId} compact />
          </div>
          <button onClick={runAnalysis} disabled={!file || analyzing} className="px-4 py-2.5 bg-accent-blue hover:bg-accent-blue/80 text-white rounded-lg text-xs font-medium disabled:opacity-50 flex items-center justify-center gap-2">
            {analyzing ? <><Loader2 className="w-4 h-4 animate-spin" /> Analyzing...</> : 'Analyze & Build Causality Graph'}
          </button>
        </div>
        {realIncidents.length > 0 && (
          <p className="text-xs text-accent-green mt-2">
            Built {realIncidents.length} incident chain(s) from {analysisResult.predictions.length} predictions.
          </p>
        )}
      </div>

      {/* Live Monitor Data Banner */}
      {hasLiveData() && !liveDataLoaded && !analysisResult && (
        <div className="flex items-center gap-3 px-4 py-3 bg-accent-orange/10 border border-accent-orange/20 rounded-xl">
          <Radio className="w-4 h-4 text-accent-orange" />
          <div className="flex-1">
            <span className="text-xs font-medium text-accent-orange">Live Monitor data available</span>
            <span className="text-[10px] text-text-secondary ml-2">{getLiveData()?.totalFlows} flows from {getLiveData()?.source}</span>
          </div>
          <button
            onClick={loadLiveData}
            className="px-3 py-1 bg-accent-orange hover:bg-accent-orange/80 text-white text-[10px] font-medium rounded-lg transition-colors"
          >
            Use Live Data
          </button>
        </div>
      )}

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: 'Total Incidents', value: stats.totalIncidents, icon: Shield, color: 'text-accent-blue' },
          { label: 'Total Alerts', value: stats.totalAlerts, icon: AlertTriangle, color: 'text-accent-amber' },
          { label: 'Avg Alerts / Incident', value: stats.avgAlerts, icon: Activity, color: 'text-accent-green' },
          { label: 'Critical Incidents', value: stats.criticalCount, icon: Zap, color: 'text-accent-red' },
          { label: 'Kill-Chain Stages', value: uniqueStages.length, icon: GitBranch, color: 'text-accent-purple' },
        ].map((s) => (
          <div
            key={s.label}
            className="bg-bg-card/60 border border-bg-card rounded-xl p-4 flex flex-col items-center text-center gap-1"
          >
            <s.icon className={`w-5 h-5 ${s.color}`} />
            <span className="text-xl font-bold font-display">{s.value}</span>
            <span className="text-[11px] text-text-secondary">{s.label}</span>
          </div>
        ))}
      </div>

      {/* Search */}
      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-secondary" />
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Search incidents, attacks, IPs..."
          className="w-full pl-9 pr-4 py-2 text-sm bg-bg-card/60 border border-bg-card rounded-lg text-text-primary placeholder:text-text-secondary/50 focus:outline-none focus:ring-1 focus:ring-accent-blue/50"
        />
      </div>

      {/* Stage Legend */}
      <div className="flex flex-wrap gap-2">
        {Object.entries(STAGE_COLORS).map(([stage, color]) => (
          <span
            key={stage}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium border border-white/10"
            style={{ backgroundColor: `${color}20`, color }}
          >
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
            {stage}
          </span>
        ))}
      </div>

      {/* Incident Cards */}
      <div className="space-y-3">
        {filteredIncidents.length === 0 && (
          <div className="text-center py-12 text-text-secondary text-sm">
            No incidents match your search.
          </div>
        )}

        {filteredIncidents.map((incident) => {
          const isExpanded = expandedId === incident.id
          const timeSpan = `${incident.alerts[0].time} - ${incident.alerts[incident.alerts.length - 1].time}`
          const severityStyle = SEVERITY_STYLES[incident.severity] || SEVERITY_STYLES.medium

          return (
            <div
              key={incident.id}
              className="bg-bg-card/60 border border-bg-card rounded-xl overflow-hidden"
            >
              {/* Incident header */}
              <button
                onClick={() => toggle(incident.id)}
                className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-bg-card/40 transition-colors"
              >
                {isExpanded ? (
                  <ChevronDown className="w-4 h-4 text-text-secondary shrink-0" />
                ) : (
                  <ChevronRight className="w-4 h-4 text-text-secondary shrink-0" />
                )}

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-mono text-text-secondary">{incident.id}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${severityStyle}`}>
                      {incident.severity}
                    </span>
                    <span className="text-sm font-semibold truncate">{incident.title}</span>
                  </div>
                  <div className="flex items-center gap-4 mt-1 text-[11px] text-text-secondary">
                    <span className="flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" />
                      {incident.alerts.length} alerts
                    </span>
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {timeSpan}
                    </span>
                    <span className="flex items-center gap-1">
                      <GitBranch className="w-3 h-3" />
                      {new Set(incident.alerts.map((a) => a.stage)).size} stages
                    </span>
                  </div>
                </div>
              </button>

              {/* Expanded: Causality Chain */}
              {isExpanded && (
                <div className="border-t border-bg-card px-4 py-5 space-y-5">
                  {/* Horizontal timeline */}
                  <div className="overflow-x-auto pb-2">
                    <div className="flex items-stretch gap-0 min-w-max">
                      {incident.alerts.map((alert, idx) => {
                        const stageColor = STAGE_COLORS[alert.stage] || '#6B7280'
                        const isLast = idx === incident.alerts.length - 1

                        return (
                          <div key={alert.id} className="flex items-stretch">
                            {/* Alert node */}
                            <div
                              className="relative flex flex-col items-center p-3 rounded-xl border min-w-[160px] max-w-[180px]"
                              style={{
                                borderColor: `${stageColor}50`,
                                backgroundColor: `${stageColor}10`,
                              }}
                            >
                              {/* Stage label */}
                              <span
                                className="text-[10px] font-bold uppercase tracking-wide mb-1.5 px-2 py-0.5 rounded-full"
                                style={{ backgroundColor: `${stageColor}25`, color: stageColor }}
                              >
                                {alert.stage}
                              </span>

                              {/* Attack name */}
                              <span className="text-xs font-semibold text-center leading-tight">
                                {alert.attack}
                              </span>

                              {/* Time */}
                              <span className="text-[10px] text-text-secondary mt-1 font-mono">
                                {alert.time}
                              </span>

                              {/* Src -> Dst */}
                              <div className="flex items-center gap-1 mt-1.5 text-[10px] text-text-secondary">
                                <span className="font-mono truncate max-w-[65px]" title={alert.src}>
                                  {alert.src}
                                </span>
                                <ArrowRight className="w-2.5 h-2.5 shrink-0" />
                                <span className="font-mono truncate max-w-[65px]" title={alert.dst}>
                                  {alert.dst}
                                </span>
                              </div>

                              {/* Confidence bar */}
                              <div className="w-full mt-2">
                                <div className="flex justify-between text-[9px] text-text-secondary mb-0.5">
                                  <span>Confidence</span>
                                  <span className="font-mono">{(alert.confidence * 100).toFixed(0)}%</span>
                                </div>
                                <div className="h-1.5 bg-bg-primary/50 rounded-full overflow-hidden">
                                  <div
                                    className="h-full rounded-full transition-all"
                                    style={{
                                      width: `${alert.confidence * 100}%`,
                                      backgroundColor: stageColor,
                                    }}
                                  />
                                </div>
                              </div>

                              {/* Alert ID badge */}
                              <span
                                className="absolute -top-2 -right-2 text-[9px] font-bold px-1.5 py-0.5 rounded-full text-white"
                                style={{ backgroundColor: stageColor }}
                              >
                                {alert.id}
                              </span>
                            </div>

                            {/* Arrow connector */}
                            {!isLast && (
                              <div className="flex items-center px-1.5">
                                <div className="flex items-center">
                                  <div className="w-6 h-0.5 bg-text-secondary/30" />
                                  <ArrowRight className="w-4 h-4 text-text-secondary/50 -ml-1" />
                                </div>
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  </div>

                  {/* Root Cause Analysis */}
                  <div className="grid md:grid-cols-2 gap-3">
                    <div className="bg-bg-primary/40 border border-accent-red/20 rounded-lg p-4">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-accent-red mb-2 flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        Root Cause
                      </h4>
                      <p className="text-sm text-text-primary">{incident.rootCause}</p>
                    </div>
                    <div className="bg-bg-primary/40 border border-accent-green/20 rounded-lg p-4">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-accent-green mb-2 flex items-center gap-1.5">
                        <Shield className="w-3.5 h-3.5" />
                        Recommendation
                      </h4>
                      <p className="text-sm text-text-primary">{incident.recommendation}</p>
                    </div>
                  </div>

                  {/* Alert detail table */}
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="text-text-secondary border-b border-bg-card">
                          <th className="text-left py-2 px-2 font-semibold">ID</th>
                          <th className="text-left py-2 px-2 font-semibold">Time</th>
                          <th className="text-left py-2 px-2 font-semibold">Attack</th>
                          <th className="text-left py-2 px-2 font-semibold">Stage</th>
                          <th className="text-left py-2 px-2 font-semibold">Source</th>
                          <th className="text-left py-2 px-2 font-semibold">Destination</th>
                          <th className="text-right py-2 px-2 font-semibold">Confidence</th>
                        </tr>
                      </thead>
                      <tbody>
                        {incident.alerts.map((alert) => {
                          const stageColor = STAGE_COLORS[alert.stage] || '#6B7280'
                          return (
                            <tr key={alert.id} className="border-b border-bg-card/50 hover:bg-bg-card/30">
                              <td className="py-2 px-2 font-mono font-bold" style={{ color: stageColor }}>
                                {alert.id}
                              </td>
                              <td className="py-2 px-2 font-mono text-text-secondary">{alert.time}</td>
                              <td className="py-2 px-2 font-semibold">{alert.attack}</td>
                              <td className="py-2 px-2">
                                <span
                                  className="px-1.5 py-0.5 rounded text-[10px] font-medium"
                                  style={{ backgroundColor: `${stageColor}20`, color: stageColor }}
                                >
                                  {alert.stage}
                                </span>
                              </td>
                              <td className="py-2 px-2 font-mono text-text-secondary">{alert.src}</td>
                              <td className="py-2 px-2 font-mono text-text-secondary">{alert.dst}</td>
                              <td className="py-2 px-2 text-right font-mono">
                                {(alert.confidence * 100).toFixed(0)}%
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
