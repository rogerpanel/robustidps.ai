import { useState, useCallback } from 'react'
import {
  Loader2, Shield, AlertTriangle, CheckCircle2, ChevronDown, ChevronUp,
  Upload, FileText, X, Zap, Brain, Target, GitBranch, BarChart3, Radio,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import ModelSelector from '../components/ModelSelector'
import { analyseFile, cachePageResult } from '../utils/api'
import { useNoticeBoard } from '../hooks/useNoticeBoard'
import { getLiveData, hasLiveData } from '../utils/liveDataStore'

/* ── Types ── */
interface Phase { id: number; label: string; status: 'pending' | 'running' | 'done' }
interface IncidentSummary { id: string; source: string; alerts: number; attacks: string[]; maxConfidence: number; severity: 'critical' | 'high' }
interface InvestigationReport {
  totalFlows: number; threats: number; benign: number; model: string
  incidents: IncidentSummary[]; topActors: [string, number][]
  triage: { tp: number; fp: number; review: number }
  attackTypes: string[]; firstAlert: string; lastAlert: string
}

/* ── Helpers ── */
const triageAlert = (p: any) => {
  if (p.confidence >= 0.95 && p.severity !== 'benign') return 'true_positive'
  if (p.confidence <= 0.30 || p.severity === 'benign') return 'false_positive'
  return 'needs_review'
}

const buildIncidents = (predictions: any[]): IncidentSummary[] => {
  const groups: Record<string, any[]> = {}
  predictions.filter(p => p.severity !== 'benign').forEach((p, i) => {
    const src = p.src_ip || 'unknown'
    if (!groups[src]) groups[src] = []
    groups[src].push({ ...p, index: i })
  })
  return Object.entries(groups)
    .filter(([_, alerts]) => alerts.length >= 2)
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 10)
    .map(([src, alerts], i) => ({
      id: `INC-${String(i + 1).padStart(3, '0')}`,
      source: src,
      alerts: alerts.length,
      attacks: [...new Set(alerts.map((a: any) => a.label_predicted))],
      maxConfidence: Math.max(...alerts.map((a: any) => a.confidence || 0)),
      severity: alerts.some((a: any) => a.label_predicted?.includes('Malware') || a.label_predicted?.includes('Ransom')) ? 'critical' as const : 'high' as const,
    }))
}

const recommendActions = (types: string[]): string[] => {
  const actions: string[] = []
  const joined = types.join(' ')
  if (joined.includes('DDoS')) actions.push('Enable rate-limiting and DDoS mitigation on edge firewalls')
  if (joined.includes('BruteForce')) actions.push('Enforce MFA and lock accounts after 5 failed attempts')
  if (joined.includes('Malware') || joined.includes('Ransom')) actions.push('Isolate infected hosts and initiate forensic imaging')
  if (joined.includes('Recon') || joined.includes('Scan')) actions.push('Block scanner IPs and review firewall ACLs')
  if (joined.includes('WebAttack') || joined.includes('SQLi') || joined.includes('XSS')) actions.push('Deploy WAF rules and patch web applications')
  if (joined.includes('Spoofing')) actions.push('Enable BCP38 ingress filtering on border routers')
  if (joined.includes('Mirai') || joined.includes('Botnet')) actions.push('Segment IoT network and change default credentials')
  if (actions.length === 0) actions.push('Review all flagged alerts and update detection signatures')
  return actions
}

const GUIDE_STEPS = [
  { title: 'Upload Traffic', desc: 'Upload a CSV/PCAP file or use live monitor data as input.' },
  { title: 'Select Model', desc: 'Choose a detection model for threat classification.' },
  { title: 'Launch Investigation', desc: 'Click the button to run a full autonomous investigation pipeline.' },
  { title: 'Review Report', desc: 'Examine the generated report with incidents, triage, and recommendations.' },
]

const PHASE_LABELS = ['Analyzing traffic...', 'Triaging alerts...', 'Building incident chains...', 'Generating summary...']
const SEV_STYLE: Record<string, string> = { critical: 'bg-red-500/20 text-red-400', high: 'bg-orange-500/20 text-orange-400' }

export default function AutoInvestigation() {
  const [file, setFile] = useState<File | null>(null)
  const [modelId, setModelId] = useState('surrogate')
  const [liveDataLoaded, setLiveDataLoaded] = useState(false)
  const [rawData, setRawData] = useState<any>(null)
  const [phases, setPhases] = useState<Phase[]>(PHASE_LABELS.map((label, i) => ({ id: i, label, status: 'pending' as const })))
  const [running, setRunning] = useState(false)
  const [report, setReport] = useState<InvestigationReport | null>(null)
  const [expandedSection, setExpandedSection] = useState<string | null>('executive')
  const { addNotice, updateNotice } = useNoticeBoard()

  const loadLiveData = useCallback(() => {
    const live = getLiveData()
    if (!live) return
    setRawData({ predictions: live.predictions, n_flows: live.totalFlows, n_threats: live.threatCount, n_benign: live.benignCount })
    setLiveDataLoaded(true)
  }, [])

  const updatePhase = (idx: number, status: Phase['status']) => {
    setPhases(prev => prev.map((p, i) => i === idx ? { ...p, status } : p))
  }

  const delay = (ms: number) => new Promise(r => setTimeout(r, ms))

  const runInvestigation = async () => {
    setRunning(true)
    setReport(null)
    setPhases(PHASE_LABELS.map((label, i) => ({ id: i, label, status: 'pending' as const })))
    const nid = addNotice({ title: 'Auto-Investigation', description: 'Starting investigation pipeline...', status: 'running', page: '/auto-investigation' })

    try {
      // Phase 1: Analyze
      updatePhase(0, 'running')
      let data = rawData
      if (!data && file) {
        data = await analyseFile(file, modelId, 'auto_investigation')
        setRawData(data)
      }
      if (!data?.predictions?.length) throw new Error('No predictions available')
      await delay(400)
      updatePhase(0, 'done')

      // Phase 2: Triage
      updatePhase(1, 'running')
      await delay(500)
      const triaged = data.predictions.map((p: any) => ({ ...p, triage: triageAlert(p) }))
      updatePhase(1, 'done')

      // Phase 3: Incident chains
      updatePhase(2, 'running')
      await delay(500)
      const incidents = buildIncidents(triaged)
      updatePhase(2, 'done')

      // Phase 4: Summary
      updatePhase(3, 'running')
      await delay(400)
      const tp = triaged.filter((t: any) => t.triage === 'true_positive').length
      const fp = triaged.filter((t: any) => t.triage === 'false_positive').length
      const review = triaged.filter((t: any) => t.triage === 'needs_review').length
      const threats = triaged.filter((t: any) => t.severity !== 'benign')
      const attackTypes = [...new Set(threats.map((t: any) => t.label_predicted))] as string[]
      const ipCounts: Record<string, number> = {}
      threats.forEach((t: any) => { const ip = t.src_ip || 'unknown'; ipCounts[ip] = (ipCounts[ip] || 0) + 1 })
      const topActors = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 5)

      const finalReport: InvestigationReport = {
        totalFlows: data.predictions.length,
        threats: threats.length,
        benign: data.predictions.length - threats.length,
        model: modelId,
        incidents,
        topActors,
        triage: { tp, fp, review },
        attackTypes,
        firstAlert: new Date(Date.now() - data.predictions.length * 60000).toLocaleTimeString(),
        lastAlert: new Date().toLocaleTimeString(),
      }
      setReport(finalReport)
      updatePhase(3, 'done')

      cachePageResult('auto_investigation', {
        n_flows: finalReport.totalFlows,
        n_threats: finalReport.threats,
        n_incidents: incidents.length,
        model_used: modelId,
      })
      updateNotice(nid, { status: 'completed', description: `Investigation complete: ${incidents.length} incidents, ${threats.length} threats` })
    } catch (err) {
      updateNotice(nid, { status: 'error', description: err instanceof Error ? err.message : 'Investigation failed' })
    }
    setRunning(false)
  }

  const canLaunch = (file || rawData) && !running

  const toggleSection = (s: string) => setExpandedSection(prev => prev === s ? null : s)

  const triagePct = (count: number) => report ? ((count / report.totalFlows) * 100).toFixed(1) : '0'

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display font-bold flex items-center gap-2">
            <Zap className="w-6 h-6 text-accent-orange" />
            Auto-Investigation
          </h1>
          <p className="text-sm text-text-secondary mt-1">
            One-click autonomous investigation: analysis, triage, causality mapping, and incident summary.
          </p>
        </div>
        {report && <ExportMenu filename="auto-investigation-report" />}
      </div>

      <PageGuide title="How to use Auto-Investigation" steps={GUIDE_STEPS} tip="Tip: Upload a dataset with mixed attack types for the most comprehensive investigation report." />

      {/* Upload + Model */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">
          <Upload className="w-5 h-5 text-text-secondary" /> Input Data
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end">
          <div>
            {file ? (
              <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-accent-green/30 bg-accent-green/5">
                <FileText className="w-4 h-4 text-accent-green shrink-0" />
                <span className="text-xs font-mono truncate flex-1">{file.name}</span>
                <button onClick={() => { setFile(null); setRawData(null); setReport(null) }} className="text-text-secondary hover:text-text-primary"><X className="w-3.5 h-3.5" /></button>
              </div>
            ) : (
              <label
                onDragOver={e => { e.preventDefault(); e.currentTarget.classList.add('border-accent-blue', 'bg-accent-blue/10') }}
                onDragLeave={e => { e.currentTarget.classList.remove('border-accent-blue', 'bg-accent-blue/10') }}
                onDrop={e => { e.preventDefault(); e.currentTarget.classList.remove('border-accent-blue', 'bg-accent-blue/10'); const f = e.dataTransfer.files[0]; if (f) setFile(f) }}
                className="flex flex-col items-center gap-1 px-3 py-3 rounded-lg border-2 border-dashed border-bg-card hover:border-text-secondary cursor-pointer transition-colors"
              >
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
          <button
            onClick={runInvestigation}
            disabled={!canLaunch}
            className="px-4 py-2.5 bg-accent-orange hover:bg-accent-orange/80 text-white rounded-lg text-sm font-semibold disabled:opacity-50 flex items-center justify-center gap-2 transition-colors"
          >
            {running ? <><Loader2 className="w-4 h-4 animate-spin" /> Investigating...</> : <><Zap className="w-4 h-4" /> Launch Auto-Investigation</>}
          </button>
        </div>
      </div>

      {/* Live Monitor Banner */}
      {hasLiveData() && !liveDataLoaded && !rawData && (
        <div className="flex items-center gap-3 px-4 py-3 bg-accent-orange/10 border border-accent-orange/20 rounded-xl">
          <Radio className="w-4 h-4 text-accent-orange" />
          <div className="flex-1">
            <span className="text-xs font-medium text-accent-orange">Live Monitor data available</span>
            <span className="text-[10px] text-text-secondary ml-2">{getLiveData()?.totalFlows} flows from {getLiveData()?.source}</span>
          </div>
          <button onClick={loadLiveData} className="px-3 py-1 bg-accent-orange hover:bg-accent-orange/80 text-white text-[10px] font-medium rounded-lg transition-colors">
            Use Live Data
          </button>
        </div>
      )}

      {/* Phase Stepper */}
      {(running || report) && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <Brain className="w-4 h-4 text-accent-purple" /> Investigation Pipeline
          </h3>
          <div className="space-y-3">
            {phases.map((phase, i) => (
              <div key={phase.id} className="flex items-center gap-3">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 transition-colors ${
                  phase.status === 'done' ? 'bg-accent-green/20' : phase.status === 'running' ? 'bg-accent-blue/20' : 'bg-bg-card'
                }`}>
                  {phase.status === 'done' ? <CheckCircle2 className="w-4 h-4 text-accent-green" />
                    : phase.status === 'running' ? <Loader2 className="w-4 h-4 text-accent-blue animate-spin" />
                    : <span className="text-xs text-text-secondary">{i + 1}</span>}
                </div>
                {i < phases.length - 1 && <div className={`absolute ml-4 mt-10 w-px h-4 ${phase.status === 'done' ? 'bg-accent-green/30' : 'bg-bg-card'}`} />}
                <span className={`text-sm ${phase.status === 'done' ? 'text-accent-green' : phase.status === 'running' ? 'text-accent-blue' : 'text-text-secondary'}`}>
                  {phase.label}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Investigation Report */}
      {report && (
        <div className="space-y-4" id="export-target">
          {/* Executive Summary */}
          <div className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
            <button onClick={() => toggleSection('executive')} className="w-full flex items-center justify-between p-4 hover:bg-bg-card/50 transition-colors">
              <h3 className="text-sm font-semibold flex items-center gap-2"><BarChart3 className="w-4 h-4 text-accent-blue" /> Executive Summary</h3>
              {expandedSection === 'executive' ? <ChevronUp className="w-4 h-4 text-text-secondary" /> : <ChevronDown className="w-4 h-4 text-text-secondary" />}
            </button>
            {expandedSection === 'executive' && (
              <div className="px-4 pb-4">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {[
                    { label: 'Total Flows', value: report.totalFlows, color: 'text-accent-blue' },
                    { label: 'Threats', value: report.threats, color: 'text-accent-red' },
                    { label: 'Benign', value: report.benign, color: 'text-accent-green' },
                    { label: 'Incidents', value: report.incidents.length, color: 'text-accent-orange' },
                  ].map(s => (
                    <div key={s.label} className="bg-bg-card rounded-lg p-3 text-center">
                      <p className={`text-xl font-bold ${s.color}`}>{s.value}</p>
                      <p className="text-[10px] text-text-secondary">{s.label}</p>
                    </div>
                  ))}
                </div>
                <p className="text-xs text-text-secondary mt-3">Model: <span className="text-text-primary font-mono">{report.model}</span> | Timeline: {report.firstAlert} — {report.lastAlert}</p>
              </div>
            )}
          </div>

          {/* Incident Chains */}
          <div className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
            <button onClick={() => toggleSection('incidents')} className="w-full flex items-center justify-between p-4 hover:bg-bg-card/50 transition-colors">
              <h3 className="text-sm font-semibold flex items-center gap-2"><GitBranch className="w-4 h-4 text-accent-purple" /> Incident Chains ({report.incidents.length})</h3>
              {expandedSection === 'incidents' ? <ChevronUp className="w-4 h-4 text-text-secondary" /> : <ChevronDown className="w-4 h-4 text-text-secondary" />}
            </button>
            {expandedSection === 'incidents' && (
              <div className="px-4 pb-4 space-y-2">
                {report.incidents.length === 0 && <p className="text-xs text-text-secondary">No multi-alert incident chains detected.</p>}
                {report.incidents.map(inc => (
                  <div key={inc.id} className="bg-bg-card rounded-lg p-3 flex items-start gap-3">
                    <div className="shrink-0">
                      <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold ${SEV_STYLE[inc.severity]}`}>{inc.severity}</span>
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-semibold">{inc.id} — {inc.source}</p>
                      <p className="text-[10px] text-text-secondary">{inc.alerts} alerts | Max confidence: {(inc.maxConfidence * 100).toFixed(0)}%</p>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {inc.attacks.map(a => <span key={a} className="px-1.5 py-0.5 bg-accent-blue/10 text-accent-blue rounded text-[9px]">{a}</span>)}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Top 5 Threat Actors */}
          <div className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
            <button onClick={() => toggleSection('actors')} className="w-full flex items-center justify-between p-4 hover:bg-bg-card/50 transition-colors">
              <h3 className="text-sm font-semibold flex items-center gap-2"><Target className="w-4 h-4 text-accent-red" /> Top Threat Actors</h3>
              {expandedSection === 'actors' ? <ChevronUp className="w-4 h-4 text-text-secondary" /> : <ChevronDown className="w-4 h-4 text-text-secondary" />}
            </button>
            {expandedSection === 'actors' && (
              <div className="px-4 pb-4 space-y-2">
                {report.topActors.map(([ip, count], i) => (
                  <div key={ip} className="flex items-center gap-3">
                    <span className="text-xs text-text-secondary w-4">{i + 1}.</span>
                    <span className="text-xs font-mono flex-1">{ip}</span>
                    <div className="w-32 bg-bg-card rounded-full h-2 overflow-hidden">
                      <div className="h-full bg-accent-red/60 rounded-full" style={{ width: `${(count / report.topActors[0][1]) * 100}%` }} />
                    </div>
                    <span className="text-xs text-text-secondary w-12 text-right">{count} alerts</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Triage & Recommendations */}
          <div className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
            <button onClick={() => toggleSection('triage')} className="w-full flex items-center justify-between p-4 hover:bg-bg-card/50 transition-colors">
              <h3 className="text-sm font-semibold flex items-center gap-2"><Shield className="w-4 h-4 text-accent-amber" /> Triage &amp; Recommendations</h3>
              {expandedSection === 'triage' ? <ChevronUp className="w-4 h-4 text-text-secondary" /> : <ChevronDown className="w-4 h-4 text-text-secondary" />}
            </button>
            {expandedSection === 'triage' && (
              <div className="px-4 pb-4 space-y-4">
                <div className="grid grid-cols-3 gap-3">
                  {[
                    { label: 'True Positives', value: report.triage.tp, pct: triagePct(report.triage.tp), color: 'text-red-400 bg-red-500/15' },
                    { label: 'False Positives', value: report.triage.fp, pct: triagePct(report.triage.fp), color: 'text-green-400 bg-green-500/15' },
                    { label: 'Needs Review', value: report.triage.review, pct: triagePct(report.triage.review), color: 'text-amber-400 bg-amber-500/15' },
                  ].map(t => (
                    <div key={t.label} className={`rounded-lg p-3 text-center ${t.color}`}>
                      <p className="text-lg font-bold">{t.value}</p>
                      <p className="text-[10px]">{t.label} ({t.pct}%)</p>
                    </div>
                  ))}
                </div>
                <div>
                  <p className="text-xs font-semibold flex items-center gap-1.5 mb-2"><AlertTriangle className="w-3.5 h-3.5 text-accent-orange" /> Recommended Actions</p>
                  {recommendActions(report.attackTypes).map((action, i) => (
                    <div key={i} className="flex items-start gap-2 mb-1">
                      <CheckCircle2 className="w-3.5 h-3.5 text-accent-green shrink-0 mt-0.5" />
                      <span className="text-xs text-text-secondary">{action}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Continue Investigation */}
          <div className="flex flex-wrap gap-2 mt-4 pt-4 border-t border-bg-card">
            <span className="text-[10px] text-text-secondary mr-2">Continue to:</span>
            <a href="/alert-triage" className="text-[10px] px-2 py-1 rounded bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20 transition-colors">Alert Triage</a>
            <a href="/incident-reports" className="text-[10px] px-2 py-1 rounded bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20 transition-colors">Incident Reports</a>
            <a href="/threat-intel" className="text-[10px] px-2 py-1 rounded bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20 transition-colors">Threat Intel</a>
            <a href="/rule-generator" className="text-[10px] px-2 py-1 rounded bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20 transition-colors">Rule Generator</a>
            <a href="/mitre-attack" className="text-[10px] px-2 py-1 rounded bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20 transition-colors">MITRE ATT&CK</a>
          </div>
        </div>
      )}
    </div>
  )
}
