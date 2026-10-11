import { useState, useMemo } from 'react'
import {
  Workflow, Loader2, CheckCircle2, AlertTriangle, Upload, FileText, X,
  Radio, Zap, Search, FileBarChart, ChevronRight, Brain,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import ModelSelector from '../components/ModelSelector'
import { analyseFile, cachePageResult } from '../utils/api'
import { useNoticeBoard } from '../hooks/useNoticeBoard'
import { getLiveData, hasLiveData } from '../utils/liveDataStore'
import { registerSessionReset } from '../utils/sessionReset'

/* ── Autonomous Investigation Chain ──────────────────────────────────────
 * One-click pipeline that executes Auto-Investigation → Threat Hunt →
 * Incident Report end to end on a single dataset, with all intermediate
 * results cached for the SOC Copilot.
 */

type PhaseStatus = 'pending' | 'running' | 'done' | 'skipped'
interface Phase { id: string; label: string; desc: string; status: PhaseStatus; durationMs?: number }

interface IncidentSummary { id: string; source: string; alerts: number; attacks: string[]; maxConfidence: number; severity: 'critical' | 'high' }
interface HuntFinding {
  id: string; query: string; matchCount: number; topActor?: string;
  sample: { src_ip?: string; dst_ip?: string; label?: string; conf?: number }[]
}

interface ChainReport {
  totalFlows: number
  threats: number
  benign: number
  model: string
  startedAt: string
  finishedAt: string

  // Auto-Investigation outputs
  incidents: IncidentSummary[]
  triage: { tp: number; fp: number; review: number }
  topActors: [string, number][]
  attackTypes: string[]

  // Threat Hunt outputs
  huntFindings: HuntFinding[]

  // Incident Report (final unified)
  executiveSummary: string
  recommendations: string[]
  keyMitreTechniques: string[]
}

const PHASES_INIT: Phase[] = [
  { id: 'analyze',      label: 'Analyze Traffic',          desc: 'Run detection model over flows',                 status: 'pending' },
  { id: 'auto_invest',  label: 'Auto-Investigation',       desc: 'Triage alerts, group incidents by source IP',    status: 'pending' },
  { id: 'threat_hunt',  label: 'Threat Hunt',              desc: 'Execute canned hunt queries across the dataset', status: 'pending' },
  { id: 'incident_rpt', label: 'Build Incident Report',    desc: 'Synthesise executive summary + recommendations', status: 'pending' },
  { id: 'cache',        label: 'Cache for Copilot',        desc: 'Make findings available to SOC Copilot',         status: 'pending' },
]

const HUNT_QUERIES: { id: string; query: string; predicate: (p: any) => boolean }[] = [
  { id: 'q_ddos',         query: 'All DDoS attacks',                       predicate: p => /ddos/i.test(p.label_predicted || '') },
  { id: 'q_brute',        query: 'SSH/FTP/HTTP brute force',               predicate: p => /bruteforce/i.test(p.label_predicted || '') },
  { id: 'q_recon',        query: 'Reconnaissance / scanning',              predicate: p => /recon/i.test(p.label_predicted || '') },
  { id: 'q_malware',      query: 'Malware / ransomware / backdoor',        predicate: p => /malware|ransom|backdoor/i.test(p.label_predicted || '') },
  { id: 'q_web',          query: 'Web exploitation (SQLi/XSS/CmdInj)',     predicate: p => /webattack/i.test(p.label_predicted || '') },
  { id: 'q_botnet',       query: 'Mirai / botnet activity',                predicate: p => /mirai|botnet/i.test(p.label_predicted || '') },
  { id: 'q_high_conf',    query: 'High-confidence threats (>=95%)',        predicate: p => (p.confidence || 0) >= 0.95 && p.severity !== 'benign' },
  { id: 'q_critical',     query: 'Critical-severity events',               predicate: p => p.severity === 'critical' },
  { id: 'q_anomalous',    query: 'Anomalous low-confidence threats',       predicate: p => (p.confidence || 0) < 0.5 && p.severity !== 'benign' },
]

/* MITRE ATT&CK lookup snippet — keep concise here, the full mapper lives on /mitre-attack */
const ATTACK_LOOKUP: Record<string, string> = {
  'DDoS': 'T1498 Network DoS',
  'BruteForce': 'T1110 Brute Force',
  'Recon': 'T1046 Network Service Discovery',
  'Malware': 'T1059 Command/Scripting',
  'WebAttack': 'T1190 Public-Facing App Exploit',
  'Mirai': 'T1583.005 Botnet',
  'Spoofing': 'T1557 AiTM',
}

const triageAlert = (p: any) => {
  if (p.confidence >= 0.95 && p.severity !== 'benign') return 'true_positive'
  if (p.confidence <= 0.30 || p.severity === 'benign') return 'false_positive'
  return 'needs_review'
}

const buildIncidents = (predictions: any[]): IncidentSummary[] => {
  const groups: Record<string, any[]> = {}
  predictions.filter(p => p.severity !== 'benign').forEach(p => {
    const src = p.src_ip || 'unknown'
    if (!groups[src]) groups[src] = []
    groups[src].push(p)
  })
  return Object.entries(groups)
    .filter(([_, alerts]) => alerts.length >= 2)
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 12)
    .map(([src, alerts], i) => ({
      id: `INC-${String(i + 1).padStart(3, '0')}`,
      source: src,
      alerts: alerts.length,
      attacks: [...new Set(alerts.map((a: any) => a.label_predicted))],
      maxConfidence: Math.max(...alerts.map((a: any) => a.confidence || 0)),
      severity: alerts.some((a: any) => /malware|ransom|backdoor/i.test(a.label_predicted || '')) ? 'critical' as const : 'high' as const,
    }))
}

const recommendActions = (types: string[]): string[] => {
  const actions: string[] = []
  const joined = types.join(' ').toLowerCase()
  if (/ddos/.test(joined)) actions.push('Enable rate-limiting and DDoS mitigation on edge firewalls')
  if (/bruteforce/.test(joined)) actions.push('Enforce MFA and lock accounts after 5 failed attempts')
  if (/malware|ransom|backdoor/.test(joined)) actions.push('Isolate infected hosts and initiate forensic imaging')
  if (/recon|scan/.test(joined)) actions.push('Block scanner IPs and review firewall ACLs')
  if (/webattack|sqli|xss|cmdinjection/.test(joined)) actions.push('Deploy WAF rules and patch web applications')
  if (/spoofing/.test(joined)) actions.push('Enable BCP38 ingress filtering on border routers')
  if (/mirai|botnet/.test(joined)) actions.push('Segment IoT network and rotate default credentials')
  if (actions.length === 0) actions.push('Review all flagged alerts and update detection signatures')
  return actions
}

const _store: { file: File | null; modelId: string; report: ChainReport | null; rawData: any } = {
  file: null, modelId: 'surrogate', report: null, rawData: null,
}
registerSessionReset(() => { _store.file = null; _store.modelId = 'surrogate'; _store.report = null; _store.rawData = null })

const GUIDE_STEPS = [
  { title: 'Pick input', desc: 'Upload a CSV/PCAP or use Live Monitor data — same source, three pipelines.' },
  { title: 'Choose model', desc: 'Select a detection model. The same model classifies all flows for the entire chain.' },
  { title: 'Run chain', desc: 'Click Run Chain — Auto-Investigation, Threat Hunt and Incident Report execute back-to-back without manual hand-off.' },
  { title: 'Review report', desc: 'Each phase\'s output is shown inline; cross-page links jump to the full standalone view.' },
  { title: 'Hand off', desc: 'Final findings are cached so the SOC Copilot can answer questions like "What did the chain find?"' },
]

export default function InvestigationChain() {
  const [file, _setFile] = useState<File | null>(_store.file)
  const [modelId, _setModelId] = useState(_store.modelId)
  const [report, _setReport] = useState<ChainReport | null>(_store.report)
  const [rawData, _setRawData] = useState<any>(_store.rawData)
  const [phases, setPhases] = useState<Phase[]>(PHASES_INIT)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [liveLoaded, setLiveLoaded] = useState(false)
  const { addNotice, updateNotice } = useNoticeBoard()

  const setFile = (v: File | null) => { _store.file = v; _setFile(v) }
  const setModelId = (v: string) => { _store.modelId = v; _setModelId(v) }
  const setReport = (v: ChainReport | null) => { _store.report = v; _setReport(v) }
  const setRawData = (v: any) => { _store.rawData = v; _setRawData(v) }

  const sleep = (ms: number) => new Promise(r => setTimeout(r, ms))
  const updatePhase = (id: string, patch: Partial<Phase>) =>
    setPhases(prev => prev.map(p => p.id === id ? { ...p, ...patch } : p))

  const loadLiveData = () => {
    const live = getLiveData()
    if (!live) return
    setRawData({ predictions: live.predictions })
    setLiveLoaded(true)
  }

  const runChain = async () => {
    setRunning(true)
    setError(null)
    setReport(null)
    setPhases(PHASES_INIT.map(p => ({ ...p, status: 'pending' as PhaseStatus })))
    const startedAt = new Date().toISOString()
    const nid = addNotice({ title: 'Investigation Chain', description: 'Running Auto-Invest → Threat Hunt → Report...', status: 'running', page: '/investigation-chain' })

    try {
      // Phase 1: Analyze
      const t0 = performance.now()
      updatePhase('analyze', { status: 'running' })
      let data = rawData
      if (!data && file) {
        data = await analyseFile(file, modelId, 'auto_investigation')
        setRawData(data)
      }
      if (!data?.predictions?.length) throw new Error('No predictions available — upload a dataset or load live data first.')
      updatePhase('analyze', { status: 'done', durationMs: Math.round(performance.now() - t0) })

      // Phase 2: Auto-Investigation
      const t1 = performance.now()
      updatePhase('auto_invest', { status: 'running' })
      await sleep(180)
      const triaged = data.predictions.map((p: any) => ({ ...p, triage: triageAlert(p) }))
      const tp = triaged.filter((t: any) => t.triage === 'true_positive').length
      const fp = triaged.filter((t: any) => t.triage === 'false_positive').length
      const review = triaged.filter((t: any) => t.triage === 'needs_review').length
      const incidents = buildIncidents(triaged)
      const threats = triaged.filter((t: any) => t.severity !== 'benign')
      const attackTypes = [...new Set(threats.map((t: any) => t.label_predicted))] as string[]
      const ipCounts: Record<string, number> = {}
      threats.forEach((t: any) => { const ip = t.src_ip || 'unknown'; ipCounts[ip] = (ipCounts[ip] || 0) + 1 })
      const topActors = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 5) as [string, number][]
      cachePageResult('auto_investigation', {
        n_flows: data.predictions.length, n_threats: threats.length,
        n_incidents: incidents.length, model_used: modelId, source: 'investigation_chain',
      }).catch(() => {})
      updatePhase('auto_invest', { status: 'done', durationMs: Math.round(performance.now() - t1) })

      // Phase 3: Threat Hunt
      const t2 = performance.now()
      updatePhase('threat_hunt', { status: 'running' })
      await sleep(220)
      const huntFindings: HuntFinding[] = HUNT_QUERIES.map(q => {
        const matches = triaged.filter(q.predicate)
        const ipMap: Record<string, number> = {}
        matches.forEach((m: any) => { const ip = m.src_ip || 'unknown'; ipMap[ip] = (ipMap[ip] || 0) + 1 })
        const topActor = Object.entries(ipMap).sort((a, b) => b[1] - a[1])[0]?.[0]
        return {
          id: q.id, query: q.query, matchCount: matches.length, topActor,
          sample: matches.slice(0, 5).map((m: any) => ({ src_ip: m.src_ip, dst_ip: m.dst_ip, label: m.label_predicted, conf: m.confidence })),
        }
      }).filter(f => f.matchCount > 0)
      cachePageResult('threat_hunt', {
        n_queries_run: HUNT_QUERIES.length,
        n_findings: huntFindings.length,
        total_matches: huntFindings.reduce((s, f) => s + f.matchCount, 0),
        source: 'investigation_chain',
      }).catch(() => {})
      updatePhase('threat_hunt', { status: 'done', durationMs: Math.round(performance.now() - t2) })

      // Phase 4: Incident Report
      const t3 = performance.now()
      updatePhase('incident_rpt', { status: 'running' })
      await sleep(180)
      const recommendations = recommendActions(attackTypes)
      const mitreFamilies = new Set<string>()
      attackTypes.forEach(t => {
        for (const k of Object.keys(ATTACK_LOOKUP)) {
          if (t.toLowerCase().includes(k.toLowerCase())) mitreFamilies.add(`${ATTACK_LOOKUP[k]} (${k})`)
        }
      })
      const executiveSummary = `Out of ${data.predictions.length.toLocaleString()} flows analysed by ${modelId}, ${threats.length} threats were detected (${((threats.length / data.predictions.length) * 100).toFixed(1)}%). The chain identified ${incidents.length} multi-alert incident${incidents.length === 1 ? '' : 's'} grouped by source IP, ${huntFindings.length} hunt queries with matches, and ${attackTypes.length} distinct attack class${attackTypes.length === 1 ? '' : 'es'}. ${incidents.filter(i => i.severity === 'critical').length} critical incidents require immediate triage; ${tp} flows were classified as true positives, ${fp} as false positives, ${review} require analyst review.`
      const finishedAt = new Date().toISOString()
      const built: ChainReport = {
        totalFlows: data.predictions.length,
        threats: threats.length,
        benign: data.predictions.length - threats.length,
        model: modelId,
        startedAt, finishedAt,
        incidents, triage: { tp, fp, review }, topActors, attackTypes,
        huntFindings, executiveSummary, recommendations,
        keyMitreTechniques: Array.from(mitreFamilies),
      }
      setReport(built)
      cachePageResult('incident_reports', {
        executive_summary: executiveSummary,
        n_incidents: incidents.length,
        n_threats: threats.length,
        attack_types: attackTypes,
        recommendations,
        source: 'investigation_chain',
      }).catch(() => {})
      updatePhase('incident_rpt', { status: 'done', durationMs: Math.round(performance.now() - t3) })

      // Phase 5: Cache chain summary
      const t4 = performance.now()
      updatePhase('cache', { status: 'running' })
      await sleep(80)
      cachePageResult('investigation_chain', {
        n_flows: built.totalFlows, n_threats: built.threats,
        n_incidents: built.incidents.length, n_hunt_findings: built.huntFindings.length,
        n_recommendations: built.recommendations.length,
        critical_incidents: built.incidents.filter(i => i.severity === 'critical').length,
        attack_types: built.attackTypes,
        model_used: built.model,
      }).catch(() => {})
      updatePhase('cache', { status: 'done', durationMs: Math.round(performance.now() - t4) })

      updateNotice(nid, { status: 'completed', description: `Chain complete — ${incidents.length} incidents, ${huntFindings.length} hunt findings, ${recommendations.length} recommendations` })
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Chain execution failed'
      setError(msg)
      updateNotice(nid, { status: 'error', description: msg })
      // Mark unfinished phases as skipped
      setPhases(prev => prev.map(p => p.status === 'pending' || p.status === 'running' ? { ...p, status: 'skipped' as PhaseStatus } : p))
    }
    setRunning(false)
  }

  const canLaunch = (file || rawData) && !running

  const totalDuration = useMemo(
    () => phases.filter(p => p.status === 'done').reduce((s, p) => s + (p.durationMs || 0), 0),
    [phases]
  )

  return (
    <div className="space-y-6 chain-root">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-accent-orange/10 flex items-center justify-center">
            <Workflow className="w-5 h-5 text-accent-orange" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-text-primary">Autonomous Investigation Chain</h1>
            <p className="text-xs text-text-secondary mt-0.5">
              Auto-Investigation → Threat Hunt → Incident Report — one click, no manual hand-off
            </p>
          </div>
        </div>
        {report && <ExportMenu targetSelector=".chain-root" filename="investigation-chain-report" />}
      </div>

      <PageGuide title="How to use the Investigation Chain" steps={GUIDE_STEPS}
        tip="Tip: All three downstream pages remain fully usable on their own — the chain just orchestrates them." />

      {/* Input */}
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
                onDragOver={e => { e.preventDefault(); e.currentTarget.classList.add('border-accent-orange', 'bg-accent-orange/10') }}
                onDragLeave={e => { e.currentTarget.classList.remove('border-accent-orange', 'bg-accent-orange/10') }}
                onDrop={e => { e.preventDefault(); e.currentTarget.classList.remove('border-accent-orange', 'bg-accent-orange/10'); const f = e.dataTransfer.files[0]; if (f) setFile(f) }}
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
          <button onClick={runChain} disabled={!canLaunch}
            className="px-4 py-2.5 bg-accent-orange hover:bg-accent-orange/80 text-white rounded-lg text-sm font-semibold disabled:opacity-50 flex items-center justify-center gap-2 transition-colors">
            {running ? <><Loader2 className="w-4 h-4 animate-spin" /> Running chain...</> : <><Workflow className="w-4 h-4" /> Run Chain</>}
          </button>
        </div>
      </div>

      {/* Live banner */}
      {hasLiveData() && !liveLoaded && !rawData && (
        <div className="flex items-center gap-3 px-4 py-3 bg-accent-orange/10 border border-accent-orange/20 rounded-xl">
          <Radio className="w-4 h-4 text-accent-orange" />
          <div className="flex-1">
            <span className="text-xs font-medium text-accent-orange">Live Monitor data available</span>
            <span className="text-[10px] text-text-secondary ml-2">{getLiveData()?.totalFlows} flows from {getLiveData()?.source}</span>
          </div>
          <button onClick={loadLiveData} className="px-3 py-1 bg-accent-orange hover:bg-accent-orange/80 text-white text-[10px] font-medium rounded-lg">
            Use Live Data
          </button>
        </div>
      )}

      {error && (
        <div className="px-4 py-3 bg-red-500/10 border border-red-500/30 rounded-xl flex items-start gap-3">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
          <div className="text-xs text-red-400">{error}</div>
        </div>
      )}

      {/* Pipeline */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <Brain className="w-4 h-4 text-accent-purple" /> Pipeline Status
          </h3>
          {totalDuration > 0 && <span className="text-[10px] text-text-secondary font-mono">total: {totalDuration} ms</span>}
        </div>
        <div className="space-y-2.5">
          {phases.map((phase, i) => {
            const tone =
              phase.status === 'done'    ? { ring: 'bg-accent-green/20', icon: <CheckCircle2 className="w-4 h-4 text-accent-green" />, color: 'text-accent-green' } :
              phase.status === 'running' ? { ring: 'bg-accent-blue/20',  icon: <Loader2 className="w-4 h-4 text-accent-blue animate-spin" />, color: 'text-accent-blue'  } :
              phase.status === 'skipped' ? { ring: 'bg-bg-card',         icon: <X className="w-4 h-4 text-text-secondary" />,                color: 'text-text-secondary' } :
                                            { ring: 'bg-bg-card',         icon: <span className="text-xs text-text-secondary">{i + 1}</span>, color: 'text-text-secondary' }
            return (
              <div key={phase.id} className="flex items-center gap-3">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 transition-colors ${tone.ring}`}>{tone.icon}</div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className={`text-sm font-medium ${tone.color}`}>{phase.label}</span>
                    {phase.durationMs !== undefined && <span className="text-[10px] text-text-secondary font-mono">{phase.durationMs}ms</span>}
                  </div>
                  <p className="text-[10px] text-text-secondary">{phase.desc}</p>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Final Report */}
      {report && (
        <div className="space-y-4">
          {/* Stats */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            <StatCard label="Flows Analysed" value={report.totalFlows.toLocaleString()} color="#3B82F6" />
            <StatCard label="Threats" value={report.threats} color="#EF4444" />
            <StatCard label="Incidents" value={report.incidents.length} color="#F97316" />
            <StatCard label="Hunt Findings" value={report.huntFindings.length} color="#8B5CF6" />
            <StatCard label="Recommendations" value={report.recommendations.length} color="#22C55E" />
          </div>

          {/* Executive summary */}
          <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
            <h3 className="text-sm font-semibold flex items-center gap-2 mb-2">
              <FileBarChart className="w-4 h-4 text-accent-blue" /> Executive Summary
            </h3>
            <p className="text-sm text-text-primary leading-relaxed">{report.executiveSummary}</p>
            <p className="text-[10px] text-text-secondary mt-2 font-mono">Model {report.model} · started {new Date(report.startedAt).toLocaleTimeString()} · finished {new Date(report.finishedAt).toLocaleTimeString()}</p>
          </div>

          {/* Auto-Investigation block */}
          <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold flex items-center gap-2"><Zap className="w-4 h-4 text-accent-orange" /> Auto-Investigation</h3>
              <a href="/auto-investigate" className="text-[10px] px-2 py-1 rounded bg-accent-orange/10 text-accent-orange hover:bg-accent-orange/20">Open full view <ChevronRight className="inline w-3 h-3" /></a>
            </div>
            <div className="grid grid-cols-3 gap-2 mb-3">
              {[
                { label: 'True Positives', value: report.triage.tp,    cls: 'text-red-400 bg-red-500/15'    },
                { label: 'False Positives', value: report.triage.fp,   cls: 'text-green-400 bg-green-500/15'},
                { label: 'Needs Review', value: report.triage.review,  cls: 'text-amber-400 bg-amber-500/15'},
              ].map(t => (
                <div key={t.label} className={`rounded-lg p-3 text-center ${t.cls}`}>
                  <p className="text-lg font-bold">{t.value}</p>
                  <p className="text-[10px]">{t.label}</p>
                </div>
              ))}
            </div>
            {report.incidents.length > 0 && (
              <div>
                <p className="text-[10px] text-text-secondary uppercase tracking-wider mb-1.5">Top Incidents</p>
                <div className="space-y-1.5">
                  {report.incidents.slice(0, 5).map(inc => (
                    <div key={inc.id} className="flex items-center gap-2 text-xs px-3 py-2 rounded bg-bg-card/50">
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${inc.severity === 'critical' ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'}`}>{inc.severity}</span>
                      <span className="font-mono text-text-primary">{inc.id}</span>
                      <span className="font-mono text-text-secondary truncate flex-1">{inc.source}</span>
                      <span className="text-text-secondary">{inc.alerts} alerts</span>
                      <span className="text-text-secondary">{(inc.maxConfidence * 100).toFixed(0)}% conf</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Threat Hunt block */}
          <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold flex items-center gap-2"><Search className="w-4 h-4 text-accent-purple" /> Threat Hunt Findings</h3>
              <a href="/threat-hunt" className="text-[10px] px-2 py-1 rounded bg-accent-purple/10 text-accent-purple hover:bg-accent-purple/20">Open full view <ChevronRight className="inline w-3 h-3" /></a>
            </div>
            {report.huntFindings.length === 0 ? (
              <p className="text-xs text-text-secondary">No queries returned matches.</p>
            ) : (
              <div className="space-y-1.5">
                {report.huntFindings.map(f => (
                  <div key={f.id} className="flex items-center gap-2 text-xs px-3 py-2 rounded bg-bg-card/50">
                    <span className="text-text-primary flex-1 truncate">{f.query}</span>
                    {f.topActor && <span className="text-text-secondary font-mono text-[10px]">{f.topActor}</span>}
                    <span className="px-1.5 py-0.5 rounded bg-accent-purple/15 text-accent-purple text-[10px] font-bold">{f.matchCount}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Incident Report block */}
          <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold flex items-center gap-2"><FileBarChart className="w-4 h-4 text-accent-blue" /> Incident Report</h3>
              <a href="/incident-reports" className="text-[10px] px-2 py-1 rounded bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20">Open full view <ChevronRight className="inline w-3 h-3" /></a>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <p className="text-[10px] text-text-secondary uppercase tracking-wider mb-1.5">Top Threat Actors</p>
                {report.topActors.map(([ip, count], i) => (
                  <div key={ip} className="flex items-center gap-2 text-xs mb-1">
                    <span className="text-text-secondary w-4">{i + 1}.</span>
                    <span className="font-mono flex-1 truncate">{ip}</span>
                    <span className="text-text-secondary">{count} alerts</span>
                  </div>
                ))}
              </div>
              <div>
                <p className="text-[10px] text-text-secondary uppercase tracking-wider mb-1.5">Recommended Actions</p>
                {report.recommendations.map((r, i) => (
                  <div key={i} className="flex items-start gap-1.5 mb-1 text-xs">
                    <CheckCircle2 className="w-3 h-3 text-accent-green shrink-0 mt-0.5" />
                    <span className="text-text-secondary">{r}</span>
                  </div>
                ))}
              </div>
            </div>
            {report.keyMitreTechniques.length > 0 && (
              <div className="mt-4">
                <p className="text-[10px] text-text-secondary uppercase tracking-wider mb-1.5">MITRE ATT&CK Techniques</p>
                <div className="flex flex-wrap gap-1.5">
                  {report.keyMitreTechniques.map(t => (
                    <span key={t} className="px-2 py-0.5 bg-accent-blue/8 text-accent-blue border border-accent-blue/20 rounded-full text-[10px] font-mono">{t}</span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Continue */}
          <div className="flex flex-wrap gap-2 pt-4 border-t border-bg-card">
            <span className="text-[10px] text-text-secondary mr-2">Continue to:</span>
            <a href="/auto-investigate" className="text-[10px] px-2 py-1 rounded bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20">Auto-Investigation</a>
            <a href="/threat-hunt" className="text-[10px] px-2 py-1 rounded bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20">Threat Hunt</a>
            <a href="/incident-reports" className="text-[10px] px-2 py-1 rounded bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20">Incident Reports</a>
            <a href="/mitre-attack" className="text-[10px] px-2 py-1 rounded bg-accent-purple/10 text-accent-purple hover:bg-accent-purple/20">MITRE ATT&CK</a>
            <a href="/causality-graph" className="text-[10px] px-2 py-1 rounded bg-accent-purple/10 text-accent-purple hover:bg-accent-purple/20">Causality Graph</a>
            <a href="/copilot" className="text-[10px] px-2 py-1 rounded bg-accent-green/10 text-accent-green hover:bg-accent-green/20">Ask Copilot</a>
          </div>
        </div>
      )}
    </div>
  )
}

function StatCard({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div className="bg-bg-secondary border border-bg-card rounded-xl p-4">
      <p className="text-[10px] text-text-secondary uppercase tracking-wider mb-1">{label}</p>
      <p className="text-2xl font-bold" style={{ color }}>{value}</p>
    </div>
  )
}

