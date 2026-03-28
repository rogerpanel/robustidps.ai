import { useState, useMemo, useCallback } from 'react'
import {
  Shield, AlertTriangle, CheckCircle, XCircle, Eye,
  BarChart3, Settings, Filter, ChevronDown, ChevronUp,
  Upload, FileText, X, Loader2, Radio,
} from 'lucide-react'
import { getLiveData, hasLiveData } from '../utils/liveDataStore'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import { usePageState } from '../hooks/usePageState'
import ModelSelector from '../components/ModelSelector'
import { analyseFile } from '../utils/api'
import { useNoticeBoard } from '../hooks/useNoticeBoard'

const PAGE = 'alerttriage'

/* ── Triage rules ── */
const TRIAGE_RULES = [
  { label: 'Auto-confirm (True Positive)', condition: 'Confidence >= 95% AND Severity >= high', action: 'Escalate to response', color: 'accent-red' },
  { label: 'Auto-dismiss (False Positive)', condition: 'Confidence <= 30% AND Severity = benign', action: 'Close alert', color: 'accent-green' },
  { label: 'Needs Review', condition: 'All other alerts', action: 'Queue for analyst review', color: 'accent-amber' },
  { label: 'High uncertainty', condition: 'MC Dropout epistemic uncertainty > 0.3', action: 'Flag for model retraining', color: 'accent-purple' },
]

const RULE_BG: Record<string, string> = {
  'accent-red': 'bg-accent-red/10 border-accent-red/30 text-accent-red',
  'accent-green': 'bg-accent-green/10 border-accent-green/30 text-accent-green',
  'accent-amber': 'bg-accent-amber/10 border-accent-amber/30 text-accent-amber',
  'accent-purple': 'bg-accent-purple/10 border-accent-purple/30 text-accent-purple',
}

/* ── Severity levels ── */
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'benign'
type TriageResult = 'True Positive' | 'False Positive' | 'Needs Review'

interface Alert {
  id: string
  srcIp: string
  label: string
  confidence: number
  severity: Severity
  uncertainty: number
  timestamp: string
}

/* ── Mock alerts ── */
const MOCK_ALERTS: Alert[] = [
  { id: 'A-001', srcIp: '192.168.1.105', label: 'DDoS-SlowHTTPTest', confidence: 0.97, severity: 'critical', uncertainty: 0.04, timestamp: '2026-03-27 08:12:34' },
  { id: 'A-002', srcIp: '10.0.0.42', label: 'BruteForce-SSH', confidence: 0.98, severity: 'high', uncertainty: 0.03, timestamp: '2026-03-27 08:13:01' },
  { id: 'A-003', srcIp: '172.16.0.88', label: 'Benign', confidence: 0.12, severity: 'benign', uncertainty: 0.08, timestamp: '2026-03-27 08:13:15' },
  { id: 'A-004', srcIp: '10.0.0.7', label: 'PortScan', confidence: 0.65, severity: 'medium', uncertainty: 0.22, timestamp: '2026-03-27 08:14:02' },
  { id: 'A-005', srcIp: '192.168.2.201', label: 'SqlInjection', confidence: 0.99, severity: 'critical', uncertainty: 0.01, timestamp: '2026-03-27 08:14:30' },
  { id: 'A-006', srcIp: '10.0.1.15', label: 'Benign', confidence: 0.22, severity: 'benign', uncertainty: 0.11, timestamp: '2026-03-27 08:15:10' },
  { id: 'A-007', srcIp: '172.16.1.33', label: 'XSS', confidence: 0.72, severity: 'medium', uncertainty: 0.35, timestamp: '2026-03-27 08:15:45' },
  { id: 'A-008', srcIp: '192.168.3.12', label: 'DoS-Hulk', confidence: 0.96, severity: 'high', uncertainty: 0.05, timestamp: '2026-03-27 08:16:22' },
  { id: 'A-009', srcIp: '10.0.2.99', label: 'Benign', confidence: 0.28, severity: 'benign', uncertainty: 0.09, timestamp: '2026-03-27 08:17:01' },
  { id: 'A-010', srcIp: '172.16.2.50', label: 'Infiltration', confidence: 0.55, severity: 'medium', uncertainty: 0.28, timestamp: '2026-03-27 08:17:33' },
  { id: 'A-011', srcIp: '192.168.1.77', label: 'BruteForce-FTP', confidence: 0.91, severity: 'high', uncertainty: 0.12, timestamp: '2026-03-27 08:18:05' },
  { id: 'A-012', srcIp: '10.0.3.200', label: 'Benign', confidence: 0.15, severity: 'benign', uncertainty: 0.06, timestamp: '2026-03-27 08:18:40' },
]

/* ── Triage logic ── */
function triageAlert(a: Alert, tpThresh: number, fpThresh: number): TriageResult {
  if (a.confidence >= tpThresh && (a.severity === 'critical' || a.severity === 'high')) return 'True Positive'
  if (a.confidence <= fpThresh && a.severity === 'benign') return 'False Positive'
  return 'Needs Review'
}

const TRIAGE_STYLE: Record<TriageResult, string> = {
  'True Positive': 'bg-red-500/15 text-red-400 border-red-500/30',
  'False Positive': 'bg-green-500/15 text-green-400 border-green-500/30',
  'Needs Review': 'bg-amber-500/15 text-amber-400 border-amber-500/30',
}

const SEV_STYLE: Record<Severity, string> = {
  critical: 'bg-red-500/20 text-red-400',
  high: 'bg-orange-500/20 text-orange-400',
  medium: 'bg-amber-500/20 text-amber-400',
  low: 'bg-blue-500/20 text-blue-400',
  benign: 'bg-green-500/20 text-green-400',
}

const GUIDE_STEPS = [
  { title: 'Review Alerts', desc: 'Browse classified alerts from your latest analysis or demo data.' },
  { title: 'Understand Triage', desc: 'Each alert is auto-triaged as True Positive, False Positive, or Needs Review based on confidence and severity.' },
  { title: 'Tune Thresholds', desc: 'Adjust the TP/FP confidence thresholds in the Auto-Triage Rules section to match your risk tolerance.' },
  { title: 'Export Results', desc: 'Export the triage report as PNG or PDF for compliance documentation.' },
]

export default function AlertTriage() {
  const [tpThreshold, setTpThreshold] = usePageState(PAGE, 'tpThresh', 0.95)
  const [fpThreshold, setFpThreshold] = usePageState(PAGE, 'fpThresh', 0.30)
  const [filterResult, setFilterResult] = usePageState<TriageResult | 'all'>(PAGE, 'filter', 'all')
  const [rulesOpen, setRulesOpen] = usePageState(PAGE, 'rulesOpen', false)
  const [sortField, setSortField] = useState<'confidence' | 'severity'>('confidence')
  const [sortAsc, setSortAsc] = useState(false)

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
    const nid = addNotice({ title: 'Alert Triage Analysis', description: `Analyzing ${file.name}...`, status: 'running', page: '/alert-triage' })
    try {
      const data = await analyseFile(file, modelId, 'alert_triage')
      setAnalysisResult(data)
      updateNotice(nid, { status: 'completed', description: `${data.predictions?.length || 0} alerts triaged` })
    } catch (err) {
      updateNotice(nid, { status: 'error', description: err instanceof Error ? err.message : 'Analysis failed' })
    }
    setAnalyzing(false)
  }

  const realAlerts: Alert[] = analysisResult?.predictions?.map((p: any, i: number) => ({
    id: `R${String(i + 1).padStart(3, '0')}`,
    timestamp: new Date().toISOString(),
    srcIp: p.src_ip || p.source_ip || '—',
    label: p.label_predicted || p.label || 'Unknown',
    confidence: p.confidence ?? 0.5,
    severity: p.severity || 'medium',
    uncertainty: p.epistemic_uncertainty ?? 0,
  })) || []

  const alerts = realAlerts.length > 0 ? realAlerts : MOCK_ALERTS

  /* ── Triage all alerts ── */
  const triaged = useMemo(() => alerts.map(a => ({
    ...a,
    result: triageAlert(a, tpThreshold, fpThreshold),
  })), [alerts, tpThreshold, fpThreshold])

  /* ── Filter + sort ── */
  const filtered = useMemo(() => {
    let list = filterResult === 'all' ? triaged : triaged.filter(a => a.result === filterResult)
    const sevOrder: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, benign: 0 }
    list = [...list].sort((a, b) => {
      const va = sortField === 'confidence' ? a.confidence : sevOrder[a.severity]
      const vb = sortField === 'confidence' ? b.confidence : sevOrder[b.severity]
      return sortAsc ? va - vb : vb - va
    })
    return list
  }, [triaged, filterResult, sortField, sortAsc])

  /* ── Summary metrics ── */
  const metrics = useMemo(() => {
    const total = triaged.length
    const tp = triaged.filter(a => a.result === 'True Positive').length
    const fp = triaged.filter(a => a.result === 'False Positive').length
    const review = triaged.filter(a => a.result === 'Needs Review').length
    const autoTriaged = tp + fp
    return {
      total, tp, fp, review,
      autoTriagedPct: total ? ((autoTriaged / total) * 100).toFixed(1) : '0',
      tpRate: total ? ((tp / total) * 100).toFixed(1) : '0',
      fpRate: total ? ((fp / total) * 100).toFixed(1) : '0',
      reviewRate: total ? ((review / total) * 100).toFixed(1) : '0',
    }
  }, [triaged])

  const toggleSort = (field: 'confidence' | 'severity') => {
    if (sortField === field) setSortAsc(!sortAsc)
    else { setSortField(field); setSortAsc(false) }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="w-6 h-6 text-accent-blue" />
            Alert Triage Classifier
          </h1>
          <p className="text-sm text-text-secondary mt-1">
            ML-based triage to distinguish true positives from false positives
          </p>
        </div>
        <ExportMenu filename="alert-triage-report" />
      </div>

      <PageGuide
        title="How to use Alert Triage"
        steps={GUIDE_STEPS}
        tip="Adjust thresholds in the rules section to see how triage decisions change in real time."
      />

      {/* Summary metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Alerts', value: metrics.total, icon: BarChart3, color: 'text-accent-blue' },
          { label: 'True Positive Rate', value: `${metrics.tpRate}%`, icon: AlertTriangle, color: 'text-red-400' },
          { label: 'False Positive Rate', value: `${metrics.fpRate}%`, icon: CheckCircle, color: 'text-green-400' },
          { label: 'Auto-Triaged', value: `${metrics.autoTriagedPct}%`, icon: Settings, color: 'text-accent-purple' },
        ].map(m => (
          <div key={m.label} className="bg-bg-card border border-bg-card rounded-xl p-4">
            <div className="flex items-center gap-2 text-xs text-text-secondary mb-1">
              <m.icon className={`w-3.5 h-3.5 ${m.color}`} />
              {m.label}
            </div>
            <div className="text-2xl font-bold">{m.value}</div>
          </div>
        ))}
      </div>

      {/* Breakdown bar */}
      <div className="bg-bg-card border border-bg-card rounded-xl p-4">
        <h3 className="text-sm font-semibold mb-3">Triage Distribution</h3>
        <div className="flex h-4 rounded-full overflow-hidden gap-0.5">
          {metrics.total > 0 && (
            <>
              <div className="bg-red-500 transition-all" style={{ width: `${metrics.tpRate}%` }} title={`TP: ${metrics.tpRate}%`} />
              <div className="bg-green-500 transition-all" style={{ width: `${metrics.fpRate}%` }} title={`FP: ${metrics.fpRate}%`} />
              <div className="bg-amber-500 transition-all" style={{ width: `${metrics.reviewRate}%` }} title={`Review: ${metrics.reviewRate}%`} />
            </>
          )}
        </div>
        <div className="flex gap-4 mt-2 text-xs text-text-secondary">
          <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-red-500" /> True Positive ({metrics.tp})</span>
          <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-green-500" /> False Positive ({metrics.fp})</span>
          <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-amber-500" /> Needs Review ({metrics.review})</span>
        </div>
      </div>

      {/* Upload + Model selector */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">Upload Traffic for Real Triage</h2>
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
          <button onClick={runAnalysis} disabled={!file || analyzing} className="px-4 py-2.5 bg-accent-orange hover:bg-accent-orange/80 text-white rounded-lg text-xs font-medium disabled:opacity-50 flex items-center justify-center gap-2">
            {analyzing ? <><Loader2 className="w-4 h-4 animate-spin" /> Analyzing...</> : 'Run Triage Analysis'}
          </button>
        </div>
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

      {/* Filter bar */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-1.5 text-xs text-text-secondary">
          <Filter className="w-3.5 h-3.5" /> Filter:
        </div>
        {(['all', 'True Positive', 'False Positive', 'Needs Review'] as const).map(f => (
          <button
            key={f}
            onClick={() => setFilterResult(f)}
            className={`px-3 py-1 rounded-full text-xs font-medium border transition-colors ${
              filterResult === f
                ? 'bg-accent-blue/20 border-accent-blue/40 text-accent-blue'
                : 'border-bg-card text-text-secondary hover:text-text-primary'
            }`}
          >
            {f === 'all' ? 'All' : f} {f !== 'all' && `(${triaged.filter(a => a.result === f).length})`}
          </button>
        ))}
      </div>

      {/* Alerts table */}
      <div className="bg-bg-card border border-bg-card rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-bg-card text-text-secondary">
                <th className="px-4 py-3 text-left font-medium">ID</th>
                <th className="px-4 py-3 text-left font-medium">Timestamp</th>
                <th className="px-4 py-3 text-left font-medium">Source IP</th>
                <th className="px-4 py-3 text-left font-medium">Label</th>
                <th className="px-4 py-3 text-left font-medium cursor-pointer select-none" onClick={() => toggleSort('confidence')}>
                  <span className="flex items-center gap-1">
                    Confidence
                    {sortField === 'confidence' && (sortAsc ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />)}
                  </span>
                </th>
                <th className="px-4 py-3 text-left font-medium cursor-pointer select-none" onClick={() => toggleSort('severity')}>
                  <span className="flex items-center gap-1">
                    Severity
                    {sortField === 'severity' && (sortAsc ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />)}
                  </span>
                </th>
                <th className="px-4 py-3 text-left font-medium">Uncertainty</th>
                <th className="px-4 py-3 text-left font-medium">Triage</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(a => (
                <tr key={a.id} className="border-b border-bg-card/50 hover:bg-bg-secondary/30 transition-colors">
                  <td className="px-4 py-3 font-mono text-text-secondary">{a.id}</td>
                  <td className="px-4 py-3 text-text-secondary">{a.timestamp}</td>
                  <td className="px-4 py-3 font-mono">{a.srcIp}</td>
                  <td className="px-4 py-3 font-semibold">{a.label}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-1.5 bg-bg-secondary rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${a.confidence >= tpThreshold ? 'bg-red-500' : a.confidence <= fpThreshold ? 'bg-green-500' : 'bg-amber-500'}`}
                          style={{ width: `${a.confidence * 100}%` }}
                        />
                      </div>
                      <span>{(a.confidence * 100).toFixed(1)}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase ${SEV_STYLE[a.severity]}`}>
                      {a.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`font-mono ${a.uncertainty > 0.3 ? 'text-accent-purple' : 'text-text-secondary'}`}>
                      {a.uncertainty.toFixed(2)}
                      {a.uncertainty > 0.3 && <Eye className="w-3 h-3 inline ml-1" />}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold border ${TRIAGE_STYLE[a.result]}`}>
                      {a.result === 'True Positive' && <XCircle className="w-3 h-3 inline mr-1" />}
                      {a.result === 'False Positive' && <CheckCircle className="w-3 h-3 inline mr-1" />}
                      {a.result === 'Needs Review' && <AlertTriangle className="w-3 h-3 inline mr-1" />}
                      {a.result}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {filtered.length === 0 && (
          <div className="text-center text-text-secondary text-sm py-8">No alerts match the current filter.</div>
        )}
      </div>

      {/* Auto-Triage Rules */}
      <div className="bg-bg-card border border-bg-card rounded-xl p-5">
        <button
          onClick={() => setRulesOpen(!rulesOpen)}
          className="flex items-center justify-between w-full"
        >
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <Settings className="w-4 h-4 text-accent-blue" />
            Auto-Triage Rules
          </h3>
          {rulesOpen ? <ChevronUp className="w-4 h-4 text-text-secondary" /> : <ChevronDown className="w-4 h-4 text-text-secondary" />}
        </button>

        {rulesOpen && (
          <div className="mt-4 space-y-4">
            {/* Threshold sliders */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-text-secondary block mb-1">
                  TP Confirmation Threshold: <span className="text-text-primary font-semibold">{(tpThreshold * 100).toFixed(0)}%</span>
                </label>
                <input
                  type="range" min={0.5} max={1} step={0.01}
                  value={tpThreshold}
                  onChange={e => setTpThreshold(parseFloat(e.target.value))}
                  className="w-full accent-red-500"
                />
                <div className="flex justify-between text-[10px] text-text-secondary"><span>50%</span><span>100%</span></div>
              </div>
              <div>
                <label className="text-xs text-text-secondary block mb-1">
                  FP Dismissal Threshold: <span className="text-text-primary font-semibold">{(fpThreshold * 100).toFixed(0)}%</span>
                </label>
                <input
                  type="range" min={0} max={0.5} step={0.01}
                  value={fpThreshold}
                  onChange={e => setFpThreshold(parseFloat(e.target.value))}
                  className="w-full accent-green-500"
                />
                <div className="flex justify-between text-[10px] text-text-secondary"><span>0%</span><span>50%</span></div>
              </div>
            </div>

            {/* Rule cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {TRIAGE_RULES.map(r => (
                <div key={r.label} className={`border rounded-lg p-3 ${RULE_BG[r.color]}`}>
                  <div className="font-semibold text-xs mb-1">{r.label}</div>
                  <div className="text-[10px] opacity-80 mb-1">IF {r.condition}</div>
                  <div className="text-[10px] opacity-80">THEN {r.action}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
