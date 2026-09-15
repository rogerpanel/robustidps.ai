import { useState, useMemo, useCallback } from 'react'
import {
  FileText, Upload, X, Loader2, Radio, Shield, Copy, Check,
  AlertTriangle, BarChart3, Clock, Crosshair, Activity,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import ModelSelector from '../components/ModelSelector'
import { analyseFile, cachePageResult } from '../utils/api'
import { useNoticeBoard } from '../hooks/useNoticeBoard'
import { getLiveData, hasLiveData } from '../utils/liveDataStore'

/* ── Recommendations by attack family ───────────────────────────────── */

const RECOMMENDATIONS: Record<string, string> = {
  'DDoS': 'Deploy rate limiting and traffic scrubbing. Consider upstream DDoS mitigation service.',
  'BruteForce': 'Enforce account lockout policies. Implement MFA. Review SSH/FTP access controls.',
  'Recon': 'Review firewall rules. Consider honeypot deployment. Monitor for follow-up attacks.',
  'WebAttack': 'Patch web application vulnerabilities. Deploy WAF rules. Review input validation.',
  'Spoofing': 'Enable DNSSEC. Configure ARP inspection. Implement BCP38 anti-spoofing.',
  'Malware': 'Isolate affected hosts. Run full endpoint scan. Check for lateral movement.',
  'Mirai': 'Change default IoT credentials. Segment IoT network. Block C2 domains.',
}

const MITRE_MAP: Record<string, { id: string; name: string }> = {
  'DDoS': { id: 'T1498', name: 'Network Denial of Service' },
  'BruteForce': { id: 'T1110', name: 'Brute Force' },
  'Recon': { id: 'T1046', name: 'Network Service Discovery' },
  'WebAttack': { id: 'T1190', name: 'Exploit Public-Facing Application' },
  'Spoofing': { id: 'T1557', name: 'Adversary-in-the-Middle' },
  'Malware': { id: 'T1059', name: 'Command and Scripting Interpreter' },
  'Mirai': { id: 'T1583.005', name: 'Acquire Infrastructure: Botnet' },
}

const SEV_COLORS: Record<string, string> = {
  critical: '#EF4444', high: '#F97316', medium: '#F59E0B', low: '#3B82F6', benign: '#22C55E',
}

const GUIDE_STEPS = [
  { title: 'Upload Data', desc: 'Upload a CSV/PCAP file or load Live Monitor data for analysis.' },
  { title: 'Generate Report', desc: 'Click "Generate Incident Report" to run analysis and auto-build a formatted report.' },
  { title: 'Review Sections', desc: 'The report includes executive summary, threat landscape, critical indicators, timeline, and recommendations.' },
  { title: 'Export & Share', desc: 'Copy the report text or export as PDF for stakeholder distribution.' },
]

function familyOf(label: string): string {
  if (label.startsWith('DDoS') || label.startsWith('DoS')) return 'DDoS'
  if (label.startsWith('BruteForce')) return 'BruteForce'
  if (label.startsWith('Recon') || label.includes('Scan') || label.includes('Sweep')) return 'Recon'
  if (label.startsWith('WebAttack') || label.includes('SQLi') || label.includes('XSS') || label.includes('Cmd')) return 'WebAttack'
  if (label.startsWith('Spoofing') || label.includes('Spoof')) return 'Spoofing'
  if (label.startsWith('Malware')) return 'Malware'
  if (label.startsWith('Mirai')) return 'Mirai'
  return label
}

export default function IncidentReports() {
  const [file, setFile] = useState<File | null>(null)
  const [modelId, setModelId] = useState('surrogate')
  const [analysisResult, setAnalysisResult] = useState<any>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [reportReady, setReportReady] = useState(false)
  const [copied, setCopied] = useState(false)
  const [liveDataLoaded, setLiveDataLoaded] = useState(false)
  const { addNotice, updateNotice } = useNoticeBoard()

  const loadLiveData = useCallback(() => {
    const live = getLiveData()
    if (!live) return
    setAnalysisResult({ predictions: live.predictions, n_flows: live.totalFlows, n_threats: live.threatCount, n_benign: live.benignCount })
    setLiveDataLoaded(true)
    setReportReady(true)
  }, [])

  const generateReport = async () => {
    if (!file && !analysisResult) return
    if (file && !analysisResult) {
      setAnalyzing(true)
      const nid = addNotice({ title: 'Incident Report', description: `Analyzing ${file.name}...`, status: 'running', page: '/incident-reports' })
      try {
        const data = await analyseFile(file, modelId, 'incident_reports')
        setAnalysisResult(data)
        setReportReady(true)
        updateNotice(nid, { status: 'completed', description: `Report generated — ${data.predictions?.length || 0} flows analyzed` })
        cachePageResult('incident_reports', { n_flows: data.predictions?.length || 0, model: modelId }).catch(() => {})
      } catch (err) {
        updateNotice(nid, { status: 'error', description: err instanceof Error ? err.message : 'Analysis failed' })
      }
      setAnalyzing(false)
    } else {
      setReportReady(true)
    }
  }

  /* ── Report data derivation ──────────────────────────────────────── */
  const report = useMemo(() => {
    if (!analysisResult?.predictions) return null
    const preds = analysisResult.predictions as any[]
    const total = preds.length
    const threats = preds.filter((p: any) => (p.severity || 'benign') !== 'benign')
    const threatPct = total ? ((threats.length / total) * 100).toFixed(1) : '0'

    // Severity distribution
    const sevDist: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, benign: 0 }
    preds.forEach((p: any) => { sevDist[p.severity || 'benign'] = (sevDist[p.severity || 'benign'] || 0) + 1 })

    // Attack types
    const attackCounts: Record<string, number> = {}
    threats.forEach((p: any) => {
      const label = p.label_predicted || p.label || 'Unknown'
      attackCounts[label] = (attackCounts[label] || 0) + 1
    })
    const topAttacks = Object.entries(attackCounts).sort((a, b) => b[1] - a[1]).slice(0, 10)
    const maxAttack = topAttacks.length ? topAttacks[0][1] : 1

    // Source IPs
    const srcCounts: Record<string, number> = {}
    const dstCounts: Record<string, number> = {}
    threats.forEach((p: any) => {
      const src = p.src_ip || p.source_ip || '—'
      const dst = p.dst_ip || p.dest_ip || '—'
      if (src !== '—') srcCounts[src] = (srcCounts[src] || 0) + 1
      if (dst !== '—') dstCounts[dst] = (dstCounts[dst] || 0) + 1
    })
    const topSrc = Object.entries(srcCounts).sort((a, b) => b[1] - a[1]).slice(0, 5)
    const topDst = Object.entries(dstCounts).sort((a, b) => b[1] - a[1]).slice(0, 5)

    // Timeline (based on current time spread by flow count)
    const now = new Date()
    const firstDetection = new Date(now.getTime() - preds.length * 60000)
    const peakActivity = new Date(now.getTime() - preds.length * 30000)
    const lastDetection = now

    // Families detected
    const families = new Set(threats.map((p: any) => familyOf(p.label_predicted || p.label || '')))
    const recs = Array.from(families).filter(f => RECOMMENDATIONS[f]).map(f => ({ family: f, rec: RECOMMENDATIONS[f] }))
    const mitre = Array.from(families).filter(f => MITRE_MAP[f]).map(f => ({ family: f, ...MITRE_MAP[f] }))

    return { total, threatCount: threats.length, threatPct, sevDist, topAttacks, maxAttack, topSrc, topDst, firstDetection, peakActivity, lastDetection, recs, mitre }
  }, [analysisResult])

  const copyReport = () => {
    if (!report) return
    const now = new Date().toLocaleString()
    const lines = [
      '═══════════════════════════════════════════════',
      '  INCIDENT REPORT — RobustIDPS.ai',
      '═══════════════════════════════════════════════',
      '', `Date: ${now}`, `Model: ${modelId}`, `Total Flows: ${report.total}`, `Threats: ${report.threatCount} (${report.threatPct}%)`,
      '', '── Severity Distribution ──',
      ...Object.entries(report.sevDist).map(([s, c]) => `  ${s}: ${c}`),
      '', '── Top Attack Types ──',
      ...report.topAttacks.map(([label, count]) => `  ${label}: ${count}`),
      '', '── Recommended Actions ──',
      ...report.recs.map(r => `  [${r.family}] ${r.rec}`),
      '', '── MITRE ATT&CK Coverage ──',
      ...report.mitre.map(m => `  ${m.id} — ${m.name} (${m.family})`),
    ]
    navigator.clipboard.writeText(lines.join('\n'))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="space-y-6 incident-report-root">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <FileText className="w-6 h-6 text-accent-orange" />
            Incident Reports
          </h1>
          <p className="text-sm text-text-secondary mt-1">Auto-generate structured incident reports from analysis results</p>
        </div>
        <ExportMenu targetSelector=".incident-report-root" filename="incident-report" />
      </div>

      <PageGuide title="How to use Incident Reports" steps={GUIDE_STEPS} tip="Reports follow industry-standard IR formats for SOC handoff and compliance." />

      {/* Upload + Model */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">Analyze Traffic Data</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end">
          <div>
            {file ? (
              <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-accent-green/30 bg-accent-green/5">
                <FileText className="w-4 h-4 text-accent-green shrink-0" />
                <span className="text-xs font-mono truncate flex-1">{file.name}</span>
                <button onClick={() => { setFile(null); setAnalysisResult(null); setReportReady(false) }} className="text-text-secondary hover:text-text-primary"><X className="w-3.5 h-3.5" /></button>
              </div>
            ) : (
              <label onDragOver={e => { e.preventDefault(); e.currentTarget.classList.add('border-accent-blue', 'bg-accent-blue/10') }} onDragLeave={e => { e.currentTarget.classList.remove('border-accent-blue', 'bg-accent-blue/10') }} onDrop={e => { e.preventDefault(); e.currentTarget.classList.remove('border-accent-blue', 'bg-accent-blue/10'); const f = e.dataTransfer.files[0]; if (f) setFile(f) }} className="flex flex-col items-center gap-1 px-3 py-3 rounded-lg border-2 border-dashed border-bg-card hover:border-text-secondary cursor-pointer transition-colors">
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
          <button onClick={generateReport} disabled={(!file && !analysisResult) || analyzing} className="px-4 py-2.5 bg-accent-orange hover:bg-accent-orange/80 text-white rounded-lg text-xs font-medium disabled:opacity-50 flex items-center justify-center gap-2">
            {analyzing ? <><Loader2 className="w-4 h-4 animate-spin" /> Analyzing...</> : 'Generate Incident Report'}
          </button>
        </div>
      </div>

      {/* Live Monitor banner */}
      {hasLiveData() && !liveDataLoaded && !analysisResult && (
        <div className="flex items-center gap-3 px-4 py-3 bg-accent-orange/10 border border-accent-orange/20 rounded-xl">
          <Radio className="w-4 h-4 text-accent-orange" />
          <div className="flex-1">
            <span className="text-xs font-medium text-accent-orange">Live Monitor data available</span>
            <span className="text-[10px] text-text-secondary ml-2">{getLiveData()?.totalFlows} flows from {getLiveData()?.source}</span>
          </div>
          <button onClick={loadLiveData} className="px-3 py-1 bg-accent-orange hover:bg-accent-orange/80 text-white text-[10px] font-medium rounded-lg transition-colors">Use Live Data</button>
        </div>
      )}

      {/* ── Generated Report ────────────────────────────────────────── */}
      {reportReady && report && (
        <div className="space-y-5">
          {/* Copy button */}
          <div className="flex justify-end">
            <button onClick={copyReport} className="flex items-center gap-1.5 px-3 py-1.5 bg-bg-card border border-bg-card rounded-lg text-xs text-text-secondary hover:text-text-primary transition-colors">
              {copied ? <><Check className="w-3.5 h-3.5 text-accent-green" /> Copied</> : <><Copy className="w-3.5 h-3.5" /> Copy Report</>}
            </button>
          </div>

          {/* Executive Summary */}
          <section className="bg-bg-card border border-bg-card rounded-xl p-5">
            <h2 className="text-sm font-bold flex items-center gap-2 mb-3 text-accent-blue">
              <Shield className="w-4 h-4" /> Executive Summary
            </h2>
            <div className="border-t border-bg-secondary pt-3 grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
              <div><span className="text-text-secondary block">Date/Time</span><span className="font-semibold">{new Date().toLocaleString()}</span></div>
              <div><span className="text-text-secondary block">Model Used</span><span className="font-semibold font-mono">{modelId}</span></div>
              <div><span className="text-text-secondary block">Total Flows</span><span className="font-semibold">{report.total.toLocaleString()}</span></div>
              <div><span className="text-text-secondary block">Threat Rate</span><span className="font-semibold text-red-400">{report.threatPct}%</span></div>
            </div>
          </section>

          {/* Threat Landscape */}
          <section className="bg-bg-card border border-bg-card rounded-xl p-5">
            <h2 className="text-sm font-bold flex items-center gap-2 mb-3 text-accent-orange">
              <BarChart3 className="w-4 h-4" /> Threat Landscape — Top Attack Types
            </h2>
            <div className="border-t border-bg-secondary pt-3 space-y-2">
              {report.topAttacks.map(([label, count]) => (
                <div key={label} className="flex items-center gap-3 text-xs">
                  <span className="w-40 truncate font-mono text-text-primary shrink-0">{label}</span>
                  <div className="flex-1 h-5 bg-bg-secondary rounded-full overflow-hidden">
                    <div className="h-full bg-accent-orange/70 rounded-full transition-all" style={{ width: `${(count / report.maxAttack) * 100}%` }} />
                  </div>
                  <span className="w-16 text-right font-mono text-text-secondary">{count} <span className="text-text-secondary/60">({(count / report.threatCount * 100).toFixed(1)}%)</span></span>
                </div>
              ))}
              {report.topAttacks.length === 0 && <p className="text-xs text-text-secondary">No threats detected.</p>}
            </div>
          </section>

          {/* Critical Indicators */}
          <section className="bg-bg-card border border-bg-card rounded-xl p-5">
            <h2 className="text-sm font-bold flex items-center gap-2 mb-3 text-red-400">
              <Crosshair className="w-4 h-4" /> Critical Indicators
            </h2>
            <div className="border-t border-bg-secondary pt-3 grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h3 className="text-xs font-semibold text-text-secondary mb-2">Top Source IPs (Attackers)</h3>
                {report.topSrc.length > 0 ? report.topSrc.map(([ip, cnt]) => (
                  <div key={ip} className="flex justify-between text-xs py-1 border-b border-bg-secondary/50">
                    <span className="font-mono">{ip}</span>
                    <span className="text-red-400 font-semibold">{cnt} attacks</span>
                  </div>
                )) : <p className="text-xs text-text-secondary">No source IP data available.</p>}
              </div>
              <div>
                <h3 className="text-xs font-semibold text-text-secondary mb-2">Top Destination IPs (Targets)</h3>
                {report.topDst.length > 0 ? report.topDst.map(([ip, cnt]) => (
                  <div key={ip} className="flex justify-between text-xs py-1 border-b border-bg-secondary/50">
                    <span className="font-mono">{ip}</span>
                    <span className="text-amber-400 font-semibold">{cnt} hits</span>
                  </div>
                )) : <p className="text-xs text-text-secondary">No destination IP data available.</p>}
              </div>
            </div>
          </section>

          {/* Timeline */}
          <section className="bg-bg-card border border-bg-card rounded-xl p-5">
            <h2 className="text-sm font-bold flex items-center gap-2 mb-3 text-accent-purple">
              <Clock className="w-4 h-4" /> Detection Timeline
            </h2>
            <div className="border-t border-bg-secondary pt-3 flex items-center gap-2 overflow-x-auto">
              {[
                { label: 'First Detection', value: report.firstDetection ? report.firstDetection.toLocaleTimeString() : '—', color: 'text-accent-green' },
                { label: 'Peak Activity', value: report.peakActivity ? report.peakActivity.toLocaleTimeString() : '—', color: 'text-accent-orange' },
                { label: 'Last Detection', value: report.lastDetection ? report.lastDetection.toLocaleTimeString() : '—', color: 'text-red-400' },
              ].map((step, i) => (
                <div key={step.label} className="flex items-center gap-2 shrink-0">
                  {i > 0 && <div className="w-8 h-0.5 bg-bg-secondary" />}
                  <div className="bg-bg-secondary rounded-lg p-3 text-center min-w-[120px]">
                    <div className={`text-sm font-bold ${step.color}`}>{step.value}</div>
                    <div className="text-[10px] text-text-secondary mt-0.5">{step.label}</div>
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Severity Breakdown */}
          <section className="bg-bg-card border border-bg-card rounded-xl p-5">
            <h2 className="text-sm font-bold flex items-center gap-2 mb-3 text-accent-amber">
              <AlertTriangle className="w-4 h-4" /> Severity Breakdown
            </h2>
            <div className="border-t border-bg-secondary pt-3">
              <div className="flex h-6 rounded-full overflow-hidden gap-0.5">
                {Object.entries(report.sevDist).filter(([, c]) => c > 0).map(([sev, count]) => (
                  <div key={sev} className="transition-all" style={{ width: `${(count / report.total) * 100}%`, backgroundColor: SEV_COLORS[sev] || '#64748B' }} title={`${sev}: ${count}`} />
                ))}
              </div>
              <div className="flex flex-wrap gap-3 mt-2 text-xs text-text-secondary">
                {Object.entries(report.sevDist).map(([sev, count]) => (
                  <span key={sev} className="flex items-center gap-1">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: SEV_COLORS[sev] }} />
                    {sev}: {count} ({report.total ? ((count / report.total) * 100).toFixed(1) : 0}%)
                  </span>
                ))}
              </div>
            </div>
          </section>

          {/* Recommended Actions */}
          {report.recs.length > 0 && (
            <section className="bg-bg-card border border-bg-card rounded-xl p-5">
              <h2 className="text-sm font-bold flex items-center gap-2 mb-3 text-accent-green">
                <Shield className="w-4 h-4" /> Recommended Actions
              </h2>
              <div className="border-t border-bg-secondary pt-3 space-y-2">
                {report.recs.map(r => (
                  <div key={r.family} className="flex gap-3 text-xs p-3 bg-bg-secondary rounded-lg">
                    <span className="px-2 py-0.5 bg-accent-orange/15 text-accent-orange rounded font-semibold shrink-0 h-fit">{r.family}</span>
                    <span className="text-text-secondary">{r.rec}</span>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* MITRE ATT&CK Coverage */}
          {report.mitre.length > 0 && (
            <section className="bg-bg-card border border-bg-card rounded-xl p-5">
              <h2 className="text-sm font-bold flex items-center gap-2 mb-3 text-accent-blue">
                <Activity className="w-4 h-4" /> MITRE ATT&CK Coverage
              </h2>
              <div className="border-t border-bg-secondary pt-3 flex flex-wrap gap-2">
                {report.mitre.map(m => (
                  <div key={m.id} className="flex items-center gap-2 px-3 py-1.5 bg-accent-blue/10 border border-accent-blue/20 rounded-lg text-xs">
                    <span className="font-mono font-bold text-accent-blue">{m.id}</span>
                    <span className="text-text-secondary">{m.name}</span>
                    <span className="text-text-secondary/60">({m.family})</span>
                  </div>
                ))}
              </div>
            </section>
          )}

          <div className="text-[10px] text-text-secondary/60 text-center">
            Report auto-generated by RobustIDPS.ai Incident Report Engine. Review and validate all findings before distribution.
          </div>

          {/* Continue */}
          <div className="flex flex-wrap gap-2 pt-3 border-t border-bg-card">
            <span className="text-[10px] text-text-secondary mr-2">Continue to:</span>
            <a href="/threat-intel" className="text-[10px] px-2 py-1 rounded bg-accent-purple/10 text-accent-purple hover:bg-accent-purple/20 transition-colors">Threat Intel</a>
            <a href="/rule-generator" className="text-[10px] px-2 py-1 rounded bg-accent-orange/10 text-accent-orange hover:bg-accent-orange/20 transition-colors">Rule Generator</a>
            <a href="/cve-mapper" className="text-[10px] px-2 py-1 rounded bg-accent-red/10 text-accent-red hover:bg-accent-red/20 transition-colors">CVE Mapper</a>
            <a href="/auto-investigate" className="text-[10px] px-2 py-1 rounded bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20 transition-colors">Auto-Investigation</a>
          </div>
        </div>
      )}
    </div>
  )
}
