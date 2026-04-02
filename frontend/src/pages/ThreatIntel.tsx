import { useState, useMemo, useCallback } from 'react'
import {
  Globe, Upload, X, FileText, Loader2, Radio, Shield, Search,
  AlertTriangle, Info, ChevronDown, ChevronUp,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import ModelSelector from '../components/ModelSelector'
import { analyseFile, cachePageResult } from '../utils/api'
import { useNoticeBoard } from '../hooks/useNoticeBoard'
import { getLiveData, hasLiveData } from '../utils/liveDataStore'

/* ── Geo-location helper ────────────────────────────────────────────── */

const geoFromIP = (ip: string): string => {
  if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.16.')) return 'Internal Network'
  if (ip.startsWith('198.51.100.')) return 'TEST-NET-2 (Documentation)'
  if (ip.startsWith('203.0.113.')) return 'TEST-NET-3 (Documentation)'
  if (ip.startsWith('185.')) return 'Europe (RIPE NCC)'
  if (ip.startsWith('45.') || ip.startsWith('104.')) return 'North America (ARIN)'
  if (ip.startsWith('103.')) return 'Asia-Pacific (APNIC)'
  if (ip.startsWith('41.')) return 'Africa (AFRINIC)'
  return 'Unknown Region'
}

/* ── Threat score calculation ───────────────────────────────────────── */

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 10, high: 7, medium: 4, low: 2, benign: 0,
}

interface AttackEntry {
  label: string
  confidence: number
  severity: string
}

const threatScore = (attacks: AttackEntry[]): number => {
  if (!attacks.length) return 0
  const avgConf = attacks.reduce((s, a) => s + (a.confidence || 0), 0) / attacks.length
  const maxSeverity = Math.max(...attacks.map(a => SEVERITY_WEIGHT[a.severity] || 0))
  return Math.min(100, Math.round(attacks.length * avgConf * maxSeverity / 5))
}

const scoreColor = (score: number): string => {
  if (score <= 30) return '#22C55E'
  if (score <= 60) return '#F59E0B'
  return '#EF4444'
}

const scoreLabel = (score: number): string => {
  if (score <= 30) return 'Low'
  if (score <= 60) return 'Medium'
  return 'High'
}

const actionForScore = (score: number): string => {
  if (score <= 30) return 'Monitor — no immediate action required'
  if (score <= 60) return 'Investigate — review traffic patterns and correlate with other indicators'
  return 'Block — add to deny list and investigate affected hosts immediately'
}

/* ── Guide steps ────────────────────────────────────────────────────── */

const GUIDE_STEPS = [
  { title: 'Load Analysis Data', desc: 'Upload a CSV/PCAP file or use Live Monitor data to extract threat intelligence.' },
  { title: 'Review IP Reputation', desc: 'Each unique attacking IP is scored based on attack count, confidence, and severity.' },
  { title: 'Assess Threat Levels', desc: 'Green (0-30) = low risk, Amber (31-60) = medium, Red (61-100) = high risk.' },
  { title: 'Take Action', desc: 'Use recommended actions for each IP and export findings for your security team.' },
]

/* ── IP Intel record ────────────────────────────────────────────────── */

interface IPIntel {
  ip: string
  attacks: AttackEntry[]
  attackTypes: string[]
  count: number
  score: number
  minConf: number
  maxConf: number
  geo: string
  action: string
}

export default function ThreatIntel() {
  const [file, setFile] = useState<File | null>(null)
  const [modelId, setModelId] = useState('surrogate')
  const [analysisResult, setAnalysisResult] = useState<any>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [liveDataLoaded, setLiveDataLoaded] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [sortAsc, setSortAsc] = useState(false)
  const [showEnrichNote, setShowEnrichNote] = useState(false)
  const { addNotice, updateNotice } = useNoticeBoard()

  const loadLiveData = useCallback(() => {
    const live = getLiveData()
    if (!live) return
    setAnalysisResult({ predictions: live.predictions, n_flows: live.totalFlows, n_threats: live.threatCount })
    setLiveDataLoaded(true)
  }, [])

  const runAnalysis = async () => {
    if (!file) return
    setAnalyzing(true)
    const nid = addNotice({ title: 'Threat Intel Analysis', description: `Analyzing ${file.name}...`, status: 'running', page: '/threat-intel' })
    try {
      const data = await analyseFile(file, modelId, 'threat_intel')
      setAnalysisResult(data)
      updateNotice(nid, { status: 'completed', description: `${data.predictions?.length || 0} flows enriched` })
      cachePageResult('threat_intel', { n_flows: data.predictions?.length || 0, model: modelId }).catch(() => {})
    } catch (err) {
      updateNotice(nid, { status: 'error', description: err instanceof Error ? err.message : 'Analysis failed' })
    }
    setAnalyzing(false)
  }

  /* ── Build IP intelligence ────────────────────────────────────────── */
  const ipIntel = useMemo((): IPIntel[] => {
    if (!analysisResult?.predictions) return []
    const preds = analysisResult.predictions as any[]
    const ipMap: Record<string, AttackEntry[]> = {}

    preds.forEach((p: any) => {
      const sev = p.severity || 'benign'
      if (sev === 'benign') return
      const ip = p.src_ip || p.source_ip || '—'
      if (ip === '—') return
      if (!ipMap[ip]) ipMap[ip] = []
      ipMap[ip].push({ label: p.label_predicted || p.label || 'Unknown', confidence: p.confidence ?? 0.5, severity: sev })
    })

    return Object.entries(ipMap).map(([ip, attacks]) => {
      const types = [...new Set(attacks.map(a => a.label))]
      const confs = attacks.map(a => a.confidence)
      const score = threatScore(attacks)
      return {
        ip, attacks, attackTypes: types, count: attacks.length, score,
        minConf: Math.min(...confs), maxConf: Math.max(...confs),
        geo: geoFromIP(ip), action: actionForScore(score),
      }
    }).sort((a, b) => sortAsc ? a.score - b.score : b.score - a.score)
  }, [analysisResult, sortAsc])

  const filtered = useMemo(() => {
    if (!searchQuery.trim()) return ipIntel
    const q = searchQuery.toLowerCase()
    return ipIntel.filter(i => i.ip.includes(q) || i.attackTypes.some(t => t.toLowerCase().includes(q)) || i.geo.toLowerCase().includes(q))
  }, [ipIntel, searchQuery])

  const stats = useMemo(() => {
    if (!ipIntel.length) return null
    const avgScore = Math.round(ipIntel.reduce((s, i) => s + i.score, 0) / ipIntel.length)
    const mostActive = ipIntel[0]
    return { total: ipIntel.length, avgScore, mostActive }
  }, [ipIntel])

  return (
    <div className="space-y-6 threat-intel-root">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Globe className="w-6 h-6 text-accent-purple" />
            Threat Intelligence
          </h1>
          <p className="text-sm text-text-secondary mt-1">IP reputation scoring and threat history from analysis results</p>
        </div>
        <ExportMenu targetSelector=".threat-intel-root" filename="threat-intel-report" />
      </div>

      <PageGuide title="How to use Threat Intelligence" steps={GUIDE_STEPS} tip="Threat scores combine attack volume, detection confidence, and severity for prioritized response." />

      {/* Upload + Model */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">Load Analysis Data</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end">
          <div>
            {file ? (
              <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-accent-green/30 bg-accent-green/5">
                <FileText className="w-4 h-4 text-accent-green shrink-0" />
                <span className="text-xs font-mono truncate flex-1">{file.name}</span>
                <button onClick={() => { setFile(null); setAnalysisResult(null) }} className="text-text-secondary hover:text-text-primary"><X className="w-3.5 h-3.5" /></button>
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
          <button onClick={runAnalysis} disabled={!file || analyzing} className="px-4 py-2.5 bg-accent-orange hover:bg-accent-orange/80 text-white rounded-lg text-xs font-medium disabled:opacity-50 flex items-center justify-center gap-2">
            {analyzing ? <><Loader2 className="w-4 h-4 animate-spin" /> Analyzing...</> : 'Analyze & Enrich'}
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

      {/* Summary stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-bg-card border border-bg-card rounded-xl p-4">
            <div className="text-xs text-text-secondary mb-1 flex items-center gap-1"><Shield className="w-3.5 h-3.5 text-accent-blue" /> Total Attackers</div>
            <div className="text-2xl font-bold">{stats.total}</div>
          </div>
          <div className="bg-bg-card border border-bg-card rounded-xl p-4">
            <div className="text-xs text-text-secondary mb-1 flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5 text-accent-amber" /> Avg Threat Score</div>
            <div className="text-2xl font-bold" style={{ color: scoreColor(stats.avgScore) }}>{stats.avgScore}</div>
          </div>
          <div className="bg-bg-card border border-bg-card rounded-xl p-4">
            <div className="text-xs text-text-secondary mb-1 flex items-center gap-1"><Globe className="w-3.5 h-3.5 text-red-400" /> Most Active IP</div>
            <div className="text-lg font-bold font-mono truncate">{stats.mostActive?.ip || '—'}</div>
          </div>
          <div className="bg-bg-card border border-bg-card rounded-xl p-4">
            <div className="text-xs text-text-secondary mb-1 flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5 text-red-400" /> Highest Score</div>
            <div className="text-2xl font-bold" style={{ color: scoreColor(stats.mostActive?.score || 0) }}>{stats.mostActive?.score || 0}</div>
          </div>
        </div>
      )}

      {/* Search + Sort + Enrich */}
      {ipIntel.length > 0 && (
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-secondary" />
            <input type="text" placeholder="Search IP, attack type, or region..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)} className="w-full pl-9 pr-3 py-2 bg-bg-secondary border border-bg-card rounded-lg text-xs text-text-primary placeholder-text-secondary/50 focus:outline-none focus:border-accent-blue/40" />
          </div>
          <button onClick={() => setSortAsc(!sortAsc)} className="flex items-center gap-1 px-3 py-2 bg-bg-secondary border border-bg-card rounded-lg text-xs text-text-secondary hover:text-text-primary transition-colors">
            Score {sortAsc ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>
          <button onClick={() => setShowEnrichNote(!showEnrichNote)} className="px-3 py-2 bg-accent-purple/10 border border-accent-purple/20 rounded-lg text-xs text-accent-purple hover:bg-accent-purple/20 transition-colors">
            Enrich with External Sources
          </button>
          <span className="text-xs text-text-secondary">{filtered.length} of {ipIntel.length} IPs</span>
        </div>
      )}

      {showEnrichNote && (
        <div className="flex items-center gap-2 px-4 py-3 bg-accent-purple/5 border border-accent-purple/20 rounded-xl text-xs text-accent-purple">
          <Info className="w-4 h-4 shrink-0" />
          Connect OTX/AbuseIPDB API keys in Settings for live enrichment. Currently showing locally-derived intelligence only.
        </div>
      )}

      {/* IP Reputation Cards */}
      {filtered.length > 0 && (
        <div className="space-y-3">
          {filtered.map(intel => {
            const color = scoreColor(intel.score)
            return (
              <div key={intel.ip} className="bg-bg-card border rounded-xl p-4" style={{ borderColor: `${color}30` }}>
                <div className="flex items-start justify-between gap-4 flex-wrap">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0" style={{ backgroundColor: `${color}15` }}>
                      <span className="text-sm font-bold" style={{ color }}>{intel.score}</span>
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-text-primary">{intel.ip}</span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold" style={{ backgroundColor: `${color}20`, color }}>{scoreLabel(intel.score)}</span>
                      </div>
                      <div className="text-[10px] text-text-secondary mt-0.5">{intel.geo}</div>
                    </div>
                  </div>
                  <div className="text-right text-xs">
                    <div className="text-text-secondary">{intel.count} attack{intel.count !== 1 ? 's' : ''}</div>
                    <div className="text-text-secondary/60">Confidence: {(intel.minConf * 100).toFixed(0)}%–{(intel.maxConf * 100).toFixed(0)}%</div>
                  </div>
                </div>

                <div className="mt-3 flex flex-wrap gap-1.5">
                  {intel.attackTypes.map(t => (
                    <span key={t} className="px-2 py-0.5 bg-bg-secondary rounded text-[10px] font-mono text-text-secondary">{t}</span>
                  ))}
                </div>

                {/* Threat score bar */}
                <div className="mt-3 flex items-center gap-2">
                  <div className="flex-1 h-2 bg-bg-secondary rounded-full overflow-hidden">
                    <div className="h-full rounded-full transition-all" style={{ width: `${intel.score}%`, backgroundColor: color }} />
                  </div>
                  <span className="text-[10px] font-mono w-8 text-right" style={{ color }}>{intel.score}</span>
                </div>

                <div className="mt-2 text-[10px] text-text-secondary/80 flex items-center gap-1.5">
                  <Shield className="w-3 h-3 shrink-0" />
                  {intel.action}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Empty state */}
      {analysisResult && ipIntel.length === 0 && (
        <div className="text-center py-12 text-text-secondary">
          <Shield className="w-8 h-8 mx-auto mb-2 opacity-40" />
          <p className="text-sm">No threatening source IPs detected in this dataset.</p>
        </div>
      )}

      {!analysisResult && (
        <div className="flex items-center gap-2 px-3 py-2 bg-accent-blue/5 border border-accent-blue/10 rounded-lg text-xs text-accent-blue">
          <Info className="w-3.5 h-3.5 shrink-0" />
          Upload a dataset or use Live Monitor data to generate threat intelligence.
        </div>
      )}

      <div className="text-[10px] text-text-secondary/60 text-center">
        Threat intelligence derived locally from RobustIDPS.ai analysis. Geo-location is estimated from IP range heuristics.
      </div>
    </div>
  )
}
