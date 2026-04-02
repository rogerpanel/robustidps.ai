import { useState, useCallback, useMemo } from 'react'
import {
  Search, Loader2, Shield, Upload, FileText, X, Radio,
  Clock, Trash2, ChevronRight, BarChart3, Filter, Zap,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import ModelSelector from '../components/ModelSelector'
import { analyseFile, cachePageResult } from '../utils/api'
import { useNoticeBoard } from '../hooks/useNoticeBoard'
import { getLiveData, hasLiveData } from '../utils/liveDataStore'

/* ── Query parsing ── */
interface QueryResult {
  type: 'list' | 'aggregation'
  data: any[]
  total: number
}

const parseQuery = (query: string, predictions: any[]): QueryResult => {
  const q = query.toLowerCase()
  let filtered = [...predictions]

  // Attack type filters
  if (q.includes('ddos')) filtered = filtered.filter(p => p.label_predicted?.toLowerCase().includes('ddos'))
  if (q.includes('brute force') || q.includes('bruteforce') || q.includes('ssh'))
    filtered = filtered.filter(p => p.label_predicted?.toLowerCase().includes('bruteforce'))
  if (q.includes('recon') || q.includes('scan') || q.includes('reconnaissance'))
    filtered = filtered.filter(p => p.label_predicted?.toLowerCase().includes('recon'))
  if (q.includes('malware') || q.includes('ransomware') || q.includes('backdoor'))
    filtered = filtered.filter(p => p.label_predicted?.toLowerCase().includes('malware'))
  if (q.includes('spoof'))
    filtered = filtered.filter(p => p.label_predicted?.toLowerCase().includes('spoof'))
  if (q.includes('web attack') || q.includes('sqli') || q.includes('xss') || q.includes('injection'))
    filtered = filtered.filter(p => p.label_predicted?.toLowerCase().includes('webattack') || p.label_predicted?.toLowerCase().includes('sql') || p.label_predicted?.toLowerCase().includes('xss'))
  if (q.includes('mirai') || q.includes('botnet'))
    filtered = filtered.filter(p => p.label_predicted?.toLowerCase().includes('mirai'))

  // Confidence filters
  const confMatch = q.match(/confidence\s*(?:above|over|>|>=)\s*(\d+)/)
  if (confMatch) filtered = filtered.filter(p => (p.confidence || 0) >= parseInt(confMatch[1]) / 100)

  // Severity filters
  if (q.includes('critical')) filtered = filtered.filter(p => p.severity === 'critical')
  else if (q.includes('high') && !q.includes('high confidence'))
    filtered = filtered.filter(p => p.severity === 'high' || p.severity === 'critical')

  // Benign exclusion
  if (q.includes('threat') || q.includes('attack') || q.includes('malicious'))
    filtered = filtered.filter(p => p.severity !== 'benign')

  // Anomalous / low confidence
  if (q.includes('anomalous') || q.includes('low confidence'))
    filtered = filtered.filter(p => (p.confidence || 0) < 0.5 && p.severity !== 'benign')

  // Port filters
  const portMatch = q.match(/port\s*(\d+)/)
  if (portMatch) filtered = filtered.filter(p => String(p.dst_port) === portMatch[1] || String(p.src_port) === portMatch[1])

  // Top N
  const topMatch = q.match(/top\s*(\d+)/)

  // Source IP aggregation
  if (q.includes('source ip') || q.includes('attacking ip') || q.includes('top')) {
    const ipCounts: Record<string, number> = {}
    filtered.forEach(p => { const ip = p.src_ip || 'unknown'; ipCounts[ip] = (ipCounts[ip] || 0) + 1 })
    const limit = topMatch ? parseInt(topMatch[1]) : 10
    return { type: 'aggregation', data: Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, limit), total: filtered.length }
  }

  return { type: 'list', data: filtered.slice(0, 100), total: filtered.length }
}

/* ── Constants ── */
const GUIDE_STEPS = [
  { title: 'Load Data', desc: 'Upload a CSV/PCAP file or use live monitor data to populate the threat database.' },
  { title: 'Select Model', desc: 'Choose the detection model for classifying network flows.' },
  { title: 'Enter Query', desc: 'Type a natural language query or click a suggested query chip.' },
  { title: 'Review Results', desc: 'Browse filtered results, aggregations, and export findings.' },
]

const SUGGESTED_QUERIES = [
  'Show all DDoS attacks',
  'Find SSH brute force from external IPs',
  'High confidence threats (>95%)',
  'Reconnaissance activity in the last hour',
  'All attacks targeting port 443',
  'Anomalous traffic with low confidence',
  'Top 10 attacking source IPs',
  'Malware and ransomware detections',
]

const SEV_STYLE: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400',
  high: 'bg-orange-500/20 text-orange-400',
  medium: 'bg-amber-500/20 text-amber-400',
  low: 'bg-blue-500/20 text-blue-400',
  benign: 'bg-green-500/20 text-green-400',
}

export default function ThreatHunt() {
  const [file, setFile] = useState<File | null>(null)
  const [modelId, setModelId] = useState('surrogate')
  const [predictions, setPredictions] = useState<any[]>([])
  const [analyzing, setAnalyzing] = useState(false)
  const [liveDataLoaded, setLiveDataLoaded] = useState(false)
  const [query, setQuery] = useState('')
  const [result, setResult] = useState<QueryResult | null>(null)
  const [searching, setSearching] = useState(false)
  const [history, setHistory] = useState<string[]>([])
  const { addNotice, updateNotice } = useNoticeBoard()

  const loadLiveData = useCallback(() => {
    const live = getLiveData()
    if (!live) return
    setPredictions(live.predictions || [])
    setLiveDataLoaded(true)
  }, [])

  const runAnalysis = async () => {
    if (!file) return
    setAnalyzing(true)
    const nid = addNotice({ title: 'Threat Hunt - Data Load', description: `Analyzing ${file.name}...`, status: 'running', page: '/threat-hunt' })
    try {
      const data = await analyseFile(file, modelId, 'threat_hunt')
      setPredictions(data.predictions || [])
      updateNotice(nid, { status: 'completed', description: `${data.predictions?.length || 0} flows loaded for hunting` })
    } catch (err) {
      updateNotice(nid, { status: 'error', description: err instanceof Error ? err.message : 'Analysis failed' })
    }
    setAnalyzing(false)
  }

  const submitQuery = (q?: string) => {
    const queryText = q || query
    if (!queryText.trim() || predictions.length === 0) return
    setSearching(true)
    // Simulate brief processing delay
    setTimeout(() => {
      const res = parseQuery(queryText, predictions)
      setResult(res)
      setSearching(false)
      setHistory(prev => {
        const next = [queryText, ...prev.filter(h => h !== queryText)].slice(0, 5)
        return next
      })
      cachePageResult('threat_hunt', {
        query: queryText,
        results: res.total,
        type: res.type,
        model_used: modelId,
      })
    }, 300)
  }

  const dataLoaded = predictions.length > 0

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display font-bold flex items-center gap-2">
            <Search className="w-6 h-6 text-accent-blue" />
            Threat Hunt
          </h1>
          <p className="text-sm text-text-secondary mt-1">
            Natural language threat hunting across classified network traffic.
          </p>
        </div>
        {result && <ExportMenu filename="threat-hunt-results" />}
      </div>

      <PageGuide title="How to use Threat Hunt" steps={GUIDE_STEPS} tip="Tip: Start with a broad query like 'Show all DDoS attacks', then refine with confidence or port filters." />

      {/* Upload + Model */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">
          <Upload className="w-5 h-5 text-text-secondary" /> Load Traffic Data
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end">
          <div>
            {file ? (
              <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-accent-green/30 bg-accent-green/5">
                <FileText className="w-4 h-4 text-accent-green shrink-0" />
                <span className="text-xs font-mono truncate flex-1">{file.name}</span>
                <button onClick={() => { setFile(null); setPredictions([]); setResult(null) }} className="text-text-secondary hover:text-text-primary"><X className="w-3.5 h-3.5" /></button>
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
          <button onClick={runAnalysis} disabled={!file || analyzing} className="px-4 py-2.5 bg-accent-blue hover:bg-accent-blue/80 text-white rounded-lg text-xs font-medium disabled:opacity-50 flex items-center justify-center gap-2">
            {analyzing ? <><Loader2 className="w-4 h-4 animate-spin" /> Analyzing...</> : 'Load & Classify'}
          </button>
        </div>
        {dataLoaded && (
          <p className="text-xs text-accent-green mt-2">{predictions.length} flows loaded and ready for hunting.</p>
        )}
      </div>

      {/* Live Monitor Banner */}
      {hasLiveData() && !liveDataLoaded && predictions.length === 0 && (
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

      {/* Query Input */}
      {dataLoaded && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-4">
          <h2 className="text-lg font-display font-semibold flex items-center gap-2">
            <Filter className="w-5 h-5 text-accent-purple" /> Natural Language Query
          </h2>
          <div className="flex gap-2">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-secondary" />
              <input
                type="text"
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && submitQuery()}
                placeholder="e.g., Show me all SSH brute force attacks with confidence above 90%"
                className="w-full pl-10 pr-4 py-3 bg-bg-card border border-bg-card rounded-lg text-sm text-text-primary placeholder-text-secondary/50 focus:outline-none focus:border-accent-blue transition-colors"
              />
            </div>
            <button
              onClick={() => submitQuery()}
              disabled={!query.trim() || searching}
              className="px-5 py-3 bg-accent-blue hover:bg-accent-blue/80 text-white rounded-lg text-sm font-medium disabled:opacity-50 flex items-center gap-2 transition-colors"
            >
              {searching ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
              Hunt
            </button>
          </div>

          {/* Suggested queries */}
          <div>
            <p className="text-[10px] text-text-secondary mb-2">Suggested queries:</p>
            <div className="flex flex-wrap gap-2">
              {SUGGESTED_QUERIES.map(sq => (
                <button
                  key={sq}
                  onClick={() => { setQuery(sq); submitQuery(sq) }}
                  className="px-3 py-1.5 bg-bg-card hover:bg-accent-blue/10 border border-bg-card hover:border-accent-blue/30 rounded-full text-[11px] text-text-secondary hover:text-accent-blue transition-colors"
                >
                  {sq}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Query History */}
      {history.length > 0 && (
        <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-semibold flex items-center gap-1.5"><Clock className="w-3.5 h-3.5 text-text-secondary" /> Recent Queries</h3>
            <button onClick={() => setHistory([])} className="text-[10px] text-text-secondary hover:text-text-primary flex items-center gap-1"><Trash2 className="w-3 h-3" /> Clear</button>
          </div>
          <div className="flex flex-wrap gap-2">
            {history.map((h, i) => (
              <button key={i} onClick={() => { setQuery(h); submitQuery(h) }} className="flex items-center gap-1 px-2.5 py-1 bg-bg-card rounded-lg text-[11px] text-text-secondary hover:text-accent-blue transition-colors">
                <ChevronRight className="w-3 h-3" /> {h}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-4" id="export-target">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-accent-green" /> Results
            </h3>
            <span className="text-xs text-text-secondary">
              Found <span className="text-accent-blue font-semibold">{result.total}</span> matching flows out of {predictions.length} total
              {result.type === 'list' && result.total > 100 && <span className="text-text-secondary/60"> (showing first 100)</span>}
            </span>
          </div>

          {result.type === 'aggregation' ? (
            <div className="space-y-2">
              {(result.data as [string, number][]).map(([ip, count], i) => {
                const maxCount = (result.data as [string, number][])[0]?.[1] || 1
                return (
                  <div key={ip} className="flex items-center gap-3">
                    <span className="text-xs text-text-secondary w-5 text-right">{i + 1}.</span>
                    <span className="text-xs font-mono w-36 truncate">{ip}</span>
                    <div className="flex-1 bg-bg-card rounded-full h-2.5 overflow-hidden">
                      <div className="h-full bg-accent-blue/60 rounded-full transition-all" style={{ width: `${(count / maxCount) * 100}%` }} />
                    </div>
                    <span className="text-xs text-text-secondary w-16 text-right">{count} flows</span>
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-left text-text-secondary border-b border-bg-card">
                    <th className="pb-2 pr-3">Source IP</th>
                    <th className="pb-2 pr-3">Dest IP</th>
                    <th className="pb-2 pr-3">Label</th>
                    <th className="pb-2 pr-3">Confidence</th>
                    <th className="pb-2">Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {result.data.map((p: any, i: number) => (
                    <tr key={i} className="border-b border-bg-card/50 hover:bg-bg-card/30">
                      <td className="py-1.5 pr-3 font-mono">{p.src_ip || '—'}</td>
                      <td className="py-1.5 pr-3 font-mono">{p.dst_ip || '—'}</td>
                      <td className="py-1.5 pr-3">{p.label_predicted || '—'}</td>
                      <td className="py-1.5 pr-3">
                        <span className={`${(p.confidence || 0) >= 0.9 ? 'text-accent-red' : (p.confidence || 0) >= 0.7 ? 'text-accent-amber' : 'text-text-secondary'}`}>
                          {((p.confidence || 0) * 100).toFixed(1)}%
                        </span>
                      </td>
                      <td className="py-1.5">
                        <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] ${SEV_STYLE[p.severity] || 'bg-gray-500/20 text-gray-400'}`}>
                          {p.severity || '—'}
                        </span>
                      </td>
                    </tr>
                  ))}
                  {result.data.length === 0 && (
                    <tr><td colSpan={5} className="py-6 text-center text-text-secondary">No matching flows found. Try a different query.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
