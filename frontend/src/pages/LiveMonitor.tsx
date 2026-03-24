import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Play, Pause, Upload, Radio, Shield, ShieldAlert, Cpu, Eye, Server, Terminal, ChevronDown, ChevronUp, Network, CheckCircle2, AlertTriangle, BarChart3, PieChart as PieChartIcon, Send, TrendingUp, Brain, Download, Filter, Wifi, Usb, Monitor, Clock, Ban, Lock, Copy, ExternalLink, Layers, Zap, HardDrive } from 'lucide-react'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend, BarChart, Bar, XAxis, YAxis } from 'recharts'
import FileUpload from '../components/FileUpload'
import ModelSelector from '../components/ModelSelector'
import LiveCaptureModelSelector from '../components/LiveCaptureModelSelector'
import PageGuide from '../components/PageGuide'
import { uploadFile, connectStream } from '../utils/api'
import { useAnalysis } from '../hooks/useAnalysis'
import { registerSessionReset } from '../utils/sessionReset'

interface ModelPrediction {
  model_id: string
  label_predicted: string
  confidence: number
  severity: string
}

interface FlowEvent {
  flow_id: number
  src_ip: string
  dst_ip: string
  label_predicted: string
  confidence: number
  severity: string
  cycle?: number
  auto_blocked?: boolean
  block_status?: string
  src_port?: number
  dst_port?: number
  protocol?: number
  model_predictions?: ModelPrediction[]
  primary_model?: string
}

const SEV_COLOR: Record<string, string> = {
  benign: 'text-accent-blue',
  low: 'text-accent-green',
  medium: 'text-accent-amber',
  high: 'text-accent-orange',
  critical: 'text-accent-red',
}

const PIE_COLORS = [
  '#3B82F6', '#EF4444', '#F59E0B', '#22C55E', '#A855F7',
  '#F97316', '#06B6D4', '#EC4899', '#8B5CF6', '#14B8A6',
  '#6366F1', '#D946EF', '#0EA5E9',
]

const SEV_BAR_COLORS: Record<string, string> = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#F59E0B',
  low: '#22C55E',
  benign: '#3B82F6',
}

const TOOLTIP_STYLE = {
  background: '#1E293B',
  border: '1px solid #334155',
  borderRadius: '8px',
  color: '#F8FAFC',
  fontSize: '12px',
}

const COMPARISON_ROWS = [
  { feature: 'Detection Approach', robustidps: 'Hybrid ML: 8-model ensemble (adversarial training, stochastic transformers, state-space models, federated LLM, graph neural networks)', suricata: 'Signature-based rules + limited protocol anomaly detection', snort: 'Signature-based rules (community & registered rulesets)' },
  { feature: 'Zero-Day Detection', robustidps: 'Yes — learns behavioural patterns; detects novel attacks without prior signatures via uncertainty quantification', suricata: 'Limited — relies on heuristic rules; cannot detect truly novel patterns', snort: 'No — requires signature updates for new attack vectors' },
  { feature: 'Adversarial Robustness', robustidps: '96.8% accuracy under evasion attacks; adversarial training + PAC-Bayesian guarantees', suricata: 'Vulnerable to obfuscation, encoding tricks, and fragmentation evasion', snort: 'Vulnerable to polymorphic payloads and signature evasion techniques' },
  { feature: 'Confidence & Uncertainty', robustidps: 'Per-prediction confidence scores with calibrated uncertainty via MC-Dropout and Bayesian inference', suricata: 'Binary alert/no-alert; no confidence scoring', snort: 'Binary match/no-match; no probabilistic output' },
  { feature: 'Encrypted Traffic', robustidps: 'Analyses flow metadata and statistical features — works on encrypted traffic without decryption (including post-quantum)', suricata: 'Requires TLS decryption proxy for payload inspection; limited encrypted flow analysis', snort: 'Cannot inspect encrypted payloads; header-only analysis on encrypted streams' },
  { feature: 'Throughput', robustidps: '2TB+/day in production; GPU-accelerated batch inference with 56x optimization', suricata: 'Multi-threaded; ~10Gbps with hardware offload', snort: 'Single-threaded (Snort 2); multi-threaded in Snort 3; ~1-5Gbps typical' },
  { feature: 'False Positive Rate', robustidps: '60% reduction via uncertainty-calibrated thresholds; hierarchical Gaussian processes', suricata: 'High with default rulesets; requires extensive tuning', snort: 'High with community rules; manual threshold tuning required' },
  { feature: 'Automated Response', robustidps: 'Auto-generates iptables/nftables/Snort/Suricata rules from ML detections; SOC dashboard integration', suricata: 'IPS mode with drop/reject actions on rule match', snort: 'IPS mode (inline) with drop/reject/sdrop actions' },
  { feature: 'Model Updates', robustidps: 'Federated learning enables model updates across organisations without sharing raw data', suricata: 'Manual ruleset updates (ET Open/Pro, OISF)', snort: 'Manual ruleset updates (Talos, community)' },
  { feature: 'Explainability', robustidps: 'Per-flow attention maps, feature importance, uncertainty decomposition, ablation analysis', suricata: 'Rule SID reference only; no explanation of why traffic matched', snort: 'Rule SID/GID reference; no behavioural explanation' },
]

/* ── Module-level store — survives navigation ─────────────────────────── */

const _store: {
  jobId: string | null
  fileName: string
  rate: number
  events: FlowEvent[]
  running: boolean
  done: boolean
  threatCount: number
  benignCount: number
  captureMode: 'file' | 'live'
  iface: string
  captureInterval: number
  captureStatus: string
  currentCycle: number
  wsError: string
  showComparison: boolean
  showSetup: boolean
  showAnalytics: boolean
  sentToUpload: boolean
  selectedModel: string
  selectedModels: string[]
  showDongleGuide: boolean
  showAdvancedAnalytics: boolean
  severityFilter: string
  autoBlockCount: number
  captureId: string
  captureSizeMb: number
  maxCaptureMb: number
  captureLimitReached: boolean
  liveSource: 'interface' | 'file'
  liveFileJobId: string | null
  liveFileName: string
  liveFileLoading: boolean
} = {
  jobId: null,
  fileName: '',
  rate: 100,
  events: [],
  running: false,
  done: false,
  threatCount: 0,
  benignCount: 0,
  captureMode: 'file',
  iface: 'eth0',
  captureInterval: 30,
  captureStatus: '',
  currentCycle: 0,
  wsError: '',
  showComparison: false,
  showSetup: false,
  showAnalytics: false,
  sentToUpload: false,
  selectedModel: 'surrogate',
  selectedModels: ['surrogate'],
  showDongleGuide: false,
  showAdvancedAnalytics: false,
  severityFilter: 'all',
  autoBlockCount: 0,
  captureId: '',
  captureSizeMb: 0,
  maxCaptureMb: 500,
  captureLimitReached: false,
  liveSource: 'interface',
  liveFileJobId: null,
  liveFileName: '',
  liveFileLoading: false,
}

// Keep the WebSocket ref at module level so it survives remount
let _wsRef: WebSocket | null = null

// Register session reset so logout clears this user's data
registerSessionReset(() => {
  _store.jobId = null
  _store.fileName = ''
  _store.rate = 100
  _store.events = []
  _store.running = false
  _store.done = false
  _store.threatCount = 0
  _store.benignCount = 0
  _store.captureMode = 'file'
  _store.iface = 'eth0'
  _store.captureInterval = 30
  _store.captureStatus = ''
  _store.currentCycle = 0
  _store.wsError = ''
  _store.showComparison = false
  _store.showSetup = false
  _store.showAnalytics = false
  _store.sentToUpload = false
  _store.selectedModel = 'surrogate'
  _store.selectedModels = ['surrogate']
  _store.showDongleGuide = false
  _store.showAdvancedAnalytics = false
  _store.severityFilter = 'all'
  _store.autoBlockCount = 0
  _store.captureId = ''
  _store.captureSizeMb = 0
  _store.maxCaptureMb = 500
  _store.captureLimitReached = false
  _store.liveSource = 'interface'
  _store.liveFileJobId = null
  _store.liveFileName = ''
  _store.liveFileLoading = false
  if (_wsRef) { try { _wsRef.close() } catch {} }
  _wsRef = null
})

function wsBaseUrl(): string {
  const API = import.meta.env.VITE_API_URL || ''
  if (API) return API.replace(/^http/, 'ws')
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${proto}//${location.host}`
}

export default function LiveMonitor() {
  const [jobId, _setJobId] = useState<string | null>(_store.jobId)
  const [fileName, _setFileName] = useState(_store.fileName)
  const [rate, _setRate] = useState(_store.rate)
  const [events, _setEvents] = useState<FlowEvent[]>(_store.events)
  const [running, _setRunning] = useState(_store.running)
  const [done, _setDone] = useState(_store.done)
  const [threatCount, _setThreatCount] = useState(_store.threatCount)
  const [benignCount, _setBenignCount] = useState(_store.benignCount)
  const [captureMode, _setCaptureMode] = useState<'file' | 'live'>(_store.captureMode)
  const [iface, _setIface] = useState(_store.iface)
  const [captureInterval, _setCaptureInterval] = useState(_store.captureInterval)
  const [captureStatus, _setCaptureStatus] = useState(_store.captureStatus)
  const [currentCycle, _setCurrentCycle] = useState(_store.currentCycle)
  const [wsError, _setWsError] = useState(_store.wsError)
  const [showComparison, _setShowComparison] = useState(_store.showComparison)
  const [showSetup, _setShowSetup] = useState(_store.showSetup)
  const [showAnalytics, _setShowAnalytics] = useState(_store.showAnalytics)
  const [sentToUpload, _setSentToUpload] = useState(_store.sentToUpload)
  const [selectedModel, _setSelectedModel] = useState(_store.selectedModel)
  const [selectedModels, _setSelectedModels] = useState<string[]>(_store.selectedModels)
  const [showDongleGuide, _setShowDongleGuide] = useState(_store.showDongleGuide)
  const [showAdvancedAnalytics, _setShowAdvancedAnalytics] = useState(_store.showAdvancedAnalytics)
  const [severityFilter, _setSeverityFilter] = useState(_store.severityFilter)
  const [autoBlockCount, _setAutoBlockCount] = useState(_store.autoBlockCount)
  const [captureId, _setCaptureId] = useState(_store.captureId)
  const [captureSizeMb, _setCaptureSizeMb] = useState(_store.captureSizeMb)
  const [maxCaptureMb, _setMaxCaptureMb] = useState(_store.maxCaptureMb)
  const [captureLimitReached, _setCaptureLimitReached] = useState(_store.captureLimitReached)
  const [liveSource, _setLiveSource] = useState<'interface' | 'file'>(_store.liveSource)
  const [liveFileJobId, _setLiveFileJobId] = useState<string | null>(_store.liveFileJobId)
  const [liveFileName, _setLiveFileName] = useState(_store.liveFileName)
  const [liveFileLoading, _setLiveFileLoading] = useState(_store.liveFileLoading)

  const { setLiveResults } = useAnalysis()

  // Wrapped setters that sync to module store
  const setJobId = (v: string | null) => { _store.jobId = v; _setJobId(v) }
  const setFileName = (v: string) => { _store.fileName = v; _setFileName(v) }
  const setRate = (v: number) => { _store.rate = v; _setRate(v) }
  const setEvents = (v: FlowEvent[] | ((prev: FlowEvent[]) => FlowEvent[])) => {
    if (typeof v === 'function') {
      _setEvents(prev => { const next = v(prev); _store.events = next; return next })
    } else { _store.events = v; _setEvents(v) }
  }
  const setRunning = (v: boolean) => { _store.running = v; _setRunning(v) }
  const setDone = (v: boolean) => { _store.done = v; _setDone(v) }
  const setThreatCount = (v: number | ((c: number) => number)) => {
    if (typeof v === 'function') {
      _setThreatCount(prev => { const next = v(prev); _store.threatCount = next; return next })
    } else { _store.threatCount = v; _setThreatCount(v) }
  }
  const setBenignCount = (v: number | ((c: number) => number)) => {
    if (typeof v === 'function') {
      _setBenignCount(prev => { const next = v(prev); _store.benignCount = next; return next })
    } else { _store.benignCount = v; _setBenignCount(v) }
  }
  const setCaptureMode = (v: 'file' | 'live') => { _store.captureMode = v; _setCaptureMode(v) }
  const setIface = (v: string) => { _store.iface = v; _setIface(v) }
  const setCaptureInterval = (v: number) => { _store.captureInterval = v; _setCaptureInterval(v) }
  const setCaptureStatus = (v: string) => { _store.captureStatus = v; _setCaptureStatus(v) }
  const setCurrentCycle = (v: number) => { _store.currentCycle = v; _setCurrentCycle(v) }
  const setWsError = (v: string) => { _store.wsError = v; _setWsError(v) }
  const setShowComparison = (v: boolean) => { _store.showComparison = v; _setShowComparison(v) }
  const setShowSetup = (v: boolean) => { _store.showSetup = v; _setShowSetup(v) }
  const setShowAnalytics = (v: boolean) => { _store.showAnalytics = v; _setShowAnalytics(v) }
  const setSentToUpload = (v: boolean) => { _store.sentToUpload = v; _setSentToUpload(v) }
  const setSelectedModel = (v: string) => { _store.selectedModel = v; _setSelectedModel(v) }
  const setSelectedModels = (v: string[]) => { _store.selectedModels = v; _setSelectedModels(v) }
  const setShowDongleGuide = (v: boolean) => { _store.showDongleGuide = v; _setShowDongleGuide(v) }
  const setShowAdvancedAnalytics = (v: boolean) => { _store.showAdvancedAnalytics = v; _setShowAdvancedAnalytics(v) }
  const setSeverityFilter = (v: string) => { _store.severityFilter = v; _setSeverityFilter(v) }
  const setCaptureId = (v: string) => { _store.captureId = v; _setCaptureId(v) }
  const setCaptureSizeMb = (v: number) => { _store.captureSizeMb = v; _setCaptureSizeMb(v) }
  const setMaxCaptureMb = (v: number) => { _store.maxCaptureMb = v; _setMaxCaptureMb(v) }
  const setCaptureLimitReached = (v: boolean) => { _store.captureLimitReached = v; _setCaptureLimitReached(v) }
  const setLiveSource = (v: 'interface' | 'file') => { _store.liveSource = v; _setLiveSource(v) }
  const setLiveFileJobId = (v: string | null) => { _store.liveFileJobId = v; _setLiveFileJobId(v) }
  const setLiveFileName = (v: string) => { _store.liveFileName = v; _setLiveFileName(v) }
  const setLiveFileLoading = (v: boolean) => { _store.liveFileLoading = v; _setLiveFileLoading(v) }
  const setAutoBlockCount = (v: number | ((c: number) => number)) => {
    if (typeof v === 'function') {
      _setAutoBlockCount(prev => { const next = v(prev); _store.autoBlockCount = next; return next })
    } else { _store.autoBlockCount = v; _setAutoBlockCount(v) }
  }

  // Filtered events based on severity filter
  const filteredEvents = useMemo(() => {
    if (severityFilter === 'all') return events
    return events.filter(ev => ev.severity === severityFilter)
  }, [events, severityFilter])

  // Computed analytics from events
  const analytics = useMemo(() => {
    if (events.length === 0) return null

    // Attack distribution
    const attackDist: Record<string, number> = {}
    const sevDist: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, benign: 0 }
    const srcIpCounts: Record<string, number> = {}
    const dstIpCounts: Record<string, number> = {}
    const confidences: number[] = []
    const threatSrcIps: Record<string, number> = {}

    for (const ev of events) {
      attackDist[ev.label_predicted] = (attackDist[ev.label_predicted] || 0) + 1
      if (ev.severity in sevDist) sevDist[ev.severity]++
      if (ev.src_ip) srcIpCounts[ev.src_ip] = (srcIpCounts[ev.src_ip] || 0) + 1
      if (ev.dst_ip) dstIpCounts[ev.dst_ip] = (dstIpCounts[ev.dst_ip] || 0) + 1
      confidences.push(ev.confidence)
      if (ev.severity !== 'benign' && ev.src_ip) {
        threatSrcIps[ev.src_ip] = (threatSrcIps[ev.src_ip] || 0) + 1
      }
    }

    // Top IPs
    const topSrcIps = Object.entries(threatSrcIps)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([ip, count]) => ({ ip, count }))

    const topDstIps = Object.entries(dstIpCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([ip, count]) => ({ ip, count }))

    // Confidence histogram (10 bins)
    const confBins = Array.from({ length: 10 }, (_, i) => ({
      range: `${i * 10}-${(i + 1) * 10}%`,
      count: 0,
    }))
    for (const c of confidences) {
      confBins[Math.min(Math.floor(c * 10), 9)].count++
    }

    // Avg confidence
    const avgConf = confidences.length > 0
      ? confidences.reduce((a, b) => a + b, 0) / confidences.length
      : 0

    // Attack pie data
    const attackPie = Object.entries(attackDist)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)

    // Severity bar data
    const sevBar = Object.entries(sevDist)
      .filter(([, v]) => v > 0)
      .map(([name, value]) => ({ name, value, fill: SEV_BAR_COLORS[name] || '#94A3B8' }))

    return { attackDist, attackPie, sevBar, confBins, avgConf, topSrcIps, topDstIps, confidences }
  }, [events])

  // Build results for shared analysis context
  const sendToUploadAnalyse = useCallback(() => {
    if (!analytics || events.length === 0) return
    const attackDist = analytics.attackDist
    const perClassMetrics: Record<string, { precision: number; recall: number; f1: number }> = {}
    for (const label of Object.keys(attackDist)) {
      const count = attackDist[label]
      const total = events.length
      perClassMetrics[label] = {
        precision: count / total,
        recall: 1.0,
        f1: 2 * (count / total) / (1 + count / total),
      }
    }
    const results: Record<string, unknown> = {
      n_flows: events.length,
      n_threats: threatCount,
      n_benign: benignCount,
      attack_distribution: attackDist,
      per_class_metrics: perClassMetrics,
      predictions: events.map(ev => ({
        flow_id: ev.flow_id,
        src_ip: ev.src_ip,
        dst_ip: ev.dst_ip,
        label_predicted: ev.label_predicted,
        label_true: null,
        confidence: ev.confidence,
        severity: ev.severity,
        epistemic_uncertainty: 1 - ev.confidence,
        aleatoric_uncertainty: 0,
        total_uncertainty: 1 - ev.confidence,
      })),
      dataset_info: {
        total_rows: events.length,
        analysed_rows: events.length,
        sampled: false,
        format: captureMode === 'live' ? 'Live Capture' : 'File Replay',
        columns: [],
      },
    }
    setLiveResults(results, fileName || (captureMode === 'live' ? `Live Capture (${currentCycle} cycles)` : 'Live Monitor'))
    setSentToUpload(true)
  }, [analytics, events, threatCount, benignCount, captureMode, fileName, currentCycle, setLiveResults])

  // Ref to track if we already attached WS listeners on remount
  const wsAttached = useRef(false)

  // Re-attach WS listeners on remount if streaming is still running
  useEffect(() => {
    if (_wsRef && _store.running && !wsAttached.current) {
      wsAttached.current = true
      // WebSocket is still open from before navigation — re-attach handlers
      _wsRef.onmessage = (e) => {
        const data = JSON.parse(e.data)
        if (_store.captureMode === 'live') {
          if (data.status === 'error') { setCaptureStatus(`Error: ${data.message}`); setRunning(false); return }
          if (typeof data.capture_size_mb === 'number') setCaptureSizeMb(data.capture_size_mb)
          if (typeof data.max_capture_mb === 'number') setMaxCaptureMb(data.max_capture_mb)
          if (data.capture_id) setCaptureId(data.capture_id)
          if (data.status === 'limit_reached') {
            setCaptureStatus(data.message || 'Capture limit reached')
            setCaptureLimitReached(true)
            setRunning(false)
            if (data.capture_id) setTimeout(() => downloadCapture(data.capture_id), 500)
            return
          }
          if (data.status) { setCaptureStatus(data.message || data.status); if (data.cycle) setCurrentCycle(data.cycle) }
          if (data.type === 'flow') {
            const ev: FlowEvent = { flow_id: data.flow_id, src_ip: data.src_ip, dst_ip: data.dst_ip, label_predicted: data.label_predicted, confidence: data.confidence, severity: data.severity, cycle: data.cycle }
            setEvents((prev) => [ev, ...prev].slice(0, 500))
            if (ev.severity === 'benign') setBenignCount((c) => c + 1)
            else setThreatCount((c) => c + 1)
          }
        } else {
          if (data.error) { setWsError(data.error); setRunning(false); return }
          if (data.done) { setRunning(false); setDone(true); return }
          const ev = data as FlowEvent
          setEvents((prev) => [ev, ...prev].slice(0, 500))
          if (ev.severity === 'benign') setBenignCount((c) => c + 1)
          else setThreatCount((c) => c + 1)
        }
      }
      _wsRef.onclose = () => {
        setRunning(false)
        if (_store.captureMode === 'live') setCaptureStatus('Disconnected')
      }
    }
    return () => { wsAttached.current = false }
  }, [])

  // Restore file input display on remount
  const fileInputRef = useRef<HTMLInputElement | null>(null)
  useEffect(() => {
    if (_store.fileName && fileInputRef.current) {
      try {
        const dt = new DataTransfer()
        dt.items.add(new File([''], _store.fileName))
        fileInputRef.current.files = dt.files
      } catch { /* DataTransfer not supported */ }
    }
  }, [])

  const handleUpload = async (file: File) => {
    try {
      setWsError('')
      setFileName(file.name)
      const res = await uploadFile(file)
      setJobId(res.job_id)
      setEvents([]); setThreatCount(0); setBenignCount(0); setDone(false)
    } catch (e: any) {
      setWsError(e.message || 'Upload failed')
    }
  }

  const startStream = useCallback(() => {
    if (!jobId) return
    setRunning(true); setDone(false); setWsError('')
    const ws = connectStream(jobId, rate,
      (data) => {
        const ev = data as unknown as FlowEvent
        setEvents((prev) => [ev, ...prev].slice(0, 500))
        if (ev.severity === 'benign') setBenignCount((c) => c + 1)
        else setThreatCount((c) => c + 1)
      },
      () => { setRunning(false); setDone(true) },
      (err) => { setWsError(`WebSocket error: ${err instanceof Event ? 'connection failed' : err}`); setRunning(false) },
      selectedModel,
    )
    _wsRef = ws
  }, [jobId, rate, selectedModel])

  // Download captured traffic file from backend and free server storage
  const downloadCapture = useCallback(async (cid?: string) => {
    const id = cid || captureId
    if (!id) return
    try {
      const API = import.meta.env.VITE_API_URL || ''
      const token = localStorage.getItem('token')
      const res = await fetch(`${API}/api/live_capture/download/${id}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (!res.ok) return
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `robustidps_capture_${id.slice(0, 8)}_${new Date().toISOString().slice(0, 19).replace(/[:-]/g, '')}.csv`
      a.click()
      URL.revokeObjectURL(url)
      // Free server storage after download
      fetch(`${API}/api/live_capture/${id}`, {
        method: 'DELETE',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      }).catch(() => {})
    } catch {
      // Silent fail — user can still use CSV export
    }
  }, [captureId])

  const handleLiveFileUpload = async (file: File) => {
    try {
      setWsError('')
      setLiveFileLoading(true)
      setLiveFileName(file.name)
      const res = await uploadFile(file)
      setLiveFileJobId(res.job_id)
      setLiveFileLoading(false)
    } catch (e: any) {
      setWsError(e.message || 'Upload failed')
      setLiveFileLoading(false)
    }
  }

  const startLiveCapture = useCallback(() => {
    setRunning(true); setDone(false); setEvents([]); setThreatCount(0); setBenignCount(0)
    setCurrentCycle(0); setCaptureStatus('Connecting...'); setWsError('')
    setCaptureId(''); setCaptureSizeMb(0); setCaptureLimitReached(false)
    const wsUrl = `${wsBaseUrl()}/ws/live_capture`
    const ws = new WebSocket(wsUrl)
    ws.onopen = () => {
      const isFileSource = _store.liveSource === 'file'
      ws.send(JSON.stringify({
        source: isFileSource ? 'file' : 'interface',
        job_id: isFileSource ? _store.liveFileJobId : undefined,
        interface: iface,
        interval: captureInterval,
        model_names: selectedModels,
        model_name: selectedModels.length > 0 ? selectedModels[0] : '',
        capture_only: selectedModels.length === 0,
      }))
    }
    ws.onmessage = (e) => {
      const data = JSON.parse(e.data)
      if (data.status === 'error') { setCaptureStatus(`Error: ${data.message}`); setRunning(false); return }
      // Track capture size from any status message that includes it
      if (typeof data.capture_size_mb === 'number') setCaptureSizeMb(data.capture_size_mb)
      if (typeof data.max_capture_mb === 'number') setMaxCaptureMb(data.max_capture_mb)
      if (data.capture_id) setCaptureId(data.capture_id)
      // File replay done
      if (data.done) {
        setCaptureStatus(`Complete: ${data.total_flows || 0} flows processed in ${data.total_cycles || 0} cycles`)
        setRunning(false); setDone(true)
        return
      }
      // Storage limit reached — auto-stop and trigger download
      if (data.status === 'limit_reached') {
        setCaptureStatus(data.message || 'Capture limit reached')
        setCaptureLimitReached(true)
        setRunning(false)
        if (data.capture_id) {
          setTimeout(() => downloadCapture(data.capture_id), 500)
        }
        return
      }
      if (data.status) { setCaptureStatus(data.message || data.status); if (data.cycle) setCurrentCycle(data.cycle) }
      if (data.type === 'flow') {
        const ev: FlowEvent = {
          flow_id: data.flow_id, src_ip: data.src_ip, dst_ip: data.dst_ip,
          label_predicted: data.label_predicted, confidence: data.confidence,
          severity: data.severity, cycle: data.cycle, auto_blocked: data.auto_blocked,
          block_status: data.block_status, src_port: data.src_port, dst_port: data.dst_port,
          protocol: data.protocol, model_predictions: data.model_predictions,
          primary_model: data.primary_model,
        }
        setEvents((prev) => [ev, ...prev].slice(0, 500))
        if (ev.severity === 'benign') setBenignCount((c) => c + 1)
        else setThreatCount((c) => c + 1)
        if (ev.auto_blocked) setAutoBlockCount((c) => c + 1)
      }
      // Capture-only mode: raw flow data without model predictions
      if (data.type === 'raw_flow') {
        const ev: FlowEvent = {
          flow_id: data.flow_id, src_ip: data.src_ip, dst_ip: data.dst_ip,
          label_predicted: 'N/A (capture only)', confidence: 0,
          severity: 'benign', cycle: data.cycle,
          src_port: data.src_port, dst_port: data.dst_port, protocol: data.protocol,
        }
        setEvents((prev) => [ev, ...prev].slice(0, 500))
        setBenignCount((c) => c + 1)
      }
    }
    ws.onerror = () => { setWsError('WebSocket connection failed'); setRunning(false) }
    ws.onclose = () => {
      setRunning(false)
      setCaptureStatus((prev) => prev || 'Disconnected')
    }
    _wsRef = ws
  }, [iface, captureInterval, selectedModels, downloadCapture])

  const stopStream = useCallback(() => {
    _wsRef?.close(); _wsRef = null; setRunning(false)
    // Auto-download captured data when user manually stops live capture
    if (_store.captureMode === 'live' && _store.captureId && _store.captureSizeMb > 0) {
      setTimeout(() => downloadCapture(_store.captureId), 500)
    }
  }, [downloadCapture])

  const resetAll = useCallback(() => {
    // Don't auto-download on reset — user is clearing everything
    _wsRef?.close(); _wsRef = null; setRunning(false)
    setJobId(null); setFileName(''); setEvents([]); setThreatCount(0); setBenignCount(0)
    setDone(false); setCaptureStatus(''); setCurrentCycle(0); setWsError('')
    setShowAnalytics(false)
    setSentToUpload(false)
    setAutoBlockCount(0)
    setSeverityFilter('all')
    setCaptureId(''); setCaptureSizeMb(0); setCaptureLimitReached(false)
    setLiveFileJobId(null); setLiveFileName(''); setLiveFileLoading(false)
  }, [])

  // Do NOT close the WS on unmount — let it keep running while navigated away
  // Only close on explicit stop/reset

  const INSTALL_STEPS = [
    { step: '1. Clone and configure', code: 'git clone https://github.com/rogerpanel/robustidps.ai.git\ncd robustidps.ai\ncp .env.example .env\n# Edit .env: set ADMIN_EMAIL, ADMIN_PASSWORD, SECRET_KEY' },
    { step: '2. Deploy with Docker (CPU mode)', code: 'docker compose -f docker-compose.prod.yml up -d --build' },
    { step: '3. Deploy with GPU acceleration (optional)', code: '# Install NVIDIA Container Toolkit first\n# See: docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html\ndocker compose -f docker-compose.prod.yml --profile gpu up -d --build' },
    { step: '4. Enable Live Capture (network access)', code: '# Add to docker-compose.prod.yml under backend service:\n#   network_mode: host\n#   cap_add:\n#     - NET_ADMIN\n#     - NET_RAW\n# Then restart:\ndocker compose -f docker-compose.prod.yml up -d' },
    { step: '5. Verify deployment', code: 'curl -s https://your-server/api/health\n# Expected: {"status":"ok","model":"SurrogateIDS","device":"cuda"}' },
  ]

  const TEST_STEPS = [
    { title: 'Upload test dataset', desc: 'Use the included CIC-IoT-2023 or UNSW-NB15 sample data (in sample_data/) to verify the pipeline end-to-end in File Replay mode.' },
    { title: 'Capture test traffic', desc: 'Generate known-bad traffic with tools like hping3, nmap, or replay PCAPs from public datasets to validate detection accuracy.' },
    { title: 'Tune confidence thresholds', desc: 'Use the Analyse page to run MC-Dropout uncertainty analysis. Adjust the severity threshold in Firewall Rules to reduce false positives for your environment.' },
    { title: 'Enable live capture', desc: 'Once validated, switch to Live Capture mode with the appropriate network interface. Monitor the first few cycles to confirm correct traffic ingestion.' },
    { title: 'Export rules', desc: 'Use the Firewall Rules page to auto-generate iptables/nftables/Suricata/Snort rules from ML detections and integrate with your existing security stack.' },
  ]

  const DONGLE_SETUP = {
    overview: 'The Alfa AWUS036ACH (AC1200) dual-band USB 3.0 Wi-Fi adapter with 2x 5dBi external antennas can be used as a dedicated wireless capture interface for RobustIDPS.ai Live Monitor — without requiring Wireshark, TShark, or tcpdump. The platform captures traffic directly via NFStream on the adapter interface.',
    macSteps: [
      { step: '1. Install the Alfa driver (macOS High Sierra 10.13)', code: '# Download the AWUS036ACH macOS driver from Alfa\'s website:\n# https://alfa.com.tw/pages/download\n# Or use the open-source rtl8812au driver:\nbrew install --cask homebrew/cask-drivers/alfa-awus036ach\n# If using manual driver:\ncd ~/Downloads\nunzip AWUS036ACH_MacOS_*.zip\nsudo installer -pkg AWUS036ACH_*.pkg -target /' },
      { step: '2. Verify the adapter is detected', code: '# List all network interfaces — look for the Alfa adapter\nifconfig -a\n# It should appear as something like: en5 or wlan1\n# Alternatively:\nsystem_profiler SPUSBDataType | grep -A5 -i "alfa\\|realtek\\|RTL8812"' },
      { step: '3. Enable monitor mode on the adapter', code: '# Disable the interface first\nsudo ifconfig en5 down\n\n# Create a monitor mode interface\n# Method A — using Apple\'s airport utility:\nsudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport en5 sniff\n\n# Method B — if using the open-source driver with aircrack-ng:\nbrew install aircrack-ng\nsudo airmon-ng start en5\n# This creates en5mon (or similar monitor interface)' },
      { step: '4. Verify monitor mode is active', code: '# Check interface mode:\nifconfig en5mon 2>/dev/null || ifconfig en5\n# You should see the interface in UP state\n# With aircrack tools:\nsudo airmon-ng | grep -i mon' },
      { step: '5. Start RobustIDPS.ai Live Capture', code: '# In the Live Monitor page, set the Network Interface to:\n#   en5mon   (if using airmon-ng)\n#   en5      (if using airport sniff)\n# Set capture interval (e.g., 30s) and click "Start Live Capture"\n\n# Or via API/CLI:\ncurl -X POST http://localhost:8000/ws/live_capture \\\n  -H "Authorization: Bearer <your-jwt-token>" \\\n  -d \'{"interface": "en5mon", "interval": 30}\'' },
      { step: '6. (Optional) Set promiscuous mode on all interfaces', code: '# To capture ALL network traffic on ALL interfaces:\nfor iface in $(ifconfig -l); do\n  sudo ifconfig "$iface" promisc\n  echo "Promiscuous mode enabled on $iface"\ndone\n\n# Verify:\nifconfig en5 | grep -i promisc\n# Should show: PROMISC in the flags' },
    ],
    windowsSteps: [
      { step: '1. Install the Alfa driver (Windows 11, HP Envy)', code: '# Download the AWUS036ACH Windows driver:\n# https://alfa.com.tw/pages/download\n# Choose: AWUS036ACH Windows 10/11 driver\n# Run the installer as Administrator\n\n# Alternatively, use Npcap (required for packet capture):\n# Download from: https://npcap.com/#download\n# During install, CHECK "Install in WinPcap API-compatible mode"\n# and CHECK "Support raw 802.11 traffic for wireless adapters"' },
      { step: '2. Verify the adapter in Device Manager', code: '# Open PowerShell as Administrator:\nGet-NetAdapter | Format-Table Name, InterfaceDescription, Status\n\n# Or CMD:\nnetsh wlan show interfaces\n\n# Look for "Realtek 8812AU" or "ALFA" in the list\n# Note the interface name (e.g., "Wi-Fi 2" or "Wireless Network Connection 2")' },
      { step: '3. Enable monitor mode via Npcap', code: '# With Npcap installed (with raw 802.11 support):\n# The adapter automatically supports monitor mode via Npcap\n\n# Verify Npcap is installed:\nwhere npcap 2>nul || echo "Check C:\\Program Files\\Npcap"\n\n# List capture-capable interfaces:\n# PowerShell:\nGet-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select Name, InterfaceIndex' },
      { step: '4. Set up promiscuous mode', code: '# Enable promiscuous mode via PowerShell (Admin):\n$adapter = Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*Realtek 8812*"}\nSet-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*ReceiveBuffers" -RegistryValue "2048"\n\n# Or via netsh:\nnetsh wlan set profileparameter name="YourNetwork" nonBroadcast=yes\n\n# For all interfaces promiscuous mode:\nGet-NetAdapter | ForEach-Object {\n  Set-NetAdapterAdvancedProperty -Name $_.Name -AllProperties -RegistryKeyword "PromiscuousMode" -RegistryValue "1" -ErrorAction SilentlyContinue\n}' },
      { step: '5. Start RobustIDPS.ai (Docker Desktop for Windows)', code: '# Ensure Docker Desktop is running with WSL2 backend\n# In docker-compose.prod.yml, set network_mode and capabilities:\n#   backend:\n#     network_mode: host\n#     cap_add:\n#       - NET_ADMIN\n#       - NET_RAW\n\n# Find the interface name inside WSL2/Docker:\ndocker exec -it robustidps-backend bash -c "ip link show"\n# Look for the Alfa adapter (may appear as wlan1 or wlx...)\n\n# In the Live Monitor page, enter the WSL2 interface name\n# and click "Start Live Capture"' },
      { step: '6. Alternative: Direct capture without Docker', code: '# If running the backend natively on Windows:\n# Install Python 3.10+ and dependencies:\npip install nfstream\n\n# Find the correct interface name:\npython -c "from nfstream import NFStreamer; print(NFStreamer.interfaces())"\n\n# The Alfa adapter will be listed — use that name in Live Monitor\n# e.g., "\\\\Device\\\\NPF_{GUID}" or the friendly name' },
    ],
    tips: [
      'The Alfa AWUS036ACH supports both 2.4GHz and 5GHz bands — the dual-band capability means it captures traffic on both frequency ranges.',
      'The 2x 5dBi external antennas provide significantly better range than built-in laptop Wi-Fi — ideal for monitoring larger network areas.',
      'USB 3.0 connection ensures sufficient bandwidth for high-throughput capture (up to 867 Mbps on 5GHz).',
      'For enterprise deployments, position the dongle with antennas vertical and perpendicular to each other for optimal spatial diversity.',
      'In Live Monitor, set the capture interval to 10-15s for quick detection cycles, or 60-120s for deeper flow analysis per cycle.',
      'The NFStream library used by RobustIDPS.ai extracts flow-level features directly — no need for packet-level tools like Wireshark or tcpdump.',
      'For WiFi monitoring specifically, monitor mode captures ALL wireless frames in range, not just traffic to/from your machine.',
      'RobustIDPS.ai analyses flow metadata (IPs, ports, packet counts, byte counts, durations) — it works on encrypted traffic without decryption.',
    ],
  }

  // Export events as CSV
  const exportCSV = useCallback(() => {
    if (events.length === 0) return
    const header = 'flow_id,cycle,src_ip,dst_ip,label_predicted,confidence,severity,auto_blocked\n'
    const rows = events.map(ev =>
      `${ev.flow_id},${ev.cycle || ''},${ev.src_ip},${ev.dst_ip},${ev.label_predicted},${(ev.confidence * 100).toFixed(2)},${ev.severity},${ev.auto_blocked || false}`
    ).join('\n')
    const blob = new Blob([header + rows], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `robustidps_live_monitor_${new Date().toISOString().slice(0, 19).replace(/[:-]/g, '')}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }, [events])

  // Copy interface command to clipboard
  const copyToClipboard = useCallback((text: string) => {
    navigator.clipboard.writeText(text).catch(() => {})
  }, [])

  return (
    <div className="space-y-6">
      <h1 className="text-xl md:text-2xl font-display font-bold">Live Monitor</h1>

      <PageGuide
        title="How to use Live Monitor"
        steps={[
          { title: 'Choose mode', desc: 'File Replay analyses an uploaded dataset. Live Capture monitors a real network interface continuously \u2014 capturing, classifying, and repeating.' },
          { title: 'Upload or configure', desc: 'For File mode: drop a CSV (CIC-IoT-2023, CSE-CIC-IDS2018, UNSW-NB15) or PCAP. For Live mode: set the network interface and capture interval.' },
          { title: 'Press Start', desc: 'Flows stream via WebSocket in real time. Each flow is classified by the 8-model ensemble as it arrives, with per-flow confidence and severity.' },
          { title: 'Monitor threats', desc: 'Severity is colour-coded: red = critical, orange = high, amber = medium, green = low, blue = benign. Live mode runs continuously in capture\u2192analyse cycles.' },
        ]}
        tip="Tip: For PCAP files, flows are automatically extracted using NFStream. Live Capture requires the Docker container to have NET_ADMIN capability and access to the host network."
      />

      {wsError && (
        <div className="px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" /> {wsError}
        </div>
      )}

      {!jobId && !running && (
        <div className="flex gap-3">
          <button onClick={() => setCaptureMode('file')} className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${captureMode === 'file' ? 'bg-accent-blue text-white' : 'border border-bg-card text-text-secondary hover:text-text-primary'}`}>
            <Upload className="w-4 h-4" /> File Replay
          </button>
          <button onClick={() => setCaptureMode('live')} className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${captureMode === 'live' ? 'bg-accent-green text-white' : 'border border-bg-card text-text-secondary hover:text-text-primary'}`}>
            <Radio className="w-4 h-4" /> Live Capture
          </button>
        </div>
      )}

      {captureMode === 'file' && !jobId && !running && (
        <div className="max-w-lg space-y-4">
          <p className="text-sm text-text-secondary">Upload a CSV or PCAP file to start. Flows will be streamed and classified in real time.</p>
          <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
            <ModelSelector value={selectedModel} onChange={setSelectedModel} compact />
          </div>
          <FileUpload onFileSelect={handleUpload} />
        </div>
      )}

      {captureMode === 'live' && !running && (
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
          {/* Left: Capture Settings (3 cols) */}
          <div className="lg:col-span-3 bg-bg-secondary rounded-xl border border-bg-card p-5 space-y-4">
            <div className="flex items-center gap-2 mb-2">
              <Network className="w-5 h-5 text-accent-green" />
              <h3 className="text-sm font-semibold text-text-primary">Multi-Model Capture & Detection</h3>
            </div>
            <p className="text-xs text-text-secondary">Analyse traffic with the full ML ensemble. Choose a live network interface or upload a CSV/PCAP file for multi-model replay.</p>

            {/* Source selector */}
            <div>
              <label className="block text-xs text-text-secondary mb-1.5">Capture Source</label>
              <div className="flex gap-2">
                <button onClick={() => setLiveSource('interface')} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${liveSource === 'interface' ? 'bg-accent-green/20 text-accent-green border border-accent-green/40' : 'border border-bg-card text-text-secondary hover:text-text-primary'}`}>
                  <Wifi className="w-3.5 h-3.5" /> Network Interface
                </button>
                <button onClick={() => setLiveSource('file')} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${liveSource === 'file' ? 'bg-accent-blue/20 text-accent-blue border border-accent-blue/40' : 'border border-bg-card text-text-secondary hover:text-text-primary'}`}>
                  <HardDrive className="w-3.5 h-3.5" /> CSV / PCAP File
                </button>
              </div>
            </div>

            {/* Network interface settings */}
            {liveSource === 'interface' && (
              <>
                <div>
                  <label className="block text-xs text-text-secondary mb-1">Network Interface</label>
                  <input type="text" value={iface} onChange={(e) => setIface(e.target.value)} className="w-full px-3 py-2 bg-bg-primary border border-bg-card rounded-lg text-text-primary text-sm focus:outline-none focus:ring-2 focus:ring-accent-green/50" placeholder="eth0" />
                </div>
                <div>
                  <label className="block text-xs text-text-secondary mb-1">Capture Interval: {captureInterval}s</label>
                  <input type="range" min={5} max={120} step={5} value={captureInterval} onChange={(e) => setCaptureInterval(+e.target.value)} className="w-full accent-accent-green" />
                  <div className="flex justify-between text-[10px] text-text-secondary"><span>5s (fast)</span><span>120s (thorough)</span></div>
                </div>
              </>
            )}

            {/* File upload for live capture */}
            {liveSource === 'file' && (
              <div className="space-y-2">
                <FileUpload onFileSelect={handleLiveFileUpload} fileLoading={liveFileLoading} fileName={liveFileName || undefined} />
                {liveFileJobId && (
                  <div className="flex items-center gap-2 text-xs text-accent-green">
                    <CheckCircle2 className="w-3.5 h-3.5" /> File ready for multi-model analysis
                  </div>
                )}
              </div>
            )}

            {/* Active models summary before start */}
            {selectedModels.length > 0 && (
              <div className="flex items-center gap-2 flex-wrap">
                <Brain className="w-3.5 h-3.5 text-accent-blue" />
                <span className="text-[10px] text-text-secondary">Active:</span>
                {selectedModels.map((mid) => (
                  <span key={mid} className="text-[10px] px-1.5 py-0.5 rounded-full bg-accent-blue/10 text-accent-blue font-medium">
                    {mid}
                  </span>
                ))}
              </div>
            )}
            {selectedModels.length === 0 && (
              <div className="flex items-center gap-2">
                <Zap className="w-3.5 h-3.5 text-accent-amber" />
                <span className="text-[10px] text-accent-amber font-medium">Capture-only mode — no real-time inference</span>
              </div>
            )}

            <button
              onClick={startLiveCapture}
              disabled={liveSource === 'file' && !liveFileJobId}
              className="flex items-center gap-2 px-4 py-2 bg-accent-green text-white rounded-lg text-sm font-medium hover:bg-accent-green/80 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Radio className="w-4 h-4 animate-pulse" />
              {liveSource === 'file'
                ? (selectedModels.length > 0 ? 'Start Multi-Model File Analysis' : 'Start File Replay')
                : (selectedModels.length > 0 ? 'Start Live Capture & Detection' : 'Start Live Capture')
              }
            </button>
          </div>

          {/* Right: Model Selection Panel (2 cols) */}
          <div className="lg:col-span-2 bg-bg-secondary rounded-xl border border-bg-card p-4">
            <LiveCaptureModelSelector value={selectedModels} onChange={setSelectedModels} />
          </div>
        </div>
      )}

      {(jobId || running) && (<>
        <div className="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-6">
          <div className="flex items-center gap-3">
            {captureMode === 'file' && !running ? (
              <button onClick={startStream} disabled={done} className="flex items-center gap-2 px-4 py-2 bg-accent-green text-white rounded-lg text-sm font-medium hover:bg-accent-green/80 disabled:opacity-50"><Play className="w-4 h-4" /> Start</button>
            ) : running ? (
              <button onClick={stopStream} className="flex items-center gap-2 px-4 py-2 bg-accent-red text-white rounded-lg text-sm font-medium hover:bg-accent-red/80"><Pause className="w-4 h-4" /> Stop</button>
            ) : null}
            <button onClick={resetAll} className="flex items-center gap-2 px-4 py-2 border border-bg-card rounded-lg text-sm text-text-secondary hover:text-text-primary"><Upload className="w-4 h-4" /> Reset</button>
          </div>
          {captureMode === 'file' && (
            <div className="flex items-center gap-2">
              <label className="text-xs text-text-secondary">Speed: {rate} flows/sec</label>
              <input type="range" min={10} max={1000} step={10} value={rate} onChange={(e) => setRate(+e.target.value)} className="w-32 accent-accent-blue" disabled={running} />
            </div>
          )}
          {captureMode === 'file' && fileName && (
            <span className="text-xs text-text-secondary truncate max-w-[200px]" title={fileName}>{fileName}</span>
          )}
          {captureMode === 'live' && liveSource === 'file' && liveFileName && (
            <span className="text-xs text-text-secondary truncate max-w-[200px]" title={liveFileName}>{liveFileName}</span>
          )}
          {captureMode === 'live' && selectedModels.length > 0 && (
            <div className="flex items-center gap-1 flex-wrap">
              <Brain className="w-3 h-3 text-accent-blue" />
              {selectedModels.map((mid) => (
                <span key={mid} className="text-[10px] text-accent-purple bg-accent-purple/10 px-1.5 py-0.5 rounded-full">
                  {mid}
                </span>
              ))}
            </div>
          )}
          {captureMode === 'live' && selectedModels.length === 0 && (
            <span className="flex items-center gap-1 text-[10px] text-accent-amber bg-accent-amber/10 px-2 py-0.5 rounded-full">
              <Zap className="w-3 h-3" /> Capture Only
            </span>
          )}
          {captureMode === 'file' && selectedModel && selectedModel !== 'surrogate' && (
            <span className="flex items-center gap-1 text-[10px] text-accent-purple bg-accent-purple/10 px-2 py-0.5 rounded-full">
              <Brain className="w-3 h-3" /> {selectedModel}
            </span>
          )}
          {captureMode === 'live' && captureStatus && (
            <div className="flex items-center gap-2 text-xs">
              {running && <Radio className="w-3 h-3 text-accent-green animate-pulse" />}
              <span className="text-text-secondary">Cycle {currentCycle} — {captureStatus}</span>
            </div>
          )}
          <div className="flex gap-4 sm:gap-6 sm:ml-auto text-sm items-center">
            <span className="text-accent-red font-mono">Threats: {threatCount}</span>
            <span className="text-accent-blue font-mono">Benign: {benignCount}</span>
            {autoBlockCount > 0 && <span className="text-accent-orange font-mono flex items-center gap-1"><Ban className="w-3 h-3" /> Blocked: {autoBlockCount}</span>}
            <span className="text-text-secondary font-mono">Total: {threatCount + benignCount}</span>
            {events.length > 0 && (
              <button onClick={exportCSV} className="flex items-center gap-1 px-2 py-1 text-xs text-accent-blue hover:bg-accent-blue/10 rounded transition-colors" title="Export flow summary as CSV">
                <Download className="w-3 h-3" /> CSV
              </button>
            )}
            {captureMode === 'live' && captureId && captureSizeMb > 0 && !running && (
              <button onClick={() => downloadCapture()} className="flex items-center gap-1 px-2 py-1 text-xs text-accent-green hover:bg-accent-green/10 rounded transition-colors" title="Download full raw capture data">
                <HardDrive className="w-3 h-3" /> Raw
              </button>
            )}
          </div>
        </div>

        {done && captureMode === 'file' && (
          <div className="px-4 py-2 bg-accent-green/10 border border-accent-green/30 rounded-lg text-accent-green text-sm">Stream complete — all flows processed.</div>
        )}

        {/* Live capture storage progress bar */}
        {captureMode === 'live' && (captureSizeMb > 0 || running) && (
          <div className="bg-bg-secondary rounded-xl border border-bg-card p-4 space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <HardDrive className="w-4 h-4 text-accent-blue" />
                <span className="text-xs font-medium text-text-primary">Capture Storage</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs font-mono text-text-secondary">
                  {captureSizeMb.toFixed(2)} MB / {maxCaptureMb} MB
                </span>
                {!running && captureSizeMb > 0 && captureId && (
                  <button
                    onClick={() => downloadCapture()}
                    className="flex items-center gap-1 px-2 py-1 text-xs text-accent-green hover:bg-accent-green/10 rounded transition-colors"
                    title="Download captured traffic data"
                  >
                    <Download className="w-3 h-3" /> Download Capture
                  </button>
                )}
              </div>
            </div>
            <div className="w-full h-3 bg-bg-card rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-500 ${
                  captureSizeMb / maxCaptureMb > 0.9 ? 'bg-accent-red' :
                  captureSizeMb / maxCaptureMb > 0.7 ? 'bg-accent-orange' :
                  captureSizeMb / maxCaptureMb > 0.5 ? 'bg-accent-amber' :
                  'bg-accent-green'
                }`}
                style={{ width: `${Math.min(100, (captureSizeMb / maxCaptureMb) * 100)}%` }}
              />
            </div>
            <div className="flex justify-between text-[10px] text-text-secondary">
              <span>{running ? 'Capturing...' : captureLimitReached ? 'Limit reached — capture stopped' : 'Capture complete'}</span>
              <span>{Math.min(100, (captureSizeMb / maxCaptureMb) * 100).toFixed(1)}% used</span>
            </div>
          </div>
        )}

        {/* Limit reached banner */}
        {captureLimitReached && (
          <div className="px-4 py-2 bg-accent-orange/10 border border-accent-orange/30 rounded-lg text-accent-orange text-sm flex items-center gap-2">
            <HardDrive className="w-4 h-4 shrink-0" />
            Capture storage limit reached ({maxCaptureMb} MB). Capture stopped automatically. Your captured data has been downloaded.
          </div>
        )}

        {/* Severity filter bar */}
        {events.length > 0 && (
          <div className="flex items-center gap-2 flex-wrap">
            <Filter className="w-3.5 h-3.5 text-text-secondary" />
            <span className="text-xs text-text-secondary">Filter:</span>
            {['all', 'critical', 'high', 'medium', 'low', 'benign'].map(sev => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${
                  severityFilter === sev
                    ? sev === 'all' ? 'bg-accent-blue text-white' : sev === 'critical' ? 'bg-accent-red text-white' : sev === 'high' ? 'bg-accent-orange text-white' : sev === 'medium' ? 'bg-accent-amber text-white' : sev === 'low' ? 'bg-accent-green text-white' : 'bg-accent-blue text-white'
                    : 'text-text-secondary hover:text-text-primary border border-bg-card'
                }`}
              >
                {sev === 'all' ? `All (${events.length})` : `${sev} (${events.filter(e => e.severity === sev).length})`}
              </button>
            ))}
          </div>
        )}

        <div className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
          <div className="max-h-[400px] md:max-h-[600px] overflow-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-bg-secondary z-10">
                <tr className="text-text-secondary text-xs">
                  <th className="px-3 py-2 text-left">#</th>
                  {captureMode === 'live' && <th className="px-3 py-2 text-left">Cycle</th>}
                  <th className="px-3 py-2 text-left">Src IP</th>
                  <th className="px-3 py-2 text-left">Dst IP</th>
                  {captureMode === 'live' && selectedModels.length > 1 && <th className="px-3 py-2 text-left">Model</th>}
                  <th className="px-3 py-2 text-left">Label</th>
                  <th className="px-3 py-2 text-left">Confidence</th>
                  <th className="px-3 py-2 text-left">Severity</th>
                  <th className="px-3 py-2 text-left">Status</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.map((ev, i) => (
                  <tr key={`${ev.flow_id}-${ev.cycle || 0}-${i}`} className={`border-t border-bg-card/50 ${i === 0 && running ? 'animate-pulse' : ''}`}>
                    <td className="px-3 py-1.5 font-mono text-text-secondary text-xs">{ev.flow_id}</td>
                    {captureMode === 'live' && <td className="px-3 py-1.5 font-mono text-text-secondary text-xs">{ev.cycle}</td>}
                    <td className="px-3 py-1.5 font-mono text-xs">{ev.src_ip}</td>
                    <td className="px-3 py-1.5 font-mono text-xs">{ev.dst_ip}</td>
                    {captureMode === 'live' && selectedModels.length > 1 && (
                      <td className="px-3 py-1.5 text-xs">
                        {ev.model_predictions && ev.model_predictions.length > 1 ? (
                          <div className="flex flex-col gap-0.5">
                            {ev.model_predictions.map((mp) => (
                              <span key={mp.model_id} className={`text-[9px] px-1 py-0.5 rounded ${
                                mp.model_id === ev.primary_model ? 'bg-accent-blue/10 text-accent-blue font-semibold' : 'text-text-secondary'
                              }`}>
                                {mp.model_id}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span className="text-[10px] text-text-secondary">{ev.primary_model || selectedModels[0] || '—'}</span>
                        )}
                      </td>
                    )}
                    <td className="px-3 py-1.5 text-xs">
                      {ev.model_predictions && ev.model_predictions.length > 1 ? (
                        <div className="flex flex-col gap-0.5">
                          {ev.model_predictions.map((mp) => (
                            <span key={mp.model_id} className={mp.model_id === ev.primary_model ? 'font-semibold' : 'text-text-secondary'}>
                              {mp.label_predicted}
                            </span>
                          ))}
                        </div>
                      ) : ev.label_predicted}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-xs">
                      {ev.model_predictions && ev.model_predictions.length > 1 ? (
                        <div className="flex flex-col gap-0.5">
                          {ev.model_predictions.map((mp) => (
                            <span key={mp.model_id} className={mp.model_id === ev.primary_model ? 'font-semibold' : 'text-text-secondary'}>
                              {(mp.confidence * 100).toFixed(1)}%
                            </span>
                          ))}
                        </div>
                      ) : `${(ev.confidence * 100).toFixed(1)}%`}
                    </td>
                    <td className="px-3 py-1.5">
                      {ev.model_predictions && ev.model_predictions.length > 1 ? (
                        <div className="flex flex-col gap-0.5">
                          {ev.model_predictions.map((mp) => (
                            <span key={mp.model_id} className={`text-xs font-medium ${SEV_COLOR[mp.severity] || ''}`}>{mp.severity}</span>
                          ))}
                        </div>
                      ) : (
                        <span className={`text-xs font-medium ${SEV_COLOR[ev.severity] || ''}`}>{ev.severity}</span>
                      )}
                    </td>
                    <td className="px-3 py-1.5 text-xs">
                      {ev.auto_blocked ? (
                        <span className="flex items-center gap-1 text-accent-orange"><Ban className="w-3 h-3" /> Blocked</span>
                      ) : ev.severity !== 'benign' ? (
                        <span className="text-text-secondary">Detected</span>
                      ) : (
                        <span className="text-accent-blue/50">Clean</span>
                      )}
                    </td>
                  </tr>
                ))}
                {filteredEvents.length === 0 && (
                  <tr><td colSpan={captureMode === 'live' ? (selectedModels.length > 1 ? 9 : 8) : 7} className="px-3 py-8 text-center text-text-secondary text-sm">{events.length === 0 ? (captureMode === 'live' ? 'Waiting for first capture cycle...' : 'Press Start to begin streaming') : 'No events match the selected filter'}</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Analytics Panel — shows when events exist and not currently running (or done) */}
        {events.length > 0 && analytics && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <button
                onClick={() => setShowAnalytics(!showAnalytics)}
                className="flex items-center gap-2 text-sm font-semibold text-text-primary hover:text-accent-blue transition-colors"
              >
                <BarChart3 className="w-4 h-4 text-accent-blue" />
                Detection Analytics ({events.length} flows)
                {showAnalytics ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>
              <div className="flex items-center gap-2">
                {!sentToUpload ? (
                  <button
                    onClick={sendToUploadAnalyse}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-accent-blue/15 text-accent-blue rounded-lg text-xs font-medium hover:bg-accent-blue/25 transition-colors"
                  >
                    <Send className="w-3 h-3" /> Send to Upload &amp; Analyse
                  </button>
                ) : (
                  <span className="text-xs text-accent-green flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> Sent — view on Upload &amp; Analyse page
                  </span>
                )}
              </div>
            </div>

            {showAnalytics && (
              <div className="space-y-4">
                {/* Summary stats row */}
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                  <div className="bg-bg-secondary rounded-xl p-3 border border-bg-card">
                    <div className="text-[10px] text-text-secondary uppercase">Total Flows</div>
                    <div className="text-lg font-bold text-text-primary font-mono">{events.length.toLocaleString()}</div>
                  </div>
                  <div className="bg-bg-secondary rounded-xl p-3 border border-bg-card">
                    <div className="text-[10px] text-text-secondary uppercase">Threats</div>
                    <div className="text-lg font-bold text-accent-red font-mono">{threatCount.toLocaleString()}</div>
                  </div>
                  <div className="bg-bg-secondary rounded-xl p-3 border border-bg-card">
                    <div className="text-[10px] text-text-secondary uppercase">Benign</div>
                    <div className="text-lg font-bold text-accent-blue font-mono">{benignCount.toLocaleString()}</div>
                  </div>
                  <div className="bg-bg-secondary rounded-xl p-3 border border-bg-card">
                    <div className="text-[10px] text-text-secondary uppercase">Threat Rate</div>
                    <div className="text-lg font-bold text-accent-orange font-mono">
                      {events.length > 0 ? ((threatCount / events.length) * 100).toFixed(1) : '0'}%
                    </div>
                  </div>
                  <div className="bg-bg-secondary rounded-xl p-3 border border-bg-card">
                    <div className="text-[10px] text-text-secondary uppercase">Avg Confidence</div>
                    <div className="text-lg font-bold text-accent-green font-mono">{(analytics.avgConf * 100).toFixed(1)}%</div>
                  </div>
                </div>

                {/* Charts row */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Attack Distribution Pie */}
                  <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                    <h3 className="text-sm font-medium text-text-secondary mb-4 flex items-center gap-2">
                      <PieChartIcon className="w-4 h-4" /> Attack Distribution
                    </h3>
                    <ResponsiveContainer width="100%" height={280}>
                      <PieChart>
                        <Pie
                          data={analytics.attackPie}
                          dataKey="value"
                          nameKey="name"
                          cx="50%"
                          cy="50%"
                          innerRadius={55}
                          outerRadius={100}
                          paddingAngle={2}
                          stroke="none"
                        >
                          {analytics.attackPie.map((_, i) => (
                            <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={TOOLTIP_STYLE} />
                        <Legend wrapperStyle={{ fontSize: '11px', color: '#94A3B8' }} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>

                  {/* Confidence Distribution */}
                  <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                    <h3 className="text-sm font-medium text-text-secondary mb-4 flex items-center gap-2">
                      <TrendingUp className="w-4 h-4" /> Confidence Distribution
                    </h3>
                    <ResponsiveContainer width="100%" height={280}>
                      <BarChart data={analytics.confBins}>
                        <XAxis dataKey="range" tick={{ fill: '#94A3B8', fontSize: 10 }} axisLine={{ stroke: '#334155' }} />
                        <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} axisLine={{ stroke: '#334155' }} />
                        <Tooltip contentStyle={TOOLTIP_STYLE} />
                        <Bar dataKey="count" fill="#3B82F6" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Severity breakdown + Top threat sources */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Severity Breakdown */}
                  <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                    <h3 className="text-sm font-medium text-text-secondary mb-4 flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4" /> Severity Breakdown
                    </h3>
                    <ResponsiveContainer width="100%" height={200}>
                      <BarChart data={analytics.sevBar} layout="vertical" margin={{ left: 60 }}>
                        <XAxis type="number" tick={{ fill: '#94A3B8', fontSize: 10 }} axisLine={{ stroke: '#334155' }} />
                        <YAxis type="category" dataKey="name" tick={{ fill: '#94A3B8', fontSize: 10 }} axisLine={{ stroke: '#334155' }} width={55} />
                        <Tooltip contentStyle={TOOLTIP_STYLE} />
                        <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                          {analytics.sevBar.map((entry, i) => (
                            <Cell key={i} fill={entry.fill} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>

                  {/* Top Threat Source IPs */}
                  <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                    <h3 className="text-sm font-medium text-text-secondary mb-3 flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-accent-red" /> Top Threat Source IPs
                    </h3>
                    {analytics.topSrcIps.length > 0 ? (
                      <div className="space-y-1.5 max-h-[200px] overflow-auto">
                        {analytics.topSrcIps.map((item, i) => (
                          <div key={item.ip} className="flex items-center justify-between px-2.5 py-1.5 rounded bg-bg-card/50">
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] text-text-secondary font-mono w-4">{i + 1}.</span>
                              <span className="text-xs font-mono text-text-primary">{item.ip}</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <div className="w-16 h-1.5 bg-bg-card rounded-full overflow-hidden">
                                <div
                                  className="h-full bg-accent-red rounded-full"
                                  style={{ width: `${Math.min(100, (item.count / (analytics.topSrcIps[0]?.count || 1)) * 100)}%` }}
                                />
                              </div>
                              <span className="text-xs font-mono text-accent-red w-8 text-right">{item.count}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-text-secondary">No threats detected</p>
                    )}
                  </div>
                </div>

                {/* Top Targeted Destinations */}
                <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                  <h3 className="text-sm font-medium text-text-secondary mb-3 flex items-center gap-2">
                    <Network className="w-4 h-4 text-accent-blue" /> Top Destination IPs (Most Targeted)
                  </h3>
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
                    {analytics.topDstIps.map((item, i) => (
                      <div key={item.ip} className="flex items-center justify-between px-2.5 py-1.5 rounded bg-bg-card/50">
                        <span className="text-xs font-mono text-text-primary truncate">{item.ip}</span>
                        <span className="text-xs font-mono text-accent-blue ml-2">{item.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </>)}

      {/* Comparison Section */}
      <div className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
        <button onClick={() => setShowComparison(!showComparison)} className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-bg-card/30 transition-colors">
          <div className="flex items-center gap-3">
            <ShieldAlert className="w-5 h-5 text-accent-blue" />
            <div>
              <h3 className="text-sm font-semibold text-text-primary">Why RobustIDPS.ai vs Suricata &amp; Snort?</h3>
              <p className="text-xs text-text-secondary">Hybrid ML ensemble vs signature-based detection — capability comparison</p>
            </div>
          </div>
          {showComparison ? <ChevronUp className="w-4 h-4 text-text-secondary" /> : <ChevronDown className="w-4 h-4 text-text-secondary" />}
        </button>
        {showComparison && (
          <div className="px-5 pb-5 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="p-3 rounded-lg bg-accent-blue/10 border border-accent-blue/20">
                <div className="flex items-center gap-2 mb-2"><Cpu className="w-4 h-4 text-accent-blue" /><span className="text-xs font-semibold text-accent-blue">RobustIDPS.ai</span></div>
                <p className="text-[11px] text-text-secondary leading-relaxed">8-model hybrid ML ensemble with adversarial training, uncertainty quantification, and automated response. Detects zero-days, works on encrypted traffic, and provides per-flow confidence with explainable AI.</p>
              </div>
              <div className="p-3 rounded-lg bg-bg-card/50 border border-bg-card">
                <div className="flex items-center gap-2 mb-2"><Shield className="w-4 h-4 text-text-secondary" /><span className="text-xs font-semibold text-text-secondary">Suricata</span></div>
                <p className="text-[11px] text-text-secondary leading-relaxed">Open-source signature-based IDS/IPS with multi-threading and protocol analysis. Strong at known-threat detection but limited against novel attacks without rule updates.</p>
              </div>
              <div className="p-3 rounded-lg bg-bg-card/50 border border-bg-card">
                <div className="flex items-center gap-2 mb-2"><Shield className="w-4 h-4 text-text-secondary" /><span className="text-xs font-semibold text-text-secondary">Snort</span></div>
                <p className="text-[11px] text-text-secondary leading-relaxed">Industry-standard signature-based IDS by Cisco. Reliable for pattern matching against known signatures but cannot learn or adapt to new attack patterns.</p>
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead><tr className="border-b border-bg-card"><th className="px-3 py-2 text-left text-text-secondary font-medium">Capability</th><th className="px-3 py-2 text-left text-accent-blue font-semibold">RobustIDPS.ai</th><th className="px-3 py-2 text-left text-text-secondary font-medium">Suricata</th><th className="px-3 py-2 text-left text-text-secondary font-medium">Snort</th></tr></thead>
                <tbody>{COMPARISON_ROWS.map((row, i) => (<tr key={i} className="border-t border-bg-card/50"><td className="px-3 py-2 font-medium text-text-primary whitespace-nowrap">{row.feature}</td><td className="px-3 py-2 text-text-primary">{row.robustidps}</td><td className="px-3 py-2 text-text-secondary">{row.suricata}</td><td className="px-3 py-2 text-text-secondary">{row.snort}</td></tr>))}</tbody>
              </table>
            </div>
            <div className="text-[11px] text-text-secondary italic px-1">Note: RobustIDPS.ai is designed to complement, not replace, signature-based systems. The optimal deployment combines ML-based detection (for zero-days and encrypted traffic) with Suricata/Snort rules (for known threats), with RobustIDPS.ai auto-generating compatible rules from its ML detections.</div>
          </div>
        )}
      </div>

      {/* Setup Guide Section */}
      <div className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
        <button onClick={() => setShowSetup(!showSetup)} className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-bg-card/30 transition-colors">
          <div className="flex items-center gap-3">
            <Server className="w-5 h-5 text-accent-green" />
            <div>
              <h3 className="text-sm font-semibold text-text-primary">Deployment &amp; Setup Guide</h3>
              <p className="text-xs text-text-secondary">Requirements, installation, and step-by-step instructions for plugging Live Monitor into your network</p>
            </div>
          </div>
          {showSetup ? <ChevronUp className="w-4 h-4 text-text-secondary" /> : <ChevronDown className="w-4 h-4 text-text-secondary" />}
        </button>
        {showSetup && (
          <div className="px-5 pb-5 space-y-5">
            <div>
              <h4 className="flex items-center gap-2 text-xs font-semibold text-text-primary mb-3"><CheckCircle2 className="w-4 h-4 text-accent-green" /> System Requirements</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="p-3 rounded-lg bg-bg-card/50 border border-bg-card">
                  <span className="text-[11px] font-semibold text-accent-blue block mb-1">Minimum (File Replay Mode)</span>
                  <ul className="text-[11px] text-text-secondary space-y-0.5 list-disc list-inside"><li>CPU: 4 cores (x86_64)</li><li>RAM: 8 GB</li><li>Storage: 10 GB SSD</li><li>Docker 24+ &amp; Docker Compose V2</li><li>No GPU required (CPU inference supported)</li></ul>
                </div>
                <div className="p-3 rounded-lg bg-bg-card/50 border border-bg-card">
                  <span className="text-[11px] font-semibold text-accent-green block mb-1">Recommended (Live Capture + GPU)</span>
                  <ul className="text-[11px] text-text-secondary space-y-0.5 list-disc list-inside"><li>CPU: 8+ cores</li><li>RAM: 16 GB+</li><li>GPU: NVIDIA with 4GB+ VRAM (CUDA 11.8+)</li><li>Network: SPAN/mirror port or inline tap</li><li>Docker with NVIDIA Container Toolkit</li><li>libpcap-dev (for raw packet capture)</li></ul>
                </div>
              </div>
            </div>
            <div>
              <h4 className="flex items-center gap-2 text-xs font-semibold text-text-primary mb-3"><Terminal className="w-4 h-4 text-accent-blue" /> Installation Steps</h4>
              <div className="space-y-3">
                {INSTALL_STEPS.map((item, i) => (<div key={i}><span className="text-[11px] font-semibold text-text-primary">{item.step}</span><pre className="mt-1 p-2.5 bg-bg-primary rounded-lg text-[11px] text-accent-green font-mono overflow-x-auto whitespace-pre">{item.code}</pre></div>))}
              </div>
            </div>
            <div>
              <h4 className="flex items-center gap-2 text-xs font-semibold text-text-primary mb-3"><Network className="w-4 h-4 text-accent-amber" /> Network Integration Options</h4>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="p-3 rounded-lg bg-bg-card/50 border border-bg-card"><span className="text-[11px] font-semibold text-accent-blue block mb-1">Option A: SPAN / Mirror Port</span><p className="text-[11px] text-text-secondary leading-relaxed">Configure your switch to mirror traffic to the monitoring server. Best for passive monitoring with zero impact on production traffic flow.</p></div>
                <div className="p-3 rounded-lg bg-bg-card/50 border border-bg-card"><span className="text-[11px] font-semibold text-accent-amber block mb-1">Option B: Network TAP</span><p className="text-[11px] text-text-secondary leading-relaxed">Install a passive network TAP between your firewall and core switch. Provides a full copy of all traffic without any network performance impact.</p></div>
                <div className="p-3 rounded-lg bg-bg-card/50 border border-bg-card"><span className="text-[11px] font-semibold text-accent-green block mb-1">Option C: Inline (IPS Mode)</span><p className="text-[11px] text-text-secondary leading-relaxed">Deploy inline for active prevention. RobustIDPS.ai generates iptables/nftables rules from ML detections. Requires two network interfaces and careful testing.</p></div>
              </div>
            </div>
            <div>
              <h4 className="flex items-center gap-2 text-xs font-semibold text-text-primary mb-3"><Eye className="w-4 h-4 text-accent-blue" /> Testing &amp; Validation</h4>
              <ol className="space-y-2 text-[11px] text-text-secondary">
                {TEST_STEPS.map((item, i) => (<li key={i} className="flex gap-2"><span className="shrink-0 w-5 h-5 rounded-full bg-accent-blue/15 text-accent-blue flex items-center justify-center text-[10px] font-bold">{i + 1}</span><span><strong className="text-text-primary">{item.title}</strong> — {item.desc}</span></li>))}
              </ol>
            </div>
            <div className="flex items-start gap-2 p-3 bg-accent-amber/10 border border-accent-amber/20 rounded-lg">
              <AlertTriangle className="w-4 h-4 text-accent-amber shrink-0 mt-0.5" />
              <p className="text-[11px] text-text-secondary leading-relaxed"><strong className="text-text-primary">Enterprise &amp; Commercial Use:</strong> For production deployments, GPU-accelerated inference, custom model training on your organisation's traffic, SLA-backed support, and on-premises installation assistance — contact <strong className="text-accent-blue">roger@robustidps.ai</strong> for licensing and professional services options.</p>
            </div>
          </div>
        )}
      </div>

      {/* Dongle Setup Guide — Alfa AWUS036ACH */}
      <div className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
        <button onClick={() => setShowDongleGuide(!showDongleGuide)} className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-bg-card/30 transition-colors">
          <div className="flex items-center gap-3">
            <Usb className="w-5 h-5 text-accent-purple" />
            <div>
              <h3 className="text-sm font-semibold text-text-primary">Wi-Fi Dongle Setup Guide — Alfa AWUS036ACH (AC1200)</h3>
              <p className="text-xs text-text-secondary">How to set up the Alfa Long-Range Dual-Band AC1200 USB 3.0 Wi-Fi Adapter for live network monitoring — macOS &amp; Windows</p>
            </div>
          </div>
          {showDongleGuide ? <ChevronUp className="w-4 h-4 text-text-secondary" /> : <ChevronDown className="w-4 h-4 text-text-secondary" />}
        </button>
        {showDongleGuide && (
          <div className="px-5 pb-5 space-y-6">
            {/* Overview */}
            <div className="flex items-start gap-3 p-4 bg-accent-purple/10 border border-accent-purple/20 rounded-lg">
              <Wifi className="w-5 h-5 text-accent-purple shrink-0 mt-0.5" />
              <div>
                <p className="text-[11px] text-text-primary leading-relaxed font-medium mb-1">Direct Capture — No Wireshark/TShark/tcpdump Required</p>
                <p className="text-[11px] text-text-secondary leading-relaxed">{DONGLE_SETUP.overview}</p>
              </div>
            </div>

            {/* Architecture diagram */}
            <div className="p-4 bg-bg-card/50 border border-bg-card rounded-lg">
              <h4 className="text-xs font-semibold text-text-primary mb-3 flex items-center gap-2"><Layers className="w-4 h-4 text-accent-blue" /> Capture Architecture</h4>
              <div className="flex items-center justify-center gap-2 text-[10px] font-mono text-text-secondary flex-wrap">
                <span className="px-2 py-1 bg-accent-purple/15 text-accent-purple rounded border border-accent-purple/20">Alfa AWUS036ACH</span>
                <span>→</span>
                <span className="px-2 py-1 bg-accent-green/15 text-accent-green rounded border border-accent-green/20">Monitor Mode</span>
                <span>→</span>
                <span className="px-2 py-1 bg-accent-blue/15 text-accent-blue rounded border border-accent-blue/20">NFStream</span>
                <span>→</span>
                <span className="px-2 py-1 bg-accent-amber/15 text-accent-amber rounded border border-accent-amber/20">Flow Features</span>
                <span>→</span>
                <span className="px-2 py-1 bg-accent-red/15 text-accent-red rounded border border-accent-red/20">ML Ensemble (8 models)</span>
                <span>→</span>
                <span className="px-2 py-1 bg-accent-green/15 text-accent-green rounded border border-accent-green/20">Live Monitor Dashboard</span>
              </div>
              <p className="text-[10px] text-text-secondary text-center mt-2">Two capture methods: <strong>Monitor Mode</strong> (captures all wireless frames in range) and <strong>Promiscuous Mode</strong> (captures all packets on connected network interfaces)</p>
            </div>

            {/* macOS Section */}
            <div>
              <h4 className="flex items-center gap-2 text-xs font-semibold text-text-primary mb-3">
                <Monitor className="w-4 h-4 text-text-secondary" />
                macOS (High Sierra 10.13 / MacBook Pro)
              </h4>
              <div className="space-y-3">
                {DONGLE_SETUP.macSteps.map((item, i) => (
                  <div key={i}>
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-semibold text-text-primary">{item.step}</span>
                      <button onClick={() => copyToClipboard(item.code)} className="text-[10px] text-accent-blue hover:text-accent-blue/80 flex items-center gap-1">
                        <Copy className="w-3 h-3" /> Copy
                      </button>
                    </div>
                    <pre className="mt-1 p-2.5 bg-bg-primary rounded-lg text-[11px] text-accent-green font-mono overflow-x-auto whitespace-pre">{item.code}</pre>
                  </div>
                ))}
              </div>
            </div>

            {/* Windows Section */}
            <div>
              <h4 className="flex items-center gap-2 text-xs font-semibold text-text-primary mb-3">
                <Monitor className="w-4 h-4 text-accent-blue" />
                Windows 11 (HP Envy / CMD / PowerShell)
              </h4>
              <div className="space-y-3">
                {DONGLE_SETUP.windowsSteps.map((item, i) => (
                  <div key={i}>
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-semibold text-text-primary">{item.step}</span>
                      <button onClick={() => copyToClipboard(item.code)} className="text-[10px] text-accent-blue hover:text-accent-blue/80 flex items-center gap-1">
                        <Copy className="w-3 h-3" /> Copy
                      </button>
                    </div>
                    <pre className="mt-1 p-2.5 bg-bg-primary rounded-lg text-[11px] text-accent-green font-mono overflow-x-auto whitespace-pre">{item.code}</pre>
                  </div>
                ))}
              </div>
            </div>

            {/* Method comparison: Monitor Mode vs Promiscuous Mode */}
            <div>
              <h4 className="flex items-center gap-2 text-xs font-semibold text-text-primary mb-3">
                <Shield className="w-4 h-4 text-accent-amber" />
                Capture Methods: Monitor Mode vs Promiscuous Mode
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="p-3 rounded-lg bg-accent-green/5 border border-accent-green/20">
                  <span className="text-[11px] font-semibold text-accent-green block mb-2">Method A: Monitor Mode (Recommended for Wi-Fi)</span>
                  <ul className="text-[11px] text-text-secondary space-y-1 list-disc list-inside">
                    <li>Captures <strong>all wireless frames</strong> in range (not just your network)</li>
                    <li>Uses <code className="text-accent-green">airmon-ng start &lt;iface&gt;</code> or Apple&apos;s airport utility</li>
                    <li>Equivalent to the Airodump-ng sniffing approach from your previous research</li>
                    <li>Ideal for wireless security auditing and rogue AP detection</li>
                    <li>The Alfa AWUS036ACH&apos;s 5dBi antennas provide 2-3x range vs built-in WiFi</li>
                    <li>Works with RobustIDPS.ai: enter the monitor interface (e.g., <code className="text-accent-green">wlan1mon</code>) in Live Capture</li>
                  </ul>
                </div>
                <div className="p-3 rounded-lg bg-accent-blue/5 border border-accent-blue/20">
                  <span className="text-[11px] font-semibold text-accent-blue block mb-2">Method B: Promiscuous Mode (All Interfaces)</span>
                  <ul className="text-[11px] text-text-secondary space-y-1 list-disc list-inside">
                    <li>Captures all packets on a connected network (not just addressed to your MAC)</li>
                    <li>Uses <code className="text-accent-blue">ifconfig &lt;iface&gt; promisc</code> (macOS/Linux) or adapter settings (Windows)</li>
                    <li>Works on both wired and wireless interfaces</li>
                    <li>Requires being connected to the target network</li>
                    <li>Best for monitoring specific LAN segments or switched networks with SPAN ports</li>
                    <li>Works with RobustIDPS.ai: enter the interface (e.g., <code className="text-accent-blue">en0</code>, <code className="text-accent-blue">eth0</code>) in Live Capture</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* Quick reference table */}
            <div>
              <h4 className="flex items-center gap-2 text-xs font-semibold text-text-primary mb-3">
                <Clock className="w-4 h-4 text-accent-blue" />
                Quick Reference: Interface Names for Live Monitor
              </h4>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead><tr className="border-b border-bg-card"><th className="px-3 py-2 text-left text-text-secondary font-medium">OS</th><th className="px-3 py-2 text-left text-text-secondary font-medium">Capture Method</th><th className="px-3 py-2 text-left text-text-secondary font-medium">Interface to Enter</th><th className="px-3 py-2 text-left text-text-secondary font-medium">Setup Command</th></tr></thead>
                  <tbody>
                    <tr className="border-t border-bg-card/50"><td className="px-3 py-2 text-text-primary">macOS</td><td className="px-3 py-2">Monitor (airmon-ng)</td><td className="px-3 py-2 font-mono text-accent-green">en5mon</td><td className="px-3 py-2 font-mono text-accent-green text-[10px]">sudo airmon-ng start en5</td></tr>
                    <tr className="border-t border-bg-card/50"><td className="px-3 py-2 text-text-primary">macOS</td><td className="px-3 py-2">Monitor (airport)</td><td className="px-3 py-2 font-mono text-accent-green">en5</td><td className="px-3 py-2 font-mono text-accent-green text-[10px]">sudo airport en5 sniff</td></tr>
                    <tr className="border-t border-bg-card/50"><td className="px-3 py-2 text-text-primary">macOS</td><td className="px-3 py-2">Promiscuous</td><td className="px-3 py-2 font-mono text-accent-blue">en5</td><td className="px-3 py-2 font-mono text-accent-blue text-[10px]">sudo ifconfig en5 promisc</td></tr>
                    <tr className="border-t border-bg-card/50"><td className="px-3 py-2 text-text-primary">Windows</td><td className="px-3 py-2">Monitor (Npcap)</td><td className="px-3 py-2 font-mono text-accent-green">Wi-Fi 2</td><td className="px-3 py-2 font-mono text-accent-green text-[10px]">Install Npcap with raw 802.11 support</td></tr>
                    <tr className="border-t border-bg-card/50"><td className="px-3 py-2 text-text-primary">Windows</td><td className="px-3 py-2">Promiscuous</td><td className="px-3 py-2 font-mono text-accent-blue">Wi-Fi 2</td><td className="px-3 py-2 font-mono text-accent-blue text-[10px]">Set-NetAdapterAdvancedProperty</td></tr>
                    <tr className="border-t border-bg-card/50"><td className="px-3 py-2 text-text-primary">Linux/Docker</td><td className="px-3 py-2">Monitor</td><td className="px-3 py-2 font-mono text-accent-green">wlan1mon</td><td className="px-3 py-2 font-mono text-accent-green text-[10px]">sudo airmon-ng start wlan1</td></tr>
                    <tr className="border-t border-bg-card/50"><td className="px-3 py-2 text-text-primary">Linux/Docker</td><td className="px-3 py-2">Promiscuous</td><td className="px-3 py-2 font-mono text-accent-blue">wlan1</td><td className="px-3 py-2 font-mono text-accent-blue text-[10px]">sudo ip link set wlan1 promisc on</td></tr>
                  </tbody>
                </table>
              </div>
            </div>

            {/* Tips */}
            <div>
              <h4 className="flex items-center gap-2 text-xs font-semibold text-text-primary mb-3">
                <Wifi className="w-4 h-4 text-accent-purple" /> Tips &amp; Best Practices
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {DONGLE_SETUP.tips.map((tip, i) => (
                  <div key={i} className="flex items-start gap-2 p-2.5 rounded-lg bg-bg-card/50">
                    <CheckCircle2 className="w-3.5 h-3.5 text-accent-purple shrink-0 mt-0.5" />
                    <span className="text-[11px] text-text-secondary leading-relaxed">{tip}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex items-start gap-2 p-3 bg-accent-purple/10 border border-accent-purple/20 rounded-lg">
              <Lock className="w-4 h-4 text-accent-purple shrink-0 mt-0.5" />
              <p className="text-[11px] text-text-secondary leading-relaxed"><strong className="text-text-primary">Security Note:</strong> Monitor mode captures all wireless frames within range, including frames from other networks. Only use this capability on networks you own or have explicit authorisation to monitor. Unauthorised wireless interception may violate local laws. RobustIDPS.ai analyses flow metadata — it does not decrypt or store payload content.</p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
