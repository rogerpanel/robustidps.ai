import { useCallback, useEffect, useRef, useState } from 'react'
import { Play, Pause, Upload, Radio, Shield, ShieldAlert, Cpu, Eye, Server, Terminal, ChevronDown, ChevronUp, Network, CheckCircle2, AlertTriangle } from 'lucide-react'
import FileUpload from '../components/FileUpload'
import PageGuide from '../components/PageGuide'
import { uploadFile, connectStream } from '../utils/api'

interface FlowEvent {
  flow_id: number
  src_ip: string
  dst_ip: string
  label_predicted: string
  confidence: number
  severity: string
  cycle?: number
}

const SEV_COLOR: Record<string, string> = {
  benign: 'text-accent-blue',
  low: 'text-accent-green',
  medium: 'text-accent-amber',
  high: 'text-accent-orange',
  critical: 'text-accent-red',
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
}

// Keep the WebSocket ref at module level so it survives remount
let _wsRef: WebSocket | null = null

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
    )
    _wsRef = ws
  }, [jobId, rate])

  const startLiveCapture = useCallback(() => {
    setRunning(true); setDone(false); setEvents([]); setThreatCount(0); setBenignCount(0)
    setCurrentCycle(0); setCaptureStatus('Connecting...'); setWsError('')
    const wsUrl = `${wsBaseUrl()}/ws/live_capture`
    const ws = new WebSocket(wsUrl)
    ws.onopen = () => { ws.send(JSON.stringify({ interface: iface, interval: captureInterval })) }
    ws.onmessage = (e) => {
      const data = JSON.parse(e.data)
      if (data.status === 'error') { setCaptureStatus(`Error: ${data.message}`); setRunning(false); return }
      if (data.status) { setCaptureStatus(data.message || data.status); if (data.cycle) setCurrentCycle(data.cycle) }
      if (data.type === 'flow') {
        const ev: FlowEvent = { flow_id: data.flow_id, src_ip: data.src_ip, dst_ip: data.dst_ip, label_predicted: data.label_predicted, confidence: data.confidence, severity: data.severity, cycle: data.cycle }
        setEvents((prev) => [ev, ...prev].slice(0, 500))
        if (ev.severity === 'benign') setBenignCount((c) => c + 1)
        else setThreatCount((c) => c + 1)
      }
    }
    ws.onerror = () => { setWsError('WebSocket connection failed'); setRunning(false) }
    ws.onclose = () => { setRunning(false); setCaptureStatus('Disconnected') }
    _wsRef = ws
  }, [iface, captureInterval])

  const stopStream = useCallback(() => { _wsRef?.close(); _wsRef = null; setRunning(false) }, [])

  const resetAll = useCallback(() => {
    stopStream()
    setJobId(null); setFileName(''); setEvents([]); setThreatCount(0); setBenignCount(0)
    setDone(false); setCaptureStatus(''); setCurrentCycle(0); setWsError('')
  }, [stopStream])

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
        <div className="max-w-lg">
          <p className="text-sm text-text-secondary mb-4">Upload a CSV or PCAP file to start. Flows will be streamed and classified in real time.</p>
          <FileUpload onFileSelect={handleUpload} />
        </div>
      )}

      {captureMode === 'live' && !running && (
        <div className="bg-bg-secondary rounded-xl border border-bg-card p-5 max-w-lg space-y-4">
          <div className="flex items-center gap-2 mb-2">
            <Network className="w-5 h-5 text-accent-green" />
            <h3 className="text-sm font-semibold text-text-primary">Continuous Network Capture</h3>
          </div>
          <p className="text-xs text-text-secondary">Captures live traffic on a network interface, analyses flows with the ML ensemble, then repeats — providing continuous real-time intrusion detection and prevention.</p>
          <div>
            <label className="block text-xs text-text-secondary mb-1">Network Interface</label>
            <input type="text" value={iface} onChange={(e) => setIface(e.target.value)} className="w-full px-3 py-2 bg-bg-primary border border-bg-card rounded-lg text-text-primary text-sm focus:outline-none focus:ring-2 focus:ring-accent-green/50" placeholder="eth0" />
          </div>
          <div>
            <label className="block text-xs text-text-secondary mb-1">Capture Interval: {captureInterval}s</label>
            <input type="range" min={5} max={120} step={5} value={captureInterval} onChange={(e) => setCaptureInterval(+e.target.value)} className="w-full accent-accent-green" />
            <div className="flex justify-between text-[10px] text-text-secondary"><span>5s (fast)</span><span>120s (thorough)</span></div>
          </div>
          <button onClick={startLiveCapture} className="flex items-center gap-2 px-4 py-2 bg-accent-green text-white rounded-lg text-sm font-medium hover:bg-accent-green/80">
            <Radio className="w-4 h-4 animate-pulse" /> Start Live Capture
          </button>
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
          {captureMode === 'live' && captureStatus && (
            <div className="flex items-center gap-2 text-xs">
              {running && <Radio className="w-3 h-3 text-accent-green animate-pulse" />}
              <span className="text-text-secondary">Cycle {currentCycle} — {captureStatus}</span>
            </div>
          )}
          <div className="flex gap-4 sm:gap-6 sm:ml-auto text-sm">
            <span className="text-accent-red font-mono">Threats: {threatCount}</span>
            <span className="text-accent-blue font-mono">Benign: {benignCount}</span>
            <span className="text-text-secondary font-mono">Total: {threatCount + benignCount}</span>
          </div>
        </div>

        {done && captureMode === 'file' && (
          <div className="px-4 py-2 bg-accent-green/10 border border-accent-green/30 rounded-lg text-accent-green text-sm">Stream complete — all flows processed.</div>
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
                  <th className="px-3 py-2 text-left">Label</th>
                  <th className="px-3 py-2 text-left">Confidence</th>
                  <th className="px-3 py-2 text-left">Severity</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev, i) => (
                  <tr key={`${ev.flow_id}-${ev.cycle || 0}-${i}`} className={`border-t border-bg-card/50 ${i === 0 && running ? 'animate-pulse' : ''}`}>
                    <td className="px-3 py-1.5 font-mono text-text-secondary text-xs">{ev.flow_id}</td>
                    {captureMode === 'live' && <td className="px-3 py-1.5 font-mono text-text-secondary text-xs">{ev.cycle}</td>}
                    <td className="px-3 py-1.5 font-mono text-xs">{ev.src_ip}</td>
                    <td className="px-3 py-1.5 font-mono text-xs">{ev.dst_ip}</td>
                    <td className="px-3 py-1.5 text-xs">{ev.label_predicted}</td>
                    <td className="px-3 py-1.5 font-mono text-xs">{(ev.confidence * 100).toFixed(1)}%</td>
                    <td className="px-3 py-1.5"><span className={`text-xs font-medium ${SEV_COLOR[ev.severity] || ''}`}>{ev.severity}</span></td>
                  </tr>
                ))}
                {events.length === 0 && (
                  <tr><td colSpan={captureMode === 'live' ? 7 : 6} className="px-3 py-8 text-center text-text-secondary text-sm">{captureMode === 'live' ? 'Waiting for first capture cycle...' : 'Press Start to begin streaming'}</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
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
    </div>
  )
}
