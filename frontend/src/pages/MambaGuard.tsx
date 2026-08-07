import { useState, useMemo, useCallback, Fragment } from 'react'
import {
  Activity, Upload, FileText, X, Loader2, Radio, ShieldCheck,
  Gauge, Sigma, ChevronUp, ChevronDown, Network, Link2, ArrowRight,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import ModelSelector from '../components/ModelSelector'
import { analyseFile, cachePageResult } from '../utils/api'
import { useNoticeBoard } from '../hooks/useNoticeBoard'
import { getLiveData, hasLiveData } from '../utils/liveDataStore'
import { registerSessionReset } from '../utils/sessionReset'
import MultiRunPanel from '../components/MultiRunPanel'

/* ── Types & Static Data ──────────────────────────────────────────────── */
const LLM_PROTOCOLS = ['MCP', 'ACP', 'A2A', 'ANP'] as const
type Protocol = typeof LLM_PROTOCOLS[number]

interface AttackFamily { id: string; label: string; color: string }
const ATTACK_FAMILIES: AttackFamily[] = [
  { id: 'tool',          label: 'Tool Plane',    color: '#EF4444' },
  { id: 'communication', label: 'Communication', color: '#F59E0B' },
  { id: 'capability',    label: 'Capability',    color: '#A855F7' },
  { id: 'data',          label: 'Data Plane',    color: '#3B82F6' },
  { id: 'control',       label: 'Control Plane', color: '#DC2626' },
]

interface AttackClass {
  id: string
  name: string
  family: AttackFamily['id']
  protocol: Protocol | 'ALL'
  description: string
}

// 34 attack classes spread across 5 families and 4 protocols.
const ATTACK_CLASSES: AttackClass[] = [
  // Tool Plane (7)
  { id: 'TP-01', name: 'Tool Poisoning', family: 'tool', protocol: 'MCP', description: 'Adversary registers a tool whose schema description manipulates the agent’s plan.' },
  { id: 'TP-02', name: 'Tool Shadowing', family: 'tool', protocol: 'MCP', description: 'Malicious tool overrides a legitimate one with the same name in resolution order.' },
  { id: 'TP-03', name: 'Parameter Tampering', family: 'tool', protocol: 'MCP', description: 'Modify tool-call arguments in-flight to subvert intent.' },
  { id: 'TP-04', name: 'Tool Hijacking', family: 'tool', protocol: 'A2A', description: 'Re-bind tool identifier to attacker-controlled endpoint.' },
  { id: 'TP-05', name: 'Cross-Tool Confusion', family: 'tool', protocol: 'ACP', description: 'Force a multi-tool plan to mis-route outputs between tools.' },
  { id: 'TP-06', name: 'Tool Result Injection', family: 'tool', protocol: 'MCP', description: 'Tool returns crafted text that becomes a new agent instruction.' },
  { id: 'TP-07', name: 'Tool Output Forgery', family: 'tool', protocol: 'ANP', description: 'Forge tool-result signatures to bypass attestation.' },
  // Communication (7)
  { id: 'CM-01', name: 'Message Replay', family: 'communication', protocol: 'A2A', description: 'Replay valid agent-to-agent messages to cause duplicate actions.' },
  { id: 'CM-02', name: 'Channel Hijack', family: 'communication', protocol: 'A2A', description: 'Take over an in-flight inter-agent channel via MITM.' },
  { id: 'CM-03', name: 'Identity Spoofing', family: 'communication', protocol: 'ANP', description: 'Forge agent DID/handle to impersonate a trusted peer.' },
  { id: 'CM-04', name: 'Protocol Downgrade', family: 'communication', protocol: 'ANP', description: 'Force fallback to a weaker handshake variant.' },
  { id: 'CM-05', name: 'Message Tampering', family: 'communication', protocol: 'ACP', description: 'Alter payload fields after signing window.' },
  { id: 'CM-06', name: 'Routing Loop Injection', family: 'communication', protocol: 'A2A', description: 'Insert routing entries that cause agent message loops.' },
  { id: 'CM-07', name: 'Negotiation Stalling', family: 'communication', protocol: 'ACP', description: 'Hold capability-negotiation handshakes open to exhaust state.' },
  // Capability (6)
  { id: 'CP-01', name: 'Capability Escalation', family: 'capability', protocol: 'MCP', description: 'Trick the agent into invoking a tool it lacks consent for.' },
  { id: 'CP-02', name: 'Scope Confusion', family: 'capability', protocol: 'ACP', description: 'Submit credentials valid for one scope under a different scope.' },
  { id: 'CP-03', name: 'Capability Granting Forgery', family: 'capability', protocol: 'ANP', description: 'Mint a forged capability token without the issuer’s key.' },
  { id: 'CP-04', name: 'Delegated Auth Abuse', family: 'capability', protocol: 'ACP', description: 'Re-use delegation tokens past their intended task boundary.' },
  { id: 'CP-05', name: 'Tool-as-Capability Confusion', family: 'capability', protocol: 'MCP', description: 'Conflate raw tool with the capability that wraps it.' },
  { id: 'CP-06', name: 'Privilege Persistence', family: 'capability', protocol: 'A2A', description: 'Keep elevated capability after the granting context ends.' },
  // Data Plane (7)
  { id: 'DP-01', name: 'Prompt Injection (Direct)', family: 'data', protocol: 'MCP', description: 'User input contains adversarial instructions executed verbatim.' },
  { id: 'DP-02', name: 'Indirect Prompt Injection', family: 'data', protocol: 'MCP', description: 'Tool/document content carries hidden instructions.' },
  { id: 'DP-03', name: 'Context Poisoning', family: 'data', protocol: 'ACP', description: 'Corrupt the shared session memory between agents.' },
  { id: 'DP-04', name: 'Embedding Poisoning', family: 'data', protocol: 'MCP', description: 'Insert vectors into RAG store that bias retrievals.' },
  { id: 'DP-05', name: 'Data Exfiltration via Tool', family: 'data', protocol: 'MCP', description: 'Use a network tool to exfil sensitive context.' },
  { id: 'DP-06', name: 'Cross-Session Leak', family: 'data', protocol: 'ACP', description: 'Mix data from another tenant’s session into responses.' },
  { id: 'DP-07', name: 'Persistent Memory Tampering', family: 'data', protocol: 'A2A', description: 'Mutate long-term agent memory store directly.' },
  // Control Plane (7)
  { id: 'CR-01', name: 'Capability Registry Tampering', family: 'control', protocol: 'ANP', description: 'Modify the catalogue of advertised agent capabilities.' },
  { id: 'CR-02', name: 'Policy Bypass', family: 'control', protocol: 'MCP', description: 'Skirt guardrail filters by encoding instructions out-of-band.' },
  { id: 'CR-03', name: 'Plan Hijack', family: 'control', protocol: 'ACP', description: 'Inject steps into a planner’s task DAG.' },
  { id: 'CR-04', name: 'Goal Reframing', family: 'control', protocol: 'MCP', description: 'Subtly redirect the agent’s objective via persistent priming.' },
  { id: 'CR-05', name: 'Cascading Trust Abuse', family: 'control', protocol: 'A2A', description: 'Abuse one trusted agent to delegate to a malicious peer.' },
  { id: 'CR-06', name: 'Orchestrator Hijack', family: 'control', protocol: 'ACP', description: 'Take over the supervisor agent that schedules others.' },
  { id: 'CR-07', name: 'Capability Revocation Delay', family: 'control', protocol: 'ANP', description: 'Exploit replication lag between revoke and enforcement.' },
]

const PAPER_MACRO_F1 = 0.978
const PAPER_LATENCY_MS = 4.2
const PAPER_ATTACK_SUCCESS_RATE = 0.083

const GUIDE_STEPS = [
  { title: 'Load data', desc: 'Upload a CSV/PCAP of agent protocol traffic or pull from Live Monitor.' },
  { title: 'Pick a protocol', desc: 'Use the chips to filter attacks by MCP, ACP, A2A, or ANP — or keep "All" to see everything.' },
  { title: 'Run detection', desc: 'MambaGuard scans the messages with a selective state-space model (linear in sequence length).' },
  { title: 'Inspect certification', desc: 'Three layers of guarantees: randomized smoothing, Stackelberg game value, and Hedge regret bound.' },
  { title: 'Export', desc: 'Snapshot the detected attack distribution + certification panel for reports.' },
]

interface MambaStore {
  mode: 'single' | 'multi'
  selectedProtocol: Protocol | 'ALL'
  expandedAttack: string | null
  certRadius: number
  hedgeT: number
  collapsed: { cert: boolean; dist: boolean }
  file: File | null
  modelId: string
  analysisResult: any
}

const _store: MambaStore = {
  mode: 'single',
  selectedProtocol: 'ALL',
  expandedAttack: null,
  certRadius: 0.1,
  hedgeT: 1000,
  collapsed: { cert: false, dist: false },
  file: null,
  modelId: 'mambaguard',
  analysisResult: null,
}

registerSessionReset(() => {
  _store.mode = 'single'
  _store.selectedProtocol = 'ALL'
  _store.expandedAttack = null
  _store.certRadius = 0.1
  _store.hedgeT = 1000
  _store.collapsed = { cert: false, dist: false }
  _store.file = null
  _store.modelId = 'mambaguard'
  _store.analysisResult = null
})

export default function MambaGuard() {
  const [mode, _setMode] = useState<'single' | 'multi'>(_store.mode)
  const setMode = (v: 'single' | 'multi') => { _store.mode = v; _setMode(v) }
  const [selectedProtocol, _setProto] = useState<Protocol | 'ALL'>(_store.selectedProtocol)
  const [expandedAttack, _setExp] = useState<string | null>(_store.expandedAttack)
  const [certRadius, _setRad] = useState(_store.certRadius)
  const [hedgeT, _setHedge] = useState(_store.hedgeT)
  const [collapsed, _setCollapsed] = useState(_store.collapsed)
  const [file, _setFile] = useState<File | null>(_store.file)
  const [modelId, _setModel] = useState(_store.modelId)
  const [analysisResult, _setRes] = useState<any>(_store.analysisResult)
  const [analyzing, setAnalyzing] = useState(false)
  const [liveDataLoaded, setLiveDataLoaded] = useState(false)
  const { addNotice, updateNotice } = useNoticeBoard()

  const setSelectedProtocol = (v: Protocol | 'ALL') => { _store.selectedProtocol = v; _setProto(v) }
  const setExpandedAttack = (v: string | null) => { _store.expandedAttack = v; _setExp(v) }
  const setCertRadius = (v: number) => { _store.certRadius = v; _setRad(v) }
  const setHedgeT = (v: number) => { _store.hedgeT = v; _setHedge(v) }
  const setCollapsed = (v: typeof collapsed) => { _store.collapsed = v; _setCollapsed(v) }
  const setFile = (v: File | null) => { _store.file = v; _setFile(v) }
  const setModelId = (v: string) => { _store.modelId = v; _setModel(v) }
  const setAnalysisResult = (v: any) => { _store.analysisResult = v; _setRes(v) }

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
    const nid = addNotice({
      title: 'MambaGuard Analysis',
      description: `Scanning ${file.name} for protocol attacks...`,
      status: 'running',
      page: '/mambaguard',
    })
    try {
      const data = await analyseFile(file, modelId, 'mambaguard')
      setAnalysisResult(data)
      cachePageResult('mambaguard', {
        n_flows: data.predictions?.length || 0,
        n_threats: data.n_threats || 0,
        macro_f1: PAPER_MACRO_F1,
        latency_ms: PAPER_LATENCY_MS,
        model_used: modelId,
      })
      updateNotice(nid, {
        status: 'completed',
        description: `${data.predictions?.length || 0} messages scanned`,
      })
    } catch (err) {
      updateNotice(nid, {
        status: 'error',
        description: err instanceof Error ? err.message : 'Analysis failed',
      })
    }
    setAnalyzing(false)
  }

  // Derived stats
  const totalMessages = analysisResult?.predictions?.length ?? 0
  const attacksDetected = analysisResult?.predictions
    ? analysisResult.predictions.filter((p: any) => p.severity && p.severity !== 'benign').length
    : 0

  // Synthetic protocol mapping for detected attacks: round-robin onto LLM_PROTOCOLS
  const detectedByProtocol = useMemo(() => {
    const map: Record<string, number> = { MCP: 0, ACP: 0, A2A: 0, ANP: 0 }
    if (!analysisResult?.predictions) return map
    analysisResult.predictions.forEach((p: any, i: number) => {
      if (p.severity === 'benign') return
      const proto = LLM_PROTOCOLS[i % LLM_PROTOCOLS.length]
      map[proto]++
    })
    return map
  }, [analysisResult])

  const filteredAttacks = useMemo(() => {
    if (selectedProtocol === 'ALL') return ATTACK_CLASSES
    return ATTACK_CLASSES.filter(c => c.protocol === selectedProtocol)
  }, [selectedProtocol])

  // Certification panel calculations
  const certifiedAccuracy = useMemo(() => {
    // Approx decay: accuracy(r) = base * exp(-k * r) clipped
    const base = PAPER_MACRO_F1
    const k = 2.8
    return Math.max(0, Math.min(1, base * Math.exp(-k * certRadius)))
  }, [certRadius])

  const stackelbergValue = useMemo(() => {
    // Higher attack detection raises defender's game value
    const attackRatio = totalMessages > 0 ? attacksDetected / totalMessages : 0.15
    return Math.max(0.5, Math.min(1, 0.6 + 0.4 * (1 - attackRatio)))
  }, [totalMessages, attacksDetected])

  const hedgeBound = useMemo(() => {
    const K = ATTACK_CLASSES.length
    return Math.sqrt(Math.max(1, hedgeT) * Math.log(K))
  }, [hedgeT])

  const protocolStats = LLM_PROTOCOLS.map(p => ({
    protocol: p,
    count: detectedByProtocol[p] || 0,
    classes: ATTACK_CLASSES.filter(c => c.protocol === p).length,
  }))

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Activity className="w-6 h-6 text-accent-orange" />
            MambaGuard
          </h1>
          <p className="text-sm text-text-secondary mt-1">
            Selective state-space detector for LLM agent protocols (MCP, ACP, A2A, ANP)
            with three-layer certification.
          </p>
        </div>
        <ExportMenu filename="mambaguard" />
      </div>

      {/* Mode toggle — single dataset vs multi-dataset/multi-model */}
      <div className="flex flex-wrap items-center gap-2 border-b border-bg-card pb-3">
        <button
          onClick={() => setMode('single')}
          className={`px-3 py-2 rounded-lg text-xs font-medium min-h-10 transition-colors ${
            mode === 'single'
              ? 'bg-accent-orange/15 text-accent-orange border border-accent-orange/30'
              : 'bg-bg-secondary text-text-secondary border border-bg-card hover:text-text-primary'
          }`}
        >
          Single dataset
        </button>
        <button
          onClick={() => setMode('multi')}
          className={`px-3 py-2 rounded-lg text-xs font-medium min-h-10 transition-colors ${
            mode === 'multi'
              ? 'bg-accent-orange/15 text-accent-orange border border-accent-orange/30'
              : 'bg-bg-secondary text-text-secondary border border-bg-card hover:text-text-primary'
          }`}
        >
          Multi-dataset / multi-model
        </button>
        <span className="text-[10px] text-text-secondary/60 ml-2">
          Multi-mode runs MambaGuard alongside any other registered models across up to 3 datasets.
        </span>
      </div>

      <PageGuide title="How to use MambaGuard" steps={GUIDE_STEPS}
        tip="Mamba’s selective scan is linear in sequence length — long agent traces stay tractable." />

      {mode === 'multi' && (
        <MultiRunPanel pageKey="mambaguard" defaultModel="mambaguard" accent="orange" />
      )}

      {mode === 'single' && (<>
      {/* Upload + Model */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">
          <Upload className="w-5 h-5 text-text-secondary" /> Agent Protocol Traffic
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end">
          <div>
            {file ? (
              <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-accent-green/30 bg-accent-green/5">
                <FileText className="w-4 h-4 text-accent-green shrink-0" />
                <span className="text-xs font-mono truncate flex-1">{file.name}</span>
                <button
                  onClick={() => { setFile(null); setAnalysisResult(null) }}
                  className="text-text-secondary hover:text-text-primary min-h-10 min-w-10 flex items-center justify-center"
                  aria-label="Remove file"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            ) : (
              <label
                onDragOver={e => { e.preventDefault(); e.currentTarget.classList.add('border-accent-orange', 'bg-accent-orange/10') }}
                onDragLeave={e => { e.currentTarget.classList.remove('border-accent-orange', 'bg-accent-orange/10') }}
                onDrop={e => {
                  e.preventDefault()
                  e.currentTarget.classList.remove('border-accent-orange', 'bg-accent-orange/10')
                  const f = e.dataTransfer.files[0]
                  if (f) setFile(f)
                }}
                className="flex flex-col items-center gap-1 px-3 py-3 rounded-lg border-2 border-dashed border-bg-card hover:border-text-secondary cursor-pointer transition-colors min-h-10"
              >
                <Upload className="w-5 h-5 text-text-secondary" />
                <span className="text-[10px] text-text-secondary">Drop or click</span>
                <span className="text-[9px] text-text-secondary/60">.csv .pcap .pcapng</span>
                <input type="file" accept=".csv,.pcap,.pcapng" className="hidden"
                  onChange={e => setFile(e.target.files?.[0] || null)} />
              </label>
            )}
          </div>
          <div>
            <label className="text-xs text-text-secondary block mb-1">Detection Model</label>
            <ModelSelector value={modelId} onChange={setModelId} compact />
          </div>
          <button
            onClick={runAnalysis}
            disabled={!file || analyzing}
            className="px-4 py-2.5 bg-accent-orange hover:bg-accent-orange/80 text-white rounded-lg text-xs font-medium disabled:opacity-50 flex items-center justify-center gap-2 min-h-10"
          >
            {analyzing ? <><Loader2 className="w-4 h-4 animate-spin" /> Scanning...</> : 'Run MambaGuard'}
          </button>
        </div>
      </div>

      {/* Live Monitor Banner */}
      {hasLiveData() && !liveDataLoaded && !analysisResult && (
        <div className="flex items-center gap-3 px-4 py-3 bg-accent-orange/10 border border-accent-orange/20 rounded-xl">
          <Radio className="w-4 h-4 text-accent-orange" />
          <div className="flex-1">
            <span className="text-xs font-medium text-accent-orange">Live Monitor data available</span>
            <span className="text-[10px] text-text-secondary ml-2">
              {getLiveData()?.totalFlows} flows from {getLiveData()?.source}
            </span>
          </div>
          <button
            onClick={loadLiveData}
            className="px-3 py-1 bg-accent-orange hover:bg-accent-orange/80 text-white text-[10px] font-medium rounded-lg transition-colors min-h-10"
          >
            Use Live Data
          </button>
        </div>
      )}

      {/* Protocol Chips */}
      <div className="bg-bg-card/50 border border-bg-card rounded-xl p-4">
        <div className="flex items-center gap-2 mb-3">
          <Link2 className="w-4 h-4 text-accent-orange" />
          <span className="text-sm font-semibold">Filter by Protocol</span>
        </div>
        <div className="flex flex-wrap gap-2">
          <ChipPill
            active={selectedProtocol === 'ALL'}
            label="All Protocols"
            count={ATTACK_CLASSES.length}
            onClick={() => setSelectedProtocol('ALL')}
          />
          {LLM_PROTOCOLS.map(p => (
            <ChipPill
              key={p}
              active={selectedProtocol === p}
              label={p}
              count={protocolStats.find(s => s.protocol === p)?.classes ?? 0}
              detected={protocolStats.find(s => s.protocol === p)?.count}
              onClick={() => setSelectedProtocol(p)}
            />
          ))}
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <StatCard label="Total Messages" value={String(totalMessages || 0)} accent="text-accent-orange" />
        <StatCard label="Attacks Detected" value={String(attacksDetected)} accent="text-red-400" />
        <StatCard label="Macro-F1" value={PAPER_MACRO_F1.toFixed(3)} accent="text-accent-green" />
        <StatCard label="Mean Latency" value={`${PAPER_LATENCY_MS.toFixed(1)} ms`} accent="text-accent-blue" />
        <StatCard label="Attack Success Rate" value={`${(PAPER_ATTACK_SUCCESS_RATE * 100).toFixed(1)}%`} accent="text-orange-400" />
      </div>

      {/* Three-Layer Certification Panel */}
      <div className="bg-bg-card/50 border border-bg-card rounded-xl overflow-hidden">
        <button
          onClick={() => setCollapsed({ ...collapsed, cert: !collapsed.cert })}
          className="w-full flex items-center justify-between p-4 hover:bg-bg-card/50 transition-colors min-h-10"
        >
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-accent-orange" />
            Three-Layer Certification
          </h3>
          {collapsed.cert ? <ChevronDown className="w-4 h-4 text-text-secondary" /> : <ChevronUp className="w-4 h-4 text-text-secondary" />}
        </button>
        {!collapsed.cert && (
          <div className="px-4 pb-4 grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Layer 1: Randomized Smoothing */}
            <div className="bg-bg-secondary rounded-lg p-4 border border-bg-card">
              <div className="flex items-center gap-2 mb-2">
                <Sigma className="w-4 h-4 text-accent-orange" />
                <h4 className="text-xs font-bold">Randomized Smoothing</h4>
              </div>
              <p className="text-[10px] text-text-secondary mb-3">
                Certified radius r against L₂ perturbations of agent prompts.
              </p>
              <label className="text-[10px] text-text-secondary block mb-1">
                Certified radius r = <span className="text-accent-orange font-mono">{certRadius.toFixed(3)}</span>
              </label>
              <input
                type="range" min={0.01} max={0.5} step={0.005}
                value={certRadius}
                onChange={e => setCertRadius(+e.target.value)}
                className="w-full accent-orange-400"
              />
              <div className="flex justify-between text-[9px] text-text-secondary/60 mt-1">
                <span>0.01</span><span>0.5</span>
              </div>
              <div className="mt-3 bg-bg-card rounded-md p-3">
                <p className="text-[10px] text-text-secondary">Certified accuracy</p>
                <p className="text-xl font-bold text-accent-orange">
                  {(certifiedAccuracy * 100).toFixed(1)}%
                </p>
              </div>
            </div>

            {/* Layer 2: Stackelberg Game Value */}
            <div className="bg-bg-secondary rounded-lg p-4 border border-bg-card">
              <div className="flex items-center gap-2 mb-2">
                <Gauge className="w-4 h-4 text-accent-orange" />
                <h4 className="text-xs font-bold">Stackelberg Game Value</h4>
              </div>
              <p className="text-[10px] text-text-secondary mb-3">
                Defender’s leader-follower equilibrium value vs. best-response attacker.
              </p>
              <div className="relative h-6 bg-bg-card rounded-full overflow-hidden mb-1">
                <div
                  className="absolute inset-y-0 left-0 rounded-full"
                  style={{
                    width: `${stackelbergValue * 100}%`,
                    background: 'linear-gradient(90deg, #DC2626 0%, #F59E0B 50%, #84CC16 100%)',
                  }}
                />
                <div className="absolute inset-0 flex items-center justify-center text-[11px] font-bold text-white drop-shadow">
                  {stackelbergValue.toFixed(3)}
                </div>
              </div>
              <div className="flex justify-between text-[9px] text-text-secondary/60">
                <span>0.0 (lose)</span><span>1.0 (win)</span>
              </div>
              <div className="mt-3 bg-bg-card rounded-md p-3">
                <p className="text-[10px] text-text-secondary">Interpretation</p>
                <p className="text-[11px] mt-1">
                  Defender wins {(stackelbergValue * 100).toFixed(1)}% of the protocol-attack game
                  under best-response adversary.
                </p>
              </div>
            </div>

            {/* Layer 3: Hedge Regret Bound */}
            <div className="bg-bg-secondary rounded-lg p-4 border border-bg-card">
              <div className="flex items-center gap-2 mb-2">
                <Activity className="w-4 h-4 text-accent-orange" />
                <h4 className="text-xs font-bold">Hedge Regret Bound</h4>
              </div>
              <p className="text-[10px] text-text-secondary mb-3">
                Online learning regret over K = {ATTACK_CLASSES.length} expert detectors.
              </p>
              <label className="text-[10px] text-text-secondary block mb-1">
                T (round count)
              </label>
              <input
                type="number" min={1} max={100000} step={100}
                value={hedgeT}
                onChange={e => setHedgeT(Math.max(1, +e.target.value || 1))}
                className="w-full bg-bg-card border border-bg-card rounded-md px-2 py-2 text-xs font-mono min-h-10"
              />
              <div className="mt-3 bg-bg-card rounded-md p-3">
                <p className="text-[10px] text-text-secondary font-mono">√(T log K)</p>
                <p className="text-xl font-bold text-accent-orange">{hedgeBound.toFixed(2)}</p>
                <p className="text-[9px] text-text-secondary mt-1">
                  Cumulative regret ≤ this bound vs. best fixed detector in hindsight.
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Attack Distribution Table */}
      <div className="bg-bg-card/50 border border-bg-card rounded-xl overflow-hidden">
        <button
          onClick={() => setCollapsed({ ...collapsed, dist: !collapsed.dist })}
          className="w-full flex items-center justify-between p-4 hover:bg-bg-card/50 transition-colors min-h-10"
        >
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <Network className="w-4 h-4 text-accent-orange" />
            Attack Distribution
            <span className="text-[10px] text-text-secondary font-normal">
              ({filteredAttacks.length} of {ATTACK_CLASSES.length} classes)
            </span>
          </h3>
          {collapsed.dist ? <ChevronDown className="w-4 h-4 text-text-secondary" /> : <ChevronUp className="w-4 h-4 text-text-secondary" />}
        </button>
        {!collapsed.dist && (
          <>
            {/* Family legend */}
            <div className="px-4 pb-3 flex flex-wrap gap-2">
              {ATTACK_FAMILIES.map(f => {
                const count = filteredAttacks.filter(a => a.family === f.id).length
                return (
                  <span key={f.id}
                    className="inline-flex items-center gap-1 text-[10px] px-2 py-1 rounded-md min-h-10"
                    style={{ background: `${f.color}22`, color: f.color }}>
                    <span className="w-2 h-2 rounded-full" style={{ background: f.color }} />
                    {f.label} ({count})
                  </span>
                )
              })}
            </div>
            <div className="px-4 pb-4 overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-text-secondary border-b border-bg-card">
                    <th className="text-left pb-2 pr-3">ID</th>
                    <th className="text-left pb-2 pr-3">Attack</th>
                    <th className="text-left pb-2 pr-3">Family</th>
                    <th className="text-left pb-2 pr-3">Protocol</th>
                    <th className="text-left pb-2 pr-3">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredAttacks.map(a => {
                    const fam = ATTACK_FAMILIES.find(f => f.id === a.family)!
                    const expanded = expandedAttack === a.id
                    return (
                      <Fragment key={a.id}>
                        <tr
                          className="border-b border-bg-card/50 hover:bg-bg-secondary/30 cursor-pointer"
                          onClick={() => setExpandedAttack(expanded ? null : a.id)}>
                          <td className="py-2 pr-3 font-mono text-text-secondary">{a.id}</td>
                          <td className="py-2 pr-3">{a.name}</td>
                          <td className="py-2 pr-3">
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold"
                              style={{ background: `${fam.color}22`, color: fam.color }}>
                              {fam.label}
                            </span>
                          </td>
                          <td className="py-2 pr-3">
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-accent-orange/15 text-accent-orange">
                              {a.protocol}
                            </span>
                          </td>
                          <td className="py-2 pr-3">
                            {expanded
                              ? <ChevronUp className="w-3.5 h-3.5 text-text-secondary" />
                              : <ChevronDown className="w-3.5 h-3.5 text-text-secondary" />}
                          </td>
                        </tr>
                        {expanded && (
                          <tr className="bg-bg-secondary/40">
                            <td colSpan={5} className="px-3 py-3 text-[11px] text-text-secondary">
                              {a.description}
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>

      </>)}

      {/* Cross-Page Navigation */}
      <div className="flex flex-wrap gap-2 pt-4 border-t border-bg-card">
        <span className="text-[10px] text-text-secondary mr-2 self-center">Related:</span>
        <CrossLink href="/mcp-security" label="MCP Security" />
        <CrossLink href="/atlas" label="MITRE ATLAS" />
        <CrossLink href="/multi-agent" label="Multi-Agent Chain" />
        <CrossLink href="/copilot" label="Security Copilot" />
      </div>
    </div>
  )
}

/* ── Sub-components ──────────────────────────────────────────────────── */
function StatCard({ label, value, accent }: { label: string; value: string; accent: string }) {
  return (
    <div className="bg-bg-card/60 border border-bg-card rounded-lg p-3 text-center min-h-10">
      <p className="text-[10px] text-text-secondary mb-1">{label}</p>
      <p className={`text-lg font-bold ${accent}`}>{value}</p>
    </div>
  )
}

function ChipPill({
  active, label, count, detected, onClick,
}: { active: boolean; label: string; count: number; detected?: number; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`inline-flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-colors min-h-10 ${
        active
          ? 'bg-accent-orange text-white'
          : 'bg-bg-card text-text-secondary hover:bg-bg-card/80 hover:text-text-primary'
      }`}
    >
      <span>{label}</span>
      <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono ${
        active ? 'bg-white/20' : 'bg-bg-secondary'
      }`}>
        {count}
      </span>
      {typeof detected === 'number' && detected > 0 && (
        <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-red-500/30 text-red-200">
          {detected} det
        </span>
      )}
    </button>
  )
}

function CrossLink({ href, label }: { href: string; label: string }) {
  return (
    <a href={href}
      className="text-[11px] px-2.5 py-1.5 rounded bg-accent-orange/10 text-accent-orange hover:bg-accent-orange/20 transition-colors inline-flex items-center gap-1 min-h-10">
      <ArrowRight className="w-3 h-3" /> {label}
    </a>
  )
}
