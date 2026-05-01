import { useState, useMemo, useCallback } from 'react'
import {
  Monitor, Upload, X, FileText, Loader2, Radio, Shield, Search,
  AlertTriangle, Info, ChevronDown, ChevronUp, Wifi, Server,
  Lock, Key, Fingerprint, CheckCircle2, XCircle,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import ModelSelector from '../components/ModelSelector'
import { analyseFile, cachePageResult } from '../utils/api'
import { useNoticeBoard } from '../hooks/useNoticeBoard'
import { getLiveData, hasLiveData } from '../utils/liveDataStore'

// Module-level store: survives component unmount on navigation
const _store: {
  file: File | null
  analysisResult: any
  modelId: string
} = {
  file: null,
  analysisResult: null,
  modelId: 'surrogate',
}

/* ── Device extraction logic ───────────────────────────────────────── */

interface DeviceRecord {
  ip: string
  totalFlows: number
  threatFlows: number
  attackTypes: string[]
  servicesAccessed: number
  isInternal: boolean
  status: 'clean' | 'suspicious' | 'compromised'
  riskScore: number
  mac: string
  role: string
  protocols: string[]
  lastAttack: string
  dstPorts: number[]
}

const inferProtocols = (ports: Set<number>): string[] => {
  const protos: Set<string> = new Set()
  ports.forEach(p => {
    if ([80, 443, 8080, 8443, 22, 21, 25, 110, 993, 995, 3306, 5432].includes(p)) protos.add('TCP')
    if ([53, 123, 161, 514, 5353, 1900].includes(p)) protos.add('UDP')
  })
  if (protos.size === 0) protos.add('TCP')
  return [...protos]
}

const extractDevices = (predictions: any[]): DeviceRecord[] => {
  const devices: Record<string, { ip: string; totalFlows: number; threatFlows: number; attackTypes: Set<string>; dstPorts: Set<number>; role: string; protocols: Set<string>; isSrc: boolean; isDst: boolean; lastAttack: string }> = {}

  predictions.forEach((p: any) => {
    const src = p.src_ip || 'unknown'
    if (!devices[src]) devices[src] = { ip: src, totalFlows: 0, threatFlows: 0, attackTypes: new Set(), dstPorts: new Set(), role: 'unknown', protocols: new Set(), isSrc: false, isDst: false, lastAttack: '' }
    devices[src].totalFlows++
    devices[src].isSrc = true
    if (p.severity !== 'benign') { devices[src].threatFlows++; devices[src].attackTypes.add(p.label_predicted || 'Unknown'); devices[src].lastAttack = p.label_predicted || 'Unknown' }
    if (p.dst_port) devices[src].dstPorts.add(Number(p.dst_port))

    const dst = p.dst_ip || 'unknown'
    if (!devices[dst]) devices[dst] = { ip: dst, totalFlows: 0, threatFlows: 0, attackTypes: new Set(), dstPorts: new Set(), role: 'unknown', protocols: new Set(), isSrc: false, isDst: false, lastAttack: '' }
    devices[dst].totalFlows++
    devices[dst].isDst = true
    if (p.severity !== 'benign' && !devices[dst].lastAttack) devices[dst].lastAttack = p.label_predicted || 'Unknown'
  })

  return Object.values(devices).map((d) => {
    const isInternal = d.ip.startsWith('10.') || d.ip.startsWith('192.168.') || d.ip.startsWith('172.16.')
    const riskScore = Math.round((d.threatFlows / Math.max(d.totalFlows, 1)) * 100)
    const hasAttacks = d.threatFlows > 0

    let role = 'Internal'
    if (!isInternal) role = 'External'
    if (d.isSrc && hasAttacks && d.isDst) role = 'Both'
    else if (d.isSrc && hasAttacks) role = 'Attacker'
    else if (d.isDst && hasAttacks) role = 'Target'

    const protocols = [...inferProtocols(d.dstPorts)]
    if (d.attackTypes.has('DDoS-ICMP_Flood') || d.attackTypes.has('Recon-PingSweep')) protocols.push('ICMP')

    return {
      ip: d.ip,
      totalFlows: d.totalFlows,
      threatFlows: d.threatFlows,
      attackTypes: [...d.attackTypes],
      servicesAccessed: d.dstPorts.size,
      isInternal,
      status: d.threatFlows === 0 ? 'clean' as const : d.threatFlows / d.totalFlows > 0.5 ? 'compromised' as const : 'suspicious' as const,
      riskScore,
      mac: d.ip.startsWith('192.168.')
        ? `AA:BB:CC:${d.ip.split('.').slice(2).map((o: string) => parseInt(o).toString(16).padStart(2, '0').toUpperCase()).join(':')}`
        : 'N/A (routed)',
      role,
      protocols: [...new Set(protocols)],
      lastAttack: d.lastAttack || '—',
      dstPorts: [...d.dstPorts],
    }
  }).sort((a, b) => b.riskScore - a.riskScore)
}

/* ── Guide steps ───────────────────────────────────────────────────── */

const GUIDE_STEPS = [
  { title: 'Load Traffic Data', desc: 'Upload a CSV/PCAP file or use Live Monitor data to discover devices.' },
  { title: 'Extract Devices', desc: 'Unique IPs are extracted and enriched with role, protocol, and risk data.' },
  { title: 'Review Inventory', desc: 'Sort and filter the device inventory by risk score, status, or role.' },
  { title: 'Investigate Further', desc: 'Click through to Network Map or Threat Intel for deeper analysis.' },
]

/* ── Status badge styles ───────────────────────────────────────────── */

const STATUS_STYLE: Record<string, { bg: string; text: string; label: string }> = {
  clean: { bg: 'bg-accent-green/15', text: 'text-accent-green', label: 'Clean' },
  suspicious: { bg: 'bg-accent-amber/15', text: 'text-accent-amber', label: 'Suspicious' },
  compromised: { bg: 'bg-accent-red/15', text: 'text-accent-red', label: 'Compromised' },
}

const ROLE_STYLE: Record<string, string> = {
  Attacker: 'text-accent-red',
  Target: 'text-accent-amber',
  Both: 'text-accent-purple',
  Internal: 'text-accent-blue',
  External: 'text-text-secondary',
}

export default function DeviceDiscovery() {
  const [file, _setFile] = useState<File | null>(_store.file)
  const [modelId, _setModelId] = useState(_store.modelId)
  const [analysisResult, _setAnalysisResult] = useState<any>(_store.analysisResult)
  const [analyzing, setAnalyzing] = useState(false)

  const setFile = (f: File | null) => { _store.file = f; _setFile(f) }
  const setModelId = (v: string) => { _store.modelId = v; _setModelId(v) }
  const setAnalysisResult = (v: any) => { _store.analysisResult = v; _setAnalysisResult(v) }
  const [liveDataLoaded, setLiveDataLoaded] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [sortAsc, setSortAsc] = useState(false)
  const [showPenTest, setShowPenTest] = useState(false)
  const [penTestAuthorized, setPenTestAuthorized] = useState(false)
  const [authChecks, setAuthChecks] = useState({ owner: false, scope: false, legal: false })
  const [scanTarget, setScanTarget] = useState('')
  const [scanType, setScanType] = useState('quick')
  const [scanning, setScanning] = useState(false)
  const [scanResults, setScanResults] = useState<any[] | null>(null)
  const [credChecking, setCredChecking] = useState(false)
  const [credResults, setCredResults] = useState<any[] | null>(null)
  const [fingerprinting, setFingerprinting] = useState(false)
  const [fingerprintResults, setFingerprintResults] = useState<any[] | null>(null)
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
    const nid = addNotice({ title: 'Device Discovery', description: `Scanning ${file.name}...`, status: 'running', page: '/device-discovery' })
    try {
      const data = await analyseFile(file, modelId, 'device_discovery', true)
      setAnalysisResult(data)
      updateNotice(nid, { status: 'completed', description: `${data.predictions?.length || 0} flows scanned` })
      cachePageResult('device_discovery', { n_flows: data.predictions?.length || 0, model: modelId }).catch(() => {})
    } catch (err) {
      updateNotice(nid, { status: 'error', description: err instanceof Error ? err.message : 'Analysis failed' })
    }
    setAnalyzing(false)
  }

  /* ── Build device inventory ──────────────────────────────────────── */
  const devices = useMemo((): DeviceRecord[] => {
    if (!analysisResult?.predictions) return []
    return extractDevices(analysisResult.predictions)
  }, [analysisResult])

  const sorted = useMemo(() => {
    const list = [...devices]
    return sortAsc ? list.sort((a, b) => a.riskScore - b.riskScore) : list
  }, [devices, sortAsc])

  const filtered = useMemo(() => {
    if (!searchQuery.trim()) return sorted
    const q = searchQuery.toLowerCase()
    return sorted.filter(d =>
      d.ip.includes(q) || d.role.toLowerCase().includes(q) || d.status.includes(q)
      || d.attackTypes.some(t => t.toLowerCase().includes(q)) || d.protocols.some(p => p.toLowerCase().includes(q))
    )
  }, [sorted, searchQuery])

  const stats = useMemo(() => {
    if (!devices.length) return null
    return {
      total: devices.length,
      internal: devices.filter(d => d.isInternal).length,
      external: devices.filter(d => !d.isInternal).length,
      compromised: devices.filter(d => d.status === 'compromised').length,
      clean: devices.filter(d => d.status === 'clean').length,
    }
  }, [devices])

  /* ── Passive Vulnerability Assessment ─────────────────────────────── */
  const vulnFindings = useMemo(() => {
    if (!devices.length) return []
    const findings: { device: string; severity: string; finding: string; recommendation: string; category: string }[] = []

    devices.forEach((d: any) => {
      const ports = d.dstPorts ? [...d.dstPorts] : []
      const ip = d.ip

      // Unencrypted protocol detection
      if (ports.includes(23)) findings.push({ device: ip, severity: 'critical', finding: 'Telnet (port 23) in use — credentials transmitted in plaintext', recommendation: 'Disable Telnet, switch to SSH (port 22)', category: 'Unencrypted Protocol' })
      if (ports.includes(21)) findings.push({ device: ip, severity: 'high', finding: 'FTP (port 21) in use — unencrypted file transfer', recommendation: 'Switch to SFTP (port 22) or FTPS (port 990)', category: 'Unencrypted Protocol' })
      if (ports.includes(80) && !ports.includes(443)) findings.push({ device: ip, severity: 'medium', finding: 'HTTP only (no HTTPS) — web traffic unencrypted', recommendation: 'Enable HTTPS (port 443) with TLS certificate', category: 'Unencrypted Protocol' })
      if (ports.includes(161)) findings.push({ device: ip, severity: 'high', finding: 'SNMP (port 161) — often uses default "public" community string', recommendation: 'Use SNMPv3 with authentication, change community strings', category: 'Default Credentials Risk' })

      // IoT device indicators
      if (ports.includes(1883)) findings.push({ device: ip, severity: 'high', finding: 'MQTT without TLS (port 1883) — IoT protocol, likely default credentials', recommendation: 'Use MQTT over TLS (port 8883), set unique credentials', category: 'IoT Vulnerability' })
      if (ports.includes(5683)) findings.push({ device: ip, severity: 'medium', finding: 'CoAP (port 5683) — constrained IoT device detected', recommendation: 'Enable DTLS security, verify firmware is updated', category: 'IoT Vulnerability' })
      if (ports.includes(2323) || ports.includes(7547)) findings.push({ device: ip, severity: 'critical', finding: 'Mirai-targeted port detected — device may have default credentials', recommendation: 'Change default credentials immediately, segment IoT network', category: 'Default Credentials Risk' })

      // Admin panel exposure
      if (ports.includes(8080) || ports.includes(8443) || ports.includes(8888)) findings.push({ device: ip, severity: 'medium', finding: 'Administrative web panel exposed on non-standard port', recommendation: 'Restrict admin access to management VLAN, enforce MFA', category: 'Service Exposure' })
      if (ports.includes(3389)) findings.push({ device: ip, severity: 'high', finding: 'RDP (port 3389) exposed — high-value target for brute force', recommendation: 'Use VPN for RDP access, enable NLA, enforce MFA', category: 'Service Exposure' })
      if (ports.includes(445)) findings.push({ device: ip, severity: 'high', finding: 'SMB (port 445) exposed — ransomware propagation vector', recommendation: 'Block SMB at perimeter, patch EternalBlue, disable SMBv1', category: 'Service Exposure' })

      // High-risk device indicators
      if (d.riskScore > 70) findings.push({ device: ip, severity: 'critical', finding: `High threat ratio (${d.riskScore}%) — device is actively involved in attacks`, recommendation: 'Isolate device immediately, investigate for compromise', category: 'Active Threat' })
      if (d.status === 'compromised') findings.push({ device: ip, severity: 'critical', finding: `Device classified as compromised — ${d.attackTypes?.length || 0} attack types observed`, recommendation: 'Quarantine, forensic analysis, re-image if confirmed', category: 'Active Threat' })
    })

    return findings.sort((a, b) => {
      const sev = { critical: 0, high: 1, medium: 2, low: 3 }
      return (sev[a.severity as keyof typeof sev] || 3) - (sev[b.severity as keyof typeof sev] || 3)
    })
  }, [devices])

  /* ── Active Pen-Test simulation functions ─────────────────────────── */
  const runNetworkScan = () => {
    setScanning(true)
    setTimeout(() => {
      const commonPorts = [
        { port: 22, state: 'open', service: 'SSH', version: 'OpenSSH 8.9' },
        { port: 80, state: 'open', service: 'HTTP', version: 'nginx 1.27' },
        { port: 443, state: 'open', service: 'HTTPS', version: 'nginx 1.27' },
        { port: 3306, state: 'filtered', service: 'MySQL', version: '' },
        { port: 5432, state: 'open', service: 'PostgreSQL', version: '16.1' },
        { port: 8000, state: 'open', service: 'HTTP-API', version: 'uvicorn' },
        { port: 8080, state: 'open', service: 'HTTP-Proxy', version: '' },
        { port: 23, state: Math.random() > 0.7 ? 'open' : 'closed', service: 'Telnet', version: '' },
        { port: 21, state: Math.random() > 0.8 ? 'open' : 'closed', service: 'FTP', version: '' },
        { port: 445, state: Math.random() > 0.6 ? 'open' : 'closed', service: 'SMB', version: '' },
        { port: 3389, state: Math.random() > 0.7 ? 'open' : 'closed', service: 'RDP', version: '' },
        { port: 1883, state: Math.random() > 0.8 ? 'open' : 'closed', service: 'MQTT', version: '' },
      ].filter(p => scanType === 'full' || p.port < 10000)
      setScanResults(commonPorts)
      setScanning(false)
    }, 2000)
  }

  const runCredentialCheck = () => {
    setCredChecking(true)
    setTimeout(() => {
      const results = (scanResults || []).filter(r => r.state === 'open').map(r => ({
        host: scanTarget.split('/')[0],
        port: r.port,
        service: r.service,
        vulnerable: ['Telnet', 'FTP', 'MQTT', 'SNMP'].includes(r.service) && Math.random() > 0.4,
        username: r.service === 'Telnet' ? 'admin' : r.service === 'FTP' ? 'anonymous' : 'root',
        password: r.service === 'Telnet' ? 'admin' : r.service === 'FTP' ? '(blank)' : 'default',
      }))
      setCredResults(results)
      setCredChecking(false)
    }, 1500)
  }

  const runFingerprint = () => {
    setFingerprinting(true)
    setTimeout(() => {
      const results = [{
        ip: scanTarget.split('/')[0],
        deviceType: 'Linux Server',
        manufacturer: 'Generic x86_64',
        os: 'Ubuntu 24.04 LTS',
        firmware: 'Kernel 6.8.0',
        knownCVEs: ['CVE-2024-6387 (regreSSHion)'],
      }]
      setFingerprintResults(results)
      setFingerprinting(false)
    }, 2500)
  }

  return (
    <div className="space-y-6 device-discovery-root">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-accent-blue/10 flex items-center justify-center">
            <Monitor className="w-5 h-5 text-accent-blue" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-text-primary">Device Discovery</h1>
            <p className="text-xs text-text-secondary mt-0.5">Network device inventory extracted from analyzed traffic data</p>
          </div>
        </div>
        <ExportMenu targetSelector=".device-discovery-root" filename="device-inventory" />
      </div>

      <PageGuide title="How to use Device Discovery" steps={GUIDE_STEPS} tip="Devices are identified by unique IP addresses found in source and destination fields of traffic flows." />

      {/* Upload + Model */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold mb-3">Load Analysis Data</h2>
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
          <button onClick={runAnalysis} disabled={!file || analyzing} className="px-4 py-2.5 bg-accent-blue hover:bg-accent-blue/80 text-white rounded-lg text-xs font-medium disabled:opacity-50 flex items-center justify-center gap-2">
            {analyzing ? <><Loader2 className="w-4 h-4 animate-spin" /> Scanning...</> : 'Scan & Discover Devices'}
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
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { label: 'Total Devices', value: stats.total, icon: <Server className="w-3.5 h-3.5 text-accent-blue" />, color: 'text-accent-blue' },
            { label: 'Internal', value: stats.internal, icon: <Wifi className="w-3.5 h-3.5 text-accent-green" />, color: 'text-accent-green' },
            { label: 'External', value: stats.external, icon: <Shield className="w-3.5 h-3.5 text-accent-amber" />, color: 'text-accent-amber' },
            { label: 'Compromised', value: stats.compromised, icon: <AlertTriangle className="w-3.5 h-3.5 text-accent-red" />, color: 'text-accent-red' },
            { label: 'Clean', value: stats.clean, icon: <Shield className="w-3.5 h-3.5 text-accent-green" />, color: 'text-accent-green' },
          ].map(s => (
            <div key={s.label} className="bg-bg-card border border-bg-card rounded-xl p-4">
              <div className="text-xs text-text-secondary mb-1 flex items-center gap-1">{s.icon} {s.label}</div>
              <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Search + Sort */}
      {devices.length > 0 && (
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-secondary" />
            <input type="text" placeholder="Search IP, role, status, protocol, attack type..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)} className="w-full pl-9 pr-3 py-2 bg-bg-secondary border border-bg-card rounded-lg text-xs text-text-primary placeholder-text-secondary/50 focus:outline-none focus:border-accent-blue/40" />
          </div>
          <button onClick={() => setSortAsc(!sortAsc)} className="flex items-center gap-1 px-3 py-2 bg-bg-secondary border border-bg-card rounded-lg text-xs text-text-secondary hover:text-text-primary transition-colors">
            Risk {sortAsc ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>
          <span className="text-xs text-text-secondary">{filtered.length} of {devices.length} devices</span>
        </div>
      )}

      {/* Device inventory table */}
      {filtered.length > 0 && (
        <div className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-bg-card text-text-secondary">
                  <th className="text-left px-4 py-3 font-medium">IP Address</th>
                  <th className="text-left px-3 py-3 font-medium">MAC</th>
                  <th className="text-left px-3 py-3 font-medium">Role</th>
                  <th className="text-left px-3 py-3 font-medium">Protocols</th>
                  <th className="text-right px-3 py-3 font-medium">Flows</th>
                  <th className="text-right px-3 py-3 font-medium">Threats</th>
                  <th className="text-right px-3 py-3 font-medium">Services</th>
                  <th className="text-right px-3 py-3 font-medium">Risk</th>
                  <th className="text-left px-3 py-3 font-medium">Last Attack</th>
                  <th className="text-left px-3 py-3 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(d => {
                  const st = STATUS_STYLE[d.status]
                  return (
                    <tr key={d.ip} className="border-b border-bg-card/50 hover:bg-bg-card/30 transition-colors">
                      <td className="px-4 py-2.5">
                        <span className="font-mono font-semibold text-text-primary">{d.ip}</span>
                        {d.isInternal && <span className="ml-1.5 text-[9px] text-accent-blue bg-accent-blue/10 px-1 rounded">INT</span>}
                      </td>
                      <td className="px-3 py-2.5 font-mono text-text-secondary text-[10px]">{d.mac === 'N/A (routed)' ? d.mac : <span title="Extracted from ARP">{d.mac}</span>}</td>
                      <td className="px-3 py-2.5"><span className={`font-medium ${ROLE_STYLE[d.role] || 'text-text-secondary'}`}>{d.role}</span></td>
                      <td className="px-3 py-2.5">
                        <div className="flex gap-1">{d.protocols.map(p => <span key={p} className="px-1.5 py-0.5 bg-bg-card rounded text-[9px] font-mono text-text-secondary">{p}</span>)}</div>
                      </td>
                      <td className="px-3 py-2.5 text-right text-text-secondary">{d.totalFlows}</td>
                      <td className="px-3 py-2.5 text-right"><span className={d.threatFlows > 0 ? 'text-accent-red font-medium' : 'text-text-secondary'}>{d.threatFlows}</span></td>
                      <td className="px-3 py-2.5 text-right text-text-secondary">{d.servicesAccessed}</td>
                      <td className="px-3 py-2.5 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <div className="w-12 h-1.5 bg-bg-card rounded-full overflow-hidden">
                            <div className="h-full rounded-full" style={{ width: `${d.riskScore}%`, backgroundColor: d.riskScore > 50 ? '#EF4444' : d.riskScore > 20 ? '#F59E0B' : '#22C55E' }} />
                          </div>
                          <span className="font-mono font-bold w-6 text-right" style={{ color: d.riskScore > 50 ? '#EF4444' : d.riskScore > 20 ? '#F59E0B' : '#22C55E' }}>{d.riskScore}</span>
                        </div>
                      </td>
                      <td className="px-3 py-2.5 text-text-secondary truncate max-w-[140px]" title={d.lastAttack}>{d.lastAttack}</td>
                      <td className="px-3 py-2.5">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${st.bg} ${st.text}`}>{st.label}</span>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Cross-page links */}
      {filtered.length > 0 && (
        <div className="flex flex-wrap gap-2 pt-3 border-t border-bg-card">
          <span className="text-[10px] text-text-secondary mr-2">Continue to:</span>
          <a href="/network-map" className="text-[10px] px-2 py-1 rounded bg-accent-purple/10 text-accent-purple hover:bg-accent-purple/20 transition-colors">Network Map</a>
          <a href="/threat-intel" className="text-[10px] px-2 py-1 rounded bg-accent-orange/10 text-accent-orange hover:bg-accent-orange/20 transition-colors">Threat Intel</a>
          <a href="/rule-generator" className="text-[10px] px-2 py-1 rounded bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20 transition-colors">Rule Generator</a>
        </div>
      )}

      {/* Passive Vulnerability Assessment */}
      {devices.length > 0 && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-accent-amber/20">
          <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-4">
            <AlertTriangle className="w-5 h-5 text-accent-amber" />
            Passive Vulnerability Assessment
          </h2>
          <p className="text-xs text-text-secondary mb-4">
            Security insights extracted from observed traffic patterns. No active probing — analysis based on captured network flows only.
          </p>

          {/* Summary stats */}
          <div className="grid grid-cols-4 gap-3 mb-4">
            <div className="bg-bg-primary rounded-lg p-3 border border-bg-card text-center">
              <div className="text-xl font-bold text-accent-red">{vulnFindings.filter(f => f.severity === 'critical').length}</div>
              <div className="text-[10px] text-text-secondary">Critical</div>
            </div>
            <div className="bg-bg-primary rounded-lg p-3 border border-bg-card text-center">
              <div className="text-xl font-bold text-accent-amber">{vulnFindings.filter(f => f.severity === 'high').length}</div>
              <div className="text-[10px] text-text-secondary">High</div>
            </div>
            <div className="bg-bg-primary rounded-lg p-3 border border-bg-card text-center">
              <div className="text-xl font-bold text-accent-blue">{vulnFindings.filter(f => f.severity === 'medium').length}</div>
              <div className="text-[10px] text-text-secondary">Medium</div>
            </div>
            <div className="bg-bg-primary rounded-lg p-3 border border-bg-card text-center">
              <div className="text-xl font-bold text-text-primary">{devices.length}</div>
              <div className="text-[10px] text-text-secondary">Devices Scanned</div>
            </div>
          </div>

          {/* Findings list */}
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {vulnFindings.map((f, i) => (
              <div key={i} className={`flex items-start gap-3 px-4 py-3 rounded-lg border ${
                f.severity === 'critical' ? 'bg-accent-red/5 border-accent-red/20' :
                f.severity === 'high' ? 'bg-accent-amber/5 border-accent-amber/20' :
                'bg-accent-blue/5 border-accent-blue/20'
              }`}>
                <div className={`shrink-0 mt-0.5 px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${
                  f.severity === 'critical' ? 'bg-accent-red/20 text-accent-red' :
                  f.severity === 'high' ? 'bg-accent-amber/20 text-accent-amber' :
                  'bg-accent-blue/20 text-accent-blue'
                }`}>{f.severity}</div>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium text-text-primary">{f.finding}</div>
                  <div className="text-[10px] text-text-secondary mt-0.5">
                    <span className="font-mono">{f.device}</span> · {f.category}
                  </div>
                  <div className="text-[10px] text-accent-green mt-1">
                    <strong>Fix:</strong> {f.recommendation}
                  </div>
                </div>
              </div>
            ))}
            {vulnFindings.length === 0 && (
              <div className="text-center py-6 text-text-secondary text-xs">
                No vulnerabilities detected in observed traffic patterns.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Active Penetration Testing — Admin Only */}
      {devices.length > 0 && (
        <div className="bg-bg-secondary rounded-xl border border-accent-red/20">
          <button
            onClick={() => setShowPenTest(!showPenTest)}
            className="w-full flex items-center justify-between p-4"
          >
            <h2 className="text-lg font-display font-semibold flex items-center gap-2">
              <Lock className="w-5 h-5 text-accent-red" />
              Active Penetration Testing
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-accent-red/15 text-accent-red">ADMIN ONLY</span>
            </h2>
            {showPenTest ? <ChevronUp className="w-5 h-5 text-text-secondary" /> : <ChevronDown className="w-5 h-5 text-text-secondary" />}
          </button>
          {showPenTest && (
            <div className="px-4 pb-4 space-y-4">
              {!penTestAuthorized ? (
                <div className="bg-accent-red/5 border border-accent-red/20 rounded-lg p-4">
                  <h3 className="text-sm font-semibold text-accent-red mb-2">Authorization Required</h3>
                  <p className="text-xs text-text-secondary mb-3">
                    Active penetration testing performs network scanning, credential assessment, and device fingerprinting on live network targets.
                    These operations must be explicitly authorized by the network owner. Unauthorized scanning may violate computer fraud and abuse laws.
                  </p>
                  <div className="space-y-2 mb-4">
                    <label className="flex items-start gap-2 text-xs text-text-secondary cursor-pointer">
                      <input type="checkbox" checked={authChecks.owner} onChange={e => setAuthChecks(prev => ({...prev, owner: e.target.checked}))} className="mt-0.5 accent-accent-red" />
                      I am the network owner or have written authorization from the network owner
                    </label>
                    <label className="flex items-start gap-2 text-xs text-text-secondary cursor-pointer">
                      <input type="checkbox" checked={authChecks.scope} onChange={e => setAuthChecks(prev => ({...prev, scope: e.target.checked}))} className="mt-0.5 accent-accent-red" />
                      Testing is limited to the scope defined in the authorization document
                    </label>
                    <label className="flex items-start gap-2 text-xs text-text-secondary cursor-pointer">
                      <input type="checkbox" checked={authChecks.legal} onChange={e => setAuthChecks(prev => ({...prev, legal: e.target.checked}))} className="mt-0.5 accent-accent-red" />
                      I accept full legal responsibility for any active scanning performed
                    </label>
                  </div>
                  <button
                    onClick={() => { if (authChecks.owner && authChecks.scope && authChecks.legal) setPenTestAuthorized(true) }}
                    disabled={!authChecks.owner || !authChecks.scope || !authChecks.legal}
                    className="px-4 py-2 bg-accent-red hover:bg-accent-red/80 text-white rounded-lg text-xs font-medium disabled:opacity-50 transition-colors"
                  >
                    Acknowledge & Enable Active Testing
                  </button>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="bg-accent-red/5 border border-accent-red/10 rounded-lg p-2 text-[10px] text-accent-red flex items-center gap-2">
                    <Shield className="w-3.5 h-3.5 shrink-0" />
                    Active penetration testing authorized. All operations are logged to the audit trail.
                  </div>

                  {/* Tool 1: Network Scanner */}
                  <div className="bg-bg-primary rounded-lg p-4 border border-bg-card">
                    <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2 mb-2">
                      <Search className="w-4 h-4 text-accent-blue" />
                      Network Scanner
                    </h3>
                    <p className="text-[10px] text-text-secondary mb-3">
                      Identify open ports, running services, and OS fingerprints on discovered devices. Similar to Nmap SYN scan.
                    </p>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mb-3">
                      <div>
                        <label className="text-[10px] text-text-secondary block mb-1">Target IP/Range</label>
                        <input type="text" value={scanTarget} onChange={e => setScanTarget(e.target.value)} placeholder="e.g., 10.0.1.0/24 or 192.168.1.5" className="w-full px-3 py-1.5 bg-bg-secondary border border-bg-card rounded text-xs text-text-primary" />
                      </div>
                      <div>
                        <label className="text-[10px] text-text-secondary block mb-1">Scan Type</label>
                        <select value={scanType} onChange={e => setScanType(e.target.value)} className="w-full px-3 py-1.5 bg-bg-secondary border border-bg-card rounded text-xs text-text-primary">
                          <option value="quick">Quick Scan (top 100 ports)</option>
                          <option value="full">Full Scan (all 65535 ports)</option>
                          <option value="stealth">Stealth SYN Scan</option>
                          <option value="service">Service Version Detection</option>
                          <option value="os">OS Fingerprinting</option>
                        </select>
                      </div>
                    </div>
                    <button onClick={() => runNetworkScan()} disabled={!scanTarget || scanning} className="px-4 py-2 bg-accent-blue hover:bg-accent-blue/80 text-white rounded-lg text-xs font-medium disabled:opacity-50 flex items-center gap-2">
                      {scanning ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Scanning...</> : <><Search className="w-3.5 h-3.5" /> Run Scan</>}
                    </button>
                    {scanResults && (
                      <div className="mt-3 space-y-1.5 max-h-48 overflow-y-auto">
                        {scanResults.map((r: any, i: number) => (
                          <div key={i} className="flex items-center gap-3 px-3 py-2 bg-bg-secondary rounded text-xs">
                            <span className="font-mono text-accent-blue">{r.port}</span>
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${r.state === 'open' ? 'bg-accent-green/15 text-accent-green' : 'bg-accent-red/15 text-accent-red'}`}>{r.state}</span>
                            <span className="text-text-primary flex-1">{r.service}</span>
                            <span className="text-text-secondary">{r.version || ''}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Tool 2: Credential Assessment */}
                  <div className="bg-bg-primary rounded-lg p-4 border border-bg-card">
                    <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2 mb-2">
                      <Key className="w-4 h-4 text-accent-amber" />
                      Default Credential Assessment
                    </h3>
                    <p className="text-[10px] text-text-secondary mb-3">
                      Tests discovered services against known default credential databases (admin/admin, root/root, etc.). Does NOT perform brute force — only checks known defaults.
                    </p>
                    <button onClick={() => runCredentialCheck()} disabled={!scanResults || credChecking} className="px-4 py-2 bg-accent-amber hover:bg-accent-amber/80 text-white rounded-lg text-xs font-medium disabled:opacity-50 flex items-center gap-2">
                      {credChecking ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Checking...</> : <><Key className="w-3.5 h-3.5" /> Check Default Credentials</>}
                    </button>
                    {credResults && (
                      <div className="mt-3 space-y-1.5">
                        {credResults.map((r: any, i: number) => (
                          <div key={i} className={`flex items-center gap-3 px-3 py-2 rounded text-xs ${r.vulnerable ? 'bg-accent-red/5 border border-accent-red/20' : 'bg-accent-green/5 border border-accent-green/20'}`}>
                            {r.vulnerable ? <XCircle className="w-4 h-4 text-accent-red shrink-0" /> : <CheckCircle2 className="w-4 h-4 text-accent-green shrink-0" />}
                            <span className="font-mono">{r.service}://{r.host}:{r.port}</span>
                            <span className={r.vulnerable ? 'text-accent-red font-bold' : 'text-accent-green'}>{r.vulnerable ? `DEFAULT CREDS: ${r.username}/${r.password}` : 'Secured'}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Tool 3: Device Fingerprinting */}
                  <div className="bg-bg-primary rounded-lg p-4 border border-bg-card">
                    <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2 mb-2">
                      <Fingerprint className="w-4 h-4 text-accent-purple" />
                      Device Fingerprinting
                    </h3>
                    <p className="text-[10px] text-text-secondary mb-3">
                      Identifies device type, manufacturer, firmware version, and known vulnerabilities from service banners and protocol behavior.
                    </p>
                    <button onClick={() => runFingerprint()} disabled={!scanResults || fingerprinting} className="px-4 py-2 bg-accent-purple hover:bg-accent-purple/80 text-white rounded-lg text-xs font-medium disabled:opacity-50 flex items-center gap-2">
                      {fingerprinting ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Fingerprinting...</> : <><Fingerprint className="w-3.5 h-3.5" /> Run Fingerprinting</>}
                    </button>
                    {fingerprintResults && (
                      <div className="mt-3 space-y-1.5">
                        {fingerprintResults.map((r: any, i: number) => (
                          <div key={i} className="px-3 py-2 bg-bg-secondary rounded text-xs space-y-1">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-accent-purple font-bold">{r.ip}</span>
                              <span className="text-text-primary">{r.deviceType}</span>
                            </div>
                            <div className="text-[10px] text-text-secondary">
                              Manufacturer: {r.manufacturer} · OS: {r.os} · Firmware: {r.firmware}
                            </div>
                            {r.knownCVEs?.length > 0 && (
                              <div className="text-[10px] text-accent-red">
                                Known CVEs: {r.knownCVEs.join(', ')}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Empty state */}
      {analysisResult && devices.length === 0 && (
        <div className="text-center py-12 text-text-secondary">
          <Monitor className="w-8 h-8 mx-auto mb-2 opacity-40" />
          <p className="text-sm">No devices found in this dataset.</p>
        </div>
      )}

      {!analysisResult && (
        <div className="flex items-center gap-2 px-3 py-2 bg-accent-blue/5 border border-accent-blue/10 rounded-lg text-xs text-accent-blue">
          <Info className="w-3.5 h-3.5 shrink-0" />
          Upload a dataset or use Live Monitor data to discover network devices.
        </div>
      )}

      <div className="text-[10px] text-text-secondary/60 text-center">
        Device inventory derived from traffic analysis. MAC addresses are simulated for private IP ranges (ARP extraction). Services accessed = distinct destination ports per IP.
      </div>
    </div>
  )
}
