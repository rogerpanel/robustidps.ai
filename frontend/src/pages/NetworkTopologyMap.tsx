import { useState, useMemo, useCallback } from 'react'
import {
  Network, Upload, X, FileText, Loader2, Radio, Shield, Info,
  AlertTriangle, Server, Globe,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import ModelSelector from '../components/ModelSelector'
import { analyseFile, cachePageResult } from '../utils/api'
import { useNoticeBoard } from '../hooks/useNoticeBoard'
import { getLiveData, hasLiveData } from '../utils/liveDataStore'

/* ── Topology types ────────────────────────────────────────────────── */

interface TopoNode {
  id: string; x: number; y: number; type: 'internal' | 'external'
  threats: number; total: number
}

interface TopoEdge {
  from: string; to: string; count: number; hasThreat: boolean
}

interface Topology {
  nodes: TopoNode[]; edges: TopoEdge[]
}

/* ── Build topology from predictions ───────────────────────────────── */

const buildTopology = (predictions: any[]): Topology => {
  const nodes: Record<string, TopoNode> = {}
  const edgeMap: Record<string, { count: number; hasThreat: boolean }> = {}

  predictions.forEach((p: any) => {
    const src = p.src_ip || 'unknown'
    const dst = p.dst_ip || 'unknown'

    if (!nodes[src]) nodes[src] = { id: src, x: 0, y: 0, type: src.startsWith('10.') || src.startsWith('192.168.') || src.startsWith('172.16.') ? 'internal' : 'external', threats: 0, total: 0 }
    if (!nodes[dst]) nodes[dst] = { id: dst, x: 0, y: 0, type: dst.startsWith('10.') || dst.startsWith('192.168.') || dst.startsWith('172.16.') ? 'internal' : 'external', threats: 0, total: 0 }

    nodes[src].total++
    nodes[dst].total++
    if (p.severity !== 'benign') { nodes[src].threats++; nodes[dst].threats++ }

    const edgeKey = `${src}→${dst}`
    if (!edgeMap[edgeKey]) edgeMap[edgeKey] = { count: 0, hasThreat: false }
    edgeMap[edgeKey].count++
    if (p.severity !== 'benign') edgeMap[edgeKey].hasThreat = true
  })

  // Position nodes in circular layout
  const nodeList = Object.values(nodes)
  const internals = nodeList.filter(n => n.type === 'internal')
  const externals = nodeList.filter(n => n.type === 'external')

  internals.forEach((n, i) => {
    const angle = (i / Math.max(internals.length, 1)) * 2 * Math.PI - Math.PI / 2
    n.x = 400 + Math.cos(angle) * 150
    n.y = 300 + Math.sin(angle) * 150
  })

  externals.forEach((n, i) => {
    const angle = (i / Math.max(externals.length, 1)) * 2 * Math.PI - Math.PI / 2
    n.x = 400 + Math.cos(angle) * 280
    n.y = 300 + Math.sin(angle) * 240
  })

  const edgeList = Object.entries(edgeMap).map(([key, val]) => {
    const [from, to] = key.split('→')
    return { from, to, ...val }
  })

  return { nodes: nodeList.slice(0, 30), edges: edgeList.slice(0, 50) }
}

/* ── Guide steps ───────────────────────────────────────────────────── */

const GUIDE_STEPS = [
  { title: 'Load Traffic Data', desc: 'Upload a CSV/PCAP file or use Live Monitor data to build the topology.' },
  { title: 'Explore the Map', desc: 'Hover over nodes to see IP details. Click a node for the detail panel.' },
  { title: 'Identify Threats', desc: 'Red nodes are compromised, red edges indicate attack paths between devices.' },
]

export default function NetworkTopologyMap() {
  const [file, setFile] = useState<File | null>(null)
  const [modelId, setModelId] = useState('surrogate')
  const [analysisResult, setAnalysisResult] = useState<any>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [liveDataLoaded, setLiveDataLoaded] = useState(false)
  const [selectedNode, setSelectedNode] = useState<TopoNode | null>(null)
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
    const nid = addNotice({ title: 'Network Map', description: `Mapping ${file.name}...`, status: 'running', page: '/network-map' })
    try {
      const data = await analyseFile(file, modelId, 'network_map')
      setAnalysisResult(data)
      updateNotice(nid, { status: 'completed', description: `${data.predictions?.length || 0} flows mapped` })
      cachePageResult('network_map', { n_flows: data.predictions?.length || 0, model: modelId }).catch(() => {})
    } catch (err) {
      updateNotice(nid, { status: 'error', description: err instanceof Error ? err.message : 'Mapping failed' })
    }
    setAnalyzing(false)
  }

  /* ── Build topology ──────────────────────────────────────────────── */
  const topology = useMemo((): Topology => {
    if (!analysisResult?.predictions) return { nodes: [], edges: [] }
    return buildTopology(analysisResult.predictions)
  }, [analysisResult])

  /* ── Stats ───────────────────────────────────────────────────────── */
  const stats = useMemo(() => {
    if (!topology.nodes.length) return null
    return {
      connections: topology.edges.length,
      threatPaths: topology.edges.filter(e => e.hasThreat).length,
      internalDevices: topology.nodes.filter(n => n.type === 'internal').length,
      externalSources: topology.nodes.filter(n => n.type === 'external').length,
    }
  }, [topology])

  /* ── Connections for selected node ───────────────────────────────── */
  const selectedConnections = useMemo(() => {
    if (!selectedNode) return []
    return topology.edges
      .filter(e => e.from === selectedNode.id || e.to === selectedNode.id)
      .map(e => {
        const peerId = e.from === selectedNode.id ? e.to : e.from
        const direction = e.from === selectedNode.id ? 'outbound' : 'inbound'
        return { peerId, direction, count: e.count, hasThreat: e.hasThreat }
      })
      .sort((a, b) => b.count - a.count)
  }, [selectedNode, topology])

  return (
    <div className="space-y-6 network-map-root">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-accent-purple/10 flex items-center justify-center">
            <Network className="w-5 h-5 text-accent-purple" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-text-primary">Network Topology Map</h1>
            <p className="text-xs text-text-secondary mt-0.5">Interactive visualization of device connections and attack paths</p>
          </div>
        </div>
        <ExportMenu targetSelector=".network-map-root" filename="network-topology" />
      </div>

      <PageGuide title="How to use the Network Map" steps={GUIDE_STEPS} tip="Internal nodes appear in the inner circle, external nodes in the outer ring. Red lines indicate traffic containing detected threats." />

      {/* Upload + Model */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold mb-3">Load Analysis Data</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end">
          <div>
            {file ? (
              <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-accent-green/30 bg-accent-green/5">
                <FileText className="w-4 h-4 text-accent-green shrink-0" />
                <span className="text-xs font-mono truncate flex-1">{file.name}</span>
                <button onClick={() => { setFile(null); setAnalysisResult(null); setSelectedNode(null) }} className="text-text-secondary hover:text-text-primary"><X className="w-3.5 h-3.5" /></button>
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
          <button onClick={runAnalysis} disabled={!file || analyzing} className="px-4 py-2.5 bg-accent-purple hover:bg-accent-purple/80 text-white rounded-lg text-xs font-medium disabled:opacity-50 flex items-center justify-center gap-2">
            {analyzing ? <><Loader2 className="w-4 h-4 animate-spin" /> Mapping...</> : 'Analyze & Build Map'}
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
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: 'Total Connections', value: stats.connections, icon: <Network className="w-3.5 h-3.5 text-accent-blue" /> },
            { label: 'Threat Paths', value: stats.threatPaths, icon: <AlertTriangle className="w-3.5 h-3.5 text-accent-red" /> },
            { label: 'Internal Devices', value: stats.internalDevices, icon: <Server className="w-3.5 h-3.5 text-accent-green" /> },
            { label: 'External Sources', value: stats.externalSources, icon: <Globe className="w-3.5 h-3.5 text-accent-amber" /> },
          ].map(s => (
            <div key={s.label} className="bg-bg-card border border-bg-card rounded-xl p-4">
              <div className="text-xs text-text-secondary mb-1 flex items-center gap-1">{s.icon} {s.label}</div>
              <div className="text-2xl font-bold">{s.value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Topology visualization */}
      {topology.nodes.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          {/* Map area */}
          <div className="lg:col-span-3">
            <div className="relative bg-bg-primary rounded-xl border border-bg-card overflow-hidden" style={{ height: 600 }}>
              <svg className="absolute inset-0 w-full h-full" viewBox="0 0 800 600" preserveAspectRatio="xMidYMid meet">
                {topology.edges.map((edge, i) => {
                  const from = topology.nodes.find(n => n.id === edge.from)
                  const to = topology.nodes.find(n => n.id === edge.to)
                  if (!from || !to) return null
                  return (
                    <line key={i} x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                      stroke={edge.hasThreat ? '#EF4444' : '#334155'} strokeWidth={Math.min(edge.count / 5, 3) + 0.5}
                      strokeOpacity={edge.hasThreat ? 0.8 : 0.3} />
                  )
                })}
              </svg>

              {topology.nodes.map((node) => {
                const isCompromised = node.threats > node.total * 0.3
                const isSelected = selectedNode?.id === node.id
                const pctX = (node.x / 800) * 100
                const pctY = (node.y / 600) * 100
                return (
                  <div key={node.id} className="absolute transform -translate-x-1/2 -translate-y-1/2 cursor-pointer group"
                    style={{ left: `${pctX}%`, top: `${pctY}%` }}
                    onClick={() => setSelectedNode(node.id === selectedNode?.id ? null : node)}
                  >
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center text-[8px] font-bold border-2 transition-all ${
                      isSelected ? 'ring-2 ring-accent-blue ring-offset-1 ring-offset-bg-primary' : ''
                    } ${
                      isCompromised ? 'bg-accent-red/20 border-accent-red text-accent-red' :
                      node.type === 'external' ? 'bg-accent-amber/20 border-accent-amber text-accent-amber' :
                      'bg-accent-green/20 border-accent-green text-accent-green'
                    }`}>
                      {node.id.split('.').pop()}
                    </div>
                    <div className="hidden group-hover:block absolute left-1/2 -translate-x-1/2 top-10 bg-bg-card border border-bg-card rounded-lg p-2 text-[9px] text-text-primary whitespace-nowrap z-10 shadow-lg">
                      <div className="font-mono font-bold">{node.id}</div>
                      <div className="text-text-secondary">{node.total} flows | {node.threats} threats</div>
                    </div>
                  </div>
                )
              })}

              {/* Legend */}
              <div className="absolute bottom-3 left-3 bg-bg-card/90 backdrop-blur rounded-lg p-2.5 text-[9px] space-y-1.5 border border-bg-card">
                <div className="font-semibold text-text-primary text-[10px] mb-1">Legend</div>
                <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-accent-green/30 border border-accent-green" /> <span className="text-text-secondary">Internal node</span></div>
                <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-accent-amber/30 border border-accent-amber" /> <span className="text-text-secondary">External node</span></div>
                <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-accent-red/30 border border-accent-red" /> <span className="text-text-secondary">Compromised</span></div>
                <div className="flex items-center gap-2"><div className="w-6 h-0.5 bg-accent-red" /> <span className="text-text-secondary">Threat edge</span></div>
                <div className="flex items-center gap-2"><div className="w-6 h-0.5 bg-slate-600" /> <span className="text-text-secondary">Clean edge</span></div>
              </div>
            </div>
          </div>

          {/* Detail panel */}
          <div className="lg:col-span-1">
            {selectedNode ? (
              <div className="bg-bg-secondary rounded-xl border border-bg-card p-4 space-y-4 sticky top-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-text-primary">Node Detail</h3>
                  <button onClick={() => setSelectedNode(null)} className="text-text-secondary hover:text-text-primary"><X className="w-3.5 h-3.5" /></button>
                </div>

                <div>
                  <div className="text-[10px] text-text-secondary">IP Address</div>
                  <div className="font-mono font-bold text-text-primary">{selectedNode.id}</div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="bg-bg-card rounded-lg p-2.5 text-center">
                    <div className="text-lg font-bold text-accent-blue">{selectedNode.total}</div>
                    <div className="text-[9px] text-text-secondary">Total Flows</div>
                  </div>
                  <div className="bg-bg-card rounded-lg p-2.5 text-center">
                    <div className="text-lg font-bold text-accent-red">{selectedNode.threats}</div>
                    <div className="text-[9px] text-text-secondary">Threats</div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-text-secondary">Type:</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                    selectedNode.type === 'internal' ? 'bg-accent-green/15 text-accent-green' : 'bg-accent-amber/15 text-accent-amber'
                  }`}>{selectedNode.type === 'internal' ? 'Internal' : 'External'}</span>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-text-secondary">Status:</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                    selectedNode.threats > selectedNode.total * 0.3
                      ? 'bg-accent-red/15 text-accent-red' : selectedNode.threats > 0
                      ? 'bg-accent-amber/15 text-accent-amber' : 'bg-accent-green/15 text-accent-green'
                  }`}>{selectedNode.threats > selectedNode.total * 0.3 ? 'Compromised' : selectedNode.threats > 0 ? 'Suspicious' : 'Clean'}</span>
                </div>

                {/* Connected devices */}
                <div>
                  <div className="text-[10px] text-text-secondary mb-2">Connected Devices ({selectedConnections.length})</div>
                  <div className="space-y-1.5 max-h-48 overflow-y-auto">
                    {selectedConnections.map((c, i) => (
                      <div key={i} className="flex items-center gap-2 text-[10px]">
                        <span className={`w-1.5 h-1.5 rounded-full ${c.hasThreat ? 'bg-accent-red' : 'bg-accent-green'}`} />
                        <span className="font-mono text-text-primary flex-1 truncate">{c.peerId}</span>
                        <span className="text-text-secondary">{c.count}</span>
                        <span className={`text-[8px] ${c.direction === 'outbound' ? 'text-accent-blue' : 'text-accent-amber'}`}>{c.direction === 'outbound' ? 'OUT' : 'IN'}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="bg-bg-secondary rounded-xl border border-bg-card p-4 text-center">
                <Shield className="w-6 h-6 mx-auto mb-2 text-text-secondary/40" />
                <p className="text-xs text-text-secondary">Click a node on the map to view details</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Cross-page links */}
      {topology.nodes.length > 0 && (
        <div className="flex flex-wrap gap-2 pt-3 border-t border-bg-card">
          <span className="text-[10px] text-text-secondary mr-2">Continue to:</span>
          <a href="/device-discovery" className="text-[10px] px-2 py-1 rounded bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20 transition-colors">Device Discovery</a>
          <a href="/threat-intel" className="text-[10px] px-2 py-1 rounded bg-accent-orange/10 text-accent-orange hover:bg-accent-orange/20 transition-colors">Threat Intel</a>
          <a href="/auto-investigate" className="text-[10px] px-2 py-1 rounded bg-accent-purple/10 text-accent-purple hover:bg-accent-purple/20 transition-colors">Auto-Investigation</a>
        </div>
      )}

      {/* Empty state */}
      {analysisResult && topology.nodes.length === 0 && (
        <div className="text-center py-12 text-text-secondary">
          <Network className="w-8 h-8 mx-auto mb-2 opacity-40" />
          <p className="text-sm">No network connections found in this dataset.</p>
        </div>
      )}

      {!analysisResult && (
        <div className="flex items-center gap-2 px-3 py-2 bg-accent-blue/5 border border-accent-blue/10 rounded-lg text-xs text-accent-blue">
          <Info className="w-3.5 h-3.5 shrink-0" />
          Upload a dataset or use Live Monitor data to build the network topology map.
        </div>
      )}

      <div className="text-[10px] text-text-secondary/60 text-center">
        Topology limited to 30 nodes and 50 edges for rendering performance. Internal/external classification based on RFC 1918 ranges.
      </div>
    </div>
  )
}
