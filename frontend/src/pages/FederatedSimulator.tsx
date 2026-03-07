import { useState } from 'react'
import {
  Network, Upload, Loader2, Server, Shield, Lock, Unlock,
  TrendingUp, BarChart3, Brain, Zap, ChevronDown, ChevronUp,
} from 'lucide-react'
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid, Legend, BarChart, Bar, Cell,
} from 'recharts'
import FileUpload from '../components/FileUpload'
import ModelSelector from '../components/ModelSelector'
import PageGuide from '../components/PageGuide'
import { runFederated } from '../utils/api'

const TT = { background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }

const NODE_COLORS = ['#3B82F6', '#22C55E', '#F59E0B', '#EF4444', '#A855F7', '#06B6D4']

const STRATEGY_OPTS = [
  { id: 'fedavg', label: 'FedAvg', desc: 'Federated Averaging — equal weight aggregation' },
  { id: 'fedprox', label: 'FedProx', desc: 'Proximal regularisation to prevent local drift' },
  { id: 'weighted', label: 'Weighted', desc: 'Weight by dataset size per node' },
]

interface NodeResult {
  node: string
  n_samples: number
  local_accuracy: number
  global_accuracy: number
  final_loss: number
  loss_curve: number[]
}

interface RoundResult {
  round: number
  global_accuracy: number
  global_confidence: number
  nodes: NodeResult[]
}

interface FedResult {
  sim_id: string
  n_nodes: number
  n_rounds: number
  local_epochs: number
  strategy: string
  dp_enabled: boolean
  dp_sigma: number | null
  iid: boolean
  n_samples_total: number
  node_distribution: { node: string; n_samples: number }[]
  baseline_accuracy: number
  final_accuracy: number
  accuracy_gain: number
  rounds: RoundResult[]
  per_class: Record<string, { count: number; accuracy: number }>
  model_used: string
  time_ms: number
}

export default function FederatedSimulator() {
  const [file, setFile] = useState<File | null>(null)
  const [selectedModel, setSelectedModel] = useState('surrogate')
  const [nNodes, setNNodes] = useState(4)
  const [rounds, setRounds] = useState(5)
  const [localEpochs, setLocalEpochs] = useState(3)
  const [lr, setLr] = useState(0.0001)
  const [strategy, setStrategy] = useState('fedavg')
  const [dpEnabled, setDpEnabled] = useState(false)
  const [dpSigma, setDpSigma] = useState(0.01)
  const [iid, setIid] = useState(true)
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<FedResult | null>(null)
  const [error, setError] = useState('')
  const [expandedRound, setExpandedRound] = useState<number | null>(null)

  const handleRun = async () => {
    if (!file) return
    setRunning(true)
    setError('')
    setResult(null)
    try {
      const data = await runFederated(file, {
        nNodes, rounds, localEpochs, lr, strategy,
        dpEnabled, dpSigma, iid, modelName: selectedModel,
      })
      setResult(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Simulation failed')
    } finally {
      setRunning(false)
    }
  }

  // Global convergence chart data
  const convergenceData = result?.rounds.map(r => ({
    round: `R${r.round}`,
    'Global Accuracy': Math.round(r.global_accuracy * 1000) / 10,
    'Confidence': Math.round(r.global_confidence * 1000) / 10,
  })) || []

  // Node accuracy over rounds
  const nodeAccData = result?.rounds.map(r => {
    const entry: Record<string, string | number> = { round: `R${r.round}` }
    r.nodes.forEach(n => { entry[n.node] = Math.round(n.local_accuracy * 1000) / 10 })
    return entry
  }) || []

  const nodeNames = result?.node_distribution.map(n => n.node) || []

  // Data distribution chart
  const distData = result?.node_distribution.map((n, i) => ({
    name: n.node,
    samples: n.n_samples,
    color: NODE_COLORS[i % NODE_COLORS.length],
  })) || []

  return (
    <div className="space-y-6">
      <PageGuide
        title="How to use Federated Learning Simulator"
        steps={[
          { title: 'Upload a dataset', desc: 'Drop a network traffic CSV — it will be split across virtual nodes.' },
          { title: 'Configure nodes', desc: 'Set the number of organisations, rounds, and aggregation strategy.' },
          { title: 'Enable privacy', desc: 'Optionally add differential privacy noise to weight updates.' },
          { title: 'Run simulation', desc: 'Watch federated training converge across distributed nodes.' },
        ]}
        tip="Federated learning lets organisations collaborate on IDS models without sharing raw traffic data."
      />

      {/* Header */}
      <div className="flex items-center gap-3">
        <Network className="w-7 h-7 text-accent-blue" />
        <div>
          <h1 className="text-xl md:text-2xl font-display font-bold">Federated Learning Simulator</h1>
          <p className="text-sm text-text-secondary mt-0.5">Privacy-preserving distributed model training</p>
        </div>
      </div>

      {/* Config Panel */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Upload + Model */}
          <div className="space-y-3">
            <FileUpload
              onFile={(f) => setFile(f)}
              label="Upload traffic dataset"
              accept=".csv,.parquet"
            />
            {file && (
              <div className="text-xs text-text-secondary flex items-center gap-1">
                <Upload className="w-3 h-3" /> {file.name}
              </div>
            )}
            <ModelSelector value={selectedModel} onChange={setSelectedModel} />
          </div>

          {/* Topology params */}
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-xs text-text-secondary block mb-1">Nodes</label>
                <input
                  type="number" min={2} max={6} value={nNodes}
                  onChange={e => setNNodes(parseInt(e.target.value) || 4)}
                  className="w-full px-2 py-1 bg-bg-primary border border-bg-card rounded text-sm text-text-primary"
                />
              </div>
              <div>
                <label className="text-xs text-text-secondary block mb-1">Rounds</label>
                <input
                  type="number" min={1} max={20} value={rounds}
                  onChange={e => setRounds(parseInt(e.target.value) || 5)}
                  className="w-full px-2 py-1 bg-bg-primary border border-bg-card rounded text-sm text-text-primary"
                />
              </div>
              <div>
                <label className="text-xs text-text-secondary block mb-1">Local Epochs</label>
                <input
                  type="number" min={1} max={10} value={localEpochs}
                  onChange={e => setLocalEpochs(parseInt(e.target.value) || 3)}
                  className="w-full px-2 py-1 bg-bg-primary border border-bg-card rounded text-sm text-text-primary"
                />
              </div>
              <div>
                <label className="text-xs text-text-secondary block mb-1">Learning Rate</label>
                <input
                  type="number" min={0.0001} max={0.1} step={0.0001} value={lr}
                  onChange={e => setLr(parseFloat(e.target.value) || 0.001)}
                  className="w-full px-2 py-1 bg-bg-primary border border-bg-card rounded text-sm text-text-primary"
                />
              </div>
            </div>

            {/* Data distribution */}
            <div>
              <label className="text-xs text-text-secondary block mb-1">Data Distribution</label>
              <div className="flex gap-2">
                <button
                  onClick={() => setIid(true)}
                  className={`flex-1 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                    iid ? 'bg-accent-blue/15 border-accent-blue/40 text-accent-blue' : 'bg-bg-primary border-bg-card text-text-secondary'
                  }`}
                >
                  IID (uniform)
                </button>
                <button
                  onClick={() => setIid(false)}
                  className={`flex-1 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                    !iid ? 'bg-accent-amber/15 border-accent-amber/40 text-accent-amber' : 'bg-bg-primary border-bg-card text-text-secondary'
                  }`}
                >
                  Non-IID (skewed)
                </button>
              </div>
            </div>
          </div>

          {/* Strategy + DP */}
          <div className="space-y-3">
            <div>
              <label className="text-xs text-text-secondary block mb-2">Aggregation Strategy</label>
              <div className="flex flex-col gap-1.5">
                {STRATEGY_OPTS.map(s => (
                  <button
                    key={s.id}
                    onClick={() => setStrategy(s.id)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors text-left ${
                      strategy === s.id
                        ? 'bg-accent-blue/15 border-accent-blue/40 text-accent-blue'
                        : 'bg-bg-primary border-bg-card text-text-secondary hover:text-text-primary'
                    }`}
                    title={s.desc}
                  >
                    {s.label}
                    <span className="text-[10px] text-text-secondary ml-1.5">{s.desc.split('—')[1]?.trim()}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Differential Privacy */}
            <div className="p-3 rounded-lg border border-bg-card bg-bg-primary">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox" checked={dpEnabled}
                  onChange={e => setDpEnabled(e.target.checked)}
                  className="rounded accent-accent-green"
                />
                <span className="text-xs font-medium flex items-center gap-1">
                  {dpEnabled ? <Lock className="w-3 h-3 text-accent-green" /> : <Unlock className="w-3 h-3 text-text-secondary" />}
                  Differential Privacy
                </span>
              </label>
              {dpEnabled && (
                <div className="mt-2">
                  <label className="text-[10px] text-text-secondary block mb-1">Noise sigma</label>
                  <input
                    type="range" min={0.001} max={0.1} step={0.001}
                    value={dpSigma}
                    onChange={e => setDpSigma(parseFloat(e.target.value))}
                    className="w-full accent-accent-green"
                  />
                  <div className="flex justify-between text-[10px] text-text-secondary">
                    <span>Low noise</span>
                    <span className="font-mono text-accent-green">{dpSigma.toFixed(3)}</span>
                    <span>High privacy</span>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        <button
          onClick={handleRun}
          disabled={!file || running}
          className="px-5 py-2.5 bg-accent-blue text-white rounded-lg text-sm font-medium hover:bg-accent-blue/80 transition-colors disabled:opacity-40 flex items-center gap-2"
        >
          {running ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Running simulation...
            </>
          ) : (
            <>
              <Network className="w-4 h-4" />
              Run Simulation
            </>
          )}
        </button>

        {error && (
          <div className="px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">
            {error}
          </div>
        )}
      </div>

      {/* Results */}
      {result && (
        <>
          {/* Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <TrendingUp className="w-3.5 h-3.5" /> Baseline
              </div>
              <div className="text-xl font-mono font-bold text-text-secondary">
                {(result.baseline_accuracy * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Shield className="w-3.5 h-3.5" /> Final
              </div>
              <div className={`text-xl font-mono font-bold ${
                result.accuracy_gain >= 0 ? 'text-accent-green' : 'text-accent-red'
              }`}>
                {(result.final_accuracy * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Zap className="w-3.5 h-3.5" /> Gain
              </div>
              <div className={`text-xl font-mono font-bold ${
                result.accuracy_gain >= 0 ? 'text-accent-green' : 'text-accent-red'
              }`}>
                {result.accuracy_gain >= 0 ? '+' : ''}{(result.accuracy_gain * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Server className="w-3.5 h-3.5" /> Nodes
              </div>
              <div className="text-xl font-mono font-bold text-accent-blue">
                {result.n_nodes}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                {result.dp_enabled ? <Lock className="w-3.5 h-3.5" /> : <Unlock className="w-3.5 h-3.5" />}
                {result.dp_enabled ? 'DP On' : 'DP Off'}
              </div>
              <div className="text-sm font-mono font-bold text-text-primary">
                {result.strategy.toUpperCase()}
                {result.dp_enabled && ` σ=${result.dp_sigma}`}
              </div>
            </div>
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Global convergence */}
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h3 className="text-sm font-semibold mb-3">Global Convergence</h3>
              <ResponsiveContainer width="100%" height={280}>
                <LineChart data={convergenceData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="round" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" domain={['auto', 'auto']} />
                  <Tooltip contentStyle={TT} />
                  <Line type="monotone" dataKey="Global Accuracy" stroke="#22C55E" strokeWidth={2} dot={{ r: 3 }} />
                  <Line type="monotone" dataKey="Confidence" stroke="#3B82F6" strokeWidth={2} dot={{ r: 3 }} strokeDasharray="5 5" />
                  <Legend wrapperStyle={{ fontSize: 11, color: '#94A3B8' }} />
                </LineChart>
              </ResponsiveContainer>
            </div>

            {/* Node data distribution */}
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h3 className="text-sm font-semibold mb-3">Data Distribution per Node</h3>
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={distData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="name" tick={{ fill: '#94A3B8', fontSize: 9 }} />
                  <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} />
                  <Tooltip contentStyle={TT} />
                  <Bar dataKey="samples" radius={[4, 4, 0, 0]}>
                    {distData.map((d, i) => (
                      <Cell key={i} fill={d.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Per-node accuracy over rounds */}
          {nodeNames.length > 0 && (
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h3 className="text-sm font-semibold mb-3">Per-Node Local Accuracy</h3>
              <ResponsiveContainer width="100%" height={280}>
                <LineChart data={nodeAccData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="round" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" domain={['auto', 'auto']} />
                  <Tooltip contentStyle={TT} />
                  {nodeNames.map((name, i) => (
                    <Line
                      key={name}
                      type="monotone"
                      dataKey={name}
                      stroke={NODE_COLORS[i % NODE_COLORS.length]}
                      strokeWidth={1.5}
                      dot={{ r: 2 }}
                    />
                  ))}
                  <Legend wrapperStyle={{ fontSize: 10, color: '#94A3B8' }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Round details */}
          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-text-secondary">Round Details</h3>
            {result.rounds.map(r => (
              <div key={r.round} className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
                <button
                  onClick={() => setExpandedRound(expandedRound === r.round ? null : r.round)}
                  className="w-full px-4 py-3 flex items-center gap-3 hover:bg-bg-card/30 transition-colors"
                >
                  <span className="text-xs font-mono bg-accent-blue/15 text-accent-blue px-2 py-0.5 rounded">
                    R{r.round}
                  </span>
                  <span className="text-sm flex-1 text-left">
                    Global: <span className="font-mono text-accent-green">{(r.global_accuracy * 100).toFixed(1)}%</span>
                  </span>
                  <span className="text-xs text-text-secondary">
                    Confidence: <span className="font-mono">{(r.global_confidence * 100).toFixed(1)}%</span>
                  </span>
                  {expandedRound === r.round ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>

                {expandedRound === r.round && (
                  <div className="px-4 pb-4 border-t border-bg-card">
                    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2 mt-3">
                      {r.nodes.map((n, i) => (
                        <div key={n.node} className="bg-bg-primary rounded-lg p-3 text-xs">
                          <div className="flex items-center gap-2 mb-2">
                            <Server className="w-3 h-3" style={{ color: NODE_COLORS[i % NODE_COLORS.length] }} />
                            <span className="font-medium truncate">{n.node}</span>
                          </div>
                          <div className="space-y-1">
                            <div className="flex justify-between">
                              <span className="text-text-secondary">Local acc:</span>
                              <span className="font-mono text-accent-green">{(n.local_accuracy * 100).toFixed(1)}%</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-text-secondary">Global acc:</span>
                              <span className="font-mono text-accent-blue">{(n.global_accuracy * 100).toFixed(1)}%</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-text-secondary">Loss:</span>
                              <span className="font-mono">{n.final_loss.toFixed(3)}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-text-secondary">Samples:</span>
                              <span className="font-mono">{n.n_samples}</span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
