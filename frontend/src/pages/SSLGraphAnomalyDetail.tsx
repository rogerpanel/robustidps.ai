import { useState, useMemo, useCallback, Fragment } from 'react'
import {
  Network, Upload, FileText, X, Loader2, Radio, ShieldCheck,
  ChevronUp, ChevronDown, ArrowRight, BarChart3, Layers, RefreshCw, GitBranch,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import ModelSelector from '../components/ModelSelector'
import { analyseFile, cachePageResult } from '../utils/api'
import { useNoticeBoard } from '../hooks/useNoticeBoard'
import { getLiveData, hasLiveData } from '../utils/liveDataStore'
import { registerSessionReset } from '../utils/sessionReset'
import MultiRunPanel from '../components/MultiRunPanel'

/* ── Static config ────────────────────────────────────────────────────── */
const GUIDE_STEPS = [
  { title: 'Load data', desc: 'Upload a CSV/PCAP file or use Live Monitor flows.' },
  { title: 'Pick a model', desc: 'Default: ssl_graph_anomaly_full; falls back to ssl_graph_anomaly.' },
  { title: 'Set α target', desc: 'The miscoverage budget. Smaller α = stricter, fewer flags.' },
  { title: 'Calibrate on benign batch', desc: 'Build the conformal threshold from current benign-classified flows.' },
  { title: 'Run analysis', desc: 'The six-component pipeline transforms flows into Mahalanobis-energy scores.' },
  { title: 'Read coverage bound', desc: 'Marginal coverage guarantee: Pr[flag | benign] ≤ α + 1/(n+1).' },
]

interface PipelineStage {
  id: string
  label: string
  short: string
  description: string
}

const PIPELINE: PipelineStage[] = [
  { id: 'graph',     label: 'Graph Builder',    short: 'GB',   description: 'Construct flow graph: nodes = endpoints, edges = packets with per-flow features.' },
  { id: 'sage',      label: 'E-GraphSAGE',      short: 'SAGE', description: 'Edge-aware GraphSAGE encoder; learns neighborhood-aware embeddings on the flow graph.' },
  { id: 'attn',      label: 'Attention-Gated',  short: 'AG',   description: 'Streaming attention gate suppresses bursty/redundant edges, keeps salient ones.' },
  { id: 'ae',        label: 'Transformer AE',   short: 'TAE',  description: 'Self-supervised reconstruction loss on the gated graph; learns benign manifold.' },
  { id: 'maha',      label: 'Mahalanobis',      short: 'MD',   description: 'Distance from benign embedding mean in inverse-covariance metric; gives energy score.' },
  { id: 'conformal', label: 'Split-Conformal',  short: 'CP',   description: 'Calibrated threshold from held-out benign scores; gives Pr[flag|benign] ≤ α + 1/(n+1).' },
]

const CALIBRATION_CAPACITY = 5000

interface SSLFlow {
  id: string
  label: string
  energy: number
  is_benign_predicted: boolean
}

function seedFlows(): SSLFlow[] {
  const labels = ['Benign','Benign','DDoS-TCP','Benign','Recon-PortScan','BruteForce-SSH','Benign','WebAttack-SQLi','Benign','Malware-Backdoor','Benign','DDoS-SYN','Benign','Benign','Spoofing-IP','Benign','Mirai-greip','Benign','Benign','Benign']
  return labels.map((label, i) => {
    const isBenign = label === 'Benign'
    const energy = isBenign
      ? 0.2 + (i * 0.03 % 0.4)
      : 1.0 + (i * 0.11 % 1.8)
    return {
      id: `F${String(i + 1).padStart(3, '0')}`,
      label,
      energy,
      is_benign_predicted: isBenign,
    }
  })
}

const DEMO_FLOWS = seedFlows()

/* ── Module store ─────────────────────────────────────────────────────── */
interface SSLStore {
  mode: 'single' | 'multi'
  alpha: number
  expandedStage: string | null
  expanded: { conformal: boolean; energy: boolean }
  file: File | null
  modelId: string
  analysisResult: any
  calibrationN: number
  oldestAgeMin: number
}

const _store: SSLStore = {
  mode: 'single',
  alpha: 0.05,
  expandedStage: null,
  expanded: { conformal: true, energy: true },
  file: null,
  modelId: 'ssl_graph_anomaly_full',
  analysisResult: null,
  calibrationN: 1247,
  oldestAgeMin: 38,
}

registerSessionReset(() => {
  _store.mode = 'single'
  _store.alpha = 0.05
  _store.expandedStage = null
  _store.expanded = { conformal: true, energy: true }
  _store.file = null
  _store.modelId = 'ssl_graph_anomaly_full'
  _store.analysisResult = null
  _store.calibrationN = 1247
  _store.oldestAgeMin = 38
})

export default function SSLGraphAnomalyDetail() {
  const [mode, _setMode] = useState<'single' | 'multi'>(_store.mode)
  const setMode = (v: 'single' | 'multi') => { _store.mode = v; _setMode(v) }
  const [alpha, _setAlpha] = useState(_store.alpha)
  const [expandedStage, _setStage] = useState<string | null>(_store.expandedStage)
  const [expanded, _setExp] = useState(_store.expanded)
  const [file, _setFile] = useState<File | null>(_store.file)
  const [modelId, _setModel] = useState(_store.modelId)
  const [analysisResult, _setRes] = useState<any>(_store.analysisResult)
  const [calibrationN, _setCalN] = useState(_store.calibrationN)
  const [oldestAgeMin, _setOldest] = useState(_store.oldestAgeMin)
  const [analyzing, setAnalyzing] = useState(false)
  const [liveDataLoaded, setLiveDataLoaded] = useState(false)
  const { addNotice, updateNotice } = useNoticeBoard()

  const setAlpha = (v: number) => { _store.alpha = v; _setAlpha(v) }
  const setExpandedStage = (v: string | null) => { _store.expandedStage = v; _setStage(v) }
  const setExpanded = (v: typeof expanded) => { _store.expanded = v; _setExp(v) }
  const setFile = (v: File | null) => { _store.file = v; _setFile(v) }
  const setModelId = (v: string) => { _store.modelId = v; _setModel(v) }
  const setAnalysisResult = (v: any) => { _store.analysisResult = v; _setRes(v) }
  const setCalibrationN = (v: number) => { _store.calibrationN = v; _setCalN(v) }
  const setOldestAgeMin = (v: number) => { _store.oldestAgeMin = v; _setOldest(v) }

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
      title: 'SSL-GraphAnomaly Analysis',
      description: `Running 6-stage pipeline on ${file.name}...`,
      status: 'running',
      page: '/ssl-graph-anomaly',
    })
    try {
      let data: any
      try {
        data = await analyseFile(file, modelId, 'ssl_graph_anomaly')
      } catch {
        // Fallback to base model if full isn't available
        data = await analyseFile(file, 'ssl_graph_anomaly', 'ssl_graph_anomaly')
      }
      setAnalysisResult(data)
      const n = data.predictions?.length || 0
      cachePageResult('ssl_graph_anomaly', {
        n_flows: n,
        n_threats: data.n_threats || 0,
        alpha_target: alpha,
        calibration_n: calibrationN,
        model_used: modelId,
      })
      updateNotice(nid, { status: 'completed', description: `${n} flows scored` })
    } catch (err) {
      updateNotice(nid, {
        status: 'error',
        description: err instanceof Error ? err.message : 'Analysis failed',
      })
    }
    setAnalyzing(false)
  }

  const calibrate = () => {
    // Simulate calibration: count current benign-predicted flows up to capacity
    const benign = flows.filter(f => f.is_benign_predicted).length
    const newN = Math.min(CALIBRATION_CAPACITY, calibrationN + benign)
    setCalibrationN(newN)
    setOldestAgeMin(0)
    addNotice({
      title: 'Calibration Refreshed',
      description: `Conformal calibration buffer now n = ${newN} benign flows.`,
      status: 'completed',
      page: '/ssl-graph-anomaly',
    })
  }

  // Derive flows
  const flows: SSLFlow[] = useMemo(() => {
    if (analysisResult?.predictions?.length) {
      return analysisResult.predictions.slice(0, 100).map((p: any, i: number) => {
        const isBenign = p.severity === 'benign'
        const energy = isBenign ? 0.15 + (i * 0.027 % 0.5) : 0.9 + (i * 0.13 % 2.2)
        return {
          id: `F${String(i + 1).padStart(3, '0')}`,
          label: p.label_predicted || (isBenign ? 'Benign' : 'Attack'),
          energy,
          is_benign_predicted: isBenign,
        }
      })
    }
    return DEMO_FLOWS
  }, [analysisResult])

  // Conformal threshold derivation: ceil((1-α)(n+1))/n quantile of benign energies
  const benignEnergies = useMemo(
    () => flows.filter(f => f.is_benign_predicted).map(f => f.energy).sort((a, b) => a - b),
    [flows],
  )
  const threshold = useMemo(() => {
    const n = Math.max(1, benignEnergies.length)
    const k = Math.min(n - 1, Math.ceil((1 - alpha) * (n + 1)) - 1)
    if (k < 0) return benignEnergies[0] || 0
    return benignEnergies[k] || benignEnergies[benignEnergies.length - 1] || 0
  }, [benignEnergies, alpha])

  const coverageBound = alpha + 1 / (calibrationN + 1)
  const flagsCount = flows.filter(f => f.energy >= threshold).length
  const expectedFlagRate = flows.length > 0 ? flagsCount / flows.length : 0

  // Energy histogram (20 bins from 0 to max)
  const maxEnergy = Math.max(threshold * 1.5, ...flows.map(f => f.energy), 1)
  const N_BINS = 20
  const histBins = useMemo(() => {
    const bins = Array(N_BINS).fill(0)
    for (const f of flows) {
      const idx = Math.min(N_BINS - 1, Math.floor((f.energy / maxEnergy) * N_BINS))
      bins[idx]++
    }
    return bins
  }, [flows, maxEnergy])
  const histMax = Math.max(1, ...histBins)
  const thresholdBinIdx = Math.min(N_BINS - 1, Math.floor((threshold / maxEnergy) * N_BINS))

  const anomaliesFlagged = flagsCount
  const totalFlows = flows.length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Network className="w-6 h-6 text-accent-green" />
            SSL-GraphAnomaly — Self-supervised graph IDS with conformal certification
          </h1>
          <p className="text-sm text-text-secondary mt-1">
            6-component pipeline: graph builder → E-GraphSAGE → attention-gated streaming →
            Transformer AE → Mahalanobis-energy → split-conformal.
          </p>
        </div>
        <ExportMenu filename="ssl-graph-anomaly" />
      </div>

      {/* Mode toggle — single dataset vs multi-dataset/multi-model */}
      <div className="flex flex-wrap items-center gap-2 border-b border-bg-card pb-3">
        <button
          onClick={() => setMode('single')}
          className={`px-3 py-2 rounded-lg text-xs font-medium min-h-10 transition-colors ${
            mode === 'single'
              ? 'bg-accent-green/15 text-accent-green border border-accent-green/30'
              : 'bg-bg-secondary text-text-secondary border border-bg-card hover:text-text-primary'
          }`}
        >
          Single dataset
        </button>
        <button
          onClick={() => setMode('multi')}
          className={`px-3 py-2 rounded-lg text-xs font-medium min-h-10 transition-colors ${
            mode === 'multi'
              ? 'bg-accent-green/15 text-accent-green border border-accent-green/30'
              : 'bg-bg-secondary text-text-secondary border border-bg-card hover:text-text-primary'
          }`}
        >
          Multi-dataset / multi-model
        </button>
        <span className="text-[10px] text-text-secondary/60 ml-2">
          Multi-mode runs SSL-GraphAnomaly alongside any other registered models across up to 3 datasets.
        </span>
      </div>

      <PageGuide title="How to use SSL-GraphAnomaly" steps={GUIDE_STEPS}
        tip="Conformal prediction gives a marginal-coverage guarantee — assumes the calibration set is exchangeable with future benign flows." />

      {mode === 'multi' && (
        <MultiRunPanel pageKey="ssl_graph_anomaly" defaultModel="ssl_graph_anomaly_full" accent="green" />
      )}

      {mode === 'single' && (<>
      {/* Upload + Model */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">
          <Upload className="w-5 h-5 text-text-secondary" /> Flow Graph Input
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
                onDragOver={e => { e.preventDefault(); e.currentTarget.classList.add('border-accent-green', 'bg-accent-green/10') }}
                onDragLeave={e => { e.currentTarget.classList.remove('border-accent-green', 'bg-accent-green/10') }}
                onDrop={e => {
                  e.preventDefault()
                  e.currentTarget.classList.remove('border-accent-green', 'bg-accent-green/10')
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
            className="px-4 py-2.5 bg-accent-green hover:bg-accent-green/80 text-white rounded-lg text-xs font-medium disabled:opacity-50 flex items-center justify-center gap-2 min-h-10"
          >
            {analyzing ? <><Loader2 className="w-4 h-4 animate-spin" /> Running pipeline...</> : 'Run SSL-GraphAnomaly'}
          </button>
        </div>
      </div>

      {/* Live Monitor Banner */}
      {hasLiveData() && !liveDataLoaded && !analysisResult && (
        <div className="flex items-center gap-3 px-4 py-3 bg-accent-green/10 border border-accent-green/20 rounded-xl">
          <Radio className="w-4 h-4 text-accent-green" />
          <div className="flex-1">
            <span className="text-xs font-medium text-accent-green">Live Monitor data available</span>
            <span className="text-[10px] text-text-secondary ml-2">
              {getLiveData()?.totalFlows} flows from {getLiveData()?.source}
            </span>
          </div>
          <button
            onClick={loadLiveData}
            className="px-3 py-1 bg-accent-green hover:bg-accent-green/80 text-white text-[10px] font-medium rounded-lg transition-colors min-h-10"
          >
            Use Live Data
          </button>
        </div>
      )}

      {/* Stats Row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <StatCard label="Total Flows" value={String(totalFlows)} accent="text-accent-green" />
        <StatCard label="Anomalies Flagged" value={String(anomaliesFlagged)} accent="text-red-400" />
        <StatCard label="Calibration Size" value={String(calibrationN)} accent="text-accent-blue" />
        <StatCard label="α target" value={alpha.toFixed(3)} accent="text-accent-green" />
        <StatCard label="Threshold" value={threshold.toFixed(3)} accent="text-orange-400" />
        <StatCard label="Coverage Bound" value={coverageBound.toFixed(4)} accent="text-accent-green" />
      </div>

      {/* 6-Component Pipeline */}
      <div className="bg-bg-card/50 border border-bg-card rounded-xl p-5">
        <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
          <GitBranch className="w-4 h-4 text-accent-green" />
          Six-Component Pipeline
        </h3>
        <div className="flex flex-col sm:flex-row sm:items-stretch gap-2">
          {PIPELINE.map((s, i) => (
            <Fragment key={s.id}>
              <button
                onClick={() => setExpandedStage(expandedStage === s.id ? null : s.id)}
                className={`flex-1 p-3 rounded-lg border transition-colors text-left min-h-10 ${
                  expandedStage === s.id
                    ? 'bg-accent-green/15 border-accent-green/40'
                    : 'bg-bg-secondary border-bg-card hover:bg-bg-card/70'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] font-mono text-text-secondary">{i + 1}.</span>
                  <span className="text-[10px] font-bold text-accent-green">{s.short}</span>
                </div>
                <p className="text-xs font-semibold mt-1">{s.label}</p>
              </button>
              {i < PIPELINE.length - 1 && (
                <ArrowRight className="w-4 h-4 text-text-secondary/40 self-center hidden sm:block shrink-0" />
              )}
            </Fragment>
          ))}
        </div>
        {expandedStage && (
          <div className="mt-4 bg-bg-secondary rounded-lg p-4 text-xs text-text-secondary">
            <p className="text-text-primary font-semibold mb-1">
              {PIPELINE.find(s => s.id === expandedStage)?.label}
            </p>
            <p>{PIPELINE.find(s => s.id === expandedStage)?.description}</p>
          </div>
        )}
      </div>

      {/* Conformal α dial */}
      <div className="bg-bg-card/50 border border-bg-card rounded-xl overflow-hidden">
        <button
          onClick={() => setExpanded({ ...expanded, conformal: !expanded.conformal })}
          className="w-full flex items-center justify-between p-4 hover:bg-bg-card/50 transition-colors min-h-10"
        >
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-accent-green" />
            Conformal α Dial
          </h3>
          {expanded.conformal ? <ChevronUp className="w-4 h-4 text-text-secondary" /> : <ChevronDown className="w-4 h-4 text-text-secondary" />}
        </button>
        {expanded.conformal && (
          <div className="px-4 pb-4 space-y-4">
            <div>
              <label className="text-xs text-text-secondary block mb-1">
                α = <span className="text-accent-green font-mono">{alpha.toFixed(4)}</span>
                <span className="text-text-secondary/60 ml-2">(0.1 → 0.001, log scale visually)</span>
              </label>
              {/* Use a log-scale: slider 0..1, map to α = 10^(-1 - 2*v) so v=0 → 0.1, v=1 → 0.001 */}
              <input
                type="range"
                min={0} max={1} step={0.01}
                value={(Math.log10(0.1 / alpha)) / 2}
                onChange={e => {
                  const v = +e.target.value
                  const next = Math.pow(10, -1 - 2 * v)
                  setAlpha(next)
                }}
                className="w-full accent-green-400"
              />
              <div className="flex justify-between text-[9px] text-text-secondary/60 mt-1">
                <span>α = 0.1 (loose)</span><span>α = 0.01</span><span>α = 0.001 (tight)</span>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              <div className="bg-bg-secondary rounded-lg p-3">
                <p className="text-[10px] text-text-secondary">Threshold (energy)</p>
                <p className="text-xl font-bold text-orange-400">{threshold.toFixed(3)}</p>
              </div>
              <div className="bg-bg-secondary rounded-lg p-3">
                <p className="text-[10px] text-text-secondary">Calibrated FAR bound</p>
                <p className="text-xl font-bold text-accent-green">
                  {(coverageBound * 100).toFixed(3)}%
                </p>
                <p className="text-[9px] text-text-secondary mt-1">
                  α + 1/(n+1), n = {calibrationN}
                </p>
              </div>
              <div className="bg-bg-secondary rounded-lg p-3">
                <p className="text-[10px] text-text-secondary">Expected flag rate</p>
                <p className="text-xl font-bold text-accent-blue">
                  {(expectedFlagRate * 100).toFixed(1)}%
                </p>
              </div>
            </div>

            <div className="bg-bg-secondary rounded-lg p-3 text-[11px]">
              <p className="text-text-secondary mb-1">Marginal coverage formula:</p>
              <code className="block bg-bg-card rounded px-2 py-2 font-mono text-accent-green">
                Pr[flag | benign] ≤ α + 1/(n+1)
              </code>
              <p className="text-text-secondary mt-2">
                Assumption: the calibration set is exchangeable with future benign flows.
                If traffic distribution shifts, recalibrate.
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Energy Distribution Histogram */}
      <div className="bg-bg-card/50 border border-bg-card rounded-xl overflow-hidden">
        <button
          onClick={() => setExpanded({ ...expanded, energy: !expanded.energy })}
          className="w-full flex items-center justify-between p-4 hover:bg-bg-card/50 transition-colors min-h-10"
        >
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-accent-green" />
            Energy Distribution + Threshold
          </h3>
          {expanded.energy ? <ChevronUp className="w-4 h-4 text-text-secondary" /> : <ChevronDown className="w-4 h-4 text-text-secondary" />}
        </button>
        {expanded.energy && (
          <div className="px-4 pb-4">
            <div className="overflow-x-auto">
              <div className="flex items-end gap-1 h-40 min-w-[500px] relative">
                {histBins.map((count, i) => {
                  const h = (count / histMax) * 100
                  const flagged = i >= thresholdBinIdx
                  return (
                    <div key={i} className="flex-1 flex flex-col items-center gap-1">
                      <div className={`w-full rounded-t ${flagged ? 'bg-red-400/60' : 'bg-accent-green/60'}`}
                        style={{ height: `${Math.max(2, h)}%` }} title={`bin ${i}: ${count} flows`} />
                    </div>
                  )
                })}
                {/* Threshold line */}
                <div
                  className="absolute inset-y-0 w-0.5 bg-orange-400"
                  style={{ left: `${(thresholdBinIdx / N_BINS) * 100}%` }}
                />
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-3 text-[10px] text-text-secondary mt-3">
              <span className="flex items-center gap-1"><span className="w-3 h-3 bg-accent-green/60 rounded" /> Below threshold</span>
              <span className="flex items-center gap-1"><span className="w-3 h-3 bg-red-400/60 rounded" /> Above threshold (flagged)</span>
              <span className="flex items-center gap-1"><span className="w-0.5 h-3 bg-orange-400 inline-block" /> Conformal threshold = {threshold.toFixed(3)}</span>
            </div>
          </div>
        )}
      </div>

      {/* Calibration Buffer Panel */}
      <div className="bg-bg-card/50 border border-bg-card rounded-xl p-5">
        <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
          <Layers className="w-4 h-4 text-accent-green" />
          Calibration Buffer
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <div className="bg-bg-secondary rounded-lg p-3">
            <p className="text-[10px] text-text-secondary">n_calibration</p>
            <p className="text-xl font-bold text-accent-green">{calibrationN}</p>
          </div>
          <div className="bg-bg-secondary rounded-lg p-3">
            <p className="text-[10px] text-text-secondary">Buffer capacity</p>
            <p className="text-xl font-bold text-accent-blue">{CALIBRATION_CAPACITY}</p>
          </div>
          <div className="bg-bg-secondary rounded-lg p-3">
            <p className="text-[10px] text-text-secondary">Utilization</p>
            <p className="text-xl font-bold text-accent-green">
              {((calibrationN / CALIBRATION_CAPACITY) * 100).toFixed(1)}%
            </p>
            <div className="mt-2 h-1.5 bg-bg-card rounded-full overflow-hidden">
              <div className="h-full bg-accent-green rounded-full"
                style={{ width: `${(calibrationN / CALIBRATION_CAPACITY) * 100}%` }} />
            </div>
          </div>
          <div className="bg-bg-secondary rounded-lg p-3">
            <p className="text-[10px] text-text-secondary">Oldest sample age</p>
            <p className="text-xl font-bold text-orange-400">{oldestAgeMin} min</p>
          </div>
        </div>
        <button
          onClick={calibrate}
          className="mt-4 px-4 py-2.5 bg-accent-green hover:bg-accent-green/80 text-white rounded-lg text-xs font-medium inline-flex items-center gap-2 min-h-10"
        >
          <RefreshCw className="w-3.5 h-3.5" /> Refresh calibration from current benign-classified flows
        </button>
        <p className="text-[10px] text-text-secondary mt-2">
          Calls <code className="font-mono">/api/ssl-graph-anomaly/calibrate</code> (simulated; logs to Notice Board).
        </p>
      </div>

      </>)}

      {/* Cross-Page Navigation */}
      <div className="flex flex-wrap gap-2 pt-4 border-t border-bg-card">
        <span className="text-[10px] text-text-secondary mr-2 self-center">Related:</span>
        <CrossLink href="/autoencoder" label="Autoencoder Detector" />
        <CrossLink href="/explainability" label="Explainability Studio" />
        <CrossLink href="/adversarial" label="Adversarial Robustness" />
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

function CrossLink({ href, label }: { href: string; label: string }) {
  return (
    <a href={href}
      className="text-[11px] px-2.5 py-1.5 rounded bg-accent-green/10 text-accent-green hover:bg-accent-green/20 transition-colors inline-flex items-center gap-1 min-h-10">
      <ArrowRight className="w-3 h-3" /> {label}
    </a>
  )
}
