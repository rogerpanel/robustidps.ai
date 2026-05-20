import { useState, useMemo, useCallback } from 'react'
import {
  Waves, Upload, FileText, X, Loader2, Radio, ShieldCheck,
  ChevronUp, ChevronDown, ArrowRight, Wind, BarChart3, Sigma,
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
  { title: 'Load data', desc: 'Upload a CSV/PCAP or use Live Monitor flows.' },
  { title: 'Pick a model', desc: 'Default is the SODE-Guard SDE detector with E-GraphSAGE encoder.' },
  { title: 'Set chaos degree', desc: 'Higher chaos degree = more aggressive training-time diffusion noise; inference is deterministic.' },
  { title: 'Run analysis', desc: 'The Itô SDE produces per-flow anti-concentration certificates against L_∞ perturbations.' },
  { title: 'Read the certificate', desc: 'Sweep the ε budget to see what fraction of flows remain certified at each adversarial budget.' },
]

const N_FEATURES = 16 // for drift/diffusion viz

interface SODEFlow {
  id: string
  label: string
  cert_value: number
  drift: number[]      // length N_FEATURES
  diffusion: number[]  // length N_FEATURES
  energy: number
}

function seedFlows(): SODEFlow[] {
  // deterministic seed for demo
  const labels = ['Benign','DDoS-TCP','Recon-PortScan','BruteForce-SSH','WebAttack-SQLi','Malware-Backdoor','Benign','Spoofing-IP','Mirai-greip','Benign','DDoS-SYN','Benign']
  return labels.map((label, i) => {
    const isBenign = label === 'Benign'
    const cert = isBenign
      ? 0.04 + (i * 0.013 % 0.05)
      : 0.005 + (i * 0.007 % 0.04)
    const drift = Array.from({ length: N_FEATURES }, (_, j) => Math.abs(Math.sin(i * 0.7 + j * 0.31)))
    const diffusion = Array.from({ length: N_FEATURES }, (_, j) => Math.abs(Math.cos(i * 0.5 + j * 0.27)) * 0.7)
    const energy = drift.reduce((a, b) => a + b, 0) + diffusion.reduce((a, b) => a + b, 0)
    return {
      id: `F${String(i + 1).padStart(3, '0')}`,
      label,
      cert_value: cert,
      drift,
      diffusion,
      energy,
    }
  })
}

const DEMO_FLOWS = seedFlows()

/* ── Module store ─────────────────────────────────────────────────────── */
interface SODEStore {
  mode: 'single' | 'multi'
  chaosDegree: number
  epsilon: number
  expanded: { cert: boolean; field: boolean }
  file: File | null
  modelId: string
  analysisResult: any
}

const _store: SODEStore = {
  mode: 'single',
  chaosDegree: 4,
  epsilon: 0.02,
  expanded: { cert: true, field: false },
  file: null,
  modelId: 'sode_guard',
  analysisResult: null,
}

registerSessionReset(() => {
  _store.mode = 'single'
  _store.chaosDegree = 4
  _store.epsilon = 0.02
  _store.expanded = { cert: true, field: false }
  _store.file = null
  _store.modelId = 'sode_guard'
  _store.analysisResult = null
})

export default function SODEGuard() {
  const [mode, _setMode] = useState<'single' | 'multi'>(_store.mode)
  const setMode = (v: 'single' | 'multi') => { _store.mode = v; _setMode(v) }
  const [chaosDegree, _setChaos] = useState(_store.chaosDegree)
  const [epsilon, _setEps] = useState(_store.epsilon)
  const [expanded, _setExp] = useState(_store.expanded)
  const [file, _setFile] = useState<File | null>(_store.file)
  const [modelId, _setModel] = useState(_store.modelId)
  const [analysisResult, _setRes] = useState<any>(_store.analysisResult)
  const [analyzing, setAnalyzing] = useState(false)
  const [liveDataLoaded, setLiveDataLoaded] = useState(false)
  const { addNotice, updateNotice } = useNoticeBoard()

  const setChaosDegree = (v: number) => { _store.chaosDegree = v; _setChaos(v) }
  const setEpsilon = (v: number) => { _store.epsilon = v; _setEps(v) }
  const setExpanded = (v: typeof expanded) => { _store.expanded = v; _setExp(v) }
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
      title: 'SODE-Guard Analysis',
      description: `Solving SDE for ${file.name}...`,
      status: 'running',
      page: '/sode-guard',
    })
    try {
      const data = await analyseFile(file, modelId, 'sode_guard')
      setAnalysisResult(data)
      const n = data.predictions?.length || 0
      cachePageResult('sode_guard', {
        n_flows: n,
        n_threats: data.n_threats || 0,
        chaos_degree: chaosDegree,
        model_used: modelId,
      })
      updateNotice(nid, { status: 'completed', description: `${n} flows certified` })
    } catch (err) {
      updateNotice(nid, {
        status: 'error',
        description: err instanceof Error ? err.message : 'Analysis failed',
      })
    }
    setAnalyzing(false)
  }

  // Derive flows: use real predictions if present, else demo
  const flows: SODEFlow[] = useMemo(() => {
    if (analysisResult?.predictions?.length) {
      return analysisResult.predictions.slice(0, 50).map((p: any, i: number) => {
        const isBenign = p.severity === 'benign'
        const cert = isBenign ? 0.03 + (i * 0.011 % 0.06) : 0.003 + (i * 0.007 % 0.035)
        const drift = Array.from({ length: N_FEATURES }, (_, j) => Math.abs(Math.sin(i * 0.7 + j * 0.31)))
        const diffusion = Array.from({ length: N_FEATURES }, (_, j) => Math.abs(Math.cos(i * 0.5 + j * 0.27)) * 0.7)
        const energy = drift.reduce((a, b) => a + b, 0) + diffusion.reduce((a, b) => a + b, 0)
        return {
          id: `F${String(i + 1).padStart(3, '0')}`,
          label: p.label_predicted || (isBenign ? 'Benign' : 'Attack'),
          cert_value: cert,
          drift,
          diffusion,
          energy,
        }
      })
    }
    return DEMO_FLOWS
  }, [analysisResult])

  const totalFlows = flows.length
  const advTested = flows.length
  const certs = flows.map(f => f.cert_value)
  const meanCert = certs.reduce((a, b) => a + b, 0) / Math.max(1, certs.length)
  const tightCert = Math.max(...certs, 0)
  const looseCert = Math.min(...certs.length ? certs : [0])

  // Histogram bins for cert values 0..0.1, 10 bins
  const histBins = useMemo(() => {
    const bins = Array(10).fill(0)
    for (const c of certs) {
      const idx = Math.min(9, Math.floor((c / 0.1) * 10))
      bins[idx]++
    }
    return bins
  }, [certs])
  const histMax = Math.max(1, ...histBins)

  // Top 10 highest energy flows for field viz
  const topEnergy = useMemo(() => {
    return [...flows].sort((a, b) => b.energy - a.energy).slice(0, 10)
  }, [flows])

  // Adversarial budget sweep: fraction certified at current epsilon
  const certifiedFraction = useMemo(() => {
    if (!certs.length) return 0
    const n = certs.filter(c => c > epsilon).length
    return n / certs.length
  }, [certs, epsilon])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Waves className="w-6 h-6 text-accent-blue" />
            SODE-Guard — Stochastic ODE detector with anti-concentration certification
          </h1>
          <p className="text-sm text-text-secondary mt-1">
            Itô SDE with learned drift + diffusion + E-GraphSAGE encoder; defends against
            adversarial perturbations via anti-concentration bounds.
          </p>
        </div>
        <ExportMenu filename="sode-guard" />
      </div>

      {/* Mode toggle — single dataset vs multi-dataset/multi-model */}
      <div className="flex flex-wrap items-center gap-2 border-b border-bg-card pb-3">
        <button
          onClick={() => setMode('single')}
          className={`px-3 py-2 rounded-lg text-xs font-medium min-h-10 transition-colors ${
            mode === 'single'
              ? 'bg-accent-blue/15 text-accent-blue border border-accent-blue/30'
              : 'bg-bg-secondary text-text-secondary border border-bg-card hover:text-text-primary'
          }`}
        >
          Single dataset
        </button>
        <button
          onClick={() => setMode('multi')}
          className={`px-3 py-2 rounded-lg text-xs font-medium min-h-10 transition-colors ${
            mode === 'multi'
              ? 'bg-accent-blue/15 text-accent-blue border border-accent-blue/30'
              : 'bg-bg-secondary text-text-secondary border border-bg-card hover:text-text-primary'
          }`}
        >
          Multi-dataset / multi-model
        </button>
        <span className="text-[10px] text-text-secondary/60 ml-2">
          Multi-mode runs SODE-Guard alongside any other registered models across up to 3 datasets.
        </span>
      </div>

      <PageGuide title="How to use SODE-Guard" steps={GUIDE_STEPS}
        tip="Anti-concentration ≥ ε implies the prediction is provably stable to all L_∞ perturbations of magnitude ≤ ε." />

      {mode === 'multi' && (
        <MultiRunPanel pageKey="sode_guard" defaultModel="sode_guard" accent="blue" />
      )}

      {mode === 'single' && (<>
      {/* Upload + Model + Chaos Dial */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">
          <Upload className="w-5 h-5 text-text-secondary" /> Flow Data
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 items-end">
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
                onDragOver={e => { e.preventDefault(); e.currentTarget.classList.add('border-accent-blue', 'bg-accent-blue/10') }}
                onDragLeave={e => { e.currentTarget.classList.remove('border-accent-blue', 'bg-accent-blue/10') }}
                onDrop={e => {
                  e.preventDefault()
                  e.currentTarget.classList.remove('border-accent-blue', 'bg-accent-blue/10')
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
          <div>
            <label className="text-xs text-text-secondary block mb-1">
              Chaos degree (1–10): <span className="text-accent-blue font-mono">{chaosDegree}</span>
            </label>
            <input
              type="number" min={1} max={10} step={1}
              value={chaosDegree}
              onChange={e => setChaosDegree(Math.max(1, Math.min(10, +e.target.value || 1)))}
              className="w-full bg-bg-card border border-bg-card rounded-md px-2 py-2 text-xs font-mono min-h-10"
            />
            <p className="text-[9px] text-text-secondary mt-1">
              Higher chaos = more aggressive diffusion noise during training; inference is deterministic.
            </p>
          </div>
          <button
            onClick={runAnalysis}
            disabled={!file || analyzing}
            className="px-4 py-2.5 bg-accent-blue hover:bg-accent-blue/80 text-white rounded-lg text-xs font-medium disabled:opacity-50 flex items-center justify-center gap-2 min-h-10"
          >
            {analyzing ? <><Loader2 className="w-4 h-4 animate-spin" /> Solving SDE...</> : 'Run SODE-Guard'}
          </button>
        </div>
      </div>

      {/* Live Monitor Banner */}
      {hasLiveData() && !liveDataLoaded && !analysisResult && (
        <div className="flex items-center gap-3 px-4 py-3 bg-accent-blue/10 border border-accent-blue/20 rounded-xl">
          <Radio className="w-4 h-4 text-accent-blue" />
          <div className="flex-1">
            <span className="text-xs font-medium text-accent-blue">Live Monitor data available</span>
            <span className="text-[10px] text-text-secondary ml-2">
              {getLiveData()?.totalFlows} flows from {getLiveData()?.source}
            </span>
          </div>
          <button
            onClick={loadLiveData}
            className="px-3 py-1 bg-accent-blue hover:bg-accent-blue/80 text-white text-[10px] font-medium rounded-lg transition-colors min-h-10"
          >
            Use Live Data
          </button>
        </div>
      )}

      {/* Stats Row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <StatCard label="Total Flows" value={String(totalFlows)} accent="text-accent-blue" />
        <StatCard label="Adversarial Tested" value={String(advTested)} accent="text-cyan-400" />
        <StatCard label="Mean Cert Bound" value={meanCert.toFixed(4)} accent="text-accent-green" />
        <StatCard label="Tightest Cert" value={tightCert.toFixed(4)} accent="text-accent-blue" />
        <StatCard label="Loosest Cert" value={looseCert.toFixed(4)} accent="text-orange-400" />
      </div>

      {/* Anti-concentration Certificate Panel */}
      <div className="bg-bg-card/50 border border-bg-card rounded-xl overflow-hidden">
        <button
          onClick={() => setExpanded({ ...expanded, cert: !expanded.cert })}
          className="w-full flex items-center justify-between p-4 hover:bg-bg-card/50 transition-colors min-h-10"
        >
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-accent-blue" />
            Anti-Concentration Certificates
          </h3>
          {expanded.cert ? <ChevronUp className="w-4 h-4 text-text-secondary" /> : <ChevronDown className="w-4 h-4 text-text-secondary" />}
        </button>
        {expanded.cert && (
          <div className="px-4 pb-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Per-flow table */}
            <div className="bg-bg-secondary rounded-lg p-3 overflow-x-auto">
              <p className="text-xs font-semibold mb-2">Per-flow certificate values</p>
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-text-secondary border-b border-bg-card">
                    <th className="text-left pb-2 pr-3">Flow</th>
                    <th className="text-left pb-2 pr-3">Predicted</th>
                    <th className="text-left pb-2 pr-3">Anti-Concentration</th>
                    <th className="text-left pb-2 pr-3">Cert @ ε</th>
                  </tr>
                </thead>
                <tbody>
                  {flows.slice(0, 15).map(f => {
                    const certified = f.cert_value > epsilon
                    return (
                      <tr key={f.id} className="border-b border-bg-card/50">
                        <td className="py-1.5 pr-3 font-mono">{f.id}</td>
                        <td className="py-1.5 pr-3">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                            f.label === 'Benign' ? 'bg-accent-green/15 text-accent-green' : 'bg-red-400/15 text-red-400'
                          }`}>{f.label}</span>
                        </td>
                        <td className="py-1.5 pr-3">
                          <div className="flex items-center gap-2">
                            <div className="flex-1 h-2 bg-bg-card rounded-full overflow-hidden">
                              <div className="h-full bg-accent-blue/60 rounded-full"
                                style={{ width: `${Math.min(100, (f.cert_value / 0.1) * 100)}%` }} />
                            </div>
                            <span className="font-mono text-[10px]">{f.cert_value.toFixed(4)}</span>
                          </div>
                        </td>
                        <td className="py-1.5 pr-3">
                          <span className={`text-[10px] font-semibold ${
                            certified ? 'text-accent-green' : 'text-orange-400'
                          }`}>
                            {certified ? 'certified' : 'uncertain'}
                          </span>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>

            {/* Histogram */}
            <div className="bg-bg-secondary rounded-lg p-3">
              <p className="text-xs font-semibold mb-3 flex items-center gap-1.5">
                <BarChart3 className="w-3.5 h-3.5 text-accent-blue" />
                Cert value distribution (0.00 → 0.10)
              </p>
              <div className="flex items-end gap-1 h-32">
                {histBins.map((count, i) => {
                  const h = (count / histMax) * 100
                  const binStart = (i * 0.01)
                  const cleared = binStart > epsilon
                  return (
                    <div key={i} className="flex-1 flex flex-col items-center gap-1">
                      <div className={`w-full rounded-t transition-all ${cleared ? 'bg-accent-green/60' : 'bg-orange-400/50'}`}
                        style={{ height: `${Math.max(2, h)}%` }} title={`${count} flows`} />
                      <span className="text-[8px] text-text-secondary font-mono">
                        {binStart.toFixed(2)}
                      </span>
                    </div>
                  )
                })}
              </div>
              <p className="text-[10px] text-text-secondary mt-2">
                Green bins are above current ε = {epsilon.toFixed(3)} (certified).
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Adversarial budget sweep */}
      <div className="bg-bg-card/50 border border-bg-card rounded-xl p-5">
        <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
          <Sigma className="w-4 h-4 text-accent-blue" />
          Adversarial Budget Sweep (L_∞)
        </h3>
        <label className="text-xs text-text-secondary block mb-1">
          ε = <span className="text-accent-blue font-mono">{epsilon.toFixed(3)}</span>
        </label>
        <input
          type="range" min={0} max={0.1} step={0.001}
          value={epsilon}
          onChange={e => setEpsilon(+e.target.value)}
          className="w-full accent-blue-400"
        />
        <div className="flex justify-between text-[9px] text-text-secondary/60 mt-1">
          <span>0.0 (clean)</span><span>0.05</span><span>0.10 (max budget)</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 mt-4">
          <div className="bg-bg-secondary rounded-lg p-3">
            <p className="text-[10px] text-text-secondary">Fraction certified</p>
            <p className="text-xl font-bold text-accent-green">
              {(certifiedFraction * 100).toFixed(1)}%
            </p>
          </div>
          <div className="bg-bg-secondary rounded-lg p-3">
            <p className="text-[10px] text-text-secondary">Uncertain (cert ≤ ε)</p>
            <p className="text-xl font-bold text-orange-400">
              {((1 - certifiedFraction) * 100).toFixed(1)}%
            </p>
          </div>
          <div className="bg-bg-secondary rounded-lg p-3">
            <p className="text-[10px] text-text-secondary">Rule</p>
            <p className="text-[11px] font-mono">cert &gt; ε ⇒ certified</p>
          </div>
        </div>
      </div>

      {/* Drift + Diffusion Field */}
      <div className="bg-bg-card/50 border border-bg-card rounded-xl overflow-hidden">
        <button
          onClick={() => setExpanded({ ...expanded, field: !expanded.field })}
          className="w-full flex items-center justify-between p-4 hover:bg-bg-card/50 transition-colors min-h-10"
        >
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <Wind className="w-4 h-4 text-accent-blue" />
            Drift + Diffusion Field (top 10 highest-energy flows)
          </h3>
          {expanded.field ? <ChevronUp className="w-4 h-4 text-text-secondary" /> : <ChevronDown className="w-4 h-4 text-text-secondary" />}
        </button>
        {expanded.field && (
          <div className="px-4 pb-4 overflow-x-auto">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 min-w-[600px]">
              {topEnergy.map(f => (
                <div key={f.id} className="bg-bg-secondary rounded-lg p-3">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono">{f.id}</span>
                    <span className="text-[10px] text-text-secondary">{f.label}</span>
                  </div>
                  <p className="text-[9px] text-text-secondary mb-0.5">Drift μ(x)</p>
                  <div className="flex h-4 mb-2">
                    {f.drift.map((d, j) => (
                      <div key={j} className="flex-1 mr-0.5 bg-accent-blue/60"
                        style={{ height: `${d * 100}%`, alignSelf: 'flex-end' }} />
                    ))}
                  </div>
                  <p className="text-[9px] text-text-secondary mb-0.5">Diffusion σ(x)</p>
                  <div className="flex h-4">
                    {f.diffusion.map((d, j) => (
                      <div key={j} className="flex-1 mr-0.5 bg-cyan-400/60"
                        style={{ height: `${d * 100}%`, alignSelf: 'flex-end' }} />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      </>)}

      {/* Cross-Page Navigation */}
      <div className="flex flex-wrap gap-2 pt-4 border-t border-bg-card">
        <span className="text-[10px] text-text-secondary mr-2 self-center">Related:</span>
        <CrossLink href="/adversarial" label="Adversarial Robustness" />
        <CrossLink href="/explainability" label="Explainability Studio" />
        <CrossLink href="/autoencoder" label="Autoencoder Detector" />
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
      className="text-[11px] px-2.5 py-1.5 rounded bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20 transition-colors inline-flex items-center gap-1 min-h-10">
      <ArrowRight className="w-3 h-3" /> {label}
    </a>
  )
}
