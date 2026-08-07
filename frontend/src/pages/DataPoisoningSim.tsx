import { useState, useCallback } from 'react'
import {
  Shuffle, KeySquare, TrendingDown, Eye, Play, RotateCcw,
  ShieldAlert, AlertTriangle, CheckCircle2, XCircle, Shield,
  Activity, Beaker, Upload, FileText, X, Loader2, Radio,
} from 'lucide-react'
import { getLiveData, hasLiveData } from '../utils/liveDataStore'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import ModelSelector from '../components/ModelSelector'
import { analyseFile } from '../utils/api'
import { useNoticeBoard } from '../hooks/useNoticeBoard'

/* ── Poison Strategies ──────────────────────────────────────────────── */
const ICON_MAP: Record<string, typeof Shuffle> = {
  Shuffle, KeySquare, TrendingDown, Eye,
}

const POISON_STRATEGIES = [
  {
    id: 'label_flip',
    name: 'Label Flipping',
    desc: 'Randomly flip labels of a percentage of training samples (e.g., benign \u2192 DDoS)',
    icon: 'Shuffle',
    severity: 'high' as const,
    params: { flip_rate: 0.1 },
  },
  {
    id: 'backdoor',
    name: 'Backdoor Trigger',
    desc: 'Insert a trigger pattern into samples that causes specific misclassification when present',
    icon: 'KeySquare',
    severity: 'critical' as const,
    params: { trigger_rate: 0.05, target_class: 'Benign' },
  },
  {
    id: 'gradient_attack',
    name: 'Gradient-Based Poisoning',
    desc: 'Craft poisoned samples that maximally degrade model loss on clean data',
    icon: 'TrendingDown',
    severity: 'critical' as const,
    params: { poison_rate: 0.03, epsilon: 0.1 },
  },
  {
    id: 'clean_label',
    name: 'Clean-Label Attack',
    desc: 'Modify feature values of correctly-labelled samples to cause misclassification at test time',
    icon: 'Eye',
    severity: 'high' as const,
    params: { perturbation: 0.05 },
  },
]

const ATTACK_CLASSES = ['DDoS', 'PortScan', 'BruteForce', 'WebAttack', 'Botnet', 'Infiltration']
const TARGET_CLASSES = ['Benign', ...ATTACK_CLASSES]

const SEVERITY_COLORS: Record<string, string> = {
  high: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
  critical: 'text-red-400 bg-red-400/10 border-red-400/30',
}

/* ── Simulation Logic ───────────────────────────────────────────────── */
interface SimResult {
  cleanAccuracy: number
  poisonedAccuracy: number
  drop: number
  detectionRate: number
  perClass: { name: string; clean: number; poisoned: number }[]
  recommendations: string[]
}

function simulatePoisoning(strategy: string, poisonRate: number, cleanAccuracy: number): SimResult {
  const degradation: Record<string, number> = {
    label_flip: poisonRate * 2.5,
    backdoor: poisonRate * 4.0,
    gradient_attack: poisonRate * 5.0,
    clean_label: poisonRate * 1.5,
  }
  const drop = degradation[strategy] || poisonRate * 2
  const poisonedAccuracy = Math.max(cleanAccuracy - drop * 100, 10)
  const detectionRate = strategy === 'label_flip' ? 0.85 : strategy === 'clean_label' ? 0.35 : 0.65

  // Per-class degradation (some classes affected more than others)
  const seed = strategy.length
  const perClass = ATTACK_CLASSES.map((name, i) => {
    const classClean = cleanAccuracy - (i % 3) * 2
    const variance = ((i + seed) % 5) / 10
    const classDrop = drop * 100 * (0.7 + variance)
    return {
      name,
      clean: Math.round(classClean * 10) / 10,
      poisoned: Math.round(Math.max(classClean - classDrop, 5) * 10) / 10,
    }
  })

  const recommendations = [
    'Apply spectral signature filtering to detect poisoned samples in the training set.',
    strategy === 'backdoor'
      ? 'Use Neural Cleanse or activation clustering to identify potential backdoor triggers.'
      : 'Implement robust aggregation (trimmed mean) during training to limit outlier influence.',
    detectionRate < 0.5
      ? 'Clean-label attacks are hard to detect statistically \u2014 consider certified defenses or differential privacy.'
      : 'Enable STRIP (STRong Intentional Perturbation) defense for real-time trigger detection.',
    'Retrain on a curated, verified subset of data to recover model accuracy.',
  ]

  return {
    cleanAccuracy,
    poisonedAccuracy: Math.round(poisonedAccuracy * 10) / 10,
    drop: Math.round(drop * 1000) / 10,
    detectionRate,
    perClass,
    recommendations,
  }
}

/* ── Component ──────────────────────────────────────────────────────── */
export default function DataPoisoningSim() {
  const [selectedStrategy, setSelectedStrategy] = useState(POISON_STRATEGIES[0].id)
  const [poisonRate, setPoisonRate] = useState(10)
  const [targetClass, setTargetClass] = useState('Benign')
  const [numSamples, setNumSamples] = useState(5000)
  const [defensesEnabled, setDefensesEnabled] = useState(false)
  const [result, setResult] = useState<SimResult | null>(null)
  const [running, setRunning] = useState(false)

  const [file, setFile] = useState<File | null>(null)
  const [modelId, setModelId] = useState('surrogate')
  const [baselineResult, setBaselineResult] = useState<any>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [cleanAccuracy, setCleanAccuracy] = useState(97.8) // default demo value
  const [liveDataLoaded, setLiveDataLoaded] = useState(false)
  const { addNotice, updateNotice } = useNoticeBoard()

  const loadLiveData = useCallback(() => {
    const live = getLiveData()
    if (!live) return
    setBaselineResult({
      predictions: live.predictions,
      n_flows: live.totalFlows,
      n_threats: live.threatCount,
      n_benign: live.benignCount,
    })
    // Compute cleanAccuracy from live predictions
    const correct = live.predictions?.filter((p: any) => p.label_predicted === p.label_true).length || 0
    const total = live.predictions?.length || 1
    const baseAcc = (correct / total) * 100
    setCleanAccuracy(baseAcc)
    setLiveDataLoaded(true)
  }, [])

  const runBaselineAnalysis = async () => {
    if (!file) return
    setAnalyzing(true)
    const nid = addNotice({ title: 'Baseline Analysis', description: `Establishing clean accuracy on ${file.name}...`, status: 'running', page: '/data-poisoning' })
    try {
      const data = await analyseFile(file, modelId, 'data_poisoning')
      setBaselineResult(data)
      // Calculate baseline accuracy from predictions
      const correct = data.predictions?.filter((p: any) => p.label_predicted === p.label_true).length || 0
      const total = data.predictions?.length || 1
      const baseAcc = (correct / total) * 100
      setCleanAccuracy(baseAcc)
      updateNotice(nid, { status: 'completed', description: `Baseline: ${baseAcc.toFixed(1)}% accuracy on ${total} samples` })
    } catch (err) {
      updateNotice(nid, { status: 'error', description: err instanceof Error ? err.message : 'Analysis failed' })
    }
    setAnalyzing(false)
  }

  const runSimulation = useCallback(() => {
    setRunning(true)
    setTimeout(() => {
      const res = simulatePoisoning(selectedStrategy, poisonRate / 100, cleanAccuracy)
      setResult(res)
      setRunning(false)
    }, 800)
  }, [selectedStrategy, poisonRate, cleanAccuracy])

  const reset = () => {
    setResult(null)
    setSelectedStrategy(POISON_STRATEGIES[0].id)
    setPoisonRate(10)
    setTargetClass('Benign')
    setNumSamples(5000)
    setDefensesEnabled(false)
    setFile(null)
    setBaselineResult(null)
    setCleanAccuracy(97.8)
  }

  const activeStrat = POISON_STRATEGIES.find(s => s.id === selectedStrategy)!

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Beaker className="w-6 h-6 text-orange-400" />
            Data Poisoning Simulator
          </h1>
          <p className="text-sm text-text-secondary mt-1">
            Inject poisoned training samples and observe model accuracy degradation across attack classes.
          </p>
        </div>
        <ExportMenu filename="data-poisoning-sim" />
      </div>

      <PageGuide
        title="How to use this simulator"
        steps={[
          { title: 'Choose a strategy', desc: 'Select one of four data poisoning attack types.' },
          { title: 'Configure parameters', desc: 'Set poison rate, target class, and sample count.' },
          { title: 'Run simulation', desc: 'Execute the poisoning simulation and view accuracy impact.' },
          { title: 'Analyze results', desc: 'Review per-class degradation and recovery recommendations.' },
        ]}
        tip="All simulations run locally with deterministic calculations \u2014 no real models are harmed."
      />

      {/* Baseline Upload & Model Selection */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">
          Establish Baseline (Optional)
        </h2>
        <p className="text-xs text-text-secondary mb-3">
          Upload a dataset and run model inference to establish real baseline accuracy before simulating poisoning effects.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end">
          {/* Drag & drop */}
          <div>
            {file ? (
              <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-accent-green/30 bg-accent-green/5">
                <FileText className="w-4 h-4 text-accent-green shrink-0" />
                <span className="text-xs font-mono truncate flex-1">{file.name}</span>
                <button onClick={() => { setFile(null); setBaselineResult(null) }} className="text-text-secondary hover:text-text-primary"><X className="w-3.5 h-3.5" /></button>
              </div>
            ) : (
              <label onDragOver={e => { e.preventDefault(); e.currentTarget.classList.add('border-accent-blue','bg-accent-blue/10') }} onDragLeave={e => { e.currentTarget.classList.remove('border-accent-blue','bg-accent-blue/10') }} onDrop={e => { e.preventDefault(); e.currentTarget.classList.remove('border-accent-blue','bg-accent-blue/10'); const f = e.dataTransfer.files[0]; if(f) setFile(f) }} className="flex flex-col items-center gap-1 px-3 py-3 rounded-lg border-2 border-dashed border-bg-card hover:border-text-secondary cursor-pointer transition-colors">
                <Upload className="w-5 h-5 text-text-secondary" />
                <span className="text-[10px] text-text-secondary">Drop or click</span>
                <span className="text-[9px] text-text-secondary/60">.csv .pcap .pcapng</span>
                <input type="file" accept=".csv,.pcap,.pcapng" className="hidden" onChange={e => setFile(e.target.files?.[0] || null)} />
              </label>
            )}
          </div>
          <div>
            <label className="text-xs text-text-secondary block mb-1">Target Model</label>
            <ModelSelector value={modelId} onChange={setModelId} compact />
          </div>
          <button onClick={runBaselineAnalysis} disabled={!file || analyzing} className="px-4 py-2.5 bg-accent-blue hover:bg-accent-blue/80 text-white rounded-lg text-xs font-medium disabled:opacity-50 flex items-center justify-center gap-2">
            {analyzing ? <><Loader2 className="w-4 h-4 animate-spin" /> Establishing Baseline...</> : 'Establish Baseline'}
          </button>
        </div>
        {baselineResult && (
          <div className="mt-3 p-3 bg-accent-green/5 border border-accent-green/20 rounded-lg text-xs text-accent-green">
            Baseline established: {cleanAccuracy.toFixed(1)}% accuracy on {baselineResult.predictions?.length || 0} samples using {modelId}
          </div>
        )}
      </div>

      {/* Live Monitor Data Banner */}
      {hasLiveData() && !liveDataLoaded && !baselineResult && (
        <div className="flex items-center gap-3 px-4 py-3 bg-accent-orange/10 border border-accent-orange/20 rounded-xl">
          <Radio className="w-4 h-4 text-accent-orange" />
          <div className="flex-1">
            <span className="text-xs font-medium text-accent-orange">Live Monitor data available</span>
            <span className="text-[10px] text-text-secondary ml-2">{getLiveData()?.totalFlows} flows from {getLiveData()?.source}</span>
          </div>
          <button
            onClick={loadLiveData}
            className="px-3 py-1 bg-accent-orange hover:bg-accent-orange/80 text-white text-[10px] font-medium rounded-lg transition-colors"
          >
            Use Live Data
          </button>
        </div>
      )}

      {/* Strategy Selector */}
      <div>
        <h2 className="text-sm font-semibold text-text-secondary mb-3 uppercase tracking-wider">
          Select Poisoning Strategy
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {POISON_STRATEGIES.map(s => {
            const Icon = ICON_MAP[s.icon] || Activity
            const active = selectedStrategy === s.id
            return (
              <button
                key={s.id}
                onClick={() => setSelectedStrategy(s.id)}
                className={`text-left p-4 rounded-xl border transition-all ${
                  active
                    ? 'border-orange-400/60 bg-orange-400/10 ring-1 ring-orange-400/30'
                    : 'border-bg-card bg-bg-card/50 hover:border-text-secondary/30'
                }`}
              >
                <div className="flex items-center gap-2 mb-2">
                  <Icon className={`w-4 h-4 ${active ? 'text-orange-400' : 'text-text-secondary'}`} />
                  <span className="text-sm font-semibold">{s.name}</span>
                </div>
                <p className="text-xs text-text-secondary leading-relaxed mb-2">{s.desc}</p>
                <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full border ${SEVERITY_COLORS[s.severity]}`}>
                  {s.severity}
                </span>
              </button>
            )
          })}
        </div>
      </div>

      {/* Configuration Panel */}
      <div className="bg-bg-card/50 border border-bg-card rounded-xl p-5">
        <h2 className="text-sm font-semibold mb-4 flex items-center gap-2">
          <Activity className="w-4 h-4 text-orange-400" />
          Configuration \u2014 {activeStrat.name}
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {/* Poison Rate Slider */}
          <div>
            <label className="block text-xs text-text-secondary mb-1">
              Poison Rate: <span className="text-orange-400 font-bold">{poisonRate}%</span>
            </label>
            <input
              type="range" min={1} max={30} value={poisonRate}
              onChange={e => setPoisonRate(+e.target.value)}
              className="w-full accent-orange-400"
            />
            <div className="flex justify-between text-[10px] text-text-secondary mt-0.5">
              <span>1%</span><span>15%</span><span>30%</span>
            </div>
          </div>

          {/* Target Class */}
          <div>
            <label className="block text-xs text-text-secondary mb-1">Target Class</label>
            <select
              value={targetClass}
              onChange={e => setTargetClass(e.target.value)}
              className="w-full bg-bg-secondary border border-bg-card rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-orange-400/50"
            >
              {TARGET_CLASSES.map(c => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          </div>

          {/* Number of Samples */}
          <div>
            <label className="block text-xs text-text-secondary mb-1">Training Samples</label>
            <input
              type="number" min={500} max={50000} step={500} value={numSamples}
              onChange={e => setNumSamples(+e.target.value)}
              className="w-full bg-bg-secondary border border-bg-card rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-orange-400/50"
            />
            <p className="text-[10px] text-text-secondary mt-0.5">
              {Math.round(numSamples * poisonRate / 100)} samples will be poisoned
            </p>
          </div>
        </div>

        {/* Defenses Toggle */}
        <div className="mt-4 flex items-center gap-3">
          <button
            onClick={() => setDefensesEnabled(!defensesEnabled)}
            className={`relative w-10 h-5 rounded-full transition-colors ${defensesEnabled ? 'bg-accent-green' : 'bg-bg-secondary border border-bg-card'}`}
          >
            <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${defensesEnabled ? 'left-5' : 'left-0.5'}`} />
          </button>
          <span className="text-xs text-text-secondary">
            <Shield className="w-3.5 h-3.5 inline mr-1" />
            Enable poison defenses (spectral signatures, STRIP)
          </span>
        </div>
      </div>

      {/* Run Button */}
      <div className="flex gap-3">
        <button
          onClick={runSimulation}
          disabled={running}
          className="flex items-center gap-2 px-5 py-2.5 bg-orange-500 hover:bg-orange-600 disabled:opacity-50 text-white font-semibold rounded-xl transition-colors text-sm"
        >
          {running ? <Activity className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          {running ? 'Running Simulation\u2026' : 'Run Poisoning Simulation'}
        </button>
        {result && (
          <button onClick={reset} className="flex items-center gap-2 px-4 py-2.5 bg-bg-secondary border border-bg-card text-text-secondary hover:text-text-primary rounded-xl text-sm transition-colors">
            <RotateCcw className="w-4 h-4" /> Reset
          </button>
        )}
      </div>

      {/* Results Panel */}
      {result && (
        <div className="space-y-5">
          {/* Accuracy Comparison */}
          <div className="bg-bg-card/50 border border-bg-card rounded-xl p-5">
            <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              Accuracy Impact
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="bg-bg-secondary rounded-lg p-4 text-center">
                <p className="text-xs text-text-secondary mb-1">Clean Accuracy</p>
                <p className="text-2xl font-bold text-accent-green">{result.cleanAccuracy}%{!baselineResult && (
                  <span className="text-[9px] text-accent-amber ml-1">(default — upload data to establish real baseline)</span>
                )}</p>
                <CheckCircle2 className="w-5 h-5 text-accent-green mx-auto mt-1" />
              </div>
              <div className="bg-bg-secondary rounded-lg p-4 text-center">
                <p className="text-xs text-text-secondary mb-1">Poisoned Accuracy</p>
                <p className="text-2xl font-bold text-red-400">{result.poisonedAccuracy}%</p>
                <XCircle className="w-5 h-5 text-red-400 mx-auto mt-1" />
              </div>
              <div className="bg-bg-secondary rounded-lg p-4 text-center">
                <p className="text-xs text-text-secondary mb-1">Accuracy Drop</p>
                <p className="text-2xl font-bold text-orange-400">\u2212{result.drop}%</p>
                <TrendingDown className="w-5 h-5 text-orange-400 mx-auto mt-1" />
              </div>
            </div>
          </div>

          {/* Per-Class Degradation */}
          <div className="bg-bg-card/50 border border-bg-card rounded-xl p-5">
            <h3 className="text-sm font-semibold mb-4">Per-Class Accuracy Degradation</h3>
            <div className="space-y-3">
              {result.perClass.map(c => (
                <div key={c.name}>
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="font-medium">{c.name}</span>
                    <span className="text-text-secondary">
                      {c.clean}% <span className="text-red-400">\u2192 {c.poisoned}%</span>
                    </span>
                  </div>
                  <div className="relative h-4 bg-bg-secondary rounded-full overflow-hidden">
                    <div
                      className="absolute inset-y-0 left-0 bg-accent-green/40 rounded-full"
                      style={{ width: `${c.clean}%` }}
                    />
                    <div
                      className="absolute inset-y-0 left-0 bg-red-400/70 rounded-full"
                      style={{ width: `${c.poisoned}%` }}
                    />
                  </div>
                </div>
              ))}
              <div className="flex items-center gap-4 text-[10px] text-text-secondary mt-2">
                <span className="flex items-center gap-1"><span className="w-3 h-2 bg-accent-green/40 rounded" /> Clean</span>
                <span className="flex items-center gap-1"><span className="w-3 h-2 bg-red-400/70 rounded" /> Poisoned</span>
              </div>
            </div>
          </div>

          {/* Detection Rate */}
          {defensesEnabled && (
            <div className="bg-bg-card/50 border border-bg-card rounded-xl p-5">
              <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                <Shield className="w-4 h-4 text-accent-blue" />
                Poison Detection Rate
              </h3>
              <div className="flex items-center gap-4">
                <div className="flex-1 h-5 bg-bg-secondary rounded-full overflow-hidden">
                  <div
                    className="h-full bg-accent-blue rounded-full transition-all"
                    style={{ width: `${result.detectionRate * 100}%` }}
                  />
                </div>
                <span className="text-sm font-bold text-accent-blue w-14 text-right">
                  {Math.round(result.detectionRate * 100)}%
                </span>
              </div>
              <p className="text-xs text-text-secondary mt-2">
                {result.detectionRate >= 0.7
                  ? 'Defenses are effective at identifying poisoned samples for this attack type.'
                  : 'This attack type is difficult to detect \u2014 consider additional certified defenses.'}
              </p>
            </div>
          )}

          {/* Recommendations */}
          <div className="bg-accent-blue/5 border border-accent-blue/20 rounded-xl p-5">
            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-yellow-400" />
              Recovery Recommendations
            </h3>
            <ul className="space-y-2">
              {result.recommendations.map((rec, i) => (
                <li key={i} className="flex gap-2 text-xs text-text-secondary">
                  <span className="shrink-0 w-5 h-5 rounded-full bg-accent-blue/15 text-accent-blue flex items-center justify-center text-[10px] font-bold">
                    {i + 1}
                  </span>
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Related */}
          <div className="flex flex-wrap gap-2 pt-3 border-t border-bg-card">
            <span className="text-[10px] text-text-secondary mr-2">Related:</span>
            <a href="/adversarial" className="text-[10px] px-2 py-1 rounded bg-accent-red/10 text-accent-red hover:bg-accent-red/20 transition-colors">Adversarial Robustness</a>
            <a href="/redteam" className="text-[10px] px-2 py-1 rounded bg-accent-amber/10 text-accent-amber hover:bg-accent-amber/20 transition-colors">Red Team Arena</a>
            <a href="/supply-chain" className="text-[10px] px-2 py-1 rounded bg-accent-purple/10 text-accent-purple hover:bg-accent-purple/20 transition-colors">Supply Chain Security</a>
          </div>
        </div>
      )}
    </div>
  )
}
