import { useRef } from 'react'
import {
  Swords, Upload, Loader2, ShieldAlert, ShieldCheck, Target, Zap,
  BarChart3, TrendingDown, AlertTriangle, ChevronDown, ChevronUp, Brain,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  Legend, CartesianGrid, Cell,
} from 'recharts'
import FileUpload from '../components/FileUpload'
import ModelSelector from '../components/ModelSelector'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import { runRedteam, fetchSampleData } from '../utils/api'
import { usePageState } from '../hooks/usePageState'

const PAGE = 'redteam'
const TT = { background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }

const ATTACK_OPTS = [
  { id: 'fgsm', label: 'FGSM', desc: 'Fast Gradient Sign — single-step, fast' },
  { id: 'pgd', label: 'PGD (10-step)', desc: 'Projected Gradient Descent — iterative, stronger' },
  { id: 'deepfool', label: 'DeepFool', desc: 'Minimal perturbation to cross boundary' },
  { id: 'gaussian', label: 'Gaussian Noise', desc: 'Random Gaussian perturbation' },
  { id: 'feature_mask', label: 'Feature Masking', desc: 'Randomly zero-out features' },
]

const SEV_COLORS: Record<string, string> = {
  fgsm: '#EF4444', pgd: '#F97316', deepfool: '#F59E0B', gaussian: '#3B82F6', feature_mask: '#A855F7',
}

interface AttackResult {
  attack: string
  label: string
  epsilon: number
  accuracy_clean: number
  accuracy_adversarial: number
  accuracy_drop: number
  confidence_clean: number
  confidence_adversarial: number
  confidence_drop: number
  flip_rate: number
  perturbation_l2: number
  time_ms: number
  per_class: Record<string, { count: number; clean_acc: number; adv_acc: number; flip_rate: number }>
  error?: string
}

interface ArenaResult {
  arena_id: string
  n_samples: number
  epsilon: number
  clean_accuracy: number
  clean_confidence: number
  attacks: AttackResult[]
  robustness_score: number
  model_used: string
}

export default function RedTeamArena() {
  const [file, setFile] = usePageState<File | null>(PAGE, 'file', null)
  const [selectedModel, setSelectedModel] = usePageState(PAGE, 'selectedModel', 'surrogate')
  const [epsilon, setEpsilon] = usePageState(PAGE, 'epsilon', 0.1)
  const [nSamples, setNSamples] = usePageState(PAGE, 'nSamples', 500)
  const [selectedAttacks, setSelectedAttacks] = usePageState<string[]>(PAGE, 'selectedAttacks', ATTACK_OPTS.map(a => a.id))
  const [running, setRunning] = usePageState(PAGE, 'running', false)
  const [result, setResult] = usePageState<ArenaResult | null>(PAGE, 'result', null)
  const [error, setError] = usePageState(PAGE, 'error', '')
  const [expandedAttack, setExpandedAttack] = usePageState<string | null>(PAGE, 'expandedAttack', null)
  const fileRef = useRef<HTMLInputElement>(null)

  const toggleAttack = (id: string) => {
    setSelectedAttacks(prev =>
      prev.includes(id) ? prev.filter(a => a !== id) : [...prev, id]
    )
  }

  const handleRun = async () => {
    if (!file) return
    setRunning(true)
    setError('')
    setResult(null)
    try {
      const data = await runRedteam(file, selectedAttacks, epsilon, nSamples, selectedModel)
      setResult(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Arena failed')
    } finally {
      setRunning(false)
    }
  }

  const radarData = result?.attacks
    .filter(a => !a.error)
    .map(a => ({
      attack: a.label,
      'Accuracy Retained': Math.round(a.accuracy_adversarial * 100),
      'Confidence Retained': Math.round(a.confidence_adversarial * 100),
    })) || []

  const barData = result?.attacks
    .filter(a => !a.error)
    .map(a => ({
      name: a.label,
      'Accuracy Drop': Math.round(a.accuracy_drop * 100 * 10) / 10,
      'Flip Rate': Math.round(a.flip_rate * 100 * 10) / 10,
    })) || []

  return (
    <div className="space-y-6">
      <PageGuide
        title="How to use Adversarial Red Team Arena"
        steps={[
          { title: 'Upload a dataset', desc: 'Drop a network traffic CSV (CIC-IoT, UNSW-NB15, etc.).' },
          { title: 'Select attacks', desc: 'Choose which adversarial attacks to run against the model.' },
          { title: 'Set epsilon', desc: 'Control the perturbation strength (higher = stronger attack).' },
          { title: 'Launch arena', desc: 'Run all selected attacks and view robustness metrics.' },
        ]}
        tip="The arena tests how well the model holds up under adversarial perturbations — essential for deployment confidence."
      />

      {/* Header */}
      <div className="flex items-center gap-3">
        <Swords className="w-7 h-7 text-accent-red" />
        <div className="flex-1">
          <h1 className="text-xl md:text-2xl font-display font-bold">Adversarial Red Team Arena</h1>
          <p className="text-sm text-text-secondary mt-0.5">Stress-test model robustness against adversarial attacks</p>
        </div>
        <ExportMenu filename="red-team" />
      </div>

      {/* Config Panel */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Left: upload + model */}
          <div className="space-y-3">
            <FileUpload
              onFile={(f) => setFile(f)}
              label="Upload traffic dataset"
              accept=".csv,.parquet"
            />
            <button
              onClick={async () => {
                try {
                  const f = await fetchSampleData()
                  setFile(f)
                } catch { setError('Failed to load demo data') }
              }}
              className="text-xs text-accent-blue hover:text-accent-blue/80 underline"
            >
              or use built-in demo data (1000 flows)
            </button>
            {file && (
              <div className="text-xs text-text-secondary flex items-center gap-1">
                <Upload className="w-3 h-3" /> {file.name}
              </div>
            )}
            <ModelSelector value={selectedModel} onChange={setSelectedModel} />
          </div>

          {/* Right: params */}
          <div className="space-y-3">
            <div>
              <label className="text-xs text-text-secondary block mb-1">Epsilon (perturbation strength)</label>
              <input
                type="range" min={0.01} max={0.5} step={0.01}
                value={epsilon}
                onChange={e => setEpsilon(parseFloat(e.target.value))}
                className="w-full accent-accent-red"
              />
              <div className="flex justify-between text-xs text-text-secondary mt-0.5">
                <span>Subtle (0.01)</span>
                <span className="font-mono text-accent-red font-semibold">{epsilon.toFixed(2)}</span>
                <span>Aggressive (0.50)</span>
              </div>
            </div>

            <div>
              <label className="text-xs text-text-secondary block mb-1">Max samples</label>
              <input
                type="number" min={50} max={5000} step={50}
                value={nSamples}
                onChange={e => setNSamples(parseInt(e.target.value) || 500)}
                className="w-24 px-2 py-1 bg-bg-primary border border-bg-card rounded text-sm text-text-primary"
              />
            </div>
          </div>
        </div>

        {/* Attack selection */}
        <div>
          <label className="text-xs text-text-secondary block mb-2">Attacks</label>
          <div className="flex flex-wrap gap-2">
            {ATTACK_OPTS.map(a => (
              <button
                key={a.id}
                onClick={() => toggleAttack(a.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                  selectedAttacks.includes(a.id)
                    ? 'bg-accent-red/15 border-accent-red/40 text-accent-red'
                    : 'bg-bg-primary border-bg-card text-text-secondary hover:text-text-primary'
                }`}
                title={a.desc}
              >
                {a.label}
              </button>
            ))}
          </div>
        </div>

        {/* Run button */}
        <button
          onClick={handleRun}
          disabled={!file || running || selectedAttacks.length === 0}
          className="px-5 py-2.5 bg-accent-red text-white rounded-lg text-sm font-medium hover:bg-accent-red/80 transition-colors disabled:opacity-40 flex items-center gap-2"
        >
          {running ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Running attacks...
            </>
          ) : (
            <>
              <Swords className="w-4 h-4" />
              Launch Arena
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
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <ShieldCheck className="w-3.5 h-3.5" /> Clean Accuracy
              </div>
              <div className="text-xl font-mono font-bold text-accent-green">
                {(result.clean_accuracy * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <ShieldAlert className="w-3.5 h-3.5" /> Robustness Score
              </div>
              <div className={`text-xl font-mono font-bold ${
                result.robustness_score > 0.7 ? 'text-accent-green' :
                result.robustness_score > 0.4 ? 'text-accent-amber' : 'text-accent-red'
              }`}>
                {(result.robustness_score * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Target className="w-3.5 h-3.5" /> Samples
              </div>
              <div className="text-xl font-mono font-bold text-text-primary">
                {result.n_samples.toLocaleString()}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Brain className="w-3.5 h-3.5" /> Model
              </div>
              <div className="text-sm font-mono font-bold text-accent-blue truncate">
                {result.model_used}
              </div>
            </div>
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Radar chart */}
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h3 className="text-sm font-semibold mb-3">Robustness Radar</h3>
              <ResponsiveContainer width="100%" height={280}>
                <RadarChart data={radarData}>
                  <PolarGrid stroke="#334155" />
                  <PolarAngleAxis dataKey="attack" tick={{ fill: '#94A3B8', fontSize: 11 }} />
                  <PolarRadiusAxis domain={[0, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} />
                  <Radar name="Accuracy %" dataKey="Accuracy Retained" stroke="#22C55E" fill="#22C55E" fillOpacity={0.2} />
                  <Radar name="Confidence %" dataKey="Confidence Retained" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.15} />
                  <Legend wrapperStyle={{ fontSize: 11, color: '#94A3B8' }} />
                </RadarChart>
              </ResponsiveContainer>
            </div>

            {/* Bar chart */}
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h3 className="text-sm font-semibold mb-3">Impact per Attack</h3>
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={barData} barGap={4}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="name" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" />
                  <Tooltip contentStyle={TT} />
                  <Bar dataKey="Accuracy Drop" fill="#EF4444" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="Flip Rate" fill="#F59E0B" radius={[4, 4, 0, 0]} />
                  <Legend wrapperStyle={{ fontSize: 11, color: '#94A3B8' }} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Per-attack detail cards */}
          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-text-secondary">Attack Details</h3>
            {result.attacks.map(atk => (
              <div key={atk.attack} className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
                <button
                  onClick={() => setExpandedAttack(expandedAttack === atk.attack ? null : atk.attack)}
                  className="w-full px-4 py-3 flex items-center gap-3 hover:bg-bg-card/30 transition-colors"
                >
                  <Zap className="w-4 h-4" style={{ color: SEV_COLORS[atk.attack] || '#94A3B8' }} />
                  <span className="font-medium text-sm flex-1 text-left">{atk.label}</span>
                  {atk.error ? (
                    <span className="text-xs text-accent-red">Error</span>
                  ) : (
                    <>
                      <span className="text-xs text-text-secondary">
                        Drop: <span className="font-mono text-accent-red">{(atk.accuracy_drop * 100).toFixed(1)}%</span>
                      </span>
                      <span className="text-xs text-text-secondary ml-3">
                        Flip: <span className="font-mono text-accent-amber">{(atk.flip_rate * 100).toFixed(1)}%</span>
                      </span>
                      <span className="text-xs text-text-secondary ml-3">
                        L2: <span className="font-mono">{atk.perturbation_l2.toFixed(3)}</span>
                      </span>
                      <span className="text-xs text-text-secondary ml-3">
                        {atk.time_ms.toFixed(0)}ms
                      </span>
                    </>
                  )}
                  {expandedAttack === atk.attack ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>

                {expandedAttack === atk.attack && !atk.error && atk.per_class && (
                  <div className="px-4 pb-4 border-t border-bg-card">
                    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2 mt-3">
                      {Object.entries(atk.per_class).slice(0, 12).map(([cls, data]) => (
                        <div key={cls} className="bg-bg-primary rounded-lg p-2 text-xs">
                          <div className="text-text-secondary truncate mb-1" title={cls}>{cls}</div>
                          <div className="flex justify-between">
                            <span className="text-accent-green">{(data.clean_acc * 100).toFixed(0)}%</span>
                            <span className="text-text-secondary">→</span>
                            <span className={data.adv_acc < data.clean_acc * 0.5 ? 'text-accent-red' : 'text-accent-amber'}>
                              {(data.adv_acc * 100).toFixed(0)}%
                            </span>
                          </div>
                          <div className="text-text-secondary mt-0.5">n={data.count}</div>
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
