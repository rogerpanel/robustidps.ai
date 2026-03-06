import { useRef } from 'react'
import FileUpload from '../components/FileUpload'
import AblationChart from '../components/AblationChart'
import ModelSelector from '../components/ModelSelector'
import { useAblation } from '../hooks/useAblation'
import {
  Loader2,
  FlaskConical,
  RotateCcw,
  TrendingDown,
  Zap,
  ToggleLeft,
  ToggleRight,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'

const BRANCH_NAMES = [
  'CT-TGNN (Neural ODE)',
  'TripleE-TGNN (Multi-scale)',
  'FedLLM-API (Zero-shot)',
  'PQ-IDPS (Post-quantum)',
  'MambaShield (State-space)',
  'Stochastic Transformer',
  'Game-Theoretic Defence',
]

const BRANCH_COLORS = [
  'from-blue-500/20 to-blue-600/5 border-blue-500/40',
  'from-purple-500/20 to-purple-600/5 border-purple-500/40',
  'from-green-500/20 to-green-600/5 border-green-500/40',
  'from-amber-500/20 to-amber-600/5 border-amber-500/40',
  'from-cyan-500/20 to-cyan-600/5 border-cyan-500/40',
  'from-rose-500/20 to-rose-600/5 border-rose-500/40',
  'from-indigo-500/20 to-indigo-600/5 border-indigo-500/40',
]

const BRANCH_ACTIVE_TEXT = [
  'text-blue-400',
  'text-purple-400',
  'text-green-400',
  'text-amber-400',
  'text-cyan-400',
  'text-rose-400',
  'text-indigo-400',
]

export default function AblationStudio() {
  const {
    loading,
    data,
    error,
    enabled,
    selectedModel,
    fileName,
    toggle,
    setEnabled,
    setSelectedModel,
    run,
    clear,
  } = useAblation()

  const fileRef = useRef<File | null>(null)
  const hiddenInputRef = useRef<HTMLInputElement>(null)

  const disabledCount = enabled.filter((v) => !v).length
  const allEnabled = enabled.every(Boolean)

  const handleFileSelect = (file: File) => {
    fileRef.current = file
    run(file)
  }

  const handleRerun = () => {
    if (fileRef.current) {
      run(fileRef.current)
    } else {
      // File ref lost after navigation — prompt re-select via hidden input
      hiddenInputRef.current?.click()
    }
  }

  const handleHiddenFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      fileRef.current = file
      run(file)
    }
  }

  const handleClear = () => {
    fileRef.current = null
    clear()
  }

  // Summary stats from results
  const fullAccuracy = data?.ablation?.['Full System']?.accuracy
  const mostImpactful = data
    ? Object.entries(data.ablation)
        .filter(([k]) => k !== 'Full System' && k !== 'Custom')
        .sort((a, b) => b[1].accuracy_drop - a[1].accuracy_drop)[0]
    : null
  const leastImpactful = data
    ? Object.entries(data.ablation)
        .filter(([k]) => k !== 'Full System' && k !== 'Custom')
        .sort((a, b) => a[1].accuracy_drop - b[1].accuracy_drop)[0]
    : null

  return (
    <div className="space-y-6">
      <PageGuide
        title="How to use Ablation Studio"
        steps={[
          { title: 'Upload a dataset', desc: 'Drop a CSV to evaluate the ensemble. Each of the 7 dissertation methods (branches) is tested independently.' },
          { title: 'Toggle branches', desc: 'Click the colored cards to enable/disable individual methods. A disabled branch is removed from the ensemble.' },
          { title: 'Observe impact', desc: 'The "Accuracy Drop" shows how much each method contributes. Higher drop = more important branch.' },
          { title: 'Experiment freely', desc: 'Toggle any combination and click "Re-run". Results persist across page navigation.' },
        ]}
        tip="The 7 branches represent: Neural ODE, Multi-scale GNN, Zero-shot LLM, Post-quantum crypto, State-space model, Bayesian transformer, and Game-theoretic defence."
      />

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
        <div>
          <h1 className="text-xl md:text-2xl font-display font-bold flex items-center gap-2">
            <FlaskConical className="w-6 h-6 text-accent-blue" />
            Ablation Studio
          </h1>
          <p className="text-sm text-text-secondary mt-1 max-w-xl">
            Toggle dissertation methods on/off to measure each contribution's impact.
            Results persist across navigation — your toggle states and analysis are saved automatically.
          </p>
        </div>
        {data && (
          <button
            onClick={handleClear}
            className="flex items-center gap-2 px-4 py-2 border border-bg-card rounded-lg text-sm text-text-secondary hover:text-text-primary hover:border-text-secondary transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Reset All
          </button>
        )}
      </div>

      {/* Model selector + Branch toggles */}
      <div className="grid grid-cols-1 xl:grid-cols-4 gap-4">
        <div className="xl:col-span-3 bg-bg-secondary rounded-xl p-4 md:p-5 border border-bg-card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-text-secondary">
              Dissertation Methods
              {selectedModel !== 'surrogate' && (
                <span className="ml-2 text-accent-amber text-xs">(ablation only with SurrogateIDS)</span>
              )}
            </h3>
            <div className="flex items-center gap-3">
              {disabledCount > 0 && (
                <span className="text-xs text-accent-red font-mono">
                  {disabledCount} disabled
                </span>
              )}
              <button
                onClick={() => setEnabled(new Array(7).fill(!allEnabled))}
                disabled={selectedModel !== 'surrogate'}
                className="text-xs text-text-secondary hover:text-text-primary transition-colors disabled:opacity-50"
              >
                {allEnabled ? 'Disable All' : 'Enable All'}
              </button>
            </div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {BRANCH_NAMES.map((name, i) => (
              <button
                key={i}
                onClick={() => toggle(i)}
                disabled={selectedModel !== 'surrogate'}
                className={`group flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all border bg-gradient-to-r ${
                  selectedModel !== 'surrogate'
                    ? 'bg-bg-card/50 border-bg-card text-text-secondary opacity-50'
                    : enabled[i]
                    ? `${BRANCH_COLORS[i]} ${BRANCH_ACTIVE_TEXT[i]}`
                    : 'bg-accent-red/5 border-accent-red/20 text-text-secondary line-through opacity-60'
                }`}
              >
                {enabled[i] ? (
                  <ToggleRight className="w-4 h-4 shrink-0 opacity-70" />
                ) : (
                  <ToggleLeft className="w-4 h-4 shrink-0 opacity-50" />
                )}
                <span className="font-mono text-xs opacity-60">M{i + 1}</span>
                <span className="truncate">{name}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="space-y-4">
          <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
            <ModelSelector value={selectedModel} onChange={setSelectedModel} compact />
          </div>

          {/* Quick stats */}
          {data && fullAccuracy !== undefined && (
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card space-y-3">
              <h4 className="text-xs font-medium text-text-secondary uppercase tracking-wider">Summary</h4>
              <div className="space-y-2">
                <div className="flex justify-between items-center">
                  <span className="text-xs text-text-secondary">Full System</span>
                  <span className="text-sm font-mono text-accent-blue font-semibold">
                    {(fullAccuracy * 100).toFixed(2)}%
                  </span>
                </div>
                {mostImpactful && (
                  <div>
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-text-secondary flex items-center gap-1">
                        <TrendingDown className="w-3 h-3 text-accent-red" />
                        Most Impact
                      </span>
                      <span className="text-xs font-mono text-accent-red">
                        -{(mostImpactful[1].accuracy_drop * 100).toFixed(2)}%
                      </span>
                    </div>
                    <p className="text-[10px] text-text-secondary mt-0.5 truncate">{mostImpactful[0]}</p>
                  </div>
                )}
                {leastImpactful && (
                  <div>
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-text-secondary flex items-center gap-1">
                        <Zap className="w-3 h-3 text-accent-green" />
                        Least Impact
                      </span>
                      <span className="text-xs font-mono text-accent-green">
                        -{(leastImpactful[1].accuracy_drop * 100).toFixed(2)}%
                      </span>
                    </div>
                    <p className="text-[10px] text-text-secondary mt-0.5 truncate">{leastImpactful[0]}</p>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* File upload + Run controls */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        {!fileName && !data ? (
          <FileUpload onFileSelect={handleFileSelect} />
        ) : (
          <div className="flex items-center gap-4">
            <div className="flex-1 flex items-center gap-3">
              <div className="w-2 h-2 rounded-full bg-accent-green animate-pulse" />
              <span className="text-sm font-mono text-text-secondary">
                {fileName || 'Previous dataset'}
              </span>
              {data && !loading && (
                <span className="text-xs text-accent-blue bg-accent-blue/10 px-2 py-0.5 rounded-full">
                  Results cached
                </span>
              )}
            </div>
            {/* Hidden file input for re-run when file ref is lost */}
            <input
              ref={hiddenInputRef}
              type="file"
              accept=".csv,.pcap,.pcapng"
              onChange={handleHiddenFile}
              className="hidden"
            />
            <button
              onClick={handleRerun}
              disabled={loading}
              className="px-6 py-2.5 bg-accent-blue text-white rounded-lg text-sm font-medium hover:bg-accent-blue/80 disabled:opacity-50 transition-colors"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin" /> Running Ablation...
                </span>
              ) : (
                'Re-run Ablation'
              )}
            </button>
            <button
              onClick={handleClear}
              className="px-4 py-2.5 border border-bg-card rounded-lg text-sm text-text-secondary hover:text-text-primary transition-colors"
            >
              Change File
            </button>
          </div>
        )}
      </div>

      {error && (
        <div className="px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">
          {error}
        </div>
      )}

      {/* Charts and visualisations */}
      {data && (
        <AblationChart
          data={data.ablation}
          pairwise={data.pairwise}
          incremental={data.incremental}
          branchNames={BRANCH_NAMES}
        />
      )}

      {/* Detailed results table */}
      {data && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Detailed Ablation Results</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-text-secondary text-xs border-b border-bg-card">
                  <th className="px-3 py-2.5 text-left">Configuration</th>
                  <th className="px-3 py-2.5 text-right">Accuracy</th>
                  <th className="px-3 py-2.5 text-right">Precision</th>
                  <th className="px-3 py-2.5 text-right">Recall</th>
                  <th className="px-3 py-2.5 text-right">F1 Score</th>
                  <th className="px-3 py-2.5 text-right">Acc. Drop</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(data.ablation).map(([name, v]) => (
                  <tr key={name} className="border-t border-bg-card/30 hover:bg-bg-card/20 transition-colors">
                    <td className="px-3 py-2.5 font-medium">
                      {name === 'Full System' ? (
                        <span className="text-accent-blue flex items-center gap-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-accent-blue" />
                          {name}
                        </span>
                      ) : (
                        <span className="flex items-center gap-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-accent-red" />
                          {name}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2.5 text-right font-mono">
                      {(v.accuracy * 100).toFixed(2)}%
                    </td>
                    <td className="px-3 py-2.5 text-right font-mono text-text-secondary">
                      {(v.precision * 100).toFixed(2)}%
                    </td>
                    <td className="px-3 py-2.5 text-right font-mono text-text-secondary">
                      {(v.recall * 100).toFixed(2)}%
                    </td>
                    <td className="px-3 py-2.5 text-right font-mono text-text-secondary">
                      {(v.f1 * 100).toFixed(2)}%
                    </td>
                    <td
                      className={`px-3 py-2.5 text-right font-mono font-semibold ${
                        v.accuracy_drop > 0.05
                          ? 'text-accent-red'
                          : v.accuracy_drop > 0
                          ? 'text-accent-amber'
                          : 'text-accent-green'
                      }`}
                    >
                      {v.accuracy_drop > 0 ? (
                        <span className="inline-flex items-center gap-1">
                          <TrendingDown className="w-3 h-3" />
                          -{(v.accuracy_drop * 100).toFixed(2)}%
                        </span>
                      ) : (
                        '—'
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
