import { useState } from 'react'
import { Sparkles, Loader2, ChevronDown, ChevronUp, Check } from 'lucide-react'
import { runAutoTune, type AutoTuneResult } from '../utils/api'

interface Props {
  /** The file to analyse for auto-tuning. Button is disabled when null. */
  file: File | null
  /** Context hint sent to backend: general, federated, continual, ablation, adversarial */
  context?: string
  /** Called with recommendations so the parent can apply them. */
  onResult?: (result: AutoTuneResult) => void
  /** Compact mode — just icon + short label */
  compact?: boolean
}

export default function AutoTuneButton({ file, context = 'general', onResult, compact }: Props) {
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<AutoTuneResult | null>(null)
  const [error, setError] = useState('')
  const [expanded, setExpanded] = useState(false)

  const handleAutoTune = async () => {
    if (!file) return
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const data = await runAutoTune(file, context)
      setResult(data)
      onResult?.(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Auto-tune failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-2">
      <button
        onClick={handleAutoTune}
        disabled={!file || loading}
        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
          result
            ? 'bg-accent-green/15 border-accent-green/40 text-accent-green'
            : 'bg-accent-purple/15 border-accent-purple/40 text-accent-purple hover:bg-accent-purple/25'
        } disabled:opacity-40 disabled:cursor-not-allowed`}
        title="Analyse dataset and recommend optimal hyperparameters"
      >
        {loading ? (
          <Loader2 className="w-3.5 h-3.5 animate-spin" />
        ) : result ? (
          <Check className="w-3.5 h-3.5" />
        ) : (
          <Sparkles className="w-3.5 h-3.5" />
        )}
        {compact ? (result ? 'Tuned' : 'Auto-Tune') : (
          loading ? 'Analysing dataset…' : result ? 'Auto-Tuned' : 'Auto-Tune Hyperparameters'
        )}
      </button>

      {error && (
        <p className="text-[10px] text-accent-red">{error}</p>
      )}

      {result && (
        <div className="bg-bg-card/50 rounded-lg border border-bg-card text-[10px]">
          <button
            onClick={() => setExpanded(!expanded)}
            className="w-full flex items-center justify-between px-3 py-1.5 text-text-secondary hover:text-text-primary"
          >
            <span className="flex items-center gap-1.5">
              <Sparkles className="w-3 h-3 text-accent-purple" />
              {result.dataset_analysis.complexity} complexity &middot; {result.dataset_analysis.n_rows.toLocaleString()} rows &middot; {result.dataset_analysis.n_classes} classes
            </span>
            {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>
          {expanded && (
            <div className="px-3 pb-2 space-y-1.5 border-t border-bg-card pt-1.5">
              {Object.entries(result.explanation).map(([key, desc]) => (
                <div key={key} className="flex gap-2">
                  <span className="font-mono text-accent-purple shrink-0">{key}:</span>
                  <span className="text-text-secondary">{desc}</span>
                </div>
              ))}
              <div className="pt-1 text-text-secondary/60">
                Balance: {(result.dataset_analysis.class_balance * 100).toFixed(0)}% &middot;
                Low-var features: {(result.dataset_analysis.low_variance_feature_ratio * 100).toFixed(0)}% &middot;
                Format: {result.dataset_analysis.format}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
