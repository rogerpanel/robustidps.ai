import { useRef, useState, useEffect } from 'react'
import FileUpload from '../components/FileUpload'
import AblationChart from '../components/AblationChart'
import MultiAblationChart from '../components/MultiAblationChart'
import ModelSelector from '../components/ModelSelector'
import ModelMultiSelector from '../components/ModelMultiSelector'
import { useAblation } from '../hooks/useAblation'
import { useMultiAblation } from '../hooks/useMultiAblation'
import {
  Loader2,
  FlaskConical,
  RotateCcw,
  TrendingDown,
  Zap,
  ToggleLeft,
  ToggleRight,
  Download,
  Image,
  FileText,
  Presentation,
  ChevronDown,
  Layers,
  FileStack,
  X,
  Plus,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import { exportAsPNG, exportAsPDF, exportAsSlides } from '../utils/exportUtils'

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

type AblationMode = 'single' | 'multi'

export default function AblationStudio() {
  const [mode, setMode] = useState<AblationMode>('single')

  return (
    <div className="space-y-6">
      <PageGuide
        title="How to use Ablation Studio"
        steps={[
          { title: 'Choose mode', desc: 'Single-dataset for focused branch analysis, or Multi-dataset for cross-dataset/cross-model comparative ablation.' },
          { title: 'Upload datasets', desc: 'Drop CSV files to evaluate the ensemble. In multi mode, upload up to 3 datasets and select multiple models.' },
          { title: 'Toggle branches', desc: 'In single mode, click the colored cards to enable/disable individual methods.' },
          { title: 'Analyze results', desc: 'View cross-dataset branch stability, model robustness rankings, deprecation/appreciation trends, and sensitivity analysis.' },
        ]}
        tip="Multi-dataset ablation reveals which branches are universally important vs. dataset-dependent. Use it to validate model robustness across diverse traffic distributions."
      />

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
        <div className="flex-1">
          <h1 className="text-xl md:text-2xl font-display font-bold flex items-center gap-2">
            <FlaskConical className="w-6 h-6 text-accent-blue" />
            Ablation Studio
          </h1>
          <p className="text-sm text-text-secondary mt-1 max-w-xl">
            {mode === 'single'
              ? 'Toggle dissertation methods on/off to measure each contribution\'s impact.'
              : 'Compare model robustness across multiple datasets with cross-ablation analysis.'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {/* Mode toggle */}
          <div className="flex items-center bg-bg-secondary border border-bg-card rounded-lg p-0.5">
            <button
              onClick={() => setMode('single')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                mode === 'single'
                  ? 'bg-accent-blue/15 text-accent-blue'
                  : 'text-text-secondary hover:text-text-primary'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              Single Dataset
            </button>
            <button
              onClick={() => setMode('multi')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                mode === 'multi'
                  ? 'bg-accent-purple/15 text-accent-purple'
                  : 'text-text-secondary hover:text-text-primary'
              }`}
            >
              <FileStack className="w-3.5 h-3.5" />
              Multi-Dataset
            </button>
          </div>
          <ExportMenu filename="ablation-study" />
        </div>
      </div>

      {mode === 'single' ? <SingleDatasetMode /> : <MultiDatasetMode />}
    </div>
  )
}

/* ════════════════════════════════════════════════════════════════════════
 *  SINGLE-DATASET MODE (original behavior)
 * ════════════════════════════════════════════════════════════════════════ */

function SingleDatasetMode() {
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
  const resultsRef = useRef<HTMLDivElement>(null)
  const [exportOpen, setExportOpen] = useState(false)
  const [exporting, setExporting] = useState(false)

  useEffect(() => {
    if (!exportOpen) return
    const handleClick = () => setExportOpen(false)
    document.addEventListener('click', handleClick)
    return () => document.removeEventListener('click', handleClick)
  }, [exportOpen])

  const handleExportPNG = async () => {
    if (!resultsRef.current) return
    setExporting(true); setExportOpen(false)
    try { await exportAsPNG(resultsRef.current, 'robustidps_ablation.png') } catch { /* ignore */ }
    setExporting(false)
  }
  const handleExportPDF = async () => {
    if (!resultsRef.current) return
    setExporting(true); setExportOpen(false)
    try { await exportAsPDF(resultsRef.current, 'robustidps_ablation.pdf') } catch { /* ignore */ }
    setExporting(false)
  }
  const handleExportSlides = async () => {
    setExporting(true); setExportOpen(false)
    try {
      const container = resultsRef.current
      if (!container) return
      const sections = Array.from(container.querySelectorAll<HTMLElement>('.bg-bg-secondary'))
      if (sections.length === 0) sections.push(container)
      await exportAsSlides(sections, 'robustidps_ablation_slides.pdf', 'RobustIDPS.AI — Ablation Study')
    } catch { /* ignore */ }
    setExporting(false)
  }

  const disabledCount = enabled.filter((v) => !v).length
  const allEnabled = enabled.every(Boolean)

  const [fileLoading, setFileLoading] = useState(false)

  const handleFileSelect = (file: File) => {
    fileRef.current = file
    setFileLoading(true)
    const delay = Math.min(Math.max(file.size / 100000, 400), 2000)
    setTimeout(() => {
      setFileLoading(false)
      run(file)
    }, delay)
  }

  const handleRerun = () => {
    if (fileRef.current) {
      run(fileRef.current)
    } else {
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
    <>
      {/* Actions bar */}
      <div className="flex items-center justify-end gap-2">
        {exporting && (
          <span className="flex items-center gap-1.5 text-xs text-accent-blue">
            <Loader2 className="w-3.5 h-3.5 animate-spin" /> Generating...
          </span>
        )}
        {data && (
          <>
            <div className="relative">
              <button
                onClick={(e) => { e.stopPropagation(); setExportOpen(!exportOpen) }}
                className="flex items-center gap-2 px-3 py-2 text-xs bg-accent-blue/15 text-accent-blue rounded-lg hover:bg-accent-blue/25 transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                Export
                <ChevronDown className="w-3 h-3" />
              </button>
              {exportOpen && (
                <div className="absolute right-0 top-full mt-1 w-52 bg-bg-secondary border border-bg-card rounded-lg shadow-xl z-50 overflow-hidden" onClick={(e) => e.stopPropagation()}>
                  <button onClick={handleExportPNG} className="w-full flex items-center gap-3 px-4 py-2.5 text-xs text-text-primary hover:bg-bg-card/50 transition-colors">
                    <Image className="w-4 h-4 text-accent-green" /> Export as PNG
                  </button>
                  <button onClick={handleExportPDF} className="w-full flex items-center gap-3 px-4 py-2.5 text-xs text-text-primary hover:bg-bg-card/50 transition-colors">
                    <FileText className="w-4 h-4 text-accent-red" /> Export as PDF
                  </button>
                  <button onClick={handleExportSlides} className="w-full flex items-center gap-3 px-4 py-2.5 text-xs text-text-primary hover:bg-bg-card/50 transition-colors">
                    <Presentation className="w-4 h-4 text-accent-purple" /> Export as PDF Slides
                  </button>
                </div>
              )}
            </div>
            <button
              onClick={handleClear}
              className="flex items-center gap-2 px-4 py-2 border border-bg-card rounded-lg text-sm text-text-secondary hover:text-text-primary hover:border-text-secondary transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Reset All
            </button>
          </>
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
          <FileUpload onFileSelect={handleFileSelect} fileLoading={fileLoading} />
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
      <div ref={resultsRef}>
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
          <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card mt-4">
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
    </>
  )
}

/* ════════════════════════════════════════════════════════════════════════
 *  MULTI-DATASET MODE (new)
 * ════════════════════════════════════════════════════════════════════════ */

function MultiDatasetMode() {
  const {
    loading,
    data: multiData,
    error,
    selectedModels,
    slots,
    setSelectedModels,
    setSlotFile,
    run,
    clear,
  } = useMultiAblation()

  const resultsRef = useRef<HTMLDivElement>(null)
  const slotInputRefs = useRef<(HTMLInputElement | null)[]>([null, null, null])
  const [selectedRunKey, setSelectedRunKey] = useState<string | null>(null)

  const activeSlots = slots.filter((s) => s.fileReady || s.fileName)
  const canRun = activeSlots.length >= 1 && selectedModels.length >= 1

  const handleSlotFileSelect = (index: number) => (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) setSlotFile(index, file)
  }

  const handleRun = () => {
    if (canRun) run()
  }

  // Derive per-run detail when user clicks a matrix cell
  const selectedRun = selectedRunKey ? multiData?.ablation_matrix[selectedRunKey] : null

  return (
    <>
      {/* Configuration grid */}
      <div className="grid grid-cols-1 xl:grid-cols-4 gap-4">
        {/* Dataset slots */}
        <div className="xl:col-span-3 bg-bg-secondary rounded-xl p-4 md:p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4 flex items-center gap-2">
            <FileStack className="w-4 h-4" />
            Datasets (up to 3)
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {slots.map((slot, i) => (
              <div
                key={i}
                className={`rounded-lg border-2 border-dashed p-4 text-center transition-all ${
                  slot.fileReady || slot.fileName
                    ? 'border-accent-green/40 bg-accent-green/5'
                    : 'border-bg-card hover:border-text-secondary'
                }`}
              >
                <input
                  ref={(el) => { slotInputRefs.current[i] = el }}
                  type="file"
                  accept=".csv,.pcap,.pcapng"
                  onChange={handleSlotFileSelect(i)}
                  className="hidden"
                />
                {slot.fileReady || slot.fileName ? (
                  <div className="space-y-2">
                    <div className="w-8 h-8 rounded-full bg-accent-green/15 flex items-center justify-center mx-auto">
                      <FileText className="w-4 h-4 text-accent-green" />
                    </div>
                    <p className="text-xs font-mono text-text-secondary truncate" title={slot.fileName || ''}>
                      {slot.fileName}
                    </p>
                    <button
                      onClick={() => setSlotFile(i, null)}
                      className="text-[10px] text-accent-red hover:text-accent-red/80 flex items-center gap-1 mx-auto"
                    >
                      <X className="w-3 h-3" /> Remove
                    </button>
                  </div>
                ) : (
                  <button
                    onClick={() => slotInputRefs.current[i]?.click()}
                    className="space-y-2 w-full"
                  >
                    <div className="w-8 h-8 rounded-full bg-bg-card flex items-center justify-center mx-auto">
                      <Plus className="w-4 h-4 text-text-secondary" />
                    </div>
                    <p className="text-xs text-text-secondary">
                      Dataset {i + 1}
                    </p>
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Model selection + Run */}
        <div className="space-y-4">
          <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
            <ModelMultiSelector value={selectedModels} onChange={setSelectedModels} />
          </div>

          <button
            onClick={handleRun}
            disabled={loading || !canRun}
            className="w-full px-6 py-3 bg-accent-purple text-white rounded-lg text-sm font-medium hover:bg-accent-purple/80 disabled:opacity-50 transition-colors flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Running Multi-Ablation...
              </>
            ) : (
              <>
                <FlaskConical className="w-4 h-4" />
                Run Multi-Ablation
              </>
            )}
          </button>

          {multiData && (
            <button
              onClick={clear}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 border border-bg-card rounded-lg text-sm text-text-secondary hover:text-text-primary transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Reset All
            </button>
          )}

          {/* Quick summary */}
          {multiData && (
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card space-y-2">
              <h4 className="text-xs font-medium text-text-secondary uppercase tracking-wider">Summary</h4>
              <div className="flex justify-between items-center">
                <span className="text-xs text-text-secondary">Datasets</span>
                <span className="text-sm font-mono text-accent-purple font-semibold">
                  {multiData.n_datasets}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-xs text-text-secondary">Models</span>
                <span className="text-sm font-mono text-accent-blue font-semibold">
                  {multiData.n_models}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-xs text-text-secondary">Total Runs</span>
                <span className="text-sm font-mono text-text-primary font-semibold">
                  {multiData.n_datasets * multiData.n_models}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>

      {error && (
        <div className="px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">
          {error}
        </div>
      )}

      {/* Multi-ablation results */}
      <div ref={resultsRef}>
        {multiData && (
          <>
            <MultiAblationChart data={multiData} />

            {/* Per-run drill-down selector */}
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card mt-4">
              <h3 className="text-sm font-medium text-text-secondary mb-4">
                Per-Run Drill Down — Select a Model × Dataset pair
              </h3>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2 mb-4">
                {Object.keys(multiData.ablation_matrix).map((key) => {
                  const [mn, ds] = key.split('|')
                  const run = multiData.ablation_matrix[key]
                  const fullAcc = run.ablation['Full System']?.accuracy ?? 0
                  return (
                    <button
                      key={key}
                      onClick={() => setSelectedRunKey(selectedRunKey === key ? null : key)}
                      className={`text-left px-3 py-2.5 rounded-lg border transition-all text-xs ${
                        selectedRunKey === key
                          ? 'border-accent-blue bg-accent-blue/10'
                          : 'border-bg-card bg-bg-card/30 hover:border-bg-card/80'
                      }`}
                    >
                      <div className="font-medium text-text-primary truncate">{mn}</div>
                      <div className="text-[10px] text-text-secondary truncate mt-0.5">{ds}</div>
                      <div className="font-mono text-accent-blue mt-1">
                        {(fullAcc * 100).toFixed(1)}%
                      </div>
                    </button>
                  )
                })}
              </div>

              {/* Show single-run chart when selected */}
              {selectedRun && (
                <div className="mt-4 space-y-4">
                  <div className="flex items-center gap-2 text-sm text-text-secondary">
                    <span className="w-2 h-2 rounded-full bg-accent-blue" />
                    <span className="font-medium">
                      {selectedRun.model_used} on {selectedRun.dataset_name}
                    </span>
                  </div>
                  <AblationChart
                    data={selectedRun.ablation}
                    pairwise={selectedRun.pairwise}
                    incremental={selectedRun.incremental}
                    branchNames={selectedRun.branch_names.length > 0 ? selectedRun.branch_names : BRANCH_NAMES}
                  />

                  {/* Per-run detail table */}
                  <div className="bg-bg-card/30 rounded-xl p-4 border border-bg-card">
                    <h4 className="text-xs font-medium text-text-secondary mb-3">
                      Ablation Details — {selectedRun.model_used} × {selectedRun.dataset_name}
                    </h4>
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="text-text-secondary border-b border-bg-card">
                            <th className="px-2 py-2 text-left">Configuration</th>
                            <th className="px-2 py-2 text-right">Accuracy</th>
                            <th className="px-2 py-2 text-right">Precision</th>
                            <th className="px-2 py-2 text-right">Recall</th>
                            <th className="px-2 py-2 text-right">F1</th>
                            <th className="px-2 py-2 text-right">Drop</th>
                          </tr>
                        </thead>
                        <tbody>
                          {Object.entries(selectedRun.ablation).map(([name, v]) => (
                            <tr key={name} className="border-t border-bg-card/20 hover:bg-bg-card/10">
                              <td className="px-2 py-2 font-medium">
                                <span className={name === 'Full System' ? 'text-accent-blue' : ''}>
                                  {name}
                                </span>
                              </td>
                              <td className="px-2 py-2 text-right font-mono">{(v.accuracy * 100).toFixed(2)}%</td>
                              <td className="px-2 py-2 text-right font-mono text-text-secondary">{(v.precision * 100).toFixed(2)}%</td>
                              <td className="px-2 py-2 text-right font-mono text-text-secondary">{(v.recall * 100).toFixed(2)}%</td>
                              <td className="px-2 py-2 text-right font-mono text-text-secondary">{(v.f1 * 100).toFixed(2)}%</td>
                              <td className={`px-2 py-2 text-right font-mono font-semibold ${
                                v.accuracy_drop > 0.05 ? 'text-accent-red' : v.accuracy_drop > 0 ? 'text-accent-amber' : 'text-accent-green'
                              }`}>
                                {v.accuracy_drop > 0 ? `-${(v.accuracy_drop * 100).toFixed(2)}%` : '—'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </>
  )
}
