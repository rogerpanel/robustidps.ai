import { useState, useMemo, useRef, useCallback } from 'react'
import {
  Eye, Loader2, BarChart3, Layers, Zap, Brain, Shield,
  ChevronDown, ChevronUp, Target, TrendingUp, GitCompare,
  Network, Sparkles, ArrowRightLeft, Workflow, Search,
  AlertTriangle, CheckCircle2, Activity, Cpu, Fingerprint,
  Share2, Microscope, Radar, Boxes, Database,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid, Cell, RadarChart, PolarGrid, PolarAngleAxis,
  PolarRadiusAxis, Radar as RechartsRadar, ScatterChart, Scatter,
  LineChart, Line, Legend, Treemap,
} from 'recharts'
import FileUpload from '../components/FileUpload'
import ModelSelector from '../components/ModelSelector'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import { runXai, runComparativeXai, runXaiMulti, fetchSampleData, fetchModels } from '../utils/api'
import { usePageState } from '../hooks/usePageState'
import { useNoticeBoard } from '../hooks/useNoticeBoard'

const PAGE = 'xai'

const TT = { background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }

const METHOD_OPTS = [
  { id: 'all', label: 'All Core Methods', desc: 'Run saliency, integrated gradients, sensitivity, SHAP, LRP, DeepLIFT', icon: Boxes },
  { id: 'comprehensive', label: 'Comprehensive', desc: 'All methods + feature interactions, counterfactuals, decision paths', icon: Microscope },
  { id: 'saliency', label: 'Gradient Saliency', desc: 'Gradient-based feature importance', icon: BarChart3 },
  { id: 'integrated_gradients', label: 'Integrated Gradients', desc: 'Path-integrated attribution (Sundararajan et al.)', icon: Layers },
  { id: 'sensitivity', label: 'Sensitivity Analysis', desc: 'Feature perturbation impact on predictions', icon: Zap },
  { id: 'shap', label: 'SHAP Values', desc: 'Shapley additive explanations via sampling', icon: Share2 },
  { id: 'lrp', label: 'LRP', desc: 'Layer-wise Relevance Propagation (epsilon-rule)', icon: Network },
  { id: 'deeplift', label: 'DeepLIFT', desc: 'Difference-from-reference attribution', icon: Activity },
  { id: 'attention', label: 'Attention Analysis', desc: 'Attention weight and pseudo-attention extraction', icon: Eye },
  { id: 'interactions', label: 'Feature Interactions', desc: 'Pairwise H-statistic interaction detection', icon: GitCompare },
  { id: 'counterfactual', label: 'Counterfactuals', desc: 'Minimal changes to flip prediction', icon: ArrowRightLeft },
  { id: 'decision_path', label: 'Decision Path', desc: 'Layer-by-layer activation flow tracing', icon: Workflow },
]

const GRADIENT_COLORS = [
  '#EF4444', '#F97316', '#F59E0B', '#EAB308', '#84CC16',
  '#22C55E', '#14B8A6', '#06B6D4', '#3B82F6', '#6366F1',
  '#8B5CF6', '#A855F7', '#D946EF', '#EC4899', '#F43F5E',
  '#64748B', '#475569', '#334155', '#1E293B', '#0F172A',
]

const METHOD_COLORS: Record<string, string> = {
  saliency: '#3B82F6', integrated_gradients: '#8B5CF6', sensitivity: '#EF4444',
  shap: '#22C55E', lrp: '#F97316', deeplift: '#06B6D4',
}

const TAB_SECTIONS = [
  { key: 'saliency', label: 'Gradient Saliency', icon: BarChart3, field: 'saliency' },
  { key: 'ig', label: 'Integrated Gradients', icon: Layers, field: 'integrated_gradients' },
  { key: 'sensitivity', label: 'Sensitivity', icon: Zap, field: 'sensitivity' },
  { key: 'shap', label: 'SHAP', icon: Share2, field: 'shap' },
  { key: 'lrp', label: 'LRP', icon: Network, field: 'lrp' },
  { key: 'deeplift', label: 'DeepLIFT', icon: Activity, field: 'deeplift' },
  { key: 'attention', label: 'Attention', icon: Eye, field: 'attention' },
  { key: 'interactions', label: 'Interactions', icon: GitCompare, field: 'feature_interactions' },
  { key: 'counterfactual', label: 'Counterfactuals', icon: ArrowRightLeft, field: 'counterfactual' },
  { key: 'decision_path', label: 'Decision Path', icon: Workflow, field: 'decision_path' },
  { key: 'agreement', label: 'Cross-Method', icon: Radar, field: 'cross_method_agreement' },
  { key: 'compare', label: 'Model Compare', icon: GitCompare, field: '__compare__' },
  { key: 'multiDataset', label: 'Multi-Dataset', icon: Database, field: '__multi_dataset__' },
] as const

type TabKey = typeof TAB_SECTIONS[number]['key']

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type XaiResult = Record<string, any>

interface SlotState {
  file: File | null
  fileName: string | null
  fileReady: boolean
  fileLoading: boolean
}

export default function ExplainabilityStudio() {
  const [file, setFile] = usePageState<File | null>(PAGE, 'file', null)
  const [fileName, setFileName] = usePageState<string | null>(PAGE, 'fileName', null)
  const [fileReady, setFileReady] = usePageState(PAGE, 'fileReady', false)
  const [fileLoading, setFileLoading] = usePageState(PAGE, 'fileLoading', false)
  const [selectedModel, setSelectedModel] = usePageState(PAGE, 'selectedModel', 'surrogate')
  const [method, setMethod] = usePageState(PAGE, 'method', 'all')
  const [nSamples, setNSamples] = usePageState(PAGE, 'nSamples', 200)
  const [running, setRunning] = usePageState(PAGE, 'running', false)
  const [result, setResult] = usePageState<XaiResult | null>(PAGE, 'result', null)
  const [compareResult, setCompareResult] = usePageState<XaiResult | null>(PAGE, 'compareResult', null)
  const [error, setError] = usePageState(PAGE, 'error', '')
  const [activeTab, setActiveTab] = usePageState<TabKey>(PAGE, 'activeTab', 'saliency')
  const [expandedClass, setExpandedClass] = usePageState<string | null>(PAGE, 'expandedClass', null)
  const [compareMode, setCompareMode] = usePageState(PAGE, 'compareMode', false)
  const [compareModels, setCompareModels] = usePageState<string[]>(PAGE, 'compareModels', ['surrogate'])
  const [runningCompare, setRunningCompare] = usePageState(PAGE, 'runningCompare', false)

  // Multi-dataset slot state
  const defaultSlot = (): SlotState => ({ file: null, fileName: null, fileReady: false, fileLoading: false })
  const [multiMode, setMultiMode] = usePageState(PAGE, 'multiMode', false)
  const [slots, setSlots] = usePageState<SlotState[]>(PAGE, 'slots', [defaultSlot(), defaultSlot(), defaultSlot()])
  const [multiModels, setMultiModels] = usePageState<string[]>(PAGE, 'multiModels', ['surrogate'])
  const [multiResult, setMultiResult] = usePageState<XaiResult | null>(PAGE, 'multiResult', null)
  const [runningMulti, setRunningMulti] = usePageState(PAGE, 'runningMulti', false)
  const [multiView, setMultiView] = usePageState(PAGE, 'multiView', 'overview')

  const resultsRef = useRef<HTMLDivElement>(null)
  const { addNotice, updateNotice } = useNoticeBoard()

  const handleFileSelect = (f: File) => {
    setFileLoading(true)
    setFileReady(false)
    setFile(f)
    setFileName(f.name)
    const size = f.size
    const delay = Math.min(Math.max(size / 100000, 400), 3000)
    setTimeout(() => {
      setFileLoading(false)
      setFileReady(true)
    }, delay)
  }

  const handleRun = async () => {
    if (!file) return
    setRunning(true)
    setError('')
    setResult(null)
    const nid = addNotice({ title: `Explainability: ${fileName || 'dataset'}`, description: `Method: ${method}, Model: ${selectedModel}`, status: 'running', page: '/xai' })
    try {
      const data = await runXai(file, method, nSamples, selectedModel)
      setResult(data)
      updateNotice(nid, { status: 'completed', title: `Explainability complete: ${fileName}` })
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'XAI analysis failed'
      setError(msg)
      updateNotice(nid, { status: 'error', title: `Explainability failed: ${fileName}`, description: msg })
    } finally {
      setRunning(false)
    }
  }

  const handleRunCompare = async () => {
    if (!file || compareModels.length < 2) return
    setRunningCompare(true)
    setError('')
    setCompareResult(null)
    try {
      const data = await runComparativeXai(file, compareModels, nSamples)
      setCompareResult(data)
      setActiveTab('compare')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Comparative analysis failed')
    } finally {
      setRunningCompare(false)
    }
  }

  const toggleCompareModel = (modelId: string) => {
    setCompareModels(prev =>
      prev.includes(modelId) ? prev.filter(m => m !== modelId) : [...prev, modelId]
    )
  }

  // Multi-dataset slot helpers
  const updateSlot = (idx: number, updates: Partial<SlotState>) => {
    setSlots((prev: SlotState[]) => prev.map((s: SlotState, i: number) => i === idx ? { ...s, ...updates } : s))
  }
  const handleSlotFileSelect = (idx: number, f: File) => {
    updateSlot(idx, { file: f, fileName: f.name, fileLoading: true, fileReady: false })
    const delay = Math.min(Math.max(f.size / 100000, 400), 3000)
    setTimeout(() => updateSlot(idx, { fileLoading: false, fileReady: true }), delay)
  }
  const toggleMultiModel = (modelId: string) => {
    setMultiModels((prev: string[]) =>
      prev.includes(modelId) ? prev.filter((m: string) => m !== modelId) : [...prev, modelId]
    )
  }

  const handleRunMulti = async () => {
    const activeFiles = slots.filter((s: SlotState) => s.file && s.fileReady)
    if (activeFiles.length === 0 || multiModels.length === 0) return
    setRunningMulti(true)
    setError('')
    setMultiResult(null)
    try {
      const files = slots.map((s: SlotState) => s.file)
      const data = await runXaiMulti(files, multiModels, method, nSamples)
      setMultiResult(data)
      setActiveTab('multiDataset')
      setMultiView('overview')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Multi-dataset XAI analysis failed')
    } finally {
      setRunningMulti(false)
    }
  }

  // Available tabs from results
  const availableTabs = useMemo(() => {
    if (!result && !compareResult && !multiResult) return []
    return TAB_SECTIONS.filter(t => {
      if (t.key === 'compare') return !!compareResult
      if (t.key === 'multiDataset') return !!multiResult
      if (!result) return false
      return result[t.field] !== undefined
    })
  }, [result, compareResult, multiResult])

  // Data transforms
  const makeBarData = (items: { name: string; [k: string]: unknown }[], valueKey: string) =>
    (items || []).slice(0, 15).map(f => ({
      name: (f.name as string).length > 18 ? (f.name as string).slice(0, 16) + '…' : f.name,
      fullName: f.name,
      value: Math.round((Number(f[valueKey]) || 0) * 1000) / 10,
    }))

  const saliencyData = makeBarData(result?.saliency?.global_importance || [], 'importance')
  const igData = makeBarData(result?.integrated_gradients?.global_attribution || [], 'attribution')
  const sensData = (result?.sensitivity?.top_sensitive_features || []).slice(0, 15).map((f: XaiResult) => ({
    name: f.name.length > 18 ? f.name.slice(0, 16) + '…' : f.name,
    fullName: f.name,
    value: Math.round((f.max_flip_rate || 0) * 1000) / 10,
  }))
  const shapData = makeBarData(result?.shap?.global_importance || [], 'importance')
  const lrpData = makeBarData(result?.lrp?.global_relevance || [], 'relevance')
  const deepliftData = makeBarData(result?.deeplift?.global_attribution || [], 'attribution')

  // Radar data for cross-method agreement
  const radarData = useMemo(() => {
    if (!result?.cross_method_agreement) return []
    const agreement = result.cross_method_agreement
    const methods = agreement.methods_compared || []
    return methods.map((m: string) => {
      const entry: Record<string, unknown> = { method: m }
      methods.forEach((m2: string) => {
        if (m === m2) { entry[m2] = 1.0; return }
        const key1 = `${m}_vs_${m2}`
        const key2 = `${m2}_vs_${m}`
        const val = agreement.pairwise_rank_agreement[key1] ?? agreement.pairwise_rank_agreement[key2] ?? 0
        entry[m2] = val
      })
      return entry
    })
  }, [result])

  return (
    <div className="space-y-6">
      <PageGuide
        title="How to use Explainability Studio"
        steps={[
          { title: 'Upload a dataset', desc: 'Drop a network traffic CSV for analysis.' },
          { title: 'Choose method', desc: 'Select individual or comprehensive multi-method analysis.' },
          { title: 'Run analysis', desc: 'The XAI engine computes attributions across 10+ methods.' },
          { title: 'Explore results', desc: 'View global/per-class importance, cross-method agreement, counterfactuals, and decision paths.' },
          { title: 'Compare models', desc: 'Enable comparison mode to see how different models explain the same data.' },
        ]}
        tip="Comprehensive mode runs all methods including feature interactions, counterfactuals, and decision path tracing — essential for full audit-grade explainability."
      />

      {/* Header */}
      <div className="flex items-center gap-3">
        <Eye className="w-7 h-7 text-accent-purple" />
        <div className="flex-1">
          <h1 className="text-xl md:text-2xl font-display font-bold">Explainability Studio</h1>
          <p className="text-sm text-text-secondary mt-0.5">
            Understand why and how models make their decisions — 10+ attribution methods with comparative analysis
          </p>
        </div>
        <ExportMenu filename="explainability" />
      </div>

      {/* Config Panel */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-4">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Column 1: File + Model */}
          <div className="space-y-3">
            <FileUpload
              onFile={handleFileSelect}
              label="Upload traffic dataset"
              accept=".csv,.parquet,.pcap,.pcapng"
              fileName={fileName}
              fileLoading={fileLoading}
            />
            <button
              onClick={async () => {
                try {
                  setFileLoading(true)
                  setFileReady(false)
                  const f = await fetchSampleData()
                  handleFileSelect(f)
                } catch {
                  setFileLoading(false)
                  setError('Failed to load demo data')
                }
              }}
              className="text-xs text-accent-purple hover:text-accent-purple/80 underline"
            >
              or use built-in demo data (1000 flows)
            </button>
            <ModelSelector value={selectedModel} onChange={setSelectedModel} />
            <div>
              <label className="text-xs text-text-secondary block mb-1">Max samples</label>
              <input
                type="number" min={50} max={2000} step={50}
                value={nSamples}
                onChange={e => setNSamples(parseInt(e.target.value) || 200)}
                className="w-24 px-2 py-1 bg-bg-primary border border-bg-card rounded text-sm text-text-primary"
              />
            </div>
          </div>

          {/* Column 2: Method Selection */}
          <div className="lg:col-span-2 space-y-3">
            <label className="text-xs text-text-secondary block">XAI Method</label>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5">
              {METHOD_OPTS.map(m => (
                <button
                  key={m.id}
                  onClick={() => setMethod(m.id)}
                  className={`flex items-center gap-1.5 px-2.5 py-2 rounded-lg text-xs font-medium border transition-colors text-left ${
                    method === m.id
                      ? 'bg-accent-purple/15 border-accent-purple/40 text-accent-purple'
                      : 'bg-bg-primary border-bg-card text-text-secondary hover:text-text-primary'
                  }`}
                  title={m.desc}
                >
                  <m.icon className="w-3.5 h-3.5 shrink-0" />
                  <span className="truncate">{m.label}</span>
                </button>
              ))}
            </div>

            {/* Mode Toggles */}
            <div className="border-t border-bg-card pt-3 flex flex-wrap gap-2">
              <button
                onClick={() => setCompareMode(!compareMode)}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium border transition-colors ${
                  compareMode
                    ? 'bg-accent-blue/15 border-accent-blue/40 text-accent-blue'
                    : 'bg-bg-primary border-bg-card text-text-secondary hover:text-text-primary'
                }`}
              >
                <GitCompare className="w-4 h-4" />
                Multi-Model Comparative Analysis
              </button>
              <button
                onClick={() => setMultiMode(!multiMode)}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium border transition-colors ${
                  multiMode
                    ? 'bg-accent-green/15 border-accent-green/40 text-accent-green'
                    : 'bg-bg-primary border-bg-card text-text-secondary hover:text-text-primary'
                }`}
              >
                <Database className="w-4 h-4" />
                Multi-Dataset Analysis
              </button>
              {compareMode && (
                <div className="mt-2 p-3 bg-bg-primary rounded-lg border border-bg-card space-y-2">
                  <p className="text-[11px] text-text-secondary">Select 2+ models to compare how they explain the same data:</p>
                  <div className="flex flex-wrap gap-1.5">
                    {['surrogate', 'neural_ode', 'optimal_transport', 'sde_tgnn', 'fedgtd', 'cybersec_llm', 'clrl_unified'].map(m => (
                      <button
                        key={m}
                        onClick={() => toggleCompareModel(m)}
                        className={`px-2.5 py-1 rounded text-xs font-mono border transition-colors ${
                          compareModels.includes(m)
                            ? 'bg-accent-blue/15 border-accent-blue/40 text-accent-blue'
                            : 'border-bg-card text-text-secondary hover:text-text-primary'
                        }`}
                      >
                        {m}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Multi-Dataset Mode */}
              {multiMode && (
                <div className="mt-2 p-3 bg-bg-primary rounded-lg border border-accent-green/20 space-y-3">
                  <p className="text-[11px] text-text-secondary">Upload up to 3 datasets to compare XAI results across different traffic distributions:</p>

                  {/* 3-Slot Dataset Upload Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    {slots.map((slot: SlotState, idx: number) => (
                      <div key={idx} className={`rounded-lg border p-3 ${
                        slot.fileReady ? 'border-accent-green/40 bg-accent-green/5' : 'border-bg-card bg-bg-secondary'
                      }`}>
                        <div className="text-xs text-text-secondary mb-1.5 font-medium">
                          Dataset {idx + 1} {idx === 0 && <span className="text-accent-red">*</span>}
                        </div>
                        <FileUpload
                          onFile={(f: File) => handleSlotFileSelect(idx, f)}
                          label={`Dataset ${idx + 1}`}
                          accept=".csv,.parquet,.pcap,.pcapng"
                          fileName={slot.fileName}
                          fileLoading={slot.fileLoading}
                        />
                        {slot.fileReady && (
                          <div className="flex items-center gap-1 mt-1.5 text-[10px] text-accent-green">
                            <CheckCircle2 className="w-3 h-3" /> Ready
                          </div>
                        )}
                      </div>
                    ))}
                  </div>

                  {/* Multi-dataset model selection */}
                  <div>
                    <p className="text-[11px] text-text-secondary mb-1.5">Models to analyse across datasets:</p>
                    <div className="flex flex-wrap gap-1.5">
                      {['surrogate', 'neural_ode', 'optimal_transport', 'sde_tgnn', 'fedgtd', 'cybersec_llm', 'clrl_unified'].map(m => (
                        <button
                          key={m}
                          onClick={() => toggleMultiModel(m)}
                          className={`px-2.5 py-1 rounded text-xs font-mono border transition-colors ${
                            multiModels.includes(m)
                              ? 'bg-accent-green/15 border-accent-green/40 text-accent-green'
                              : 'border-bg-card text-text-secondary hover:text-text-primary'
                          }`}
                        >
                          {m}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-3 flex-wrap">
          <button
            onClick={handleRun}
            disabled={!file || !fileReady || running || fileLoading}
            className="px-5 py-2.5 bg-accent-purple text-white rounded-lg text-sm font-medium hover:bg-accent-purple/80 transition-colors disabled:opacity-40 flex items-center gap-2"
          >
            {running ? (
              <><Loader2 className="w-4 h-4 animate-spin" /> Analysing ({method})...</>
            ) : (
              <><Eye className="w-4 h-4" /> Run XAI Analysis</>
            )}
          </button>

          {compareMode && (
            <button
              onClick={handleRunCompare}
              disabled={!file || !fileReady || runningCompare || fileLoading || compareModels.length < 2}
              className="px-5 py-2.5 bg-accent-blue text-white rounded-lg text-sm font-medium hover:bg-accent-blue/80 transition-colors disabled:opacity-40 flex items-center gap-2"
            >
              {runningCompare ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> Comparing {compareModels.length} models...</>
              ) : (
                <><GitCompare className="w-4 h-4" /> Compare Models ({compareModels.length})</>
              )}
            </button>
          )}

          {multiMode && (
            <button
              onClick={handleRunMulti}
              disabled={!slots.some((s: SlotState) => s.file && s.fileReady) || runningMulti || multiModels.length === 0}
              className="px-5 py-2.5 bg-accent-green text-white rounded-lg text-sm font-medium hover:bg-accent-green/80 transition-colors disabled:opacity-40 flex items-center gap-2"
            >
              {runningMulti ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> Analysing {slots.filter((s: SlotState) => s.file && s.fileReady).length} datasets...</>
              ) : (
                <><Database className="w-4 h-4" /> Multi-Dataset XAI ({slots.filter((s: SlotState) => s.file && s.fileReady).length} datasets, {multiModels.length} models)</>
              )}
            </button>
          )}
        </div>

        {error && (
          <div className="px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">
            {error}
          </div>
        )}
      </div>

      {/* Results */}
      {(result || compareResult || multiResult) && (
        <div ref={resultsRef}>
          {/* Summary Stats */}
          {result && (
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
              <StatBox icon={Target} label="Accuracy" value={`${(result.prediction_summary.accuracy * 100).toFixed(1)}%`} color="text-accent-green" />
              <StatBox icon={TrendingUp} label="Confidence" value={`${(result.prediction_summary.mean_confidence * 100).toFixed(1)}%`} color="text-accent-blue" />
              <StatBox icon={Layers} label="Features" value={result.feature_names.length} color="text-text-primary" />
              <StatBox icon={Zap} label="Time" value={`${(result.time_ms / 1000).toFixed(1)}s`} color="text-accent-amber" />
              <StatBox icon={Brain} label="Methods" value={availableTabs.length - (compareResult ? 1 : 0)} color="text-accent-purple" />
            </div>
          )}

          {/* Confidence Distribution */}
          {result?.prediction_summary?.confidence_distribution && (
            <div className="grid grid-cols-3 gap-2 mb-6">
              {[
                { label: 'High Confidence (>90%)', count: result.prediction_summary.confidence_distribution.high, color: 'bg-accent-green/15 text-accent-green border-accent-green/30' },
                { label: 'Medium (70-90%)', count: result.prediction_summary.confidence_distribution.medium, color: 'bg-accent-amber/15 text-accent-amber border-accent-amber/30' },
                { label: 'Low (<70%)', count: result.prediction_summary.confidence_distribution.low, color: 'bg-accent-red/15 text-accent-red border-accent-red/30' },
              ].map(d => (
                <div key={d.label} className={`rounded-lg p-3 border text-center ${d.color}`}>
                  <div className="text-lg font-mono font-bold">{d.count}</div>
                  <div className="text-[10px] mt-0.5">{d.label}</div>
                </div>
              ))}
            </div>
          )}

          {/* Tab Navigation */}
          <div className="flex gap-1 bg-bg-secondary rounded-lg p-1 border border-bg-card overflow-x-auto mb-6">
            {availableTabs.map(t => (
              <button
                key={t.key}
                onClick={() => setActiveTab(t.key)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
                  activeTab === t.key
                    ? 'bg-accent-purple/15 text-accent-purple'
                    : 'text-text-secondary hover:text-text-primary'
                }`}
              >
                <t.icon className="w-3.5 h-3.5" />
                {t.label}
              </button>
            ))}
          </div>

          {/* ═══════════════ SALIENCY TAB ═══════════════ */}
          {activeTab === 'saliency' && result?.saliency && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <ChartPanel title="Top Features (Gradient Saliency)" subtitle="Mean absolute gradient magnitude per feature">
                <HorizontalBarChart data={saliencyData} dataKey="value" unit="%" colors={GRADIENT_COLORS} />
              </ChartPanel>
              <PerClassPanel
                title="Per-Class Feature Importance"
                data={result.saliency.per_class_importance}
                valueKey="importance"
                expandedClass={expandedClass}
                onToggle={cls => setExpandedClass(expandedClass === cls ? null : cls)}
              />
            </div>
          )}

          {/* ═══════════════ INTEGRATED GRADIENTS TAB ═══════════════ */}
          {activeTab === 'ig' && result?.integrated_gradients && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <ChartPanel title="Top Features (Integrated Gradients)" subtitle="Path-integrated attribution scores">
                  <HorizontalBarChart data={igData} dataKey="value" unit="%" colors={GRADIENT_COLORS} />
                </ChartPanel>
                {result.integrated_gradients.per_class_attribution && (
                  <PerClassPanel
                    title="Per-Class Attribution"
                    data={result.integrated_gradients.per_class_attribution}
                    valueKey="attribution"
                    expandedClass={expandedClass}
                    onToggle={cls => setExpandedClass(expandedClass === cls ? null : cls)}
                  />
                )}
              </div>
              {result.integrated_gradients.convergence_delta !== undefined && (
                <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                  <div className="flex items-center gap-2">
                    {result.integrated_gradients.convergence_delta < 0.05 ? (
                      <CheckCircle2 className="w-4 h-4 text-accent-green" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-accent-amber" />
                    )}
                    <span className="text-xs font-medium">
                      Completeness Axiom Check: {' '}
                      <span className="font-mono">
                        delta = {result.integrated_gradients.convergence_delta.toFixed(6)}
                      </span>
                    </span>
                    <span className="text-[10px] text-text-secondary ml-2">
                      {result.integrated_gradients.convergence_delta < 0.05
                        ? 'Attributions satisfy completeness (sum ≈ output difference)'
                        : 'Higher delta — consider increasing integration steps'}
                    </span>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ═══════════════ SENSITIVITY TAB ═══════════════ */}
          {activeTab === 'sensitivity' && result?.sensitivity && (
            <div className="space-y-4">
              <ChartPanel title="Most Sensitive Features" subtitle="Features where small perturbations flip predictions">
                <HorizontalBarChart
                  data={sensData} dataKey="value" unit="%"
                  colors={sensData.map((_: unknown, i: number) => i < 5 ? '#EF4444' : i < 10 ? '#F59E0B' : '#22C55E')}
                />
                <p className="text-xs text-text-secondary mt-2">
                  Features with high flip rate are decision-critical — small perturbations change predictions.
                </p>
              </ChartPanel>
              {result.sensitivity.global_sensitivity_curve && (
                <ChartPanel title="Global Sensitivity Curve" subtitle="Model accuracy vs perturbation magnitude">
                  <ResponsiveContainer width="100%" height={300}>
                    <LineChart data={result.sensitivity.global_sensitivity_curve}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis dataKey="epsilon" tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Perturbation (ε)', position: 'insideBottom', offset: -5, fill: '#94A3B8', fontSize: 10 }} />
                      <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} domain={[0, 1]} label={{ value: 'Accuracy', angle: -90, position: 'insideLeft', fill: '#94A3B8', fontSize: 10 }} />
                      <Tooltip contentStyle={TT} />
                      <Line type="monotone" dataKey="accuracy" stroke="#8B5CF6" strokeWidth={2} dot={{ fill: '#8B5CF6', r: 4 }} />
                    </LineChart>
                  </ResponsiveContainer>
                </ChartPanel>
              )}
            </div>
          )}

          {/* ═══════════════ SHAP TAB ═══════════════ */}
          {activeTab === 'shap' && result?.shap && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <ChartPanel title="SHAP Feature Importance" subtitle="Shapley value approximation via coalition sampling">
                  <HorizontalBarChart data={shapData} dataKey="value" unit="%" colors={GRADIENT_COLORS} />
                </ChartPanel>
                <ChartPanel title="SHAP Direction" subtitle="Positive = pushes toward predicted class">
                  <div className="space-y-1.5 max-h-[380px] overflow-y-auto">
                    {(result.shap.global_importance || []).slice(0, 15).map((f: XaiResult, i: number) => (
                      <div key={i} className="flex items-center gap-2 text-xs">
                        <span className="w-28 truncate text-text-secondary">{f.name}</span>
                        <div className="flex-1 flex items-center">
                          <div className="w-full bg-bg-primary rounded h-3 relative overflow-hidden">
                            <div
                              className={`absolute top-0 h-3 rounded ${f.direction === 'positive' ? 'bg-accent-green/60' : 'bg-accent-red/60'}`}
                              style={{
                                width: `${f.importance * 50}%`,
                                left: f.direction === 'positive' ? '50%' : `${50 - f.importance * 50}%`,
                              }}
                            />
                            <div className="absolute left-1/2 top-0 w-px h-full bg-text-secondary/30" />
                          </div>
                        </div>
                        <span className={`font-mono w-14 text-right ${f.direction === 'positive' ? 'text-accent-green' : 'text-accent-red'}`}>
                          {f.direction === 'positive' ? '+' : '-'}{(f.importance * 100).toFixed(0)}%
                        </span>
                      </div>
                    ))}
                  </div>
                </ChartPanel>
              </div>
              {result.shap.per_class_shap && (
                <PerClassPanel
                  title="Per-Class SHAP Values"
                  data={result.shap.per_class_shap}
                  valueKey="shap_value"
                  expandedClass={expandedClass}
                  onToggle={cls => setExpandedClass(expandedClass === cls ? null : cls)}
                />
              )}
            </div>
          )}

          {/* ═══════════════ LRP TAB ═══════════════ */}
          {activeTab === 'lrp' && result?.lrp && (
            <ChartPanel title="Layer-wise Relevance Propagation" subtitle="Relevance scores propagated from output to input (epsilon-rule)">
              <HorizontalBarChart data={lrpData} dataKey="value" unit="%" colors={GRADIENT_COLORS} />
            </ChartPanel>
          )}

          {/* ═══════════════ DEEPLIFT TAB ═══════════════ */}
          {activeTab === 'deeplift' && result?.deeplift && (
            <ChartPanel title="DeepLIFT Attribution" subtitle="Difference-from-reference attribution (rescale rule)">
              <HorizontalBarChart data={deepliftData} dataKey="value" unit="%" colors={GRADIENT_COLORS} />
            </ChartPanel>
          )}

          {/* ═══════════════ ATTENTION TAB ═══════════════ */}
          {activeTab === 'attention' && result?.attention && (
            <div className="space-y-4">
              <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                <div className="flex items-center gap-2 mb-3">
                  <h3 className="text-sm font-semibold">Attention Analysis</h3>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full ${
                    result.attention.has_native_attention
                      ? 'bg-accent-green/15 text-accent-green'
                      : 'bg-accent-amber/15 text-accent-amber'
                  }`}>
                    {result.attention.has_native_attention ? 'Native Attention' : 'Pseudo-Attention (gradient-based)'}
                  </span>
                </div>

                {result.attention.pseudo_attention && (
                  <>
                    <h4 className="text-xs text-text-secondary mb-2">Feature Attention Heatmap</h4>
                    <div className="flex gap-px rounded overflow-hidden h-8 mb-2">
                      {result.attention.pseudo_attention.map((val: number, i: number) => (
                        <div
                          key={i}
                          className="flex-1 min-w-[2px]"
                          style={{ backgroundColor: `rgba(168, 85, 247, ${0.05 + val * 0.95})` }}
                          title={`${result.feature_names?.[i] || `f${i}`}: ${(val * 100).toFixed(0)}%`}
                        />
                      ))}
                    </div>
                    <div className="flex justify-between text-[10px] text-text-secondary">
                      <span>Feature 0</span>
                      <span>Low → High attention</span>
                      <span>Feature {result.attention.pseudo_attention.length - 1}</span>
                    </div>
                  </>
                )}
              </div>

              {result.attention.feature_attention_scores?.length > 0 && (
                <ChartPanel title="Layer-wise Neuron Importance" subtitle="Top activated neurons per layer">
                  <div className="space-y-3 max-h-[400px] overflow-y-auto">
                    {result.attention.feature_attention_scores.map((layer: XaiResult, li: number) => (
                      <div key={li} className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-mono text-accent-blue bg-accent-blue/10 px-1.5 py-0.5 rounded">{layer.layer_name}</span>
                          <span className="text-[10px] text-text-secondary">{layer.n_neurons} neurons</span>
                        </div>
                        <div className="flex gap-0.5">
                          {(layer.top_neurons || []).slice(0, 12).map((n: XaiResult, ni: number) => (
                            <div
                              key={ni}
                              className="flex-1 rounded"
                              style={{
                                height: `${Math.max(4, n.importance * 40)}px`,
                                backgroundColor: `rgba(59, 130, 246, ${0.2 + n.importance * 0.8})`,
                              }}
                              title={`Neuron ${n.index}: ${(n.importance * 100).toFixed(0)}%`}
                            />
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </ChartPanel>
              )}
            </div>
          )}

          {/* ═══════════════ FEATURE INTERACTIONS TAB ═══════════════ */}
          {activeTab === 'interactions' && result?.feature_interactions && (
            <div className="space-y-4">
              <ChartPanel
                title="Feature Interactions (H-statistic)"
                subtitle={`${result.feature_interactions.total_interactions_detected} significant pairwise interactions detected`}
              >
                <div className="space-y-2 max-h-[400px] overflow-y-auto">
                  {(result.feature_interactions.top_pairs || []).slice(0, 20).map((pair: XaiResult, i: number) => {
                    const maxStrength = result.feature_interactions.top_pairs[0]?.interaction_strength || 1
                    const pct = (pair.interaction_strength / maxStrength) * 100
                    return (
                      <div key={i} className="flex items-center gap-2 text-xs">
                        <span className="w-5 text-text-secondary font-mono">{i + 1}</span>
                        <span className="w-32 truncate text-accent-blue">{pair.feature_i_name}</span>
                        <ArrowRightLeft className="w-3 h-3 text-text-secondary shrink-0" />
                        <span className="w-32 truncate text-accent-purple">{pair.feature_j_name}</span>
                        <div className="flex-1 bg-bg-primary rounded-full h-2">
                          <div className="h-2 rounded-full bg-gradient-to-r from-accent-blue to-accent-purple" style={{ width: `${pct}%` }} />
                        </div>
                        <span className="font-mono text-text-primary w-16 text-right">
                          {(pair.interaction_strength * 1000).toFixed(1)}
                        </span>
                      </div>
                    )
                  })}
                </div>
              </ChartPanel>

              {/* Interaction Matrix Heatmap */}
              {result.feature_interactions.interaction_matrix && (
                <ChartPanel title="Interaction Matrix" subtitle="Pairwise feature interaction strengths">
                  <div className="overflow-x-auto">
                    <div className="inline-flex flex-col gap-px">
                      {result.feature_interactions.interaction_matrix.slice(0, 20).map((row: number[], ri: number) => (
                        <div key={ri} className="flex gap-px">
                          {row.slice(0, 20).map((val: number, ci: number) => {
                            const maxVal = Math.max(...result.feature_interactions.interaction_matrix.flat())
                            const intensity = maxVal > 0 ? val / maxVal : 0
                            return (
                              <div
                                key={ci}
                                className="w-4 h-4 rounded-sm"
                                style={{ backgroundColor: `rgba(139, 92, 246, ${0.05 + intensity * 0.95})` }}
                                title={`f${result.feature_interactions.feature_indices[ri]} x f${result.feature_interactions.feature_indices[ci]}: ${(val * 1000).toFixed(2)}`}
                              />
                            )
                          })}
                        </div>
                      ))}
                    </div>
                  </div>
                </ChartPanel>
              )}
            </div>
          )}

          {/* ═══════════════ COUNTERFACTUAL TAB ═══════════════ */}
          {activeTab === 'counterfactual' && result?.counterfactual && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                <StatBox icon={ArrowRightLeft} label="Counterfactuals" value={result.counterfactual.n_counterfactuals} color="text-accent-purple" />
                <StatBox icon={CheckCircle2} label="Flip Success" value={`${(result.counterfactual.flip_success_rate * 100).toFixed(0)}%`} color="text-accent-green" />
                <StatBox
                  icon={Search} label="Avg Changes"
                  value={Math.round(result.counterfactual.counterfactuals.reduce((s: number, c: XaiResult) => s + c.features_changed, 0) / Math.max(result.counterfactual.n_counterfactuals, 1))}
                  color="text-accent-blue"
                />
              </div>

              {result.counterfactual.counterfactuals.map((cf: XaiResult, ci: number) => (
                <div key={ci} className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                  <div className="flex items-center gap-3 mb-3">
                    <span className="text-xs font-mono bg-bg-card px-2 py-1 rounded">Sample #{cf.sample_index}</span>
                    <div className="flex items-center gap-1.5">
                      <span className={`text-xs px-2 py-0.5 rounded ${cf.flipped ? 'bg-accent-green/15 text-accent-green' : 'bg-accent-red/15 text-accent-red'}`}>
                        {cf.flipped ? 'Successfully Flipped' : 'Not Flipped'}
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 mb-4 text-sm">
                    <span className="px-2 py-1 bg-accent-blue/15 text-accent-blue rounded font-medium">
                      {cf.original_class_name} ({(cf.original_confidence * 100).toFixed(0)}%)
                    </span>
                    <ArrowRightLeft className="w-4 h-4 text-text-secondary" />
                    <span className="px-2 py-1 bg-accent-purple/15 text-accent-purple rounded font-medium">
                      {cf.target_class_name} ({(cf.counterfactual_confidence * 100).toFixed(0)}%)
                    </span>
                    <span className="text-xs text-text-secondary ml-auto">
                      L1 distance: <span className="font-mono">{cf.l1_distance.toFixed(2)}</span> | {cf.features_changed} features changed
                    </span>
                  </div>
                  <div className="space-y-1">
                    {(cf.top_changes || []).slice(0, 8).map((ch: XaiResult, chi: number) => {
                      if (Math.abs(ch.delta) < 0.001) return null
                      return (
                        <div key={chi} className="flex items-center gap-2 text-xs">
                          <span className="w-36 truncate text-text-secondary">{ch.feature_name}</span>
                          <span className="font-mono text-text-secondary w-16 text-right">{ch.original_value.toFixed(3)}</span>
                          <ArrowRightLeft className="w-3 h-3 text-accent-purple shrink-0" />
                          <span className="font-mono text-accent-purple w-16">{ch.counterfactual_value.toFixed(3)}</span>
                          <span className={`font-mono w-16 text-right ${ch.delta > 0 ? 'text-accent-green' : 'text-accent-red'}`}>
                            {ch.delta > 0 ? '+' : ''}{ch.delta.toFixed(3)}
                          </span>
                        </div>
                      )
                    })}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* ═══════════════ DECISION PATH TAB ═══════════════ */}
          {activeTab === 'decision_path' && result?.decision_path && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <StatBox icon={Cpu} label="Layers" value={result.decision_path.n_layers} color="text-accent-blue" />
                <StatBox icon={Brain} label="Parameters" value={result.decision_path.total_params.toLocaleString()} color="text-accent-purple" />
                <StatBox icon={AlertTriangle} label="Bottlenecks" value={result.decision_path.bottlenecks?.length || 0} color="text-accent-amber" />
                <StatBox icon={Activity} label="Traces" value={result.decision_path.traces?.length || 0} color="text-accent-green" />
              </div>

              {/* Layer Architecture */}
              <ChartPanel title="Network Architecture & Activation Flow" subtitle="Layer-by-layer sparsity and activation patterns">
                <div className="space-y-2">
                  {(result.decision_path.layers || []).map((layer: XaiResult, li: number) => (
                    <div key={li} className="flex items-center gap-3 text-xs">
                      <span className="w-6 text-text-secondary font-mono text-right">{li}</span>
                      <span className="w-32 truncate font-mono text-accent-blue">{layer.name || layer.type}</span>
                      <span className="w-20 text-text-secondary">{layer.type}</span>
                      {layer.in_features !== undefined && (
                        <span className="text-[10px] text-text-secondary">{layer.in_features}→{layer.out_features}</span>
                      )}
                      <div className="flex-1 bg-bg-primary rounded-full h-3 relative overflow-hidden">
                        {/* Sparsity bar */}
                        <div
                          className="absolute top-0 left-0 h-3 bg-accent-red/40 rounded-full"
                          style={{ width: `${(layer.sparsity || 0) * 100}%` }}
                          title={`Sparsity: ${((layer.sparsity || 0) * 100).toFixed(1)}%`}
                        />
                        {/* Activity overlay */}
                        <div
                          className="absolute top-0 left-0 h-3 bg-accent-blue/60 rounded-full"
                          style={{ width: `${Math.min((1 - (layer.sparsity || 0)) * 100, 100)}%` }}
                        />
                      </div>
                      <span className="font-mono w-14 text-right text-text-secondary">{((1 - (layer.sparsity || 0)) * 100).toFixed(0)}% active</span>
                      {layer.dead_neurons > 0 && (
                        <span className="text-accent-red text-[10px]">{layer.dead_neurons} dead</span>
                      )}
                    </div>
                  ))}
                </div>
              </ChartPanel>

              {/* Per-Sample Traces */}
              {result.decision_path.traces?.length > 0 && (
                <ChartPanel title="Decision Traces" subtitle="Layer-by-layer activation energy per sample">
                  <ResponsiveContainer width="100%" height={300}>
                    <LineChart>
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis dataKey="layer_index" tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Layer', position: 'insideBottom', offset: -5, fill: '#94A3B8', fontSize: 10 }} />
                      <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} label={{ value: 'Energy', angle: -90, position: 'insideLeft', fill: '#94A3B8', fontSize: 10 }} />
                      <Tooltip contentStyle={TT} />
                      <Legend />
                      {result.decision_path.traces.slice(0, 5).map((trace: XaiResult, ti: number) => (
                        <Line
                          key={ti}
                          data={trace.layer_flow}
                          type="monotone"
                          dataKey="energy"
                          name={`Sample #${trace.sample_index} (class ${trace.predicted_class})`}
                          stroke={GRADIENT_COLORS[ti % GRADIENT_COLORS.length]}
                          strokeWidth={2}
                          dot={{ r: 3 }}
                        />
                      ))}
                    </LineChart>
                  </ResponsiveContainer>
                </ChartPanel>
              )}

              {/* Bottleneck Warnings */}
              {result.decision_path.bottlenecks?.length > 0 && (
                <div className="bg-accent-amber/5 rounded-xl p-4 border border-accent-amber/20">
                  <h4 className="text-sm font-medium text-accent-amber flex items-center gap-2 mb-2">
                    <AlertTriangle className="w-4 h-4" /> Bottleneck Detection
                  </h4>
                  <div className="space-y-1">
                    {result.decision_path.bottlenecks.map((b: XaiResult, bi: number) => (
                      <div key={bi} className="flex items-center gap-2 text-xs">
                        <span className="font-mono text-text-secondary">Layer {b.layer_index}</span>
                        <span className="text-text-secondary">{b.layer_name}</span>
                        <span className="px-2 py-0.5 bg-accent-amber/15 text-accent-amber rounded">
                          {b.reason === 'high_sparsity' ? `Sparsity: ${(b.severity * 100).toFixed(0)}%` : `Dead neurons detected`}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ═══════════════ CROSS-METHOD AGREEMENT TAB ═══════════════ */}
          {activeTab === 'agreement' && result?.cross_method_agreement && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Radar chart of method agreement */}
                <ChartPanel title="Cross-Method Attribution Agreement" subtitle="Jaccard similarity of top-10 feature rankings">
                  {radarData.length > 2 ? (
                    <ResponsiveContainer width="100%" height={350}>
                      <RadarChart data={radarData}>
                        <PolarGrid stroke="#334155" />
                        <PolarAngleAxis dataKey="method" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                        <PolarRadiusAxis tick={{ fill: '#94A3B8', fontSize: 9 }} domain={[0, 1]} />
                        {result.cross_method_agreement.methods_compared.slice(0, 4).map((m: string, i: number) => (
                          <RechartsRadar
                            key={m}
                            name={m}
                            dataKey={m}
                            stroke={Object.values(METHOD_COLORS)[i] || GRADIENT_COLORS[i]}
                            fill={Object.values(METHOD_COLORS)[i] || GRADIENT_COLORS[i]}
                            fillOpacity={0.15}
                          />
                        ))}
                        <Legend />
                        <Tooltip contentStyle={TT} />
                      </RadarChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="text-center text-text-secondary text-xs py-12">
                      Need 3+ methods for radar visualization
                    </div>
                  )}
                </ChartPanel>

                {/* Pairwise agreement matrix */}
                <ChartPanel title="Pairwise Rank Agreement" subtitle="How much methods agree on top features">
                  <div className="space-y-1.5">
                    {Object.entries(result.cross_method_agreement.pairwise_rank_agreement || {}).map(([pair, val]) => {
                      const score = Number(val)
                      return (
                        <div key={pair} className="flex items-center gap-2 text-xs">
                          <span className="w-44 truncate text-text-secondary font-mono">{pair.replace(/_/g, ' ')}</span>
                          <div className="flex-1 bg-bg-primary rounded-full h-2.5">
                            <div
                              className={`h-2.5 rounded-full ${score > 0.6 ? 'bg-accent-green' : score > 0.3 ? 'bg-accent-amber' : 'bg-accent-red'}`}
                              style={{ width: `${score * 100}%` }}
                            />
                          </div>
                          <span className={`font-mono w-12 text-right ${score > 0.6 ? 'text-accent-green' : score > 0.3 ? 'text-accent-amber' : 'text-accent-red'}`}>
                            {(score * 100).toFixed(0)}%
                          </span>
                        </div>
                      )
                    })}
                  </div>
                </ChartPanel>
              </div>

              {/* Consensus features */}
              {result.cross_method_agreement.consensus_top_features?.length > 0 && (
                <div className="bg-accent-green/5 rounded-xl p-5 border border-accent-green/20">
                  <h4 className="text-sm font-medium text-accent-green flex items-center gap-2 mb-3">
                    <CheckCircle2 className="w-4 h-4" />
                    Consensus Features ({result.cross_method_agreement.n_consensus})
                    <span className="text-[10px] text-text-secondary font-normal">— Appear in top-10 of ALL methods</span>
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {result.cross_method_agreement.consensus_top_features.map((f: XaiResult) => (
                      <span key={f.index} className="px-3 py-1.5 bg-accent-green/10 border border-accent-green/30 rounded-lg text-xs font-medium text-accent-green">
                        {f.name}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ═══════════════ MODEL COMPARISON TAB ═══════════════ */}
          {activeTab === 'compare' && compareResult && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <StatBox icon={Brain} label="Models" value={compareResult.n_models} color="text-accent-blue" />
                <StatBox icon={Layers} label="Samples" value={compareResult.n_samples} color="text-accent-purple" />
                <StatBox icon={AlertTriangle} label="Disagreements" value={compareResult.total_disagreements} color="text-accent-red" />
                <StatBox icon={Zap} label="Time" value={`${(compareResult.time_ms / 1000).toFixed(1)}s`} color="text-accent-amber" />
              </div>

              {/* Per-model summary cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {Object.entries(compareResult.model_summaries || {}).map(([name, summary]: [string, unknown]) => {
                  const s = summary as XaiResult
                  return (
                    <div key={name} className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                      <div className="flex items-center gap-2 mb-2">
                        <Brain className="w-4 h-4 text-accent-blue" />
                        <span className="text-sm font-mono font-medium">{name}</span>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-xs mb-3">
                        <div>
                          <span className="text-text-secondary">Accuracy</span>
                          <span className="block font-mono text-accent-green">{(s.accuracy * 100).toFixed(1)}%</span>
                        </div>
                        <div>
                          <span className="text-text-secondary">Confidence</span>
                          <span className="block font-mono text-accent-blue">{(s.mean_confidence * 100).toFixed(1)}%</span>
                        </div>
                      </div>
                      <div className="text-[10px] text-text-secondary mb-1">Top features:</div>
                      <div className="flex flex-wrap gap-1">
                        {(s.top_features || []).slice(0, 5).map((f: XaiResult, i: number) => (
                          <span key={i} className="px-1.5 py-0.5 bg-bg-card rounded text-[10px] font-mono">{f.name}</span>
                        ))}
                      </div>
                    </div>
                  )
                })}
              </div>

              {/* Agreement Matrix */}
              {Object.keys(compareResult.agreement_matrix || {}).length > 0 && (
                <ChartPanel title="Model Agreement Matrix" subtitle="Prediction agreement rate between model pairs">
                  <div className="space-y-2">
                    {Object.entries(compareResult.agreement_matrix || {}).map(([pair, data]: [string, unknown]) => {
                      const d = data as XaiResult
                      return (
                        <div key={pair} className="flex items-center gap-3 text-xs">
                          <span className="w-40 font-mono text-text-secondary truncate">{pair.replace(/_vs_/g, ' vs ')}</span>
                          <div className="flex-1 bg-bg-primary rounded-full h-3">
                            <div
                              className={`h-3 rounded-full ${d.agreement_rate > 0.9 ? 'bg-accent-green' : d.agreement_rate > 0.7 ? 'bg-accent-amber' : 'bg-accent-red'}`}
                              style={{ width: `${d.agreement_rate * 100}%` }}
                            />
                          </div>
                          <span className="font-mono w-14 text-right">{(d.agreement_rate * 100).toFixed(1)}%</span>
                          <span className="text-text-secondary w-20 text-right">{d.disagreement_count} disagree</span>
                        </div>
                      )
                    })}
                  </div>
                </ChartPanel>
              )}

              {/* Attribution Correlation */}
              {Object.keys(compareResult.attribution_correlation || {}).length > 0 && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <ChartPanel title="Attribution Correlation" subtitle="Spearman rank correlation of saliency maps">
                    <div className="space-y-2">
                      {Object.entries(compareResult.attribution_correlation || {}).map(([pair, val]) => {
                        const v = Number(val)
                        return (
                          <div key={pair} className="flex items-center gap-3 text-xs">
                            <span className="w-40 font-mono text-text-secondary truncate">{pair.replace(/_vs_/g, ' vs ')}</span>
                            <div className="flex-1 bg-bg-primary rounded-full h-2.5">
                              <div
                                className={`h-2.5 rounded-full ${v > 0.7 ? 'bg-accent-green' : v > 0.4 ? 'bg-accent-amber' : 'bg-accent-red'}`}
                                style={{ width: `${Math.abs(v) * 100}%` }}
                              />
                            </div>
                            <span className={`font-mono w-14 text-right ${v > 0.7 ? 'text-accent-green' : v > 0.4 ? 'text-accent-amber' : 'text-accent-red'}`}>
                              {v.toFixed(3)}
                            </span>
                          </div>
                        )
                      })}
                    </div>
                  </ChartPanel>

                  <ChartPanel title="Confidence Correlation" subtitle="Pearson correlation of prediction confidences">
                    <div className="space-y-2">
                      {Object.entries(compareResult.confidence_correlation || {}).map(([pair, val]) => {
                        const v = Number(val)
                        return (
                          <div key={pair} className="flex items-center gap-3 text-xs">
                            <span className="w-40 font-mono text-text-secondary truncate">{pair.replace(/_vs_/g, ' vs ')}</span>
                            <div className="flex-1 bg-bg-primary rounded-full h-2.5">
                              <div className="h-2.5 rounded-full bg-accent-blue" style={{ width: `${Math.abs(v) * 100}%` }} />
                            </div>
                            <span className="font-mono text-accent-blue w-14 text-right">{v.toFixed(3)}</span>
                          </div>
                        )
                      })}
                    </div>
                  </ChartPanel>
                </div>
              )}

              {/* Disagreement Samples */}
              {compareResult.disagreement_samples?.length > 0 && (
                <ChartPanel title="Decision Disagreements" subtitle={`Samples where models predict different classes (showing ${Math.min(compareResult.disagreement_samples.length, 20)})`}>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="text-text-secondary border-b border-bg-card">
                          <th className="px-2 py-2 text-left">Sample</th>
                          {compareResult.model_names.map((m: string) => (
                            <th key={m} className="px-2 py-2 text-center font-mono">{m}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {compareResult.disagreement_samples.slice(0, 20).map((ds: XaiResult, di: number) => (
                          <tr key={di} className="border-t border-bg-card/30">
                            <td className="px-2 py-1.5 font-mono text-text-secondary">#{ds.sample_index}</td>
                            {compareResult.model_names.map((m: string) => {
                              const pred = ds.predictions[m]
                              const conf = ds.confidences[m]
                              return (
                                <td key={m} className="px-2 py-1.5 text-center">
                                  <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-bg-card">
                                    C{pred} <span className="text-text-secondary">({(conf * 100).toFixed(0)}%)</span>
                                  </span>
                                </td>
                              )
                            })}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </ChartPanel>
              )}
            </div>
          )}

          {/* ═══════════════ MULTI-DATASET TAB ═══════════════ */}
          {activeTab === 'multiDataset' && multiResult && (
            <div className="space-y-4">
              {/* Overview Stats */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <StatBox icon={Database} label="Datasets" value={multiResult.n_files} color="text-accent-green" />
                <StatBox icon={Brain} label="Models" value={multiResult.n_models} color="text-accent-blue" />
                <StatBox icon={Layers} label="Total Runs" value={multiResult.runs?.length || 0} color="text-accent-purple" />
                <StatBox icon={Zap} label="Method" value={multiResult.method || 'all'} color="text-accent-amber" />
              </div>

              {/* Sub-view navigation */}
              <div className="flex gap-1 bg-bg-secondary rounded-lg p-1 border border-bg-card overflow-x-auto">
                {[
                  { key: 'overview', label: 'Overview', icon: Target },
                  { key: 'per-run', label: 'Per-Run Details', icon: Layers },
                  { key: 'cross-dataset', label: 'Cross-Dataset', icon: Database },
                  { key: 'cross-model', label: 'Cross-Model', icon: GitCompare },
                ].map(v => (
                  <button
                    key={v.key}
                    onClick={() => setMultiView(v.key)}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
                      multiView === v.key
                        ? 'bg-accent-green/15 text-accent-green'
                        : 'text-text-secondary hover:text-text-primary'
                    }`}
                  >
                    <v.icon className="w-3.5 h-3.5" />
                    {v.label}
                  </button>
                ))}
              </div>

              {/* Overview: per-run summary cards */}
              {multiView === 'overview' && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {(multiResult.runs || []).map((run: XaiResult, ri: number) => (
                    <div key={ri} className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                      <div className="flex items-center gap-2 mb-2">
                        <Database className="w-4 h-4 text-accent-green" />
                        <span className="text-xs font-mono truncate flex-1">{run.dataset_name}</span>
                        <span className="text-[10px] px-2 py-0.5 bg-accent-blue/10 text-accent-blue rounded">{run.model_used}</span>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-xs mb-3">
                        <div>
                          <span className="text-text-secondary">Accuracy</span>
                          <span className="block font-mono text-accent-green">
                            {run.prediction_summary ? `${(run.prediction_summary.accuracy * 100).toFixed(1)}%` : 'N/A'}
                          </span>
                        </div>
                        <div>
                          <span className="text-text-secondary">Confidence</span>
                          <span className="block font-mono text-accent-blue">
                            {run.prediction_summary ? `${(run.prediction_summary.mean_confidence * 100).toFixed(1)}%` : 'N/A'}
                          </span>
                        </div>
                        <div>
                          <span className="text-text-secondary">Features</span>
                          <span className="block font-mono text-text-primary">{run.n_features || 'N/A'}</span>
                        </div>
                        <div>
                          <span className="text-text-secondary">Samples</span>
                          <span className="block font-mono text-text-primary">{run.n_samples || 'N/A'}</span>
                        </div>
                      </div>
                      {/* Top features preview */}
                      {run.saliency?.global_importance && (
                        <div>
                          <div className="text-[10px] text-text-secondary mb-1">Top features (saliency):</div>
                          <div className="flex flex-wrap gap-1">
                            {run.saliency.global_importance.slice(0, 5).map((f: XaiResult, fi: number) => (
                              <span key={fi} className="px-1.5 py-0.5 bg-bg-card rounded text-[10px] font-mono">{f.name}</span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* Per-Run Details: detailed results per dataset/model pair */}
              {multiView === 'per-run' && (
                <div className="space-y-6">
                  {(multiResult.runs || []).map((run: XaiResult, ri: number) => (
                    <div key={ri} className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-4">
                      <div className="flex items-center gap-3">
                        <Database className="w-5 h-5 text-accent-green" />
                        <div className="flex-1">
                          <h3 className="text-sm font-display font-semibold">{run.dataset_name}</h3>
                          <p className="text-[10px] text-text-secondary">Model: {run.model_used} | {run.n_samples} samples | {run.n_features} features</p>
                        </div>
                        {run.prediction_summary && (
                          <span className="text-xs font-mono text-accent-green">{(run.prediction_summary.accuracy * 100).toFixed(1)}% acc</span>
                        )}
                      </div>

                      {/* Saliency chart for this run */}
                      {run.saliency?.global_importance && (
                        <div>
                          <h4 className="text-xs font-medium mb-2">Top Features (Saliency)</h4>
                          <div className="space-y-1">
                            {run.saliency.global_importance.slice(0, 10).map((f: XaiResult, fi: number) => {
                              const max = run.saliency.global_importance[0]?.importance || 1
                              return (
                                <div key={fi} className="flex items-center gap-2 text-xs">
                                  <span className="w-4 text-text-secondary font-mono">{fi + 1}</span>
                                  <span className="w-32 truncate text-text-secondary">{f.name}</span>
                                  <div className="flex-1 bg-bg-primary rounded-full h-2">
                                    <div className="h-2 rounded-full bg-accent-purple" style={{ width: `${(f.importance / max) * 100}%` }} />
                                  </div>
                                  <span className="font-mono w-14 text-right text-accent-purple">{(f.importance * 100).toFixed(1)}%</span>
                                </div>
                              )
                            })}
                          </div>
                        </div>
                      )}

                      {/* SHAP summary for this run */}
                      {run.shap?.global_importance && (
                        <div>
                          <h4 className="text-xs font-medium mb-2">SHAP Direction</h4>
                          <div className="space-y-1">
                            {run.shap.global_importance.slice(0, 8).map((f: XaiResult, fi: number) => (
                              <div key={fi} className="flex items-center gap-2 text-xs">
                                <span className="w-28 truncate text-text-secondary">{f.name}</span>
                                <span className={`font-mono w-16 text-right ${f.direction === 'positive' ? 'text-accent-green' : 'text-accent-red'}`}>
                                  {f.direction === 'positive' ? '+' : '-'}{(f.importance * 100).toFixed(0)}%
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Sensitivity summary */}
                      {run.sensitivity?.top_sensitive_features && (
                        <div>
                          <h4 className="text-xs font-medium mb-2">Most Sensitive Features</h4>
                          <div className="flex flex-wrap gap-1.5">
                            {run.sensitivity.top_sensitive_features.slice(0, 6).map((f: XaiResult, fi: number) => (
                              <span key={fi} className={`px-2 py-1 rounded text-[10px] font-mono ${
                                f.max_flip_rate > 0.3 ? 'bg-accent-red/10 text-accent-red' : 'bg-accent-amber/10 text-accent-amber'
                              }`}>
                                {f.name}: {(f.max_flip_rate * 100).toFixed(0)}% flip
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* Cross-Dataset Comparison */}
              {multiView === 'cross-dataset' && (
                <div className="space-y-4">
                  {Object.keys(multiResult.cross_dataset_comparison || {}).length > 0 ? (
                    Object.entries(multiResult.cross_dataset_comparison).map(([model, data]: [string, unknown]) => {
                      const d = data as XaiResult
                      return (
                        <div key={model} className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-4">
                          <div className="flex items-center gap-2">
                            <Brain className="w-5 h-5 text-accent-blue" />
                            <h3 className="text-sm font-display font-semibold">{model}</h3>
                            <span className="text-[10px] text-text-secondary">
                              {d.n_stable_features} / {d.n_total_features} features stable across datasets
                            </span>
                          </div>

                          {/* Feature Stability */}
                          <ChartPanel title="Feature Importance Stability" subtitle="How consistently features rank across datasets (1.0 = appears in top-15 of ALL datasets)">
                            <div className="space-y-1 max-h-[350px] overflow-y-auto">
                              {Object.entries(d.feature_stability || {}).slice(0, 25).map(([feat, score]) => {
                                const s = Number(score)
                                return (
                                  <div key={feat} className="flex items-center gap-2 text-xs">
                                    <span className="w-36 truncate text-text-secondary">{feat}</span>
                                    <div className="flex-1 bg-bg-primary rounded-full h-2.5">
                                      <div
                                        className={`h-2.5 rounded-full ${s >= 0.8 ? 'bg-accent-green' : s >= 0.5 ? 'bg-accent-amber' : 'bg-accent-red'}`}
                                        style={{ width: `${s * 100}%` }}
                                      />
                                    </div>
                                    <span className={`font-mono w-12 text-right ${s >= 0.8 ? 'text-accent-green' : s >= 0.5 ? 'text-accent-amber' : 'text-accent-red'}`}>
                                      {(s * 100).toFixed(0)}%
                                    </span>
                                  </div>
                                )
                              })}
                            </div>
                          </ChartPanel>

                          {/* Dataset Summaries */}
                          <ChartPanel title="Dataset Performance Comparison" subtitle="Model performance across different datasets">
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                              {(d.dataset_summaries || []).map((ds: XaiResult, di: number) => (
                                <div key={di} className="bg-bg-primary rounded-lg p-3 border border-bg-card">
                                  <div className="text-xs font-mono truncate mb-2">{ds.dataset}</div>
                                  <div className="grid grid-cols-2 gap-1 text-[10px]">
                                    <div><span className="text-text-secondary">Samples:</span> <span className="font-mono">{ds.n_samples}</span></div>
                                    <div><span className="text-text-secondary">Features:</span> <span className="font-mono">{ds.n_features}</span></div>
                                    {ds.accuracy != null && (
                                      <div><span className="text-text-secondary">Accuracy:</span> <span className="font-mono text-accent-green">{(ds.accuracy * 100).toFixed(1)}%</span></div>
                                    )}
                                    {ds.confidence_mean != null && (
                                      <div><span className="text-text-secondary">Confidence:</span> <span className="font-mono text-accent-blue">{(ds.confidence_mean * 100).toFixed(1)}%</span></div>
                                    )}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </ChartPanel>
                        </div>
                      )
                    })
                  ) : (
                    <div className="text-center text-text-secondary text-sm py-12">
                      <Database className="w-8 h-8 mx-auto mb-2 opacity-40" />
                      Upload 2+ datasets to see cross-dataset comparison
                    </div>
                  )}
                </div>
              )}

              {/* Cross-Model Comparison per Dataset */}
              {multiView === 'cross-model' && (
                <div className="space-y-4">
                  {Object.keys(multiResult.cross_model_comparison || {}).length > 0 ? (
                    Object.entries(multiResult.cross_model_comparison).map(([dataset, data]: [string, unknown]) => {
                      const d = data as XaiResult
                      return (
                        <div key={dataset} className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-4">
                          <div className="flex items-center gap-2">
                            <Database className="w-5 h-5 text-accent-green" />
                            <h3 className="text-sm font-display font-semibold truncate">{dataset}</h3>
                          </div>

                          {/* Model Feature Rankings Side-by-Side */}
                          {d.model_feature_rankings && (
                            <ChartPanel title="Top Feature Rankings by Model" subtitle="Top-10 features per model on this dataset">
                              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                                {Object.entries(d.model_feature_rankings).map(([model, features]) => (
                                  <div key={model} className="bg-bg-primary rounded-lg p-3">
                                    <div className="text-xs font-mono font-medium text-accent-blue mb-2">{model}</div>
                                    <div className="space-y-0.5">
                                      {(features as string[]).map((f: string, fi: number) => (
                                        <div key={fi} className="flex items-center gap-1.5 text-[10px]">
                                          <span className="text-text-secondary w-4">{fi + 1}</span>
                                          <span className="truncate">{f}</span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </ChartPanel>
                          )}

                          {/* Pairwise Agreement */}
                          {d.pairwise_agreement && Object.keys(d.pairwise_agreement).length > 0 && (
                            <ChartPanel title="Model Pair Agreement" subtitle="Jaccard similarity of top-10 feature rankings">
                              <div className="space-y-2">
                                {Object.entries(d.pairwise_agreement).map(([pair, score]) => {
                                  const s = Number(score)
                                  return (
                                    <div key={pair} className="flex items-center gap-3 text-xs">
                                      <span className="w-44 font-mono text-text-secondary truncate">{pair.replace(/_vs_/g, ' vs ')}</span>
                                      <div className="flex-1 bg-bg-primary rounded-full h-3">
                                        <div
                                          className={`h-3 rounded-full ${s > 0.6 ? 'bg-accent-green' : s > 0.3 ? 'bg-accent-amber' : 'bg-accent-red'}`}
                                          style={{ width: `${s * 100}%` }}
                                        />
                                      </div>
                                      <span className={`font-mono w-14 text-right ${s > 0.6 ? 'text-accent-green' : s > 0.3 ? 'text-accent-amber' : 'text-accent-red'}`}>
                                        {(s * 100).toFixed(1)}%
                                      </span>
                                    </div>
                                  )
                                })}
                              </div>
                            </ChartPanel>
                          )}
                        </div>
                      )
                    })
                  ) : (
                    <div className="text-center text-text-secondary text-sm py-12">
                      <GitCompare className="w-8 h-8 mx-auto mb-2 opacity-40" />
                      Select 2+ models to see cross-model comparison per dataset
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Feature Heatmap Strip (always visible when saliency available) */}
          {result?.saliency?.heatmap && activeTab === 'saliency' && (
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card mt-4">
              <h3 className="text-sm font-semibold mb-3">Feature Importance Heatmap</h3>
              <div className="flex gap-px rounded overflow-hidden h-6">
                {result.saliency.heatmap.map((val: number, i: number) => {
                  const max = Math.max(...result.saliency.heatmap)
                  const intensity = max > 0 ? val / max : 0
                  return (
                    <div
                      key={i}
                      className="flex-1 min-w-[2px]"
                      style={{ backgroundColor: `rgba(168, 85, 247, ${0.05 + intensity * 0.95})` }}
                      title={`${result.feature_names[i] || `f${i}`}: ${(intensity * 100).toFixed(0)}%`}
                    />
                  )
                })}
              </div>
              <div className="flex justify-between text-[10px] text-text-secondary mt-1">
                <span>Feature 0</span>
                <span>Low → High importance</span>
                <span>Feature {result.saliency.heatmap.length - 1}</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/* ═══════════════ Reusable Sub-Components ═══════════════ */

function StatBox({ icon: Icon, label, value, color }: { icon: React.ElementType; label: string; value: string | number; color: string }) {
  return (
    <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
      <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
        <Icon className="w-3.5 h-3.5" /> {label}
      </div>
      <div className={`text-xl font-mono font-bold ${color}`}>{value}</div>
    </div>
  )
}

function ChartPanel({ title, subtitle, children }: { title: string; subtitle?: string; children: React.ReactNode }) {
  return (
    <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
      <h3 className="text-sm font-semibold mb-1">{title}</h3>
      {subtitle && <p className="text-[10px] text-text-secondary mb-3">{subtitle}</p>}
      {children}
    </div>
  )
}

function HorizontalBarChart({ data, dataKey, unit, colors }: { data: { name: string; value: number }[]; dataKey: string; unit?: string; colors: string[] | string }) {
  const TT_STYLE = { background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }
  const colorArr = Array.isArray(colors) ? colors : data.map(() => colors)
  return (
    <ResponsiveContainer width="100%" height={Math.max(data.length * 28, 200)}>
      <BarChart data={data} layout="vertical" margin={{ left: 10 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
        <XAxis type="number" tick={{ fill: '#94A3B8', fontSize: 10 }} unit={unit} />
        <YAxis dataKey="name" type="category" tick={{ fill: '#94A3B8', fontSize: 10 }} width={120} />
        <Tooltip contentStyle={TT_STYLE} formatter={(v: number) => `${v}${unit || ''}`} />
        <Bar dataKey="value" radius={[0, 4, 4, 0]}>
          {data.map((_, i) => (
            <Cell key={i} fill={colorArr[i % colorArr.length]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

function PerClassPanel({ title, data, valueKey, expandedClass, onToggle }: {
  title: string
  data: Record<string, XaiResult[]>
  valueKey: string
  expandedClass: string | null
  onToggle: (cls: string) => void
}) {
  return (
    <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
      <h3 className="text-sm font-semibold mb-3">{title}</h3>
      <div className="space-y-1 max-h-[420px] overflow-y-auto">
        {Object.entries(data || {}).slice(0, 15).map(([cls, features]) => (
          <div key={cls} className="border border-bg-card rounded-lg overflow-hidden">
            <button
              onClick={() => onToggle(cls)}
              className="w-full px-3 py-2 flex items-center gap-2 text-xs hover:bg-bg-card/30 transition-colors"
            >
              <span className="flex-1 text-left font-medium truncate">{cls}</span>
              {expandedClass === cls ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </button>
            {expandedClass === cls && (
              <div className="px-3 pb-2 space-y-1">
                {features.slice(0, 8).map((f: XaiResult, i: number) => (
                  <div key={f.index} className="flex items-center gap-2 text-xs">
                    <span className="w-4 text-text-secondary">{i + 1}</span>
                    <span className="flex-1 truncate text-text-secondary">{f.name}</span>
                    <div className="w-20 bg-bg-primary rounded-full h-1.5">
                      <div className="h-1.5 rounded-full bg-accent-purple" style={{ width: `${(f[valueKey] || 0) * 100}%` }} />
                    </div>
                    <span className="font-mono text-accent-purple w-12 text-right">
                      {((f[valueKey] || 0) * 100).toFixed(0)}%
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
