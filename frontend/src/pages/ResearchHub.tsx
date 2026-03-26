import { useState, useEffect, useCallback } from 'react'
import {
  FlaskConical, Clock, CheckCircle2, XCircle, Loader2, Trash2,
  Tag, Search, Download, FileText, Copy, ChevronDown, ChevronRight,
  GitCompare, Plus, RefreshCw, AlertTriangle, BarChart3, FileCode,
  Shield,
} from 'lucide-react'
import { useLLMAttackResults } from '../hooks/useLLMAttackResults'
import {
  fetchTasks, fetchTask, deleteTask,
  fetchExperiments, createExperiment, deleteExperiment, updateExperiment,
  compareExperiments, exportExperimentManifest, fetchExperimentTags,
  generateLatexComparison, generateLatexExperiment, generateCsvReport,
  fetchMitreMapping, generateLatexMitre,
  type ExperimentData,
} from '../utils/api'

// ── Tab navigation ──────────────────────────────────────────────────────

type Tab = 'tasks' | 'experiments' | 'reports' | 'llm_security' | 'publications'

const TABS: { key: Tab; label: string; icon: typeof Clock }[] = [
  { key: 'tasks', label: 'Job Queue', icon: Clock },
  { key: 'experiments', label: 'Experiments', icon: FlaskConical },
  { key: 'reports', label: 'Reports & Export', icon: FileText },
  { key: 'llm_security', label: 'LLM Security Lab', icon: Shield },
  { key: 'publications', label: 'Publications', icon: FileText },
]

// ── Status badge ────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    queued: 'bg-text-secondary/10 text-text-secondary',
    running: 'bg-accent-blue/15 text-accent-blue',
    completed: 'bg-accent-green/15 text-accent-green',
    failed: 'bg-accent-red/15 text-accent-red',
  }
  const icons: Record<string, typeof Clock> = {
    queued: Clock,
    running: Loader2,
    completed: CheckCircle2,
    failed: XCircle,
  }
  const Icon = icons[status] || Clock
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${styles[status] || styles.queued}`}>
      <Icon className={`w-3 h-3 ${status === 'running' ? 'animate-spin' : ''}`} />
      {status}
    </span>
  )
}

// ── Task Queue Tab ──────────────────────────────────────────────────────

function TaskQueueTab() {
  const [tasks, setTasks] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState<string>('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [expandedResult, setExpandedResult] = useState<any>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await fetchTasks(filter || undefined)
      setTasks(data.tasks || [])
    } catch { setTasks([]) }
    setLoading(false)
  }, [filter])

  useEffect(() => { load() }, [load])

  // Auto-refresh if any tasks are running
  useEffect(() => {
    const hasActive = tasks.some(t => t.status === 'running' || t.status === 'queued')
    if (!hasActive) return
    const id = setInterval(load, 4000)
    return () => clearInterval(id)
  }, [tasks, load])

  const handleExpand = async (taskId: string) => {
    if (expanded === taskId) { setExpanded(null); setExpandedResult(null); return }
    setExpanded(taskId)
    try {
      const detail = await fetchTask(taskId)
      setExpandedResult(detail)
    } catch { setExpandedResult(null) }
  }

  const handleDelete = async (taskId: string) => {
    await deleteTask(taskId)
    load()
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 flex-wrap">
        <h3 className="text-text-primary font-semibold text-sm">Background Tasks</h3>
        <div className="flex gap-1">
          {['', 'running', 'completed', 'failed'].map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                filter === f
                  ? 'bg-accent-blue/15 text-accent-blue'
                  : 'text-text-secondary hover:text-text-primary hover:bg-bg-card/50'
              }`}
            >
              {f || 'All'}
            </button>
          ))}
        </div>
        <button onClick={load} className="ml-auto p-1.5 rounded-lg text-text-secondary hover:text-text-primary hover:bg-bg-card/50">
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {loading && tasks.length === 0 ? (
        <div className="flex items-center justify-center py-12 text-text-secondary text-sm">
          <Loader2 className="w-4 h-4 animate-spin mr-2" /> Loading tasks...
        </div>
      ) : tasks.length === 0 ? (
        <div className="text-center py-12 text-text-secondary text-sm">
          <Clock className="w-8 h-8 mx-auto mb-2 opacity-40" />
          No background tasks yet. Tasks are created when you run operations like Red Team, Ablation, or Federated simulations.
        </div>
      ) : (
        <div className="space-y-2">
          {tasks.map(task => (
            <div key={task.task_id} className="bg-bg-card border border-bg-card rounded-lg overflow-hidden">
              <div
                className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-bg-primary/30 transition-colors"
                onClick={() => handleExpand(task.task_id)}
              >
                {expanded === task.task_id
                  ? <ChevronDown className="w-3.5 h-3.5 text-text-secondary shrink-0" />
                  : <ChevronRight className="w-3.5 h-3.5 text-text-secondary shrink-0" />}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm text-text-primary font-medium truncate">{task.name}</span>
                    <span className="text-xs text-text-secondary/60 px-1.5 py-0.5 bg-bg-primary rounded">{task.task_type}</span>
                  </div>
                  <div className="text-xs text-text-secondary mt-0.5">
                    {task.task_id} &middot; {new Date(task.created_at).toLocaleString()}
                  </div>
                </div>
                <StatusBadge status={task.status} />
                {task.status === 'running' && (
                  <div className="w-16">
                    <div className="h-1.5 bg-bg-primary rounded-full overflow-hidden">
                      <div
                        className="h-full bg-accent-blue rounded-full transition-all duration-500"
                        style={{ width: `${task.progress}%` }}
                      />
                    </div>
                    <span className="text-[10px] text-text-secondary">{task.progress}%</span>
                  </div>
                )}
                {(task.status === 'completed' || task.status === 'failed') && (
                  <button
                    onClick={(e) => { e.stopPropagation(); handleDelete(task.task_id) }}
                    className="p-1 text-text-secondary/40 hover:text-accent-red transition-colors"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>

              {expanded === task.task_id && expandedResult && (
                <div className="border-t border-bg-primary px-4 py-3 text-xs space-y-2">
                  {expandedResult.error && (
                    <div className="flex items-start gap-2 text-accent-red">
                      <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                      <span>{expandedResult.error}</span>
                    </div>
                  )}
                  {expandedResult.params && Object.keys(expandedResult.params).length > 0 && (
                    <div>
                      <span className="text-text-secondary font-medium">Parameters: </span>
                      <code className="text-text-primary/80 bg-bg-primary px-1.5 py-0.5 rounded text-[11px]">
                        {JSON.stringify(expandedResult.params, null, 0).slice(0, 200)}
                      </code>
                    </div>
                  )}
                  {expandedResult.progress_message && (
                    <div className="text-text-secondary italic">{expandedResult.progress_message}</div>
                  )}
                  {expandedResult.started_at && (
                    <div className="text-text-secondary">
                      Started: {new Date(expandedResult.started_at).toLocaleString()}
                      {expandedResult.completed_at && (
                        <> &middot; Completed: {new Date(expandedResult.completed_at).toLocaleString()}</>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Experiments Tab ─────────────────────────────────────────────────────

function ExperimentsTab() {
  const [experiments, setExperiments] = useState<ExperimentData[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [tagFilter, setTagFilter] = useState('')
  const [allTags, setAllTags] = useState<string[]>([])
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [comparison, setComparison] = useState<any>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [newName, setNewName] = useState('')
  const [newTags, setNewTags] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [expData, tagData] = await Promise.all([
        fetchExperiments(undefined, tagFilter || undefined, search || undefined),
        fetchExperimentTags(),
      ])
      setExperiments(expData.experiments || [])
      setAllTags(tagData.tags || [])
    } catch { setExperiments([]) }
    setLoading(false)
  }, [search, tagFilter])

  useEffect(() => { load() }, [load])

  const toggleSelect = (id: string) => {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const handleCompare = async () => {
    if (selected.size < 2) return
    try {
      const data = await compareExperiments(Array.from(selected))
      setComparison(data)
    } catch (e: any) {
      alert(e.message)
    }
  }

  const handleCreate = async () => {
    if (!newName.trim()) return
    await createExperiment({
      name: newName.trim(),
      tags: newTags.split(',').map(t => t.trim()).filter(Boolean),
    })
    setNewName(''); setNewTags(''); setShowCreate(false)
    load()
  }

  const handleDelete = async (id: string) => {
    await deleteExperiment(id)
    selected.delete(id)
    setSelected(new Set(selected))
    load()
  }

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[180px] max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-secondary/50" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search experiments..."
            className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-bg-primary border border-bg-card text-sm text-text-primary placeholder:text-text-secondary/40 focus:border-accent-blue/50 focus:outline-none"
          />
        </div>

        {allTags.length > 0 && (
          <select
            value={tagFilter}
            onChange={e => setTagFilter(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-bg-primary border border-bg-card text-sm text-text-primary focus:border-accent-blue/50 focus:outline-none"
          >
            <option value="">All tags</option>
            {allTags.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        )}

        <button
          onClick={() => setShowCreate(!showCreate)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-blue/15 text-accent-blue text-xs font-medium hover:bg-accent-blue/25 transition-colors"
        >
          <Plus className="w-3.5 h-3.5" /> New
        </button>

        {selected.size >= 2 && (
          <button
            onClick={handleCompare}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-amber/15 text-accent-amber text-xs font-medium hover:bg-accent-amber/25 transition-colors"
          >
            <GitCompare className="w-3.5 h-3.5" /> Compare ({selected.size})
          </button>
        )}

        <button onClick={load} className="ml-auto p-1.5 rounded-lg text-text-secondary hover:text-text-primary hover:bg-bg-card/50">
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Quick create form */}
      {showCreate && (
        <div className="bg-bg-card border border-bg-card rounded-lg p-4 space-y-3">
          <input
            type="text" value={newName} onChange={e => setNewName(e.target.value)}
            placeholder="Experiment name"
            className="w-full px-3 py-1.5 rounded-lg bg-bg-primary border border-bg-card text-sm text-text-primary placeholder:text-text-secondary/40 focus:outline-none focus:border-accent-blue/50"
          />
          <input
            type="text" value={newTags} onChange={e => setNewTags(e.target.value)}
            placeholder="Tags (comma-separated)"
            className="w-full px-3 py-1.5 rounded-lg bg-bg-primary border border-bg-card text-sm text-text-primary placeholder:text-text-secondary/40 focus:outline-none focus:border-accent-blue/50"
          />
          <div className="flex gap-2">
            <button onClick={handleCreate} className="px-3 py-1.5 rounded-lg bg-accent-blue text-white text-xs font-medium hover:bg-accent-blue/90">
              Create
            </button>
            <button onClick={() => setShowCreate(false)} className="px-3 py-1.5 rounded-lg text-text-secondary text-xs hover:text-text-primary">
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Comparison view */}
      {comparison && (
        <div className="bg-bg-card border border-accent-amber/30 rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-text-primary font-semibold text-sm flex items-center gap-2">
              <GitCompare className="w-4 h-4 text-accent-amber" /> Experiment Comparison
            </h4>
            <button onClick={() => setComparison(null)} className="text-text-secondary/40 hover:text-text-primary text-xs">
              Close
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-bg-primary">
                  <th className="text-left py-2 pr-3 text-text-secondary font-medium">Metric</th>
                  {comparison.experiments.map((exp: any) => (
                    <th key={exp.experiment_id} className="text-right py-2 px-2 text-text-primary font-medium">
                      {exp.name}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(comparison.metric_keys || []).map((key: string) => {
                  const row = comparison.metric_table[key] || {}
                  const vals = Object.values(row).filter((v): v is number => typeof v === 'number')
                  const best = vals.length > 0 ? Math.max(...vals) : null
                  return (
                    <tr key={key} className="border-b border-bg-primary/50">
                      <td className="py-1.5 pr-3 text-text-secondary">{key.replace(/_/g, ' ')}</td>
                      {comparison.experiments.map((exp: any) => {
                        const val = row[exp.experiment_id]
                        const isBest = typeof val === 'number' && val === best
                        return (
                          <td key={exp.experiment_id} className={`text-right py-1.5 px-2 ${isBest ? 'text-accent-green font-semibold' : 'text-text-primary'}`}>
                            {val === null || val === undefined ? '--' : typeof val === 'number' ? val.toFixed(4) : String(val)}
                          </td>
                        )
                      })}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Experiments list */}
      {loading && experiments.length === 0 ? (
        <div className="flex items-center justify-center py-12 text-text-secondary text-sm">
          <Loader2 className="w-4 h-4 animate-spin mr-2" /> Loading experiments...
        </div>
      ) : experiments.length === 0 ? (
        <div className="text-center py-12 text-text-secondary text-sm">
          <FlaskConical className="w-8 h-8 mx-auto mb-2 opacity-40" />
          No experiments saved yet. Save results from Upload, Red Team, Ablation, or other modules as experiments.
        </div>
      ) : (
        <div className="space-y-2">
          {experiments.map(exp => (
            <div key={exp.experiment_id} className="bg-bg-card border border-bg-card rounded-lg overflow-hidden">
              <div className="flex items-center gap-3 px-4 py-3">
                <input
                  type="checkbox"
                  checked={selected.has(exp.experiment_id)}
                  onChange={() => toggleSelect(exp.experiment_id)}
                  className="w-3.5 h-3.5 rounded border-text-secondary/30 bg-bg-primary accent-[#3b82f6] cursor-pointer"
                />
                <div
                  className="flex-1 min-w-0 cursor-pointer"
                  onClick={() => setExpanded(expanded === exp.experiment_id ? null : exp.experiment_id)}
                >
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm text-text-primary font-medium">{exp.name}</span>
                    {exp.task_type && (
                      <span className="text-xs text-text-secondary/60 px-1.5 py-0.5 bg-bg-primary rounded">{exp.task_type}</span>
                    )}
                    {exp.model_used && (
                      <span className="text-xs text-accent-blue/70 px-1.5 py-0.5 bg-accent-blue/10 rounded">{exp.model_used}</span>
                    )}
                    {(exp.tags || []).map(tag => (
                      <span key={tag} className="text-xs text-accent-amber/70 px-1.5 py-0.5 bg-accent-amber/10 rounded flex items-center gap-0.5">
                        <Tag className="w-2.5 h-2.5" /> {tag}
                      </span>
                    ))}
                  </div>
                  <div className="text-xs text-text-secondary mt-0.5">
                    {exp.experiment_id}
                    {exp.dataset_name && <> &middot; {exp.dataset_name}</>}
                    {' '}&middot; {new Date(exp.created_at).toLocaleString()}
                  </div>
                </div>

                {/* Quick metrics */}
                {exp.metrics && Object.keys(exp.metrics).length > 0 && (
                  <div className="hidden md:flex items-center gap-3 text-xs">
                    {exp.metrics.accuracy !== undefined && (
                      <span className="text-accent-green">Acc: {Number(exp.metrics.accuracy).toFixed(2)}</span>
                    )}
                    {exp.metrics.f1 !== undefined && (
                      <span className="text-accent-blue">F1: {Number(exp.metrics.f1).toFixed(2)}</span>
                    )}
                    {exp.metrics.macro_f1 !== undefined && (
                      <span className="text-accent-blue">F1μ: {Number(exp.metrics.macro_f1).toFixed(2)}</span>
                    )}
                  </div>
                )}

                <div className="flex items-center gap-1">
                  <button
                    onClick={() => exportExperimentManifest(exp.experiment_id)}
                    className="p-1 text-text-secondary/40 hover:text-accent-blue transition-colors"
                    title="Download manifest"
                  >
                    <Download className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => handleDelete(exp.experiment_id)}
                    className="p-1 text-text-secondary/40 hover:text-accent-red transition-colors"
                    title="Delete"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {expanded === exp.experiment_id && (
                <div className="border-t border-bg-primary px-4 py-3 text-xs space-y-2">
                  {exp.description && (
                    <p className="text-text-secondary">{exp.description}</p>
                  )}
                  {exp.metrics && Object.keys(exp.metrics).length > 0 && (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                      {Object.entries(exp.metrics).map(([k, v]) => (
                        <div key={k} className="bg-bg-primary rounded px-2 py-1">
                          <span className="text-text-secondary">{k.replace(/_/g, ' ')}: </span>
                          <span className="text-text-primary font-medium">
                            {typeof v === 'number' ? v.toFixed(4) : String(v)}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                  {exp.params && Object.keys(exp.params).length > 0 && (
                    <div>
                      <span className="text-text-secondary font-medium">Parameters: </span>
                      <code className="text-text-primary/80 bg-bg-primary px-1.5 py-0.5 rounded text-[11px]">
                        {JSON.stringify(exp.params)}
                      </code>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Reports Tab ─────────────────────────────────────────────────────────

function ReportsTab() {
  const [experiments, setExperiments] = useState<ExperimentData[]>([])
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [latex, setLatex] = useState('')
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    fetchExperiments().then(d => setExperiments(d.experiments || [])).catch(() => {})
  }, [])

  const toggleSelect = (id: string) => {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const handleLatexComparison = async () => {
    if (selected.size < 2) return
    setLoading(true)
    try {
      const text = await generateLatexComparison(Array.from(selected))
      setLatex(text)
    } catch (e: any) { alert(e.message) }
    setLoading(false)
  }

  const handleLatexSingle = async () => {
    const id = Array.from(selected)[0]
    if (!id) return
    setLoading(true)
    try {
      const text = await generateLatexExperiment(id)
      setLatex(text)
    } catch (e: any) { alert(e.message) }
    setLoading(false)
  }

  const handleLatexMitre = async () => {
    const id = Array.from(selected)[0]
    if (!id) return
    setLoading(true)
    try {
      const text = await generateLatexMitre(id)
      setLatex(text)
    } catch (e: any) { alert(e.message) }
    setLoading(false)
  }

  const handleCsvExport = async () => {
    if (selected.size === 0) return
    await generateCsvReport(Array.from(selected))
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(latex)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="space-y-4">
      <p className="text-text-secondary text-xs">
        Select experiments below, then generate publication-ready LaTeX tables, CSV reports, or MITRE ATT&CK mappings.
      </p>

      {/* Experiment selector */}
      <div className="max-h-48 overflow-y-auto space-y-1 border border-bg-card rounded-lg p-2 bg-bg-primary">
        {experiments.length === 0 ? (
          <div className="text-center py-4 text-text-secondary text-xs">No experiments to export</div>
        ) : experiments.map(exp => (
          <label key={exp.experiment_id} className="flex items-center gap-2.5 px-2 py-1.5 rounded hover:bg-bg-card/50 cursor-pointer">
            <input
              type="checkbox"
              checked={selected.has(exp.experiment_id)}
              onChange={() => toggleSelect(exp.experiment_id)}
              className="w-3.5 h-3.5 rounded border-text-secondary/30 bg-bg-primary accent-[#3b82f6]"
            />
            <span className="text-sm text-text-primary flex-1 truncate">{exp.name}</span>
            <span className="text-xs text-text-secondary/50">{exp.task_type}</span>
          </label>
        ))}
      </div>

      {/* Action buttons */}
      <div className="flex items-center gap-2 flex-wrap">
        <button
          onClick={handleLatexComparison}
          disabled={selected.size < 2 || loading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-blue/15 text-accent-blue text-xs font-medium hover:bg-accent-blue/25 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <FileCode className="w-3.5 h-3.5" />
          LaTeX Comparison
        </button>
        <button
          onClick={handleLatexSingle}
          disabled={selected.size !== 1 || loading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-blue/15 text-accent-blue text-xs font-medium hover:bg-accent-blue/25 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <BarChart3 className="w-3.5 h-3.5" />
          LaTeX Tables
        </button>
        <button
          onClick={handleLatexMitre}
          disabled={selected.size !== 1 || loading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-amber/15 text-accent-amber text-xs font-medium hover:bg-accent-amber/25 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <Shield className="w-3.5 h-3.5" />
          MITRE ATT&CK LaTeX
        </button>
        <button
          onClick={handleCsvExport}
          disabled={selected.size === 0 || loading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-green/15 text-accent-green text-xs font-medium hover:bg-accent-green/25 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <Download className="w-3.5 h-3.5" />
          CSV Report
        </button>
        {loading && <Loader2 className="w-3.5 h-3.5 animate-spin text-accent-blue" />}
      </div>

      {/* LaTeX output */}
      {latex && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs text-text-secondary font-medium">Generated LaTeX</span>
            <button
              onClick={handleCopy}
              className="flex items-center gap-1 text-xs text-accent-blue hover:text-accent-blue/80 transition-colors"
            >
              <Copy className="w-3 h-3" />
              {copied ? 'Copied!' : 'Copy to clipboard'}
            </button>
          </div>
          <pre className="bg-bg-primary border border-bg-card rounded-lg p-4 text-xs text-text-primary/80 overflow-x-auto max-h-96 font-mono leading-relaxed">
            {latex}
          </pre>
        </div>
      )}
    </div>
  )
}

// ── LLM Security Lab Tab ────────────────────────────────────────────────

function LLMSecurityLabTab() {
  const {
    promptInjection, jailbreakFindings, ragPoisoning, multiAgent,
    getCondensedSummary, lastUpdated,
  } = useLLMAttackResults()

  const summary = getCondensedSummary()
  const pi = summary.prompt_injection || {}
  const jb = summary.jailbreak_taxonomy || {}
  const rp = summary.rag_poisoning || {}
  const ma = summary.multi_agent || {}

  const hasData = (pi.total_tests || 0) + (jb.techniques_analyzed || 0) + (rp.total_simulations || 0) + (ma.total_scenarios || 0) > 0

  return (
    <div className="space-y-4">
      <p className="text-text-secondary text-xs">
        Aggregated security posture from all 4 LLM Attack Surface testing modules. Run tests on the individual pages to populate this dashboard.
      </p>

      {!hasData ? (
        <div className="text-center py-12 text-text-secondary text-sm">
          <Shield className="w-8 h-8 mx-auto mb-2 opacity-40" />
          No LLM security test results yet. Run tests on Prompt Injection, Jailbreak Taxonomy, RAG Poisoning, or Multi-Agent Chain pages first.
        </div>
      ) : (
        <>
          {/* Overview Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-bg-card border border-bg-card rounded-lg p-3">
              <div className="text-[10px] text-text-secondary uppercase tracking-wider">Prompt Injection</div>
              <div className="text-xl font-display font-bold text-accent-orange mt-1">{pi.total_tests || 0}</div>
              <div className="text-[10px] text-text-secondary">
                {pi.blocked || 0} blocked · {pi.bypassed || 0} bypassed
              </div>
              {(pi.block_rate ?? 0) > 0 && (
                <div className="mt-1 h-1.5 bg-bg-primary rounded-full overflow-hidden">
                  <div className="h-full bg-accent-green rounded-full" style={{ width: `${(pi.block_rate * 100).toFixed(0)}%` }} />
                </div>
              )}
            </div>
            <div className="bg-bg-card border border-bg-card rounded-lg p-3">
              <div className="text-[10px] text-text-secondary uppercase tracking-wider">Jailbreak Techniques</div>
              <div className="text-xl font-display font-bold text-accent-amber mt-1">{jb.techniques_analyzed || 0}</div>
              <div className="text-[10px] text-text-secondary">
                {(jb.categories || []).length} categories analyzed
              </div>
            </div>
            <div className="bg-bg-card border border-bg-card rounded-lg p-3">
              <div className="text-[10px] text-text-secondary uppercase tracking-wider">RAG Poisoning</div>
              <div className="text-xl font-display font-bold text-accent-red mt-1">{rp.total_simulations || 0}</div>
              <div className="text-[10px] text-text-secondary">
                {rp.high_risk || 0} high risk · {rp.mitigated || 0} mitigated
              </div>
            </div>
            <div className="bg-bg-card border border-bg-card rounded-lg p-3">
              <div className="text-[10px] text-text-secondary uppercase tracking-wider">Multi-Agent Chain</div>
              <div className="text-xl font-display font-bold text-accent-purple mt-1">{ma.total_scenarios || 0}</div>
              <div className="text-[10px] text-text-secondary">
                {ma.agents_compromised || 0}/{ma.agents_total || 0} agents compromised
              </div>
            </div>
          </div>

          {/* Defense Effectiveness Summary */}
          {(pi.total_tests || 0) > 0 && (
            <div className="bg-bg-card border border-bg-card rounded-lg p-4">
              <h3 className="text-sm font-semibold text-text-primary mb-3 flex items-center gap-2">
                <Shield className="w-4 h-4 text-accent-green" />
                Defense Effectiveness — Prompt Injection
              </h3>
              <div className="grid grid-cols-3 gap-3 text-xs">
                <div className="p-2 bg-bg-secondary rounded-lg text-center">
                  <div className="text-lg font-bold text-accent-green">{((pi.block_rate || 0) * 100).toFixed(0)}%</div>
                  <div className="text-text-secondary">Block Rate</div>
                </div>
                <div className="p-2 bg-bg-secondary rounded-lg text-center">
                  <div className="text-lg font-bold text-text-primary">{((pi.avg_confidence || 0) * 100).toFixed(0)}%</div>
                  <div className="text-text-secondary">Avg Confidence</div>
                </div>
                <div className="p-2 bg-bg-secondary rounded-lg text-center">
                  <div className="text-lg font-bold text-accent-red">{pi.critical_bypasses || 0}</div>
                  <div className="text-text-secondary">Critical Bypasses</div>
                </div>
              </div>
            </div>
          )}

          {/* Recent Test Results */}
          {promptInjection.length > 0 && (
            <div className="bg-bg-card border border-bg-card rounded-lg p-4">
              <h3 className="text-sm font-semibold text-text-primary mb-3">Recent Prompt Injection Tests</h3>
              <div className="space-y-1.5 max-h-48 overflow-y-auto">
                {promptInjection.slice(-10).reverse().map((r, i) => (
                  <div key={i} className="flex items-center gap-3 px-3 py-2 bg-bg-secondary rounded-lg text-xs">
                    <span className={`w-2 h-2 rounded-full ${r.blocked ? 'bg-accent-green' : 'bg-accent-red'}`} />
                    <span className="text-text-primary font-medium flex-1 truncate">{r.template}</span>
                    <span className="text-text-secondary">{r.defense}</span>
                    <span className="text-text-secondary">{r.confidence}%</span>
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                      r.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                      r.severity === 'high' ? 'bg-accent-amber/20 text-accent-amber' :
                      'bg-accent-blue/20 text-accent-blue'
                    }`}>{r.severity}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {lastUpdated && (
            <p className="text-[10px] text-text-secondary text-right">
              Last updated: {new Date(lastUpdated).toLocaleString()}
            </p>
          )}
        </>
      )}
    </div>
  )
}

// ── Publications Tab ────────────────────────────────────────────────────

function PublicationsTab() {
  const [expandedPaper, setExpandedPaper] = useState<string | null>(null)

  const PAPERS = [
    {
      id: 'tnnls_1',
      title: 'RobustIDPS: An Adversarially Robust IDS with Continual Learning and Constrained RL for Autonomous Response',
      authors: 'Roger Nick Anaedevha, Alexander G. Trofimov',
      target: 'IEEE Transactions on Neural Networks and Learning Systems (TNNLS)',
      status: 'draft',
      statusLabel: 'Working Draft',
      statusColor: 'bg-accent-amber/15 text-accent-amber',
      abstract: 'Presents a 7-branch surrogate ensemble with MC dropout uncertainty (T=20), EWC continual learning with experience replay, CPO-based RL response agent, unified Fisher information framework (\u03B2=0.7), adversarial robustness against 6 attacks, and Byzantine-resilient federated learning (FedGTD). Evaluated on CICIDS2017, NSL-KDD, CIC-IoT-2023, UNSW-NB15 with 34 attack classes achieving 97.8% accuracy.',
      file: 'papers/paper1_robust_ids_clrl.tex',
      pages: '~12 pages (1066 lines LaTeX)',
      keywords: ['Intrusion Detection', 'Continual Learning', 'Constrained RL', 'Adversarial Robustness', 'Federated Learning'],
    },
    {
      id: 'tnnls_2',
      title: 'Securing LLM-Integrated Network Defense: Detecting and Mitigating Prompt Injection, RAG Poisoning, and Multi-Agent Chain Attacks in SOC Copilot Systems',
      authors: 'Roger Nick Anaedevha, Alexander G. Trofimov',
      target: 'IEEE Transactions on Neural Networks and Learning Systems (TNNLS)',
      status: 'draft',
      statusLabel: 'Working Draft',
      statusColor: 'bg-accent-amber/15 text-accent-amber',
      abstract: 'Presents a comprehensive framework for securing LLM-integrated SOC systems against prompt injection (8 categories), RAG poisoning (4 vectors), and multi-agent chain attacks (5 patterns). Implements real defense pipelines with input sanitization, boundary enforcement, RAG hardening, and inter-agent trust architecture. Tested across Claude, GPT-4o, Gemini, and DeepSeek.',
      file: 'papers/paper2_llm_security_nids.tex',
      pages: '~10 pages (899 lines LaTeX)',
      keywords: ['LLM Security', 'Prompt Injection', 'RAG Poisoning', 'Multi-Agent Systems', 'SOC Copilot'],
    },
  ]

  const FOUNDATION_PAPERS = [
    { title: 'SDE-TGNN: Stochastic Differential Equation Temporal Graph Neural Network for NIDS', model: 'SDE-TGNN', status: 'Implemented' },
    { title: 'Byzantine-Resilient Stochastic Games for Federated Multi-Cloud Intrusion Detection', model: 'FedGTD', status: 'Implemented' },
    { title: 'CyberSecLLM: Mamba-CrossAttention-MoE Cybersecurity Foundation Model', model: 'CyberSecLLM', status: 'Implemented' },
    { title: 'Neural ODE Temporal Adaptive IDS with Point Processes', model: 'CT-TGNN', status: 'Implemented' },
    { title: 'Optimal Transport for Federated Domain Adaptation in Multi-Cloud IDS', model: 'PPFOT-IDS', status: 'Implemented' },
    { title: 'Continual Learning and RL-Driven Autonomous Response for Adversarially Robust NIDS', model: 'CL-RL Unified', status: 'Proposal' },
  ]

  return (
    <div className="space-y-6">
      {/* Zenodo Citation */}
      <div className="bg-accent-blue/5 border border-accent-blue/20 rounded-xl p-4">
        <h3 className="text-sm font-semibold text-accent-blue mb-2 flex items-center gap-2">
          <FileText className="w-4 h-4" />
          Cite This Software
        </h3>
        <div className="bg-bg-primary rounded-lg p-3 font-mono text-xs text-text-primary leading-relaxed">
          Anaedevha, R. N. and Trofimov A. G. (2026). RobustIDPS.ai: Advanced AI-powered intrusion detection &amp; prevention system (Version 1.1.0) [Computer software]. Zenodo. https://doi.org/10.5281/zenodo.19129512
        </div>
        <div className="flex items-center gap-3 mt-2">
          <button
            onClick={() => { navigator.clipboard.writeText('Anaedevha, R. N. and Trofimov A. G. (2026). RobustIDPS.ai: Advanced AI-powered intrusion detection & prevention system (Version 1.1.0) [Computer software]. Zenodo. https://doi.org/10.5281/zenodo.19129512') }}
            className="text-xs text-accent-blue hover:text-accent-blue/80 flex items-center gap-1"
          >
            <Copy className="w-3 h-3" /> Copy APA
          </button>
          <button
            onClick={() => { navigator.clipboard.writeText('@software{anaedevha2026robustidps,\n  author = {Anaedevha, Roger Nick and Trofimov, Alexander G.},\n  title = {RobustIDPS.ai: Advanced AI-powered intrusion detection \\& prevention system},\n  year = {2026},\n  version = {1.1.0},\n  publisher = {Zenodo},\n  doi = {10.5281/zenodo.19129512},\n  url = {https://doi.org/10.5281/zenodo.19129512}\n}') }}
            className="text-xs text-accent-blue hover:text-accent-blue/80 flex items-center gap-1"
          >
            <Copy className="w-3 h-3" /> Copy BibTeX
          </button>
          <a
            href="https://doi.org/10.5281/zenodo.19129512"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-accent-green hover:text-accent-green/80 flex items-center gap-1"
          >
            <Download className="w-3 h-3" /> Zenodo DOI
          </a>
        </div>
      </div>

      {/* IEEE TNNLS Draft Papers */}
      <div>
        <h3 className="text-sm font-semibold text-text-primary mb-3">Target Journal Papers</h3>
        <div className="space-y-3">
          {PAPERS.map(paper => (
            <div key={paper.id} className="bg-bg-card border border-bg-card rounded-lg overflow-hidden">
              <div
                className="px-4 py-3 cursor-pointer hover:bg-bg-primary/30 transition-colors"
                onClick={() => setExpandedPaper(expandedPaper === paper.id ? null : paper.id)}
              >
                <div className="flex items-start gap-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className={`text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded ${paper.statusColor}`}>
                        {paper.statusLabel}
                      </span>
                      <span className="text-[10px] text-text-secondary">{paper.target}</span>
                    </div>
                    <h4 className="text-sm font-medium text-text-primary leading-snug">{paper.title}</h4>
                    <p className="text-xs text-text-secondary mt-1">{paper.authors} · {paper.pages}</p>
                  </div>
                  {expandedPaper === paper.id
                    ? <ChevronDown className="w-4 h-4 text-text-secondary shrink-0 mt-1" />
                    : <ChevronRight className="w-4 h-4 text-text-secondary shrink-0 mt-1" />
                  }
                </div>
              </div>
              {expandedPaper === paper.id && (
                <div className="border-t border-bg-primary px-4 py-3 space-y-3 text-xs">
                  <div>
                    <span className="text-text-secondary font-medium">Abstract: </span>
                    <span className="text-text-primary/80">{paper.abstract}</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {paper.keywords.map(kw => (
                      <span key={kw} className="px-2 py-0.5 rounded bg-accent-blue/10 text-accent-blue text-[10px]">{kw}</span>
                    ))}
                  </div>
                  <div className="text-text-secondary">
                    Source: <code className="bg-bg-primary px-1.5 py-0.5 rounded">{paper.file}</code>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Foundation / Model Papers */}
      <div>
        <h3 className="text-sm font-semibold text-text-primary mb-3">Foundation &amp; Model Papers</h3>
        <p className="text-xs text-text-secondary mb-3">
          Research papers that informed the model implementations in RobustIDPS.ai. Each model in the platform traces back to a specific paper.
        </p>
        <div className="space-y-1.5">
          {FOUNDATION_PAPERS.map((fp, i) => (
            <div key={i} className="flex items-center gap-3 px-3 py-2 bg-bg-card rounded-lg text-xs">
              <FileText className="w-3.5 h-3.5 text-text-secondary shrink-0" />
              <span className="text-text-primary flex-1">{fp.title}</span>
              <span className="text-accent-blue text-[10px] px-1.5 py-0.5 bg-accent-blue/10 rounded">{fp.model}</span>
              <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                fp.status === 'Implemented' ? 'bg-accent-green/10 text-accent-green' : 'bg-accent-amber/10 text-accent-amber'
              }`}>{fp.status}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Main Page Component ─────────────────────────────────────────────────

export default function ResearchHub() {
  const [tab, setTab] = useState<Tab>('experiments')

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-display font-bold text-text-primary">Research Hub</h1>
        <p className="text-sm text-text-secondary mt-1">
          Track experiments, manage background jobs, and generate publication-ready exports.
        </p>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-bg-card">
        {TABS.map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
              tab === t.key
                ? 'border-accent-blue text-accent-blue'
                : 'border-transparent text-text-secondary hover:text-text-primary'
            }`}
          >
            <t.icon className="w-4 h-4" />
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === 'tasks' && <TaskQueueTab />}
      {tab === 'experiments' && <ExperimentsTab />}
      {tab === 'reports' && <ReportsTab />}
      {tab === 'llm_security' && <LLMSecurityLabTab />}
      {tab === 'publications' && <PublicationsTab />}
    </div>
  )
}
