import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Trophy, UploadCloud, FolderOpen, FileJson, Server, Loader2, Trash2, Pencil, CheckCircle2,
  XCircle, AlertTriangle, ChevronDown, ChevronRight, Lightbulb, Info, ShieldCheck, ShieldAlert,
  Database,
} from 'lucide-react'
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend,
} from 'recharts'
import { authHeaders, getUser } from '../utils/auth'
import ExportMenu from '../components/ExportMenu'
import PackBrowser from '../components/bluesec/PackBrowser'
import RunComparison, { type CompareRun } from '../components/bluesec/RunComparison'

const API = import.meta.env.VITE_API_URL || ''
const MAX_UPLOAD_BYTES = 25 * 1024 * 1024

interface RunMeta {
  id: string; name: string; notes: string; source: string; pt_run_id: string; agent_model: string
  started_at: string | null; created_at: string; n_tasks: number; n_completed: number
  mean_quality: number; mean_efficiency: number; mean_reward: number; mean_tool_calls: number
  label?: string; config?: { ablations?: string[] }
  metrics?: { overall?: { verdict_accuracy?: number | null } }
}
interface TaskResult {
  completion_reason: string; quality_score: number; efficiency_score: number; total_reward: number
  tool_calls: number; steps_taken: number; wall_time_seconds: number
}
interface Step {
  type: 'tool_call' | 'thinking' | 'text'; text?: string; tool?: string; status?: string
  arguments?: Record<string, unknown>; spent_so_far?: number; result?: string; reward?: number
}
interface Task {
  task_id: string; model?: string; alert?: unknown; tools?: string[]; steps: Step[]
  submission?: Record<string, unknown> | null; calls_spent?: number; calls_saved_by_cache?: number
  wall_seconds?: number; error?: string | null; result: TaskResult; from_summary_only?: boolean
}
interface RunFull extends RunMeta { tasks: Task[]; aggregates: Record<string, number> }
interface ServerFolder { name: string; n_files: number; has_summary: boolean; modified: string; imported: boolean }

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${API}${path}`, {
    ...init, headers: { 'Content-Type': 'application/json', ...authHeaders(), ...(init?.headers || {}) },
  })
  if (!r.ok) {
    let detail: unknown
    try { detail = (await r.json()).detail } catch { /* non-JSON error body */ }
    throw new Error(typeof detail === 'string' ? detail : detail ? JSON.stringify(detail) : `HTTP ${r.status}`)
  }
  return r.json()
}

const fmt = (v: number | undefined, d = 3) => (typeof v === 'number' ? v.toFixed(d) : '–')
const when = (r: RunMeta) => new Date(r.started_at || r.created_at)

// ── Reading a dropped or selected trace folder ────────────────────────────
interface Picked { files: File[]; folder: string }

function folderOf(path: string): string {
  const parts = path.replace(/^\/+/, '').split('/')
  return parts.length > 1 ? parts[parts.length - 2] : ''
}

async function filesFromDrop(items: DataTransferItemList): Promise<Picked> {
  const files: File[] = []
  let folder = ''
  const walk = async (entry: FileSystemEntry): Promise<void> => {
    if (entry.isFile) {
      const file = await new Promise<File>((res, rej) => (entry as FileSystemFileEntry).file(res, rej))
      files.push(file)
      if (!folder) folder = folderOf(entry.fullPath)
    } else if (entry.isDirectory) {
      const reader = (entry as FileSystemDirectoryEntry).createReader()
      for (;;) {
        const batch = await new Promise<FileSystemEntry[]>((res, rej) => reader.readEntries(res, rej))
        if (!batch.length) break
        for (const e of batch) await walk(e)
      }
    }
  }
  for (const item of Array.from(items)) {
    const entry = item.webkitGetAsEntry?.()
    if (entry) await walk(entry)
  }
  return { files, folder }
}

// ── Small presentational pieces ───────────────────────────────────────────
const COMPLETION: Record<string, { label: string; cls: string; icon: JSX.Element }> = {
  terminated: { label: 'completed', cls: 'text-accent-green', icon: <CheckCircle2 className="w-3.5 h-3.5" /> },
  truncated: { label: 'truncated', cls: 'text-accent-amber', icon: <AlertTriangle className="w-3.5 h-3.5" /> },
  aborted: { label: 'aborted', cls: 'text-accent-red', icon: <XCircle className="w-3.5 h-3.5" /> },
  error: { label: 'error', cls: 'text-accent-red', icon: <XCircle className="w-3.5 h-3.5" /> },
}
function Completion({ reason }: { reason: string }) {
  const c = COMPLETION[reason] || { label: reason, cls: 'text-text-secondary', icon: <Info className="w-3.5 h-3.5" /> }
  return <span className={`inline-flex items-center gap-1 text-xs ${c.cls}`}>{c.icon}{c.label}</span>
}

const STEP_STATUS: Record<string, { label: string; cls: string }> = {
  ok: { label: 'ok', cls: 'border-bg-card text-text-secondary' },
  cached: { label: 'cached · no call spent', cls: 'border-accent-green/40 text-accent-green' },
  refused_locally: { label: 'refused locally · no call spent', cls: 'border-accent-amber/40 text-accent-amber' },
  error: { label: 'error', cls: 'border-accent-red/40 text-accent-red' },
  terminal: { label: 'submitted', cls: 'border-accent-blue/40 text-accent-blue' },
}

function Bar({ value, label }: { value: number; label: string }) {
  const pct = Math.max(0, Math.min(1, value || 0)) * 100
  return (
    <div className="flex items-center gap-2 min-w-[110px]" title={`${label}: ${fmt(value)}`}>
      <div className="h-1.5 flex-1 rounded bg-bg-primary overflow-hidden">
        <div className="h-full rounded" style={{ width: `${pct}%`, background: 'var(--chart-1)' }} />
      </div>
      <span className="text-xs tabular-nums text-text-primary w-10 text-right">{fmt(value, 2)}</span>
    </div>
  )
}

function Tile({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="bg-bg-primary rounded-lg p-3 border border-bg-card">
      <div className="text-[10px] uppercase tracking-wide text-text-secondary">{label}</div>
      <div className="text-xl font-semibold text-text-primary tabular-nums mt-0.5">{value}</div>
      {sub && <div className="text-[11px] text-text-secondary mt-0.5">{sub}</div>}
    </div>
  )
}

function StepView({ step }: { step: Step }) {
  const [open, setOpen] = useState(false)
  if (step.type !== 'tool_call') {
    return (
      <div className="flex gap-2 text-xs text-text-secondary italic pl-1">
        <Lightbulb className="w-3.5 h-3.5 shrink-0 mt-0.5 text-accent-amber" />
        <span className="whitespace-pre-wrap">{step.text}</span>
      </div>
    )
  }
  const st = STEP_STATUS[step.status || ''] || { label: step.status || 'unknown', cls: 'border-bg-card text-text-secondary' }
  const args = Object.entries(step.arguments || {}).filter(([k]) => k !== 'reasoning' && k !== 'submission')
  const purpose = typeof step.arguments?.reasoning === 'string' ? (step.arguments.reasoning as string) : ''
  return (
    <div className="rounded-lg border border-bg-card bg-bg-primary/60 p-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-xs text-text-primary">{step.tool}</span>
        <span className={`text-[10px] px-1.5 py-0.5 rounded border ${st.cls}`}>{st.label}</span>
        {step.status !== 'cached' && step.status !== 'refused_locally' && !!step.spent_so_far && (
          <span className="text-[10px] text-text-secondary">call #{step.spent_so_far}</span>
        )}
        {step.result && (
          <button onClick={() => setOpen(!open)} className="ml-auto text-[10px] text-accent-blue hover:underline">
            {open ? 'hide result' : 'result'}
          </button>
        )}
      </div>
      {purpose && <p className="text-xs mt-1 text-text-primary">{purpose}</p>}
      {args.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-1.5">
          {args.map(([k, v]) => (
            <span key={k} className="px-1.5 py-0.5 rounded bg-bg-secondary text-[11px] font-mono break-all">
              {k}={typeof v === 'string' ? v : JSON.stringify(v)}
            </span>
          ))}
        </div>
      )}
      {open && (
        <pre className="mt-2 text-[11px] bg-bg-secondary rounded p-2 overflow-auto max-h-64 whitespace-pre-wrap break-all">
          {step.result}
        </pre>
      )}
    </div>
  )
}

function Submission({ sub }: { sub: Record<string, unknown> }) {
  const verdict = String(sub.verdict || '')
  const malicious = verdict === 'malicious'
  const artifacts = (sub.ir_artifacts as { entity_id: string; kind: string }[]) || []
  const evidence = (sub.legitimacy_evidence as { anchor: string; entity_id?: string; relation_id?: string; property_fields?: string[] }[]) || []
  return (
    <div className="rounded-lg border border-bg-card p-3 space-y-2">
      <div className="flex items-center gap-2">
        <span className={`inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded border ${
          malicious ? 'bg-accent-red/15 text-accent-red border-accent-red/30' : 'bg-accent-green/15 text-accent-green border-accent-green/30'}`}>
          {malicious ? <ShieldAlert className="w-3.5 h-3.5" /> : <ShieldCheck className="w-3.5 h-3.5" />}{verdict || 'no verdict'}
        </span>
        <span className="text-xs text-text-secondary">submission</span>
      </div>
      {typeof sub.reasoning === 'string' && <p className="text-sm text-text-primary">{sub.reasoning}</p>}
      {artifacts.length > 0 && (
        <table className="w-full text-xs">
          <thead><tr className="text-left text-text-secondary"><th className="font-normal py-1">Entity</th><th className="font-normal">Response</th></tr></thead>
          <tbody>
            {artifacts.map((a, i) => (
              <tr key={i} className="border-t border-bg-card">
                <td className="py-1 font-mono break-all">{a.entity_id}</td>
                <td><span className="px-1.5 py-0.5 rounded bg-bg-secondary">{a.kind}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {evidence.length > 0 && (
        <ul className="space-y-1 text-xs">
          {evidence.map((e, i) => (
            <li key={i} className="flex flex-wrap gap-1 items-center">
              <span className="text-text-secondary">{e.anchor}</span>
              <span className="font-mono break-all">{e.entity_id || e.relation_id}</span>
              {(e.property_fields || []).map(f => <span key={f} className="px-1.5 py-0.5 rounded bg-bg-secondary font-mono">{f}</span>)}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function TaskDetail({ task }: { task: Task }) {
  const [alertOpen, setAlertOpen] = useState(false)
  return (
    <div className="space-y-3 p-3 bg-bg-secondary/40 rounded-lg">
      <div className="flex flex-wrap gap-3 text-xs text-text-secondary">
        <span>calls spent: <b className="text-text-primary">{task.result.tool_calls}</b></span>
        {!!task.calls_saved_by_cache && <span>saved by cache: <b className="text-text-primary">{task.calls_saved_by_cache}</b></span>}
        {!!task.wall_seconds && <span>time: <b className="text-text-primary">{task.wall_seconds}s</b></span>}
        {task.model && <span>model: <b className="text-text-primary">{task.model}</b></span>}
      </div>
      {task.error && (
        <div className="text-xs text-accent-red flex gap-1.5"><AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />{task.error}</div>
      )}
      {task.alert !== undefined && task.alert !== null && (
        <div>
          <button onClick={() => setAlertOpen(!alertOpen)} className="text-xs text-accent-blue hover:underline">
            {alertOpen ? 'Hide alert' : 'Show alert'}
          </button>
          {alertOpen && (
            <pre className="mt-1 text-[11px] bg-bg-primary rounded p-2 overflow-auto max-h-64 whitespace-pre-wrap break-all">
              {JSON.stringify(task.alert, null, 2)}
            </pre>
          )}
        </div>
      )}
      {task.from_summary_only ? (
        <p className="text-xs text-text-secondary">Only the summary was uploaded for this task, so there are no steps.</p>
      ) : (
        <div className="space-y-1.5">{task.steps.map((s, i) => <StepView key={i} step={s} />)}</div>
      )}
      {task.submission && <Submission sub={task.submission} />}
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────
type SortKey = 'task_id' | 'quality_score' | 'efficiency_score' | 'tool_calls' | 'total_reward'

export default function BlueSecRuns() {
  const isAdmin = getUser()?.role === 'admin'
  const [runs, setRuns] = useState<RunMeta[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [picked, setPicked] = useState<Picked | null>(null)
  const [name, setName] = useState('')
  const [notes, setNotes] = useState('')
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState('')
  const [dragging, setDragging] = useState(false)
  const [server, setServer] = useState<{ enabled: boolean; folders: ServerFolder[] } | null>(null)
  const [importing, setImporting] = useState('')
  const [selected, setSelected] = useState<RunFull | null>(null)
  const [openTask, setOpenTask] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('task_id')
  const [sortDesc, setSortDesc] = useState(false)
  const [compareIds, setCompareIds] = useState<string[]>([])
  const folderInput = useRef<HTMLInputElement>(null)
  const filesInput = useRef<HTMLInputElement>(null)

  const loadRuns = useCallback(async () => {
    try {
      setRuns((await call<{ runs: RunMeta[] }>('/api/bluesec-runs')).runs)
    } catch (e) { setError((e as Error).message) } finally { setLoading(false) }
  }, [])
  const fetchCompare = useCallback(async (ids: string[]) =>
    (await call<{ runs: CompareRun[] }>(`/api/bluesec-runs/compare?ids=${ids.map(encodeURIComponent).join(',')}`)).runs, [])
  const toggleCompare = (id: string) =>
    setCompareIds(prev => (prev.includes(id) ? prev.filter(x => x !== id) : prev.length >= 12 ? prev : [...prev, id]))
  const loadServer = useCallback(async () => {
    if (!isAdmin) return
    try { setServer(await call('/api/bluesec-runs/server')) } catch { setServer(null) }
  }, [isAdmin])

  useEffect(() => { loadRuns(); loadServer() }, [loadRuns, loadServer])

  const open = async (id: string) => {
    setError(''); setOpenTask('')
    try { setSelected(await call<RunFull>(`/api/bluesec-runs/${id}`)) } catch (e) { setError((e as Error).message) }
  }

  const choose = (list: FileList | null) => {
    if (!list || !list.length) return
    const files = Array.from(list)
    const rel = (files[0] as File & { webkitRelativePath?: string }).webkitRelativePath || ''
    setPicked({ files, folder: rel ? folderOf('/' + rel) : '' })
    setMessage('')
  }

  const upload = async () => {
    if (!picked) return
    setSaving(true); setMessage(''); setError('')
    try {
      const jsonFiles = picked.files.filter(f => f.name.toLowerCase().endsWith('.json'))
      const size = jsonFiles.reduce((n, f) => n + f.size, 0)
      if (!jsonFiles.length) throw new Error('No .json files in the selection.')
      if (size > MAX_UPLOAD_BYTES) throw new Error('The selected traces are larger than 25 MB.')
      const documents: unknown[] = []
      let unreadable = 0
      for (const f of jsonFiles) {
        try { documents.push(JSON.parse(await f.text())) } catch { unreadable++ }
      }
      const run = await call<RunMeta & { ignored_files: number }>('/api/bluesec-runs', {
        method: 'POST', body: JSON.stringify({ name, notes, folder: picked.folder, documents }),
      })
      const skipped = run.ignored_files + unreadable
      setMessage(`Saved "${run.name}": ${run.n_tasks} task(s)${skipped ? `, ${skipped} file(s) skipped` : ''}.`)
      setPicked(null); setName(''); setNotes('')
      await loadRuns(); open(run.id)
    } catch (e) { setError((e as Error).message) } finally { setSaving(false) }
  }

  const importFolder = async (folder: string) => {
    setImporting(folder); setError('')
    try {
      const run = await call<RunMeta>('/api/bluesec-runs/server/import', { method: 'POST', body: JSON.stringify({ folder }) })
      await Promise.all([loadRuns(), loadServer()]); open(run.id)
    } catch (e) { setError((e as Error).message) } finally { setImporting('') }
  }

  const remove = async (r: RunMeta) => {
    if (!window.confirm(`Delete "${r.name}"? This cannot be undone.`)) return
    try {
      await call(`/api/bluesec-runs/${r.id}`, { method: 'DELETE' })
      if (selected?.id === r.id) setSelected(null)
      setCompareIds(prev => prev.filter(x => x !== r.id))
      await Promise.all([loadRuns(), loadServer()])
    } catch (e) { setError((e as Error).message) }
  }

  const edit = async () => {
    if (!selected) return
    const newName = window.prompt('Run name', selected.name)
    if (newName === null) return
    const newNotes = window.prompt('Notes (what changed in the agent for this run?)', selected.notes)
    if (newNotes === null) return
    const newLabel = window.prompt('Configuration label (row name in the ablation table)', selected.label || '')
    if (newLabel === null) return
    try {
      const meta = await call<RunMeta>(`/api/bluesec-runs/${selected.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ name: newName.trim() || selected.name, notes: newNotes, label: newLabel.trim() }),
      })
      setSelected({ ...selected, ...meta }); loadRuns()
    } catch (e) { setError((e as Error).message) }
  }

  const trend = useMemo(() => [...runs].sort((a, b) => +when(a) - +when(b)).map(r => ({
    label: when(r).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + ' ' +
      when(r).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }),
    name: r.name, quality: r.mean_quality, efficiency: r.mean_efficiency,
  })), [runs])

  const tasks = useMemo(() => {
    if (!selected) return []
    const list = [...selected.tasks]
    list.sort((a, b) => {
      const va = sortKey === 'task_id' ? a.task_id : a.result[sortKey]
      const vb = sortKey === 'task_id' ? b.task_id : b.result[sortKey]
      const c = va < vb ? -1 : va > vb ? 1 : 0
      return sortDesc ? -c : c
    })
    return list
  }, [selected, sortKey, sortDesc])

  const sortBy = (k: SortKey) => { if (k === sortKey) setSortDesc(!sortDesc); else { setSortKey(k); setSortDesc(k !== 'task_id' && k !== 'tool_calls') } }
  const th = (k: SortKey, label: string) => (
    <th className="font-normal py-1.5 cursor-pointer select-none hover:text-text-primary" onClick={() => sortBy(k)}>
      {label}{sortKey === k ? (sortDesc ? ' ↓' : ' ↑') : ''}
    </th>
  )

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-display font-bold flex items-center gap-2">
            <Trophy className="w-6 h-6 text-accent-blue" /> BlueSec Runs
          </h1>
          <p className="text-sm text-text-secondary mt-1 max-w-3xl">
            Review runs of the BlueSec investigation agent: every task, every tool call with its purpose,
            what the cache and local checks saved, the submission, and the scores the competition runtime returned.
            Save each run to compare agent versions over time.
          </p>
        </div>
        <ExportMenu filename="bluesec-run" />
      </div>

      {error && (
        <div className="text-sm text-accent-red bg-accent-red/10 border border-accent-red/30 rounded-lg px-3 py-2 flex gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />{error}
        </div>
      )}

      <div className="grid lg:grid-cols-3 gap-6">
        <div className="space-y-6">
          <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card space-y-3">
            <h2 className="font-semibold flex items-center gap-2"><UploadCloud className="w-4 h-4" /> Add a run</h2>
            <div
              onDragOver={e => { e.preventDefault(); setDragging(true) }}
              onDragLeave={() => setDragging(false)}
              onDrop={async e => { e.preventDefault(); setDragging(false); setPicked(await filesFromDrop(e.dataTransfer.items)); setMessage('') }}
              className={`rounded-lg border-2 border-dashed p-4 text-center text-xs transition-colors ${
                dragging ? 'border-accent-blue bg-accent-blue/5' : 'border-bg-card'}`}
            >
              <p className="text-text-secondary">Drop a run folder from <span className="font-mono">traces/</span> here, or</p>
              <div className="flex justify-center gap-2 mt-2">
                <button onClick={() => folderInput.current?.click()} className="px-2.5 py-1.5 rounded bg-bg-primary border border-bg-card hover:border-accent-blue flex items-center gap-1">
                  <FolderOpen className="w-3.5 h-3.5" /> Choose folder
                </button>
                <button onClick={() => filesInput.current?.click()} className="px-2.5 py-1.5 rounded bg-bg-primary border border-bg-card hover:border-accent-blue flex items-center gap-1">
                  <FileJson className="w-3.5 h-3.5" /> Choose files
                </button>
              </div>
              <input ref={folderInput} type="file" className="hidden" onChange={e => choose(e.target.files)}
                {...({ webkitdirectory: '', directory: '' } as Record<string, string>)} />
              <input ref={filesInput} type="file" multiple accept=".json,application/json" className="hidden"
                onChange={e => choose(e.target.files)} />
            </div>
            {picked && (
              <p className="text-xs text-text-secondary">
                {picked.files.filter(f => f.name.toLowerCase().endsWith('.json')).length} JSON file(s)
                {picked.folder && <> from <span className="font-mono text-text-primary">{picked.folder}</span></>}
              </p>
            )}
            <input value={name} onChange={e => setName(e.target.value)} maxLength={255}
              placeholder="Name (default: the folder name)"
              className="w-full bg-bg-primary border border-bg-card rounded-lg px-3 py-2 text-sm" />
            <textarea value={notes} onChange={e => setNotes(e.target.value)} maxLength={5000} rows={2}
              placeholder="Notes: what changed in the agent for this run?"
              className="w-full bg-bg-primary border border-bg-card rounded-lg px-3 py-2 text-sm" />
            <button onClick={upload} disabled={!picked || saving}
              className="w-full py-2 rounded-lg bg-accent-blue text-white text-sm font-medium disabled:opacity-40 flex items-center justify-center gap-2">
              {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Database className="w-4 h-4" />} Save run
            </button>
            {message && <p className="text-xs text-accent-green">{message}</p>}
          </div>

          {isAdmin && server?.enabled && (
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card space-y-2">
              <h2 className="font-semibold flex items-center gap-2"><Server className="w-4 h-4" /> Import from server</h2>
              <p className="text-xs text-text-secondary">Run folders in the agent's traces directory on this server.</p>
              {server.folders.length === 0 && <p className="text-xs text-text-secondary">No run folders yet.</p>}
              <ul className="space-y-1.5 max-h-72 overflow-auto">
                {server.folders.map(f => (
                  <li key={f.name} className="flex items-center gap-2 text-xs">
                    <span className="font-mono break-all flex-1">{f.name}</span>
                    <span className="text-text-secondary">{f.n_files}</span>
                    {f.imported
                      ? <span className="text-accent-green flex items-center gap-1"><CheckCircle2 className="w-3.5 h-3.5" />saved</span>
                      : (
                        <button onClick={() => importFolder(f.name)} disabled={!!importing}
                          className="px-2 py-1 rounded bg-bg-primary border border-bg-card hover:border-accent-blue disabled:opacity-40">
                          {importing === f.name ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Import'}
                        </button>
                      )}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card text-xs text-text-secondary space-y-1.5">
            <h2 className="font-semibold text-sm text-text-primary flex items-center gap-2"><Info className="w-4 h-4" /> Where traces come from</h2>
            <p>Each agent run writes a folder <span className="font-mono">traces/&lt;date-time&gt;-&lt;run&gt;/</span> with one JSON file per task and a <span className="font-mono">summary.json</span>.</p>
            <p>Run the agent from <span className="font-mono">~/bluesec1-agent</span>:</p>
            <pre className="bg-bg-primary rounded p-2 overflow-auto text-[11px]">uv run --with anthropic --with jsonschema --env-file .env \{'\n'}  python -m bluesec1_agent.robust.cli --pack robustidps-bluesec-pack.zip</pre>
            <p>For an ablation study, add <span className="font-mono">--ablation-suite</span>: it runs the full agent and each component turned off in turn (6 runs). Import all six folders, tick them in Saved runs and the comparison appears below.</p>
          </div>
        </div>

        <div className="lg:col-span-2 space-y-6">
          <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
            <div className="flex items-center gap-2 mb-3">
              <h2 className="font-semibold mr-auto">Saved runs</h2>
              <span className="text-xs text-text-secondary">
                {compareIds.length === 0 ? 'Tick two or more runs to compare them' : `${compareIds.length} selected for comparison`}
              </span>
            </div>
            {loading ? <Loader2 className="w-5 h-5 animate-spin text-text-secondary" />
              : runs.length === 0 ? <p className="text-sm text-text-secondary">No runs saved yet. Add one on the left.</p>
              : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left text-xs text-text-secondary">
                        <th className="w-6" /><th className="font-normal py-1.5">Run</th><th className="font-normal">When</th>
                        <th className="font-normal">Tasks</th><th className="font-normal">Quality</th>
                        <th className="font-normal">Efficiency</th><th className="font-normal text-right">Calls/task</th>
                        <th className="font-normal text-right">Verdict acc.</th>
                        <th className="font-normal text-right">Reward</th><th />
                      </tr>
                    </thead>
                    <tbody>
                      {runs.map(r => (
                        <tr key={r.id} onClick={() => open(r.id)}
                          className={`border-t border-bg-card cursor-pointer hover:bg-bg-primary/50 ${selected?.id === r.id ? 'bg-bg-primary/70' : ''}`}>
                          <td className="pr-1" onClick={e => e.stopPropagation()}>
                            <input type="checkbox" aria-label={`Compare ${r.name}`} checked={compareIds.includes(r.id)}
                              onChange={() => toggleCompare(r.id)} className="accent-[rgb(var(--color-accent-blue))]" />
                          </td>
                          <td className="py-2 pr-2 min-w-[180px]">
                            <div className="font-medium break-words">{r.name}</div>
                            {r.label && <span className="inline-block mt-0.5 px-1.5 py-0.5 rounded bg-bg-primary text-[10px] text-text-secondary">{r.label}</span>}
                            <div className="text-[11px] text-text-secondary">{r.agent_model || '–'}{r.source.startsWith('server:') ? ' · from server' : ''}</div>
                          </td>
                          <td className="text-xs text-text-secondary whitespace-nowrap pr-2">{when(r).toLocaleString()}</td>
                          <td className="text-xs whitespace-nowrap pr-2">{r.n_completed}/{r.n_tasks}</td>
                          <td className="pr-2"><Bar value={r.mean_quality} label="mean quality" /></td>
                          <td className="pr-2"><Bar value={r.mean_efficiency} label="mean efficiency" /></td>
                          <td className="text-right tabular-nums text-xs">{fmt(r.mean_tool_calls, 1)}</td>
                          <td className="text-right tabular-nums text-xs">
                            {typeof r.metrics?.overall?.verdict_accuracy === 'number' ? `${(r.metrics.overall.verdict_accuracy * 100).toFixed(0)}%` : '–'}
                          </td>
                          <td className="text-right tabular-nums text-xs">{fmt(r.mean_reward, 3)}</td>
                          <td className="text-right pl-2">
                            <button onClick={e => { e.stopPropagation(); remove(r) }} title="Delete run"
                              className="p-1 text-text-secondary hover:text-accent-red"><Trash2 className="w-4 h-4" /></button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
          </div>

          {trend.length >= 2 && (
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <h2 className="font-semibold">Quality and efficiency across runs</h2>
              <p className="text-xs text-text-secondary mb-2">Mean per run, oldest to newest. The table above has the exact values.</p>
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={trend} margin={{ top: 8, right: 16, bottom: 0, left: -12 }}>
                    <CartesianGrid stroke="rgb(var(--color-bg-card))" strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="label" tick={{ fontSize: 11, fill: 'rgb(var(--color-text-secondary))' }} stroke="rgb(var(--color-bg-card))" />
                    <YAxis domain={[0, 1]} tick={{ fontSize: 11, fill: 'rgb(var(--color-text-secondary))' }} stroke="rgb(var(--color-bg-card))" />
                    <Tooltip
                      contentStyle={{ background: 'rgb(var(--color-bg-primary))', border: '1px solid rgb(var(--color-bg-card))', borderRadius: 8, fontSize: 12 }}
                      labelFormatter={(_, p) => (p?.[0]?.payload?.name as string) || ''}
                      formatter={(v: number, n: string) => [v.toFixed(3), n]}
                    />
                    <Legend wrapperStyle={{ fontSize: 12 }} />
                    <Line type="monotone" dataKey="quality" name="Mean quality" stroke="var(--chart-1)" strokeWidth={2}
                      dot={{ r: 4, strokeWidth: 2, stroke: 'rgb(var(--color-bg-secondary))', fill: 'var(--chart-1)' }} activeDot={{ r: 6 }} />
                    <Line type="monotone" dataKey="efficiency" name="Mean efficiency" stroke="var(--chart-2)" strokeWidth={2}
                      dot={{ r: 4, strokeWidth: 2, stroke: 'rgb(var(--color-bg-secondary))', fill: 'var(--chart-2)' }} activeDot={{ r: 6 }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}
        </div>
      </div>

      {compareIds.length >= 2 && (
        <RunComparison ids={compareIds} fetchRuns={fetchCompare} onClear={() => setCompareIds([])} />
      )}

      <PackBrowser />

      {selected && (
        <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card space-y-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold break-all">{selected.name}</h2>
              <p className="text-xs text-text-secondary">
                {when(selected).toLocaleString()} · {selected.agent_model || 'model unknown'}
                {selected.pt_run_id && <> · runtime run <span className="font-mono">{selected.pt_run_id}</span></>}
              </p>
              {selected.notes && <p className="text-sm mt-1">{selected.notes}</p>}
            </div>
            <button onClick={edit} className="text-xs px-2.5 py-1.5 rounded bg-bg-primary border border-bg-card hover:border-accent-blue flex items-center gap-1">
              <Pencil className="w-3.5 h-3.5" /> Rename / notes
            </button>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
            <Tile label="Tasks completed" value={`${selected.n_completed}/${selected.n_tasks}`} />
            <Tile label="Mean quality" value={fmt(selected.mean_quality)} />
            <Tile label="Mean efficiency" value={fmt(selected.mean_efficiency)} />
            <Tile label="Mean reward" value={fmt(selected.mean_reward)} />
            <Tile label="Calls per task" value={fmt(selected.mean_tool_calls, 1)} />
            <Tile label="Calls saved" value={String(selected.aggregates?.calls_saved_by_cache ?? 0)} sub="by the local cache" />
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-text-secondary">
                  <th className="w-5" />{th('task_id', 'Task')}<th className="font-normal">Outcome</th>
                  <th className="font-normal">Verdict</th>{th('quality_score', 'Quality')}{th('efficiency_score', 'Efficiency')}
                  {th('tool_calls', 'Calls')}{th('total_reward', 'Reward')}
                </tr>
              </thead>
              <tbody>
                {tasks.map(t => {
                  const isOpen = openTask === t.task_id
                  const verdict = (t.submission?.verdict as string) || '–'
                  return (
                    <Fragment key={t.task_id}>
                      <tr onClick={() => setOpenTask(isOpen ? '' : t.task_id)}
                        className="border-t border-bg-card cursor-pointer hover:bg-bg-primary/50">
                        <td className="text-text-secondary">{isOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}</td>
                        <td className="py-2 pr-2 font-mono text-xs break-all">{t.task_id}</td>
                        <td className="pr-2"><Completion reason={t.result.completion_reason} /></td>
                        <td className="pr-2 text-xs">{verdict}</td>
                        <td className="pr-2"><Bar value={t.result.quality_score} label="quality" /></td>
                        <td className="pr-2"><Bar value={t.result.efficiency_score} label="efficiency" /></td>
                        <td className="tabular-nums text-xs">{t.result.tool_calls}</td>
                        <td className="tabular-nums text-xs">{fmt(t.result.total_reward)}</td>
                      </tr>
                      {isOpen && (
                        <tr><td colSpan={8} className="pb-3"><TaskDetail task={t} /></td></tr>
                      )}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
