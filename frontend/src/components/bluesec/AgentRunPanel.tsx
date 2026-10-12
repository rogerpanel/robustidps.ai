import { useCallback, useEffect, useRef, useState } from 'react'
import { Play, FlaskConical, Square, Loader2, KeyRound, AlertTriangle, CheckCircle2, ChevronDown, ChevronRight } from 'lucide-react'
import { authHeaders } from '../../utils/auth'

const API = import.meta.env.VITE_API_URL || ''
const BASE = '/api/bluesec-runs/agent'
const POLL_MS = 3000

type Pack = 'v1.1' | 'blind' | 'mimicry'
type Provider = 'anthropic' | 'openai'
const COMPONENTS = ['cache', 'validation', 'grounding', 'budget', 'method'] as const
const PACK_LABEL: Record<Pack, string> = {
  'v1.1': 'SOCGraph-21 v1.1',
  blind: 'blind (label cues removed)',
  mimicry: 'mimicry (attacker names renamed)',
}

interface Status { available: boolean; reason?: string; busy?: boolean; packs?: Record<Pack, number | null>; tasks?: string[] }
interface Saved { folder: string; run_id: string | null; skipped?: string }
interface Job {
  id: string; status: 'running' | 'done' | 'failed' | 'cancelled'
  params: { pack: Pack; suite: boolean; ablate: string[]; provider: Provider; model: string; label: string }
  done_tasks: number; total_tasks: number; current: string; folders: string[]
  errors?: string[]; log: string[]; started: string; finished: string | null; saved?: Saved[]
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${API}${BASE}${path}`, {
    ...init, headers: { 'Content-Type': 'application/json', ...authHeaders(), ...(init?.headers || {}) },
  })
  if (!r.ok) {
    let detail: unknown
    try { detail = (await r.json()).detail } catch { /* non-JSON error body */ }
    throw new Error(typeof detail === 'string' ? detail : `HTTP ${r.status}`)
  }
  return r.json()
}

/** Start the command-line agent on a SOCGraph pack from the browser (admins only).
 *  Runs execute in the server's runner container; finished runs are saved to BlueSec Runs. */
export default function AgentRunPanel({ onSaved }: { onSaved: () => void }) {
  const [status, setStatus] = useState<Status | null>(null)
  const [pack, setPack] = useState<Pack>('v1.1')
  const [config, setConfig] = useState('full')
  const [provider, setProvider] = useState<Provider>('anthropic')
  const [model, setModel] = useState('')
  const [effort, setEffort] = useState('high')
  const [baseUrl, setBaseUrl] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [label, setLabel] = useState('')
  const [concurrency, setConcurrency] = useState(4)
  const [quick, setQuick] = useState(true)
  const [job, setJob] = useState<Job | null>(null)
  const [error, setError] = useState('')
  const [starting, setStarting] = useState(false)
  const [showLog, setShowLog] = useState(false)
  const timer = useRef<number | null>(null)
  const savedNotified = useRef('')

  const loadStatus = useCallback(async () => {
    try { setStatus(await call<Status>('/status')) } catch (e) { setStatus({ available: false, reason: (e as Error).message }) }
  }, [])

  const poll = useCallback(async (id: string) => {
    try {
      const j = await call<Job>(`/runs/${id}`)
      setJob(j)
      if (j.status === 'running') {
        timer.current = window.setTimeout(() => poll(id), POLL_MS)
      } else if (savedNotified.current !== id) {
        savedNotified.current = id
        if (j.saved?.some(s => s.run_id)) onSaved()
        loadStatus()
      }
    } catch (e) { setError((e as Error).message) }
  }, [onSaved, loadStatus])

  useEffect(() => {
    loadStatus()
    // Resume the display of a run that is still going (e.g. after a page reload).
    call<{ runs: Job[] }>('/runs').then(r => {
      const running = r.runs.find(j => j.status === 'running')
      if (running) poll(running.id)
    }).catch(() => { /* runner unavailable: the status line says so */ })
    return () => { if (timer.current) window.clearTimeout(timer.current) }
  }, [loadStatus, poll])

  const quickTasks = (): string[] => {
    const ids = status?.tasks || []
    const win = ids.find(t => !t.startsWith('linux-'))
    const lin = ids.find(t => t.startsWith('linux-'))
    return [win, lin].filter((t): t is string => !!t)
  }

  const start = async (suite: boolean) => {
    setError(''); setStarting(true); setShowLog(false)
    try {
      const body = {
        pack, suite, provider, effort, concurrency,
        ablate: !suite && config !== 'full' ? [config] : [],
        model: model.trim(), base_url: provider === 'openai' ? baseUrl.trim() : '',
        api_key: apiKey, label: suite ? '' : label.trim(),
        tasks: quick ? quickTasks() : [],
      }
      const j = await call<Job>('/runs', { method: 'POST', body: JSON.stringify(body) })
      setJob(j)
      poll(j.id)
    } catch (e) { setError((e as Error).message) } finally { setStarting(false) }
  }

  const cancel = async () => {
    if (!job) return
    try { setJob(await call<Job>(`/runs/${job.id}/cancel`, { method: 'POST' })) } catch (e) { setError((e as Error).message) }
  }

  if (status && !status.available) {
    return (
      <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card space-y-1.5 text-xs text-text-secondary">
        <h2 className="font-semibold text-sm text-text-primary flex items-center gap-2"><Play className="w-4 h-4" /> Run agent</h2>
        <p>Not available: {status.reason}</p>
        <p>Start the runner with <span className="font-mono">docker compose -f docker-compose.prod.yml up -d --build bluesec-runner backend</span>.</p>
      </div>
    )
  }

  const running = job?.status === 'running'
  const keyOk = apiKey.length > 0 && (provider === 'anthropic' || (baseUrl.trim() && model.trim()))
  const packAvailable = (p: Pack) => status?.packs?.[p] != null
  const pct = job && job.total_tasks ? Math.min(100, Math.round((100 * job.done_tasks) / job.total_tasks)) : 0
  const field = 'w-full bg-bg-primary border border-bg-card rounded-lg px-3 py-2 text-sm'

  return (
    <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card space-y-3">
      <h2 className="font-semibold flex items-center gap-2"><Play className="w-4 h-4" /> Run agent</h2>
      <p className="text-xs text-text-secondary">
        Runs the same command-line agent as the study on a SOCGraph pack, in the server's runner container.
        Finished runs appear under Saved runs. Results for the paper are produced with the command line.
      </p>

      <div className="grid grid-cols-2 gap-2">
        <label className="text-xs text-text-secondary col-span-2">Pack
          <select value={pack} onChange={e => setPack(e.target.value as Pack)} className={field} disabled={running}>
            {(Object.keys(PACK_LABEL) as Pack[]).map(p => (
              <option key={p} value={p} disabled={!packAvailable(p)}>
                {PACK_LABEL[p]}{status?.packs?.[p] ? ` · ${status.packs[p]} tasks` : packAvailable(p) ? '' : ' · not on server'}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs text-text-secondary col-span-2">Configuration (for Run)
          <select value={config} onChange={e => setConfig(e.target.value)} className={field} disabled={running}>
            <option value="full">Full agent</option>
            {COMPONENTS.map(c => <option key={c} value={c}>No {c}</option>)}
          </select>
        </label>
        <label className="text-xs text-text-secondary">Provider
          <select value={provider} onChange={e => setProvider(e.target.value as Provider)} className={field} disabled={running}>
            <option value="anthropic">Anthropic</option>
            <option value="openai">OpenAI-compatible</option>
          </select>
        </label>
        {provider === 'anthropic' ? (
          <label className="text-xs text-text-secondary">Effort
            <select value={effort} onChange={e => setEffort(e.target.value)} className={field} disabled={running}>
              {['low', 'medium', 'high', 'xhigh', 'max'].map(x => <option key={x} value={x}>{x}</option>)}
            </select>
          </label>
        ) : (
          <label className="text-xs text-text-secondary">Concurrency
            <select value={concurrency} onChange={e => setConcurrency(Number(e.target.value))} className={field} disabled={running}>
              {[1, 2, 3, 4].map(n => <option key={n} value={n}>{n}</option>)}
            </select>
          </label>
        )}
        {provider === 'openai' && (
          <input value={baseUrl} onChange={e => setBaseUrl(e.target.value)} disabled={running}
            placeholder="Base URL, e.g. https://api.deepseek.com or http://gpu-host:8000/v1"
            className={`${field} col-span-2`} />
        )}
        <input value={model} onChange={e => setModel(e.target.value)} disabled={running} maxLength={120}
          placeholder={provider === 'anthropic' ? 'Model (default claude-opus-5-5)' : 'Model name (required)'}
          className={`${field} col-span-2`} />
        <div className="col-span-2 relative">
          <KeyRound className="w-4 h-4 absolute left-3 top-2.5 text-text-secondary" />
          <input type="password" value={apiKey} onChange={e => setApiKey(e.target.value)} disabled={running}
            autoComplete="off" placeholder="API key (sent to this server for this run only; not stored)"
            className={`${field} pl-9`} />
        </div>
        <input value={label} onChange={e => setLabel(e.target.value)} disabled={running} maxLength={120}
          placeholder="Label (optional, e.g. full, deepseek)" className={`${field} col-span-2`} />
        <label className="col-span-2 flex items-center gap-2 text-xs">
          <input type="checkbox" checked={quick} onChange={e => setQuick(e.target.checked)} disabled={running}
            className="accent-[rgb(var(--color-accent-blue))]" />
          Quick test: 2 tasks (one Windows, one Linux) instead of all
        </label>
      </div>

      <div className="flex gap-2">
        <button onClick={() => start(false)} disabled={!keyOk || running || starting || !status}
          className="flex-1 py-2 rounded-lg bg-accent-blue text-white text-sm font-medium disabled:opacity-40 flex items-center justify-center gap-2">
          {starting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Run
        </button>
        <button onClick={() => start(true)} disabled={!keyOk || running || starting || !status}
          title="Full agent, then each component turned off in turn (6 runs)"
          className="flex-1 py-2 rounded-lg bg-bg-primary border border-bg-card text-sm font-medium hover:border-accent-blue disabled:opacity-40 flex items-center justify-center gap-2">
          <FlaskConical className="w-4 h-4" /> Run ablation suite
        </button>
      </div>
      <p className="text-[11px] text-text-secondary">
        Uses your key's tokens: with the study's model, a full 21-task run takes 2–3 minutes and reads about
        0.75 M cached prompt tokens and writes about 33 k output tokens; the ablation suite is six runs.
      </p>
      {error && <p className="text-xs text-accent-red flex items-start gap-1"><AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />{error}</p>}

      {job && (
        <div className="rounded-lg bg-bg-primary border border-bg-card p-3 space-y-2 text-xs">
          <div className="flex items-center gap-2">
            {running ? <Loader2 className="w-3.5 h-3.5 animate-spin text-accent-blue" />
              : job.status === 'done' && !job.errors?.length ? <CheckCircle2 className="w-3.5 h-3.5 text-accent-green" />
              : <AlertTriangle className={`w-3.5 h-3.5 ${job.saved?.some(x => x.run_id) ? 'text-accent-amber' : 'text-accent-red'}`} />}
            <span className="font-medium">
              {job.params.suite ? 'Ablation suite' : job.params.ablate.length ? `No ${job.params.ablate.join(', ')}` : 'Full agent'}
              {' · '}{job.params.pack} · {job.status}
            </span>
            {running && (
              <button onClick={cancel} className="ml-auto px-2 py-1 rounded border border-bg-card hover:border-accent-red flex items-center gap-1">
                <Square className="w-3 h-3" /> Cancel
              </button>
            )}
          </div>
          <div className="h-2 rounded bg-bg-card overflow-hidden" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
            <div className="h-full bg-accent-blue transition-all" style={{ width: `${pct}%` }} />
          </div>
          <p className="text-text-secondary">
            {job.done_tasks}/{job.total_tasks} investigations{job.current ? ` · configuration: ${job.current}` : ''}
          </p>
          {!!job.errors?.length && (
            <ul className="text-accent-red space-y-0.5">
              {job.errors.slice(-3).map((e, i) => <li key={i} className="break-words">{e}</li>)}
            </ul>
          )}
          {!!job.saved?.length && (
            <ul className="space-y-0.5">
              {job.saved.map(s => (
                <li key={s.folder} className={s.run_id ? 'text-accent-green' : 'text-text-secondary'}>
                  <span className="font-mono">{s.folder}</span>: {s.run_id ? 'saved' : s.skipped}
                </li>
              ))}
            </ul>
          )}
          {!!job.log?.length && (
            <div>
              <button onClick={() => setShowLog(v => !v)} className="flex items-center gap-1 text-text-secondary hover:text-text-primary">
                {showLog ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />} Log
              </button>
              {showLog && (
                <pre className="mt-1 max-h-60 overflow-auto bg-bg-secondary rounded p-2 text-[10px] whitespace-pre-wrap">
                  {job.log.join('\n')}
                </pre>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
