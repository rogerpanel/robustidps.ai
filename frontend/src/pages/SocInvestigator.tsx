import { useEffect, useRef, useState } from 'react'
import {
  Bot, Play, Loader2, CheckCircle2, XCircle, Target, Lightbulb, ListChecks,
  AlertTriangle, SearchCheck, HelpCircle,
} from 'lucide-react'
import { authHeaders } from '../utils/auth'
import ExportMenu from '../components/ExportMenu'

const API = import.meta.env.VITE_API_URL || ''

interface Mission { id: string; title: string; difficulty: string; brief: Record<string, unknown> }
interface ProviderInfo { default_model: string; server_key: boolean }
interface Verdict {
  verdict: string; severity: string; confidence: number; summary: string; root_cause: string
  attack_techniques: string[]; affected_hosts: string[]; affected_accounts: string[]; indicators: string[]
  timeline: { ts: string; event_id: string; description: string }[]
  hypotheses: { hypothesis: string; status: string; evidence_event_ids: string[] }[]
  recommended_actions: string[]
}
interface Step {
  type: 'reasoning' | 'tool_call' | 'note' | 'verdict'
  text?: string; n?: number; tool?: string; rationale?: string
  input?: Record<string, unknown>; result?: Record<string, unknown>; is_error?: boolean; verdict?: Verdict
}
interface Trace {
  status: string; provider: string; model: string; max_tool_calls: number; steps: Step[]
  tool_calls: number; verdict: Verdict | null; stop_reason: string | null; error: string | null
  usage: Record<string, number>; duration_s: number | null
}
interface Score {
  quality: number; efficiency: number | null; score: number; tool_calls: number
  optimal_tool_calls: number | null; breakdown: Record<string, number>; invented_event_ids?: string[]; note?: string
}
interface RunState { trace: Trace; score: Score | null; answer: (Record<string, unknown> & { explanation?: string }) | null }

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

const VERDICT_STYLE: Record<string, string> = {
  true_positive: 'bg-accent-red/15 text-accent-red border-accent-red/30',
  false_positive: 'bg-accent-green/15 text-accent-green border-accent-green/30',
  benign_true_positive: 'bg-accent-amber/15 text-accent-amber border-accent-amber/30',
}
const STATUS_ICON: Record<string, JSX.Element> = {
  confirmed: <CheckCircle2 className="w-3.5 h-3.5 text-accent-green shrink-0" />,
  refuted: <XCircle className="w-3.5 h-3.5 text-accent-red shrink-0" />,
  inconclusive: <HelpCircle className="w-3.5 h-3.5 text-text-secondary shrink-0" />,
}

function resultSummary(r?: Record<string, unknown>): string {
  if (!r) return ''
  if (typeof r.error === 'string') return `error: ${r.error}`
  if (typeof r.total_matches === 'number')
    return `${r.total_matches} event(s)${r.truncated ? `, showing ${r.returned}` : ''}`
  if (r.process) return `process tree: ${(r.ancestors as unknown[])?.length ?? 0} ancestor(s), ${(r.children as unknown[])?.length ?? 0} child(ren)`
  if (typeof r.verdict === 'string') return `intel: ${r.verdict}${r.category ? ` (${r.category})` : ''}`
  if (r.role) return `asset: ${r.role}`
  return 'result'
}

function Chips({ label, items }: { label: string; items: string[] }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wide text-text-secondary mb-1">{label}</div>
      {items.length === 0 ? <span className="text-xs text-text-secondary">none</span> : (
        <div className="flex flex-wrap gap-1">
          {items.map(i => <span key={i} className="px-1.5 py-0.5 rounded bg-bg-primary border border-bg-card text-[11px] font-mono break-all">{i}</span>)}
        </div>
      )}
    </div>
  )
}

function StepView({ step }: { step: Step }) {
  const [open, setOpen] = useState(false)
  if (step.type === 'reasoning')
    return <p className="text-xs italic text-text-secondary whitespace-pre-wrap pl-3 border-l-2 border-bg-card">{step.text}</p>
  if (step.type === 'note')
    return <p className="text-xs text-accent-amber flex items-center gap-1.5"><AlertTriangle className="w-3.5 h-3.5" />{step.text}</p>
  if (step.type === 'verdict')
    return <p className="text-xs text-accent-green flex items-center gap-1.5"><CheckCircle2 className="w-3.5 h-3.5" />Verdict submitted</p>
  return (
    <div className={`rounded-lg border p-3 ${step.is_error ? 'border-accent-red/30 bg-accent-red/5' : 'border-bg-card bg-bg-secondary'}`}>
      <div className="flex items-center gap-2 text-xs">
        <span className="font-mono text-accent-blue">#{step.n}</span>
        <span className="font-semibold">{step.tool}</span>
        <span className="text-text-secondary">→ {resultSummary(step.result)}</span>
        <button onClick={() => setOpen(!open)} className="ml-auto text-[10px] text-text-secondary hover:text-accent-blue">
          {open ? 'hide' : 'raw'}
        </button>
      </div>
      {step.rationale && (
        <p className="text-xs mt-1.5 flex gap-1.5"><Lightbulb className="w-3.5 h-3.5 text-accent-amber shrink-0 mt-0.5" /><span>{step.rationale}</span></p>
      )}
      {step.input && Object.keys(step.input).length > 0 && (
        <div className="flex flex-wrap gap-1 mt-1.5">
          {Object.entries(step.input).map(([k, v]) => (
            <span key={k} className="px-1.5 py-0.5 rounded bg-bg-primary text-[10px] font-mono">{k}={String(v)}</span>
          ))}
        </div>
      )}
      {open && <pre className="mt-2 text-[10px] bg-bg-primary rounded p-2 overflow-x-auto max-h-72">{JSON.stringify(step.result, null, 2)}</pre>}
    </div>
  )
}

export default function SocInvestigator() {
  const [missions, setMissions] = useState<Mission[]>([])
  const [providers, setProviders] = useState<Record<string, ProviderInfo>>({})
  const [missionId, setMissionId] = useState('')
  const [provider, setProvider] = useState('anthropic')
  const [model, setModel] = useState('')
  const [effort, setEffort] = useState('high')
  const [budget, setBudget] = useState(15)
  const [apiKey, setApiKey] = useState('')
  const [run, setRun] = useState<RunState | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [starting, setStarting] = useState(false)
  const pollRef = useRef<number | null>(null)

  useEffect(() => {
    call<{ missions: Mission[]; providers: Record<string, ProviderInfo> }>('/api/investigator/missions')
      .then(d => { setMissions(d.missions); setProviders(d.providers); if (d.missions[0]) setMissionId(d.missions[0].id) })
      .catch(e => setError(String(e.message || e)))
    return () => { if (pollRef.current) window.clearTimeout(pollRef.current) }
  }, [])

  const poll = (runId: string) => {
    call<RunState>(`/api/investigator/runs/${runId}`)
      .then(r => {
        setRun(r)
        if (r.trace.status === 'running') pollRef.current = window.setTimeout(() => poll(runId), 1200)
      })
      .catch(e => setError(String(e.message || e)))
  }

  const start = async () => {
    setError(null); setRun(null); setStarting(true)
    try {
      const { run_id } = await call<{ run_id: string }>('/api/investigator/runs', {
        method: 'POST',
        body: JSON.stringify({ mission_id: missionId, provider, model: model || null, effort,
                               max_tool_calls: budget, api_key: apiKey || null }),
      })
      poll(run_id)
    } catch (e) {
      setError(String((e as Error).message || e))
    } finally {
      setStarting(false)
    }
  }

  const mission = missions.find(m => m.id === missionId)
  const running = run?.trace.status === 'running'
  const v = run?.trace.verdict
  const needsKey = providers[provider] && !providers[provider].server_key && !apiKey

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2"><Bot className="w-6 h-6 text-accent-blue" />SOC Investigator</h1>
          <p className="text-sm text-text-secondary mt-1 max-w-3xl">
            An autonomous agent that investigates an alert the way a SOC analyst does: it forms competing
            hypotheses, requests only the evidence that would settle them, reconstructs the timeline, and
            submits a verdict. Every query records the hypothesis it tests, and the scorecard rates quality
            and the number of queries used.
          </p>
        </div>
        <ExportMenu filename="soc-investigation" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-bg-secondary border border-bg-card rounded-xl p-4 space-y-3">
          <label className="text-xs text-text-secondary">Incident</label>
          <select value={missionId} onChange={e => setMissionId(e.target.value)} disabled={running}
                  className="w-full bg-bg-primary border border-bg-card rounded-lg px-3 py-2 text-sm">
            {missions.map(m => <option key={m.id} value={m.id}>{m.title} — {m.difficulty}</option>)}
          </select>
          {mission && (
            <pre className="text-[11px] bg-bg-primary rounded-lg p-3 overflow-x-auto max-h-48">{JSON.stringify(mission.brief, null, 2)}</pre>
          )}
        </div>

        <div className="bg-bg-secondary border border-bg-card rounded-xl p-4 space-y-3 text-sm">
          <div>
            <label className="text-xs text-text-secondary">Model provider</label>
            <select value={provider} onChange={e => setProvider(e.target.value)} disabled={running}
                    className="w-full bg-bg-primary border border-bg-card rounded-lg px-3 py-2 mt-1">
              {Object.entries(providers).map(([p, info]) => (
                <option key={p} value={p}>{p} ({info.default_model}){info.server_key ? '' : ' — needs key'}</option>
              ))}
            </select>
          </div>
          <input value={model} onChange={e => setModel(e.target.value)} disabled={running}
                 placeholder={`model (default ${providers[provider]?.default_model ?? ''})`}
                 className="w-full bg-bg-primary border border-bg-card rounded-lg px-3 py-2 text-xs" />
          <div className="flex gap-2">
            {provider === 'anthropic' && (
              <select value={effort} onChange={e => setEffort(e.target.value)} disabled={running}
                      className="flex-1 bg-bg-primary border border-bg-card rounded-lg px-2 py-2 text-xs">
                {['low', 'medium', 'high', 'xhigh', 'max'].map(x => <option key={x} value={x}>effort: {x}</option>)}
              </select>
            )}
            <label className="flex-1 flex items-center gap-1 text-xs">
              <span className="text-text-secondary">budget</span>
              <input type="number" min={1} max={60} value={budget} disabled={running}
                     onChange={e => setBudget(Math.max(1, Math.min(60, Number(e.target.value) || 1)))}
                     className="w-full bg-bg-primary border border-bg-card rounded-lg px-2 py-2" />
            </label>
          </div>
          <input type="password" value={apiKey} onChange={e => setApiKey(e.target.value)} disabled={running}
                 placeholder="API key (optional if the server has one)" autoComplete="off"
                 className="w-full bg-bg-primary border border-bg-card rounded-lg px-3 py-2 text-xs" />
          <button onClick={start} disabled={!missionId || running || starting || needsKey}
                  className="w-full flex items-center justify-center gap-2 bg-accent-blue hover:bg-accent-blue/90 disabled:opacity-40 text-white rounded-lg py-2 font-medium">
            {running || starting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            {running ? 'Investigating…' : 'Investigate'}
          </button>
          {needsKey && <p className="text-[11px] text-accent-amber">No server key for {provider}: enter one above.</p>}
        </div>
      </div>

      {error && <div className="text-sm text-accent-red bg-accent-red/10 border border-accent-red/30 rounded-lg p-3">{error}</div>}

      {run && (
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
          <div className="lg:col-span-3 bg-bg-secondary border border-bg-card rounded-xl p-4 space-y-2">
            <div className="flex items-center gap-2 text-sm font-semibold">
              <SearchCheck className="w-4 h-4 text-accent-blue" />Investigation trace
              <span className="ml-auto text-xs font-normal text-text-secondary">
                {run.trace.model} · {run.trace.tool_calls}/{run.trace.max_tool_calls} queries
                {run.trace.duration_s != null && ` · ${run.trace.duration_s}s`}
              </span>
            </div>
            {run.trace.steps.length === 0 && running && <p className="text-xs text-text-secondary">Forming hypotheses…</p>}
            {run.trace.steps.map((s, i) => <StepView key={i} step={s} />)}
            {running && <p className="text-xs text-text-secondary flex items-center gap-1.5"><Loader2 className="w-3 h-3 animate-spin" />working</p>}
            {run.trace.error && <p className="text-xs text-accent-red">Run failed: {run.trace.error}</p>}
            {run.trace.status === 'done' && !v && (
              <p className="text-xs text-accent-amber">Stopped without a verdict ({run.trace.stop_reason}).</p>
            )}
          </div>

          <div className="lg:col-span-2 space-y-4">
            {v && (
              <div className="bg-bg-secondary border border-bg-card rounded-xl p-4 space-y-3">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`px-2 py-0.5 rounded border text-xs font-semibold ${VERDICT_STYLE[v.verdict] || ''}`}>{v.verdict.replace(/_/g, ' ')}</span>
                  <span className="text-xs text-text-secondary">severity {v.severity} · confidence {Math.round(v.confidence * 100)}%</span>
                </div>
                <p className="text-sm">{v.summary}</p>
                <p className="text-xs text-text-secondary"><span className="font-semibold text-text-primary">Root cause:</span> {v.root_cause}</p>
                <div className="grid grid-cols-2 gap-3">
                  <Chips label="ATT&CK" items={v.attack_techniques} />
                  <Chips label="Hosts" items={v.affected_hosts} />
                  <Chips label="Accounts" items={v.affected_accounts} />
                </div>
                <Chips label="Indicators" items={v.indicators} />
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-text-secondary mb-1">Hypotheses</div>
                  {v.hypotheses.map((h, i) => (
                    <div key={i} className="flex gap-1.5 text-xs mb-1">{STATUS_ICON[h.status]}<span>{h.hypothesis}</span></div>
                  ))}
                </div>
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-text-secondary mb-1">Timeline</div>
                  {v.timeline.map((t, i) => (
                    <div key={i} className="text-xs mb-1"><span className="font-mono text-text-secondary">{t.ts}</span> {t.description} <span className="font-mono text-[10px] text-accent-blue">{t.event_id}</span></div>
                  ))}
                </div>
                {v.recommended_actions.length > 0 && (
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-text-secondary mb-1 flex items-center gap-1"><ListChecks className="w-3 h-3" />Recommended actions</div>
                    <ul className="text-xs list-disc pl-4 space-y-0.5">{v.recommended_actions.map((a, i) => <li key={i}>{a}</li>)}</ul>
                  </div>
                )}
              </div>
            )}

            {run.score && (
              <div className="bg-bg-secondary border border-bg-card rounded-xl p-4 space-y-3">
                <div className="flex items-center gap-2 text-sm font-semibold"><Target className="w-4 h-4 text-accent-purple" />Scorecard</div>
                <div className="flex items-baseline gap-4">
                  <span className="text-3xl font-bold">{run.score.score}</span>
                  <span className="text-xs text-text-secondary">quality {Math.round(run.score.quality * 100)}%
                    {run.score.efficiency != null && ` · efficiency ${Math.round(run.score.efficiency * 100)}%`}
                    {run.score.optimal_tool_calls != null && ` · ${run.score.tool_calls} queries (reference ${run.score.optimal_tool_calls})`}
                  </span>
                </div>
                {Object.entries(run.score.breakdown).map(([k, x]) => (
                  <div key={k} className="text-xs">
                    <div className="flex justify-between"><span>{k.replace(/_/g, ' ')}</span><span className="font-mono">{Math.round(x * 100)}%</span></div>
                    <div className="h-1.5 bg-bg-primary rounded"><div className="h-1.5 rounded bg-accent-blue" style={{ width: `${x * 100}%` }} /></div>
                  </div>
                ))}
                {run.score.invented_event_ids && run.score.invented_event_ids.length > 0 && (
                  <p className="text-xs text-accent-red">Cited event ids it never retrieved: {run.score.invented_event_ids.join(', ')}</p>
                )}
                {run.answer?.explanation && (
                  <p className="text-xs text-text-secondary border-t border-bg-card pt-2">
                    <span className="font-semibold text-text-primary">Expected:</span> {String(run.answer.verdict).replace(/_/g, ' ')} — {run.answer.explanation}
                  </p>
                )}
                <p className="text-[10px] text-text-secondary">Weights approximate the competition's stated criteria; the official formula is not published.</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
