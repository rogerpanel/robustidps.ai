import { useEffect, useMemo, useState } from 'react'
import { Loader2, FileDown, GitCompare, X, CheckCircle2, XCircle } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend } from 'recharts'
import { downloadCsv, type Cell } from './csv'

type Num = number | null | undefined
interface Group {
  tasks: number; completed?: number; mean_quality: Num; mean_efficiency: Num; mean_reward: Num
  verdict_accuracy?: Num; false_positive_rate?: Num; false_negative_rate?: Num; mean_tool_calls: Num
  mean_wall_seconds?: Num; tokens_input?: number; tokens_output?: number; llm_calls?: number
}
interface Metrics { overall?: Group; by_platform?: Record<string, Group>; by_expected_verdict?: Record<string, Group> }
interface TaskCell {
  quality: Num; efficiency: Num; reward: Num; calls: Num; completion: string
  verdict: string | null; expected_verdict: string | null; platform: string | null
}
export interface CompareRun {
  id: string; name: string; label: string; agent_model: string; n_tasks: number; n_completed: number
  mean_quality: number; mean_efficiency: number; mean_reward: number; mean_tool_calls: number
  config: { ablations?: string[]; effort?: string; concurrency?: number; model?: string }
  metrics: Metrics; tasks: Record<string, TaskCell>
}

const f = (v: Num, d = 3) => (typeof v === 'number' ? v.toFixed(d) : '–')
const pct = (v: Num) => (typeof v === 'number' ? `${(v * 100).toFixed(0)}%` : '–')
const nameOf = (r: CompareRun) => r.label || r.name

// Runs uploaded before metrics were recorded still compare on the stored means.
function overall(r: CompareRun): Group {
  return r.metrics?.overall ?? {
    tasks: r.n_tasks, completed: r.n_completed, mean_quality: r.mean_quality,
    mean_efficiency: r.mean_efficiency, mean_reward: r.mean_reward, mean_tool_calls: r.mean_tool_calls,
  }
}

const COLS: { key: keyof Group; title: string; fmt: (v: Num) => string; better: 'high' | 'low' }[] = [
  { key: 'mean_quality', title: 'Quality', fmt: v => f(v), better: 'high' },
  { key: 'mean_efficiency', title: 'Efficiency', fmt: v => f(v), better: 'high' },
  { key: 'mean_reward', title: 'Reward', fmt: v => f(v), better: 'high' },
  { key: 'verdict_accuracy', title: 'Verdict acc.', fmt: pct, better: 'high' },
  { key: 'false_positive_rate', title: 'FP rate', fmt: pct, better: 'low' },
  { key: 'false_negative_rate', title: 'FN rate', fmt: pct, better: 'low' },
  { key: 'mean_tool_calls', title: 'Calls/task', fmt: v => f(v, 2), better: 'low' },
  { key: 'mean_wall_seconds', title: 'Sec/task', fmt: v => f(v, 1), better: 'low' },
]

function Section({ title, onCsv, children, note }: { title: string; onCsv: () => void; children: React.ReactNode; note?: string }) {
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <h3 className="font-semibold text-sm mr-auto">{title}</h3>
        <button onClick={onCsv} className="text-xs flex items-center gap-1 text-text-secondary hover:text-text-primary"><FileDown className="w-3.5 h-3.5" /> CSV</button>
      </div>
      {note && <p className="text-xs text-text-secondary">{note}</p>}
      <div className="overflow-x-auto">{children}</div>
    </div>
  )
}

export default function RunComparison({ ids, fetchRuns, onClear }: {
  ids: string[]; fetchRuns: (ids: string[]) => Promise<CompareRun[]>; onClear: () => void
}) {
  const [runs, setRuns] = useState<CompareRun[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [baseId, setBaseId] = useState('')

  useEffect(() => {
    let live = true
    setLoading(true); setError('')
    fetchRuns(ids)
      .then(r => {
        if (!live) return
        setRuns(r)
        setBaseId(prev => (r.some(x => x.id === prev) ? prev : (r.find(x => x.label === 'full') ?? r[0])?.id ?? ''))
      })
      .catch(e => live && setError((e as Error).message))
      .finally(() => live && setLoading(false))
    return () => { live = false }
  }, [ids, fetchRuns])

  const base = runs.find(r => r.id === baseId) ?? runs[0]
  const taskIds = useMemo(() => Array.from(new Set(runs.flatMap(r => Object.keys(r.tasks)))).sort(), [runs])

  if (loading) return <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card"><Loader2 className="w-5 h-5 animate-spin text-text-secondary" /></div>
  if (error) return <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card text-sm text-accent-red">{error}</div>
  if (runs.length < 2) return null

  const b = overall(base)
  const best = (key: keyof Group, better: 'high' | 'low') => {
    const vals = runs.map(r => overall(r)[key]).filter((v): v is number => typeof v === 'number')
    if (!vals.length) return null
    return better === 'high' ? Math.max(...vals) : Math.min(...vals)
  }

  const ablationCsv = () => downloadCsv('bluesec-ablation-table', [
    ['configuration', 'run', 'ablations', 'model', 'effort', 'tasks', ...COLS.map(c => c.key), 'delta_reward', 'delta_quality', 'tokens_input', 'tokens_output'],
    ...runs.map(r => {
      const m = overall(r)
      return [nameOf(r), r.name, (r.config.ablations ?? []).join('+'), r.config.model ?? r.agent_model, r.config.effort ?? '', m.tasks,
        ...COLS.map(c => m[c.key] as Cell),
        r === base ? 0 : +((m.mean_reward ?? 0) - (b.mean_reward ?? 0)).toFixed(4),
        r === base ? 0 : +((m.mean_quality ?? 0) - (b.mean_quality ?? 0)).toFixed(4),
        m.tokens_input ?? '', m.tokens_output ?? '']
    }),
  ])

  const groups: { key: 'by_platform' | 'by_expected_verdict'; value: string; title: string }[] = [
    { key: 'by_platform', value: 'windows', title: 'Windows' }, { key: 'by_platform', value: 'linux', title: 'Linux' },
    { key: 'by_expected_verdict', value: 'malicious', title: 'Malicious' }, { key: 'by_expected_verdict', value: 'benign', title: 'Benign' },
  ]
  const breakdownCsv = () => downloadCsv('bluesec-breakdown', [
    ['configuration', ...groups.flatMap(g => [`${g.value}_tasks`, `${g.value}_quality`, `${g.value}_verdict_accuracy`])],
    ...runs.map(r => [nameOf(r), ...groups.flatMap(g => {
      const m = r.metrics?.[g.key]?.[g.value]
      return [m?.tasks ?? '', m?.mean_quality ?? '', m?.verdict_accuracy ?? '']
    })]),
  ])

  const matrixCsv = () => downloadCsv('bluesec-task-matrix', [
    ['task', 'platform', 'expected_verdict', ...runs.flatMap(r => [`${nameOf(r)}:verdict`, `${nameOf(r)}:quality`, `${nameOf(r)}:reward`, `${nameOf(r)}:calls`])],
    ...taskIds.map(t => {
      const any = runs.map(r => r.tasks[t]).find(Boolean)
      return [t, any?.platform ?? '', any?.expected_verdict ?? '', ...runs.flatMap(r => {
        const c = r.tasks[t]
        return [c?.verdict ?? '', c?.quality ?? '', c?.reward ?? '', c?.calls ?? '']
      })]
    }),
  ])

  const chart = runs.map(r => ({ name: nameOf(r), quality: overall(r).mean_quality ?? 0, efficiency: overall(r).mean_efficiency ?? 0, reward: overall(r).mean_reward ?? 0 }))

  return (
    <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="font-semibold flex items-center gap-2 mr-auto"><GitCompare className="w-4 h-4" /> Comparison and ablation ({runs.length} runs)</h2>
        <label className="text-xs text-text-secondary flex items-center gap-1.5">Baseline
          <select value={base?.id} onChange={e => setBaseId(e.target.value)} className="bg-bg-primary border border-bg-card rounded px-2 py-1 text-xs text-text-primary">
            {runs.map(r => <option key={r.id} value={r.id}>{nameOf(r)}</option>)}
          </select>
        </label>
        <button onClick={onClear} className="text-xs flex items-center gap-1 text-text-secondary hover:text-text-primary"><X className="w-3.5 h-3.5" /> Clear selection</button>
      </div>

      <Section title="Ablation table" onCsv={ablationCsv}
        note={`One row per configuration. Δ is the change against the baseline (${nameOf(base)}) on the same tasks; the best value in each column is bold. FP rate = benign tasks judged malicious; FN rate = malicious tasks judged benign.`}>
        <table className="w-full text-sm">
          <thead><tr className="text-left text-xs text-text-secondary">
            <th className="font-normal py-1.5">Configuration</th><th className="font-normal">Turned off</th><th className="font-normal text-right">Tasks</th>
            {COLS.map(c => <th key={c.key} className="font-normal text-right">{c.title}</th>)}
            <th className="font-normal text-right">Δ Reward</th><th className="font-normal text-right">Δ Quality</th>
          </tr></thead>
          <tbody>
            {runs.map(r => {
              const m = overall(r)
              const dR = (m.mean_reward ?? 0) - (b.mean_reward ?? 0)
              const dQ = (m.mean_quality ?? 0) - (b.mean_quality ?? 0)
              return (
                <tr key={r.id} className={`border-t border-bg-card ${r === base ? 'bg-bg-primary/60' : ''}`}>
                  <td className="py-1.5 pr-2 font-medium">{nameOf(r)}{r === base && <span className="ml-1 text-[10px] text-text-secondary">(baseline)</span>}</td>
                  <td className="pr-2 text-xs text-text-secondary">{(r.config.ablations ?? []).join(', ') || '—'}</td>
                  <td className="text-right tabular-nums text-xs pr-2">{m.tasks}</td>
                  {COLS.map(c => {
                    const v = m[c.key] as Num
                    const top = typeof v === 'number' && v === best(c.key, c.better)
                    return <td key={c.key} className={`text-right tabular-nums text-xs pr-2 ${top ? 'font-semibold text-text-primary' : ''}`}>{c.fmt(v)}</td>
                  })}
                  <td className="text-right tabular-nums text-xs pr-2">{r === base ? '—' : `${dR >= 0 ? '+' : ''}${dR.toFixed(3)}`}</td>
                  <td className="text-right tabular-nums text-xs">{r === base ? '—' : `${dQ >= 0 ? '+' : ''}${dQ.toFixed(3)}`}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </Section>

      <div>
        <h3 className="font-semibold text-sm">Quality and efficiency by configuration</h3>
        <p className="text-xs text-text-secondary mb-2">Mean per run; exact values in the table above.</p>
        <div className="h-60">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chart} margin={{ top: 8, right: 16, bottom: 0, left: -12 }} barGap={2}>
              <CartesianGrid stroke="rgb(var(--color-bg-card))" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="name" tick={{ fontSize: 11, fill: 'rgb(var(--color-text-secondary))' }} stroke="rgb(var(--color-bg-card))" interval={0} />
              <YAxis domain={[0, 1]} tick={{ fontSize: 11, fill: 'rgb(var(--color-text-secondary))' }} stroke="rgb(var(--color-bg-card))" />
              <Tooltip cursor={{ fill: 'rgb(var(--color-bg-card) / 0.3)' }}
                contentStyle={{ background: 'rgb(var(--color-bg-primary))', border: '1px solid rgb(var(--color-bg-card))', borderRadius: 8, fontSize: 12 }}
                formatter={(v: number, n: string) => [v.toFixed(3), n]} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Bar dataKey="quality" name="Mean quality" fill="var(--chart-1)" radius={[4, 4, 0, 0]} maxBarSize={36} />
              <Bar dataKey="efficiency" name="Mean efficiency" fill="var(--chart-2)" radius={[4, 4, 0, 0]} maxBarSize={36} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <Section title="Breakdown by platform and expected verdict" onCsv={breakdownCsv}
        note="Mean quality and verdict accuracy per slice. Accuracy on benign tasks is 1 − FP rate; on malicious tasks 1 − FN rate.">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-text-secondary">
              <th className="font-normal py-1.5" rowSpan={2}>Configuration</th>
              {groups.map(g => <th key={g.value} colSpan={2} className="font-normal text-center border-l border-bg-card">{g.title}</th>)}
            </tr>
            <tr className="text-xs text-text-secondary">
              {groups.map(g => [
                <th key={`${g.value}q`} className="font-normal text-right border-l border-bg-card px-1">Quality</th>,
                <th key={`${g.value}a`} className="font-normal text-right px-1">Acc.</th>,
              ])}
            </tr>
          </thead>
          <tbody>
            {runs.map(r => (
              <tr key={r.id} className="border-t border-bg-card">
                <td className="py-1.5 pr-2 font-medium">{nameOf(r)}</td>
                {groups.map(g => {
                  const m = r.metrics?.[g.key]?.[g.value]
                  return [
                    <td key={`${g.value}q`} className="text-right tabular-nums text-xs border-l border-bg-card px-1">{m ? f(m.mean_quality) : '–'}</td>,
                    <td key={`${g.value}a`} className="text-right tabular-nums text-xs px-1">{m ? pct(m.verdict_accuracy) : '–'}</td>,
                  ]
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="Per-task results" onCsv={matrixCsv}
        note="Reward per task and configuration; the icon shows whether the verdict matched the expected one (practice tasks only). The best reward in each row is bold.">
        <table className="w-full text-xs">
          <thead><tr className="text-left text-text-secondary">
            <th className="font-normal py-1.5">Task</th><th className="font-normal">Platform</th><th className="font-normal">Expected</th>
            {runs.map(r => <th key={r.id} className="font-normal text-right px-1">{nameOf(r)}</th>)}
          </tr></thead>
          <tbody>
            {taskIds.map(t => {
              const cells = runs.map(r => r.tasks[t])
              const any = cells.find(Boolean)
              const top = Math.max(...cells.map(c => (typeof c?.reward === 'number' ? c.reward : -1)))
              return (
                <tr key={t} className="border-t border-bg-card">
                  <td className="py-1 pr-2 font-mono">{t}</td>
                  <td className="pr-2 text-text-secondary">{any?.platform ?? '–'}</td>
                  <td className="pr-2 text-text-secondary">{any?.expected_verdict ?? '–'}</td>
                  {cells.map((c, i) => (
                    <td key={runs[i].id} className={`text-right tabular-nums px-1 ${c && c.reward === top ? 'font-semibold text-text-primary' : ''}`}>
                      {c ? (
                        <span className="inline-flex items-center gap-1 justify-end">
                          {c.expected_verdict && (c.verdict === c.expected_verdict
                            ? <CheckCircle2 className="w-3 h-3 text-accent-green" aria-label="verdict correct" />
                            : <XCircle className="w-3 h-3 text-accent-red" aria-label="verdict wrong" />)}
                          {f(c.reward)}
                        </span>
                      ) : '–'}
                    </td>
                  ))}
                </tr>
              )
            })}
          </tbody>
        </table>
      </Section>
    </div>
  )
}
