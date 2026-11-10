import { useEffect, useRef, useState } from 'react'
import { Download, FileSpreadsheet, FileJson, FileText, Image, Loader2 } from 'lucide-react'
import { downloadCsv, type Cell } from './csv'

// Lazy-loaded like the page-wide ExportMenu: only fetched when a report is exported.
const loadHtml2Canvas = () => import('html2canvas').then(m => m.default)
const loadJsPDF = () => import('jspdf').then(m => m.default)

interface ExportTask {
  task_id: string
  result: {
    completion_reason: string; quality_score: number; efficiency_score: number
    total_reward: number; tool_calls: number; wall_time_seconds?: number
  }
  submission?: Record<string, unknown> | null
  task_meta?: { platform?: string; expected_verdict?: string; attack?: string }
  calls_saved_by_cache?: number
  wall_seconds?: number
  usage?: { input?: number; output?: number; cache_read?: number; llm_calls?: number }
  steps?: unknown[]
}
export interface ExportRun {
  id: string; name: string; label?: string; source: string; agent_model: string
  started_at: string | null; created_at: string; notes: string
  n_tasks: number; n_completed: number; mean_quality: number; mean_efficiency: number
  mean_reward: number; mean_tool_calls: number
  config?: Record<string, unknown>; metrics?: Record<string, unknown>
  aggregates?: Record<string, number>; tasks: ExportTask[]
}

const safeName = (s: string) => (s || 'bluesec-run').replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 80)

export function taskRows(run: ExportRun): Cell[][] {
  const header: Cell[] = [
    'task_id', 'platform', 'attack', 'expected_verdict', 'verdict', 'verdict_correct', 'completion',
    'quality', 'efficiency', 'reward', 'tool_calls', 'calls_saved_by_cache', 'wall_seconds',
    'tokens_input', 'tokens_output', 'tokens_cache_read', 'model_calls',
  ]
  const rows = run.tasks.map(t => {
    const verdict = (t.submission?.verdict as string) || ''
    const expected = t.task_meta?.expected_verdict || ''
    return [
      t.task_id, t.task_meta?.platform || '', t.task_meta?.attack || '', expected, verdict,
      expected && verdict ? (expected === verdict ? 'yes' : 'no') : '',
      t.result.completion_reason, t.result.quality_score, t.result.efficiency_score,
      t.result.total_reward, t.result.tool_calls, t.calls_saved_by_cache ?? '',
      t.wall_seconds ?? t.result.wall_time_seconds ?? '',
      t.usage?.input ?? '', t.usage?.output ?? '', t.usage?.cache_read ?? '', t.usage?.llm_calls ?? '',
    ] as Cell[]
  })
  return [header, ...rows]
}

function downloadJson(filename: string, data: unknown): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename.endsWith('.json') ? filename : `${filename}.json`
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/** Export one saved run: per-task results (CSV), the full run with every tool call (JSON),
 *  and a report image or PDF of the run's detail panel (`targetId`). */
export default function RunExport({ run, targetId }: { run: ExportRun; targetId: string }) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState('')
  const ref = useRef<HTMLDivElement>(null)
  const base = safeName(run.name)

  useEffect(() => {
    const close = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [])

  const capture = async () => {
    const el = document.getElementById(targetId)
    if (!el) return null
    const html2canvas = await loadHtml2Canvas()
    return html2canvas(el, { backgroundColor: '#0F172A', scale: 2, useCORS: true, logging: false })
  }

  const report = async (kind: 'png' | 'pdf') => {
    setBusy(kind)
    try {
      const canvas = await capture()
      if (!canvas) return
      if (kind === 'png') {
        const a = document.createElement('a')
        a.download = `${base}.png`
        a.href = canvas.toDataURL('image/png')
        a.click()
        return
      }
      const JsPDF = await loadJsPDF()
      const pdf = new JsPDF('p', 'mm', 'a4')
      const margin = 10
      const pageW = pdf.internal.pageSize.getWidth()
      const pageH = pdf.internal.pageSize.getHeight()
      const w = pageW - 2 * margin
      const pxPerPage = ((pageH - 2 * margin) / w) * canvas.width
      for (let y = 0, page = 0; y < canvas.height; y += pxPerPage, page++) {
        if (page) pdf.addPage()
        const h = Math.min(pxPerPage, canvas.height - y)
        const slice = document.createElement('canvas')
        slice.width = canvas.width
        slice.height = h
        slice.getContext('2d')!.drawImage(canvas, 0, y, canvas.width, h, 0, 0, canvas.width, h)
        pdf.addImage(slice.toDataURL('image/png'), 'PNG', margin, margin, w, (h / canvas.width) * w)
      }
      pdf.save(`${base}.pdf`)
    } finally { setBusy(''); setOpen(false) }
  }

  const item = 'w-full text-left px-3 py-2 text-xs hover:bg-bg-card flex items-center gap-2 disabled:opacity-40'
  return (
    <div ref={ref} className="relative">
      <button onClick={() => setOpen(o => !o)}
        className="text-xs px-2.5 py-1.5 rounded bg-bg-primary border border-bg-card hover:border-accent-blue flex items-center gap-1">
        {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />} Export run
      </button>
      {open && (
        <div className="absolute right-0 mt-1 w-60 z-20 rounded-lg bg-bg-secondary border border-bg-card shadow-lg py-1">
          <button className={item} onClick={() => { downloadCsv(`${base}-tasks`, taskRows(run)); setOpen(false) }}>
            <FileSpreadsheet className="w-4 h-4" /> Results per task (CSV)
          </button>
          <button className={item} onClick={() => {
            downloadJson(`${base}-summary`, {
              name: run.name, label: run.label, source: run.source, agent_model: run.agent_model,
              started_at: run.started_at, notes: run.notes, config: run.config,
              n_tasks: run.n_tasks, n_completed: run.n_completed, mean_quality: run.mean_quality,
              mean_efficiency: run.mean_efficiency, mean_reward: run.mean_reward,
              mean_tool_calls: run.mean_tool_calls, aggregates: run.aggregates, metrics: run.metrics,
            }); setOpen(false)
          }}>
            <FileJson className="w-4 h-4" /> Summary and metrics (JSON)
          </button>
          <button className={item} onClick={() => { downloadJson(`${base}-full`, run); setOpen(false) }}>
            <FileJson className="w-4 h-4" /> Full run with every tool call (JSON)
          </button>
          <div className="border-t border-bg-card my-1" />
          <button className={item} disabled={!!busy} onClick={() => report('pdf')}>
            <FileText className="w-4 h-4" /> Report of this run (PDF)
          </button>
          <button className={item} disabled={!!busy} onClick={() => report('png')}>
            <Image className="w-4 h-4" /> Report of this run (PNG)
          </button>
        </div>
      )}
    </div>
  )
}

/** All saved runs as one table (CSV). */
export function savedRunsRows(runs: Array<Omit<ExportRun, 'tasks'> & { metrics?: { overall?: Record<string, number | null> } }>): Cell[][] {
  const header: Cell[] = [
    'name', 'label', 'source', 'agent_model', 'started_at', 'tasks', 'completed', 'mean_quality',
    'mean_efficiency', 'mean_reward', 'calls_per_task', 'verdict_accuracy', 'false_positive_rate',
    'false_negative_rate', 'notes',
  ]
  return [header, ...runs.map(r => {
    const o = (r.metrics as { overall?: Record<string, number | null> } | undefined)?.overall || {}
    return [
      r.name, r.label || '', r.source, r.agent_model, r.started_at || r.created_at, r.n_tasks, r.n_completed,
      r.mean_quality, r.mean_efficiency, r.mean_reward, r.mean_tool_calls,
      o.verdict_accuracy ?? '', o.false_positive_rate ?? '', o.false_negative_rate ?? '', r.notes,
    ] as Cell[]
  })]
}
