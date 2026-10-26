import { useCallback, useEffect, useState } from 'react'
import { CheckCircle2, XCircle, Loader2, RefreshCw, AlertTriangle } from 'lucide-react'
import { guardApprovals, guardDecideApproval, type GuardApproval } from '../../guardApi'
import PredictionView from './PredictionView'
import FlowView from './FlowView'
import TypedView from './TypedView'
import DeferralPanel from './DeferralPanel'

const STATUS_STYLE: Record<string, string> = {
  pending: 'bg-accent-amber/15 text-accent-amber',
  approved: 'bg-accent-green/15 text-accent-green',
  used: 'bg-accent-green/10 text-accent-green',
  denied: 'bg-accent-red/15 text-accent-red',
  expired: 'bg-bg-primary text-text-secondary',
}

function minutesLeft(iso: string) {
  return Math.max(0, Math.round((new Date(iso).getTime() - Date.now()) / 60000))
}

/** Calls the guard answered with "ask". A person approves or denies; the agent then repeats the exact call. */
export default function ApprovalsTab({ onCount }: { onCount?: (n: number) => void }) {
  const [items, setItems] = useState<GuardApproval[]>([])
  const [showAll, setShowAll] = useState(false)
  const [notes, setNotes] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState('')
  const [err, setErr] = useState('')

  const load = useCallback(() => {
    guardApprovals(showAll ? undefined : 'pending')
      .then((list) => { setItems(list); if (!showAll) onCount?.(list.length) })
      .catch((e) => setErr(String(e.message || e)))
  }, [showAll, onCount])

  useEffect(() => {
    load()
    const t = window.setInterval(load, 5000)
    return () => window.clearInterval(t)
  }, [load])

  const decide = async (a: GuardApproval, d: 'approve' | 'deny') => {
    setBusy(a.id); setErr('')
    try { await guardDecideApproval(a.id, d, notes[a.id] || ''); load() }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
    finally { setBusy('') }
  }

  return (
    <div className="space-y-4">
      <DeferralPanel />
      <div className="flex items-center gap-3">
        <p className="text-sm text-text-secondary mr-auto">
          Each request is bound to its session and its exact arguments, and can be used once. Unanswered requests
          expire and count as denied. Agents using an API key cannot approve their own calls.
        </p>
        <label className="text-xs flex items-center gap-1.5 text-text-secondary">
          <input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} /> show decided
        </label>
        <button onClick={load} className="text-text-secondary hover:text-text-primary" title="Refresh"><RefreshCw className="w-4 h-4" /></button>
      </div>
      {err && <p className="text-sm text-accent-red">{err}</p>}
      {items.length === 0 && <div className="bg-bg-card rounded-xl p-6 text-sm text-text-secondary text-center">No {showAll ? '' : 'pending '}approval requests.</div>}
      {items.map((a) => (
        <div key={a.id} className="bg-bg-card rounded-xl p-4 space-y-3">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className={`px-2 py-0.5 rounded text-xs font-semibold uppercase ${STATUS_STYLE[a.status]}`}>{a.status}</span>
            <span className="font-mono font-semibold">{a.preview.tool}</span>
            <span className="text-text-secondary text-xs">tier {a.preview.tier}{a.preview.reversible === false ? ' · not reversible' : a.preview.reversible ? ' · reversible' : ''}</span>
            <span className="ml-auto text-xs text-text-secondary">
              {a.preview.agent_id || 'agent'} · session {a.session_id} · {a.preview.policy}
              {a.status === 'pending' && ` · expires in ${minutesLeft(a.expires_at)} min`}
            </span>
          </div>
          {a.preview.hidden_characters.length > 0 && (
            <p className="text-xs text-accent-red flex items-center gap-1.5"><AlertTriangle className="w-3.5 h-3.5" />
              Hidden characters were removed from this call: {a.preview.hidden_characters.join(' · ')}</p>
          )}
          {a.preview.prediction && <PredictionView p={a.preview.prediction} />}
          {a.preview.flow && <FlowView f={a.preview.flow} />}
          <TypedView actions={a.preview.actions} charges={a.preview.budget_charges} />
          {a.preview.deferral && a.preview.deferral.mode !== 'off' && (
            <p className="text-xs text-text-secondary">
              Calibrator: risk score {a.preview.deferral.score}
              {a.preview.deferral.eligible
                ? (a.preview.deferral.would_auto_approve ? ' · would be auto-approved' : ` · above the threshold ${a.preview.deferral.threshold ?? '(not calibrated)'}`)
                : ` · never auto-approved (${a.preview.deferral.reason})`}
            </p>
          )}
          <div className="grid md:grid-cols-2 gap-3">
            <div>
              <p className="text-xs text-text-secondary mb-1">Targets ({a.preview.n_targets})</p>
              {a.preview.targets.length === 0 ? <p className="text-xs">none named</p> : (
                <div className="flex flex-wrap gap-1">
                  {a.preview.targets.map((t, i) => <span key={i} className="px-1.5 py-0.5 rounded bg-bg-primary text-xs font-mono">{t.arg}={t.value}</span>)}
                </div>
              )}
              <p className="text-xs text-text-secondary mt-2 mb-1">Why approval is needed</p>
              <ul className="text-xs list-disc pl-4">{a.preview.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>
            </div>
            <div>
              <p className="text-xs text-text-secondary mb-1">Exact arguments (as they will run)</p>
              <pre className="text-xs bg-bg-primary rounded-lg p-2 overflow-x-auto max-h-40">{JSON.stringify(a.preview.args, null, 2)}</pre>
            </div>
          </div>
          {a.status === 'pending' ? (
            <div className="flex flex-wrap gap-2 items-center">
              <input value={notes[a.id] || ''} onChange={(e) => setNotes({ ...notes, [a.id]: e.target.value })}
                     placeholder="note (recorded in the evidence ledger)"
                     className="flex-1 min-w-48 px-3 py-1.5 bg-bg-primary border border-bg-card rounded-lg text-xs" />
              <button onClick={() => decide(a, 'approve')} disabled={busy === a.id}
                      className="px-3 py-1.5 rounded-lg bg-accent-green/20 text-accent-green text-xs font-semibold inline-flex items-center gap-1.5">
                {busy === a.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />} Approve once
              </button>
              <button onClick={() => decide(a, 'deny')} disabled={busy === a.id}
                      className="px-3 py-1.5 rounded-lg bg-accent-red/20 text-accent-red text-xs font-semibold inline-flex items-center gap-1.5">
                <XCircle className="w-3.5 h-3.5" /> Deny
              </button>
            </div>
          ) : (
            <p className="text-xs text-text-secondary">
              {a.decided_by ? `${a.status} by ${a.decided_by}` : a.status}{a.decided_at ? ` at ${new Date(a.decided_at).toLocaleString()}` : ''}
              {a.note ? ` · "${a.note}"` : ''}
            </p>
          )}
        </div>
      ))}
    </div>
  )
}
