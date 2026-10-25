import type { GuardTyped } from '../../guardApi'

const n = (v: number | null) => (v == null ? 'unbounded' : v.toLocaleString())

/** How the guard read a network call's arguments: targets, addresses, ports, probes and rates as checked. */
export default function TypedView({ actions, charges }: { actions?: GuardTyped[] | null; charges?: Record<string, number> | null }) {
  const list = actions || []
  const ch = Object.entries(charges || {})
  if (list.length === 0 && ch.length === 0) return null
  return (
    <div className="rounded-lg border border-bg-primary p-3 text-xs space-y-1.5">
      {list.map((a) => (
        <div key={a.id} className="space-y-1">
          <div className="font-semibold">Read as values ({a.id})</div>
          <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-text-secondary">
            <span>addresses {n(a.n_targets)}</span>
            {a.ports != null && <span>ports {a.ports.toLocaleString()}</span>}
            {a.probes != null && a.ports != null && <span>probes {n(a.probes)}</span>}
            {Object.entries(a.rates).map(([k, v]) => <span key={k}>{k} {v}</span>)}
          </div>
          {a.targets.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {a.targets.map((t, i) => <span key={i} className="px-1.5 py-0.5 rounded bg-bg-primary font-mono">{t}</span>)}
            </div>
          )}
          {a.projected && <div className="text-accent-blue">Cut to the scope; removed: {a.dropped.join(', ')}</div>}
        </div>
      ))}
      {ch.length > 0 && (
        <div className="text-text-secondary">
          If approved, this call counts against: {ch.map(([b, v]) => `${b} (${v})`).join(', ')}. The budget is checked
          again when the approved call is used.
        </div>
      )}
    </div>
  )
}
