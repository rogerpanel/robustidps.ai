import type { GuardPrediction } from '../../guardApi'

/** The predictive layer's view of a call: what it would take down, and whether a safe state remains. */
export default function PredictionView({ p }: { p: GuardPrediction }) {
  return (
    <div className={`rounded-lg border p-3 text-xs space-y-1.5 ${p.safe ? 'border-bg-primary' : 'border-accent-red/40 bg-accent-red/5'}`}>
      <div className="font-semibold">
        Predicted effect ({p.effect} made unavailable): {p.safe ? 'a safe state remains' : 'unsafe'} · blast radius {p.blast_radius}
        {p.session_blast_radius !== p.blast_radius && ` (session ${p.session_blast_radius})`}
      </div>
      {p.affected.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {p.affected.map((a) => (
            <span key={a.id} className="px-1.5 py-0.5 rounded bg-bg-primary">
              {a.name}{a.role ? ` · ${a.role}` : ''} · {a.dependents} dependents{a.group ? ` · ${a.group}` : ''}
            </span>
          ))}
        </div>
      )}
      {p.groups.map((g) => (
        <div key={g.group} className={g.remaining_after < g.min_available ? 'text-accent-red' : 'text-text-secondary'}>
          {g.group}: {g.remaining_after} of {g.members} available afterwards (minimum {g.min_available})
        </div>
      ))}
      {p.unknown.length > 0 && <div className="text-accent-amber">Not in the inventory (effect unknown): {p.unknown.join(', ')}</div>}
    </div>
  )
}
