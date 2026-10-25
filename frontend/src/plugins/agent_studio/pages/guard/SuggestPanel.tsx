import type { CaseDiff, GuardPolicy, SuggestResult } from '../../guardApi'

const BREADTH = ['', 'one tool or value', 'one rule', 'a whole rule or tier']

function Diff({ d, label }: { d: CaseDiff; label: string }) {
  return (
    <span className="text-text-secondary">
      {label}: fixes {d.fixed.length}{d.fixed.length ? ` (${d.fixed.join(', ')})` : ''}
      {' · '}<span className={d.broken.length ? 'text-accent-red font-semibold' : ''}>breaks {d.broken.length}{d.broken.length ? ` (${d.broken.join(', ')})` : ''}</span>
      {' · '}moves {d.changed.length} · exact {Math.round(d.exact_accuracy * 1000) / 10}%
    </span>
  )
}

/** Proposed policy edits for failing cases, each re-run on the whole suite (and the held-out suite, if chosen). */
export default function SuggestPanel({ r, onUsePolicy }: { r: SuggestResult; onUsePolicy?: (p: GuardPolicy) => void }) {
  return (
    <div className="bg-bg-card rounded-xl p-4 space-y-4 text-xs">
      <div className="space-y-1">
        <h3 className="font-semibold text-sm">
          Proposed edits for {r.failures} failing case{r.failures === 1 ? '' : 's'} ({r.strategy === 'general' ? 'widest edit that breaks nothing' : 'smallest edit'})
        </h3>
        <p className="text-text-secondary">
          {r.policy} on {r.suite}: exact {Math.round(r.exact_accuracy * 1000) / 10}%
          {r.holdout && <> · held out {r.holdout.suite}: {Math.round(r.holdout.exact_accuracy * 1000) / 10}%</>}
          {' · '}{r.candidate_runs} re-runs{r.truncated ? ' (stopped at the limit; fix some cases and run again)' : ''}.
          {' '}{r.note}
        </p>
      </div>
      {r.combined && (
        <div className="rounded-lg border border-accent-green/40 bg-accent-green/5 p-3 space-y-1">
          <div className="font-semibold">All non-breaking edits together</div>
          <ul className="list-disc ml-4">{r.combined.edits.map((e) => <li key={e.case}><span className="font-mono">{e.case}</span>: {e.description}</li>)}</ul>
          <div><Diff d={r.combined} label="this suite" /></div>
          {r.combined.holdout && <div><Diff d={r.combined.holdout} label="held out" /></div>}
          {onUsePolicy && (
            <button onClick={() => onUsePolicy(r.combined!.policy)} className="text-accent-blue hover:underline">
              Open this policy in the Test tab →
            </button>
          )}
        </div>
      )}
      {r.report.map((f) => (
        <div key={f.case} className="border-t border-bg-primary pt-3 space-y-1.5">
          <div>
            <span className="font-mono font-semibold">{f.case}</span> <span className="font-mono">{f.tool}</span>: expected
            {' '}<b>{f.expect}</b>{f.expect_rule ? ` (${f.expect_rule})` : ''}, got <b>{f.got}</b>
            <span className="text-text-secondary"> from {f.rules.join(', ')}</span>
            {f.context && <div className="text-text-secondary">{f.context}</div>}
          </div>
          {f.suggestions.length === 0 && f.notes.length === 0 && (
            <div className="text-text-secondary">No edit within the policy language fixes this case without changing its label.</div>
          )}
          {f.suggestions.map((s, i) => (
            <div key={i} className={`rounded-lg p-2 ${s.broken.length ? 'bg-accent-red/5' : 'bg-bg-primary'}`}>
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{s.description}</span>
                <span className="px-1.5 rounded bg-bg-card text-text-secondary">{BREADTH[s.breadth]}</span>
                {onUsePolicy && <button onClick={() => onUsePolicy(s.policy)} className="ml-auto text-accent-blue hover:underline">Open →</button>}
              </div>
              <div><Diff d={s} label="this suite" /></div>
              {s.holdout && <div><Diff d={s.holdout} label="held out" /></div>}
            </div>
          ))}
          {f.notes.map((n, i) => <div key={i} className="text-accent-amber">{n}</div>)}
        </div>
      ))}
    </div>
  )
}
