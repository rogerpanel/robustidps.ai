import type { GuardFlow } from '../../guardApi'

const LABEL_TEXT: Record<string, string> = {
  untrusted: 'untrusted input',
  sensitive: 'sensitive data',
  egress: 'sends data out',
}
const LABEL_STYLE: Record<string, string> = {
  untrusted: 'bg-accent-amber/15 text-accent-amber',
  sensitive: 'bg-accent-blue/15 text-accent-blue',
  egress: 'bg-accent-red/15 text-accent-red',
}

export function LabelChip({ label, title }: { label: string; title?: string }) {
  return (
    <span title={title} className={`px-1.5 py-0.5 rounded text-[11px] ${LABEL_STYLE[label] || 'bg-bg-primary text-text-secondary'}`}>
      {LABEL_TEXT[label] || label}
    </span>
  )
}

/** Session information flow for one call: what it reads or sends, and what the session had already seen. */
export default function FlowView({ f }: { f: GuardFlow }) {
  const before = Object.entries(f.session_before)
  const fired = f.rules.length > 0
  return (
    <div className={`rounded-lg border p-3 text-xs space-y-1.5 ${fired ? 'border-accent-amber/40 bg-accent-amber/5' : 'border-bg-primary'}`}>
      <div className="font-semibold">
        Information flow: {fired ? `rule ${f.rules.map((r) => r.id).join(', ')} applies` : 'no flow rule applies'}
      </div>
      <div className="flex flex-wrap items-center gap-1">
        <span className="text-text-secondary">This call:</span>
        {f.call_labels.length === 0 ? <span className="text-text-secondary">no data labels</span>
          : f.call_labels.map((l) => <LabelChip key={l} label={l} title={f.label_reasons[l]} />)}
        {f.unclassified && <span className="text-accent-amber">(tool not classified: assumed to read and send anything)</span>}
      </div>
      <div className="flex flex-wrap items-center gap-1">
        <span className="text-text-secondary">Session before it:</span>
        {before.length === 0 ? <span className="text-text-secondary">nothing read or sent yet</span>
          : before.map(([l, src]) => (
            <span key={l} className="inline-flex items-center gap-1">
              <LabelChip label={l} /><span className="text-text-secondary">from {src.tool} (call {src.call})</span>
            </span>
          ))}
      </div>
      {f.call_labels.map((l) => f.label_reasons[l] && (
        <div key={l} className="text-text-secondary">{LABEL_TEXT[l] || l}: {f.label_reasons[l]}</div>
      ))}
    </div>
  )
}
