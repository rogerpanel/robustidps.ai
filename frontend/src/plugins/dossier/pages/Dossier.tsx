import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { FileCheck2, Printer, Loader2 } from 'lucide-react'
import { generateDossier } from '../api'
import type { Dossier, Vertical, Audience } from '../api'

const VERTICAL_OPTIONS: { id: Vertical; label: string }[] = [
  { id: 'uav', label: 'UAV / Aerial Defense' },
  { id: 'agent_studio', label: 'Agent Studio + Security' },
]

const AUDIENCE_OPTIONS: { id: Audience; label: string }[] = [
  { id: 'auditor', label: 'Auditor' },
  { id: 'operator', label: 'Operator' },
  { id: 'investor', label: 'Investor' },
]

export default function DossierPage() {
  const [params, setParams] = useSearchParams()
  const initialVertical = (params.get('vertical') as Vertical) || 'uav'
  const initialAudience = (params.get('audience') as Audience) || 'auditor'
  const [vertical, setVertical] = useState<Vertical>(initialVertical)
  const [audience, setAudience] = useState<Audience>(initialAudience)
  const [dossier, setDossier] = useState<Dossier | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    setLoading(true); setErr(null); setDossier(null)
    generateDossier(vertical, audience)
      .then((d) => { setDossier(d); setParams({ vertical, audience }, { replace: true }) })
      .catch((e) => setErr(String(e)))
      .finally(() => setLoading(false))
  }, [vertical, audience, setParams])

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-3 no-print">
        <div>
          <h1 className="text-xl font-display font-bold flex items-center gap-2">
            <FileCheck2 className="w-5 h-5 text-accent-blue" /> Assurance Dossier
          </h1>
          <p className="text-xs text-text-secondary mt-1 max-w-3xl">
            Canonical assurance pack — Lipschitz / RS / PAC-Bayes / DP certificates, attack coverage,
            industry position, regulatory mapping, and reproducibility. Switch the theme to <em>Print</em>
            (sidebar footer) and hit Cmd/Ctrl+P to drop a paper-ready PDF straight into your evidence
            folder. No server-side PDF dependency.
          </p>
        </div>
        <div className="flex flex-col gap-1.5 text-[10px] font-mono">
          <div className="flex gap-1">
            {VERTICAL_OPTIONS.map((v) => (
              <button key={v.id} onClick={() => setVertical(v.id)}
                      className={`px-2 py-1 rounded ${vertical === v.id ? 'bg-accent-blue text-white' : 'bg-bg-secondary text-text-secondary hover:text-text-primary'}`}>
                {v.label}
              </button>
            ))}
          </div>
          <div className="flex gap-1">
            {AUDIENCE_OPTIONS.map((a) => (
              <button key={a.id} onClick={() => setAudience(a.id)}
                      className={`px-2 py-1 rounded ${audience === a.id ? 'bg-accent-orange text-white' : 'bg-bg-secondary text-text-secondary hover:text-text-primary'}`}>
                {a.label}
              </button>
            ))}
          </div>
          <button onClick={() => window.print()}
                  className="px-2 py-1 rounded bg-accent-blue text-white flex items-center gap-1 mt-1">
            <Printer className="w-3 h-3" /> Print to PDF
          </button>
        </div>
      </div>

      {loading && <div className="text-text-secondary text-sm flex items-center gap-2"><Loader2 className="w-4 h-4 animate-spin" />Assembling dossier…</div>}
      {err && <div className="p-3 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red">{err}</div>}
      {dossier && <DossierBody dossier={dossier} />}
    </div>
  )
}

function DossierBody({ dossier }: { dossier: Dossier }) {
  return (
    <article className="bg-bg-card rounded-xl p-6 space-y-6 print-card-accent">
      <header className="border-b border-bg-card/50 pb-3">
        <div className="flex justify-between text-[10px] font-mono text-text-secondary">
          <span>Dossier ID · {dossier.dossier_id}</span>
          <span>commit {dossier.commit}</span>
          <span>{dossier.generated_at}</span>
        </div>
        <h2 className="text-2xl font-display font-bold mt-2">{dossier.vertical_label} — Assurance Dossier</h2>
        <p className="text-sm text-text-secondary mt-1 capitalize">Audience: {dossier.audience}</p>
      </header>

      <Section title="1 · Subject" body={dossier.subject} />
      {dossier.operational_headline && (
        <Section title="2 · Operational headline" body={dossier.operational_headline} />
      )}
      {dossier.certificates && (
        <Section title="3 · Certificates" body={dossier.certificates} />
      )}
      <Section title="4 · Attack coverage" body={dossier.attack_coverage} />
      {dossier.industry_position && (
        <Section title="5 · Industry position" body={dossier.industry_position} />
      )}
      <section>
        <h3 className="text-sm font-semibold mb-2 text-accent-blue">6 · Regulatory mapping</h3>
        <table className="w-full text-xs">
          <thead className="text-text-secondary text-[10px] uppercase border-b border-bg-card/50">
            <tr>
              <th className="text-left py-1 pr-2">Jurisdiction</th>
              <th className="text-left py-1 pr-2">Instrument</th>
              <th className="text-left py-1 pr-2">Requirement</th>
              <th className="text-left py-1 pr-2">Satisfied by</th>
              <th className="text-left py-1">Evidence</th>
            </tr>
          </thead>
          <tbody>
            {(dossier.regulatory_mapping as any[]).map((r, i) => (
              <tr key={i} className="border-b border-bg-card/30 last:border-0">
                <td className="py-1.5 pr-2 font-mono text-[10px]">{r.jurisdiction}</td>
                <td className="py-1.5 pr-2 font-semibold">{r.instrument}</td>
                <td className="py-1.5 pr-2">{r.requirement}</td>
                <td className="py-1.5 pr-2 font-mono text-[10px]">{(r.satisfied_by || []).join(', ')}</td>
                <td className="py-1.5 text-[11px] italic text-text-secondary">{r.evidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <Section title="7 · Reproducibility" body={dossier.reproducibility} />
      {dossier.scan_report && (
        <Section title="8 · Scan evidence" body={dossier.scan_report} />
      )}

      <footer className="border-t border-bg-card/50 pt-3 text-[10px] text-text-secondary font-mono">
        Generated by RobustIDPS.ai assurance-dossier generator v1 · plugin path {String(dossier.subject?.plugin_path || 'n/a')}
      </footer>
    </article>
  )
}

function Section({ title, body }: { title: string; body: Record<string, unknown> }) {
  return (
    <section>
      <h3 className="text-sm font-semibold mb-2 text-accent-blue">{title}</h3>
      <KeyValue data={body} />
    </section>
  )
}

function KeyValue({ data, depth = 0 }: { data: unknown; depth?: number }) {
  if (data === null || data === undefined) return <span className="text-text-secondary italic">—</span>
  if (typeof data === 'string' || typeof data === 'number' || typeof data === 'boolean') {
    return <span className="font-mono text-xs">{String(data)}</span>
  }
  if (Array.isArray(data)) {
    if (data.length === 0) return <span className="text-text-secondary italic">[]</span>
    const allScalars = data.every((d) => typeof d !== 'object' || d === null)
    if (allScalars) {
      return (
        <div className="flex flex-wrap gap-1">
          {data.map((d, i) => (
            <span key={i} className="font-mono text-[10px] bg-bg-secondary/60 px-1.5 py-0.5 rounded">{String(d)}</span>
          ))}
        </div>
      )
    }
    return (
      <ul className="space-y-1 list-disc list-inside text-xs">
        {data.map((d, i) => <li key={i}><KeyValue data={d} depth={depth + 1} /></li>)}
      </ul>
    )
  }
  const entries = Object.entries(data as Record<string, unknown>)
  return (
    <dl className={`grid grid-cols-[max-content,1fr] gap-x-3 gap-y-1 text-xs ${depth > 0 ? 'pl-3 border-l border-bg-card/40' : ''}`}>
      {entries.map(([k, v]) => (
        <>
          <dt key={`${k}-k`} className="text-text-secondary font-mono text-[11px]">{k}</dt>
          <dd key={`${k}-v`}><KeyValue data={v} depth={depth + 1} /></dd>
        </>
      ))}
    </dl>
  )
}
