import { useEffect, useState } from 'react'
import { ShieldCheck, RefreshCw, FileCheck2 } from 'lucide-react'
import CertificateStrip from '../components/CertificateStrip'
import { fetchCertificates, fetchIndustry, fetchRegulatory } from '../api'
import type { CertificateResponse, IndustryResponse, RegulatoryEntry } from '../api'

export default function CertificationDashboard() {
  const [cert, setCert] = useState<CertificateResponse | null>(null)
  const [industry, setIndustry] = useState<IndustryResponse | null>(null)
  const [regs, setRegs] = useState<RegulatoryEntry[]>([])
  const [err, setErr] = useState<string | null>(null)
  const reload = () => Promise.all([fetchCertificates(), fetchIndustry(), fetchRegulatory()])
    .then(([c, i, r]) => { setCert(c); setIndustry(i); setRegs(r.entries) })
    .catch((e) => setErr(String(e)))
  useEffect(() => { reload() }, [])

  if (err) return <div className="p-4 text-xs text-accent-red">{err}</div>
  if (!cert || !industry) return <div className="p-4 text-text-secondary text-sm">Loading…</div>

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-display font-bold flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-accent-blue" /> Certification Dashboard
          </h1>
          <p className="text-xs text-text-secondary mt-1">
            Chapter 6 §6.6 certificates — Lipschitz–Grönwall (Theorem 6.1), randomized smoothing (Cohen),
            PAC-Bayes (Theorem 6.3), multiplicative-weights regret (Theorem 6.4) — plus regulatory mapping.
          </p>
        </div>
        <button onClick={reload} className="text-xs flex items-center gap-1 text-accent-blue hover:text-accent-orange">
          <RefreshCw className="w-3.5 h-3.5" /> Re-measure
        </button>
      </div>

      <div className="bg-bg-card rounded-xl p-4">
        <h2 className="text-sm font-semibold mb-2">Live certificates</h2>
        <CertificateStrip cert={cert} />
        <div className="mt-3 grid grid-cols-2 md:grid-cols-4 gap-2 text-[10px] font-mono">
          <Pill label="RS samples" value={String(cert.rs_samples)} />
          <Pill label="RS α" value={cert.rs_alpha.toExponential(0)} />
          <Pill label="horizon T" value={cert.horizon_T.toFixed(2)} />
          <Pill label="ε_out target" value={cert.epsilon_out.toFixed(2)} />
        </div>
        <p className="text-[10px] text-text-secondary mt-3 italic">
          Operational reading — certificates hold the {cert.operational_interpretation.regulatory_floor_label}
          {' '}MCR floor of {cert.operational_interpretation.regulatory_floor_mcr} at J/S ≤ {cert.operational_interpretation.js_db_floor} dB.
        </p>
      </div>

      <div className="bg-bg-card rounded-xl p-4">
        <h2 className="text-sm font-semibold mb-2">Industry comparison — chapter 6 Table 6.x</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-text-secondary text-[10px] uppercase tracking-wider border-b border-bg-card/50">
                <th className="text-left py-2 pr-2">Criterion</th>
                {industry.vendors.map((v) => (
                  <th key={v} className={`text-center px-2 ${v.includes('RobustIDPS') ? 'text-accent-orange' : ''}`}>
                    {v}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {industry.criteria.map((row) => (
                <tr key={row.id} className="border-b border-bg-card/30 last:border-0">
                  <td className="py-1.5 pr-2 text-text-primary">{row.label}</td>
                  {row.scores.map((s, i) => (
                    <td key={i} className="text-center px-2 font-mono">
                      <ScoreCell value={s} highlight={industry.vendors[i].includes('RobustIDPS')} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="bg-bg-card rounded-xl p-4">
        <h2 className="text-sm font-semibold mb-2 flex items-center gap-1.5">
          <FileCheck2 className="w-3.5 h-3.5 text-accent-blue" /> Regulatory evidence pack
        </h2>
        <div className="space-y-2">
          {regs.map((r) => (
            <div key={r.instrument} className="border border-bg-card/50 rounded-md p-2.5">
              <div className="flex items-center gap-2 mb-1">
                <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded ${
                  r.jurisdiction === 'RU' ? 'bg-accent-red/10 text-accent-red' : 'bg-accent-blue/10 text-accent-blue'
                }`}>{r.jurisdiction}</span>
                <span className="text-xs font-semibold">{r.instrument}</span>
              </div>
              <div className="text-[11px] text-text-secondary">{r.requirement}</div>
              <div className="text-[10px] text-text-secondary mt-1 font-mono">
                satisfied by: {r.satisfied_by.join(', ')}
              </div>
              <div className="text-[10px] text-accent-blue mt-0.5 italic">{r.evidence}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function Pill({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-bg-secondary/60 border border-bg-card/50 rounded px-2 py-1">
      <span className="text-text-secondary mr-1">{label}</span>
      <span className="text-text-primary font-semibold">{value}</span>
    </div>
  )
}

function ScoreCell({ value, highlight }: { value: string; highlight: boolean }) {
  if (value === 'full') return <span className={highlight ? 'text-accent-orange' : 'text-accent-green'}>✓</span>
  if (value === 'partial') return <span className="text-accent-amber">+</span>
  return <span className="text-text-secondary">—</span>
}
