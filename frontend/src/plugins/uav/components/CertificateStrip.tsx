import type { CertificateResponse } from '../api'

interface Props { cert: CertificateResponse }

interface Pill { label: string; value: string; tone: 'blue' | 'orange' | 'green' | 'purple' }

export default function CertificateStrip({ cert }: Props) {
  const pills: Pill[] = [
    { label: 'Lipschitz L_g',          value: cert.lipschitz_L_g.toFixed(3),         tone: 'blue' },
    { label: 'Grönwall radius',        value: cert.gronwall_radius.toFixed(3),       tone: 'blue' },
    { label: `RS l₂ radius (σ=${cert.rs_sigma})`, value: cert.rs_certified_radius.toFixed(3), tone: 'orange' },
    { label: 'PAC-Bayes bound',        value: cert.pac_bayes_bound.toFixed(3),       tone: 'green' },
    { label: 'DP (ε, δ)',              value: `${cert.dp_epsilon}, ${cert.dp_delta.toExponential(0)}`, tone: 'purple' },
  ]
  const toneClasses: Record<Pill['tone'], string> = {
    blue:   'bg-accent-blue/10   text-accent-blue   border-accent-blue/30',
    orange: 'bg-accent-orange/10 text-accent-orange border-accent-orange/30',
    green:  'bg-accent-green/10  text-accent-green  border-accent-green/30',
    purple: 'bg-accent-purple/10 text-accent-purple border-accent-purple/30',
  }
  return (
    <div className="flex flex-wrap gap-2">
      {pills.map((p) => (
        <div key={p.label}
             className={`px-3 py-1.5 rounded-md border text-xs font-mono ${toneClasses[p.tone]}`}>
          <span className="opacity-70 mr-2">{p.label}</span>
          <span className="font-semibold">{p.value}</span>
        </div>
      ))}
    </div>
  )
}
