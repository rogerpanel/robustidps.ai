import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ShieldCheck, FileSearch, FileCheck2, ArrowRight,
  CheckCircle2, Lock, Sparkles,
} from 'lucide-react'

interface SKU { id: string; name: string; price_usd: string; duration: string; summary: string }
interface TierDetail {
  name: 'community' | 'pro' | 'enterprise'
  display: string
  price_usd_per_month: number | null
  seats: number | string
  features: string[]
}

const API = import.meta.env.VITE_API_URL || ''

export default function AgentStudioPortal() {
  const [skus, setSkus] = useState<SKU[]>([])
  const [tiers, setTiers] = useState<TierDetail[]>([])
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    Promise.all([
      fetch(`${API}/api/agent-studio/sku-catalog`).then((r) => r.json()),
      fetch(`${API}/api/agent-studio/entitlement/tiers`).then((r) => r.json()),
    ])
      .then(([s, t]) => { setSkus(s.skus || []); setTiers(t.tiers || []) })
      .catch((e) => setErr(String(e)))
  }, [])

  return (
    <div className="space-y-6">
      <section className="text-center py-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-accent-blue/10 text-accent-blue text-xs font-mono mb-3">
          <Sparkles className="w-3 h-3" /> Agent Studio + Agent Security
        </div>
        <h1 className="text-3xl md:text-4xl font-display font-bold max-w-3xl mx-auto">
          We build your AI agents <span className="text-accent-blue">and</span> we secure them.
        </h1>
        <p className="text-sm text-text-secondary mt-3 max-w-2xl mx-auto">
          The first studio where every agent ships with a machine-verifiable adversarial-robustness
          dossier — and every red-team engagement converts into a hardened re-build.
        </p>
        <div className="mt-5 flex flex-wrap gap-2 justify-center">
          <Link to="/agent-scanner"
                className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-accent-blue text-white text-sm font-medium hover:bg-accent-blue/90">
            <FileSearch className="w-4 h-4" /> Run the free scanner
          </Link>
          <Link to="/dossier?vertical=agent_studio"
                className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-bg-card border border-bg-card text-sm hover:bg-bg-secondary/60">
            <FileCheck2 className="w-4 h-4" /> See a sample dossier
          </Link>
        </div>
      </section>

      {err && (
        <div className="p-3 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red">
          {err}
        </div>
      )}

      <section className="bg-bg-card rounded-xl p-5">
        <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-accent-orange" /> The five-SKU catalog
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3">
          {skus.map((s) => (
            <div key={s.id} className="border border-bg-card/40 rounded-md p-3">
              <div className="text-sm font-semibold text-accent-blue mb-0.5">{s.name}</div>
              <div className="text-[10px] font-mono text-text-secondary mb-2">
                ${s.price_usd} · {s.duration}
              </div>
              <div className="text-[11px] text-text-secondary">{s.summary}</div>
            </div>
          ))}
        </div>
      </section>

      <section>
        <h2 className="text-lg font-semibold mb-3">SaaS tiers</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {tiers.map((t) => (
            <div key={t.name}
                 className={`bg-bg-card rounded-xl p-5 border-t-2 ${
                   t.name === 'pro' ? 'border-accent-orange' :
                   t.name === 'enterprise' ? 'border-accent-blue' : 'border-bg-card/30'
                 }`}>
              <div className="text-xs font-mono text-text-secondary uppercase">{t.display}</div>
              <div className="mt-1 text-2xl font-display font-bold">
                {t.price_usd_per_month === 0 ? 'Free' :
                 t.price_usd_per_month === null ? 'Contact' :
                 `$${t.price_usd_per_month}`}
                {t.price_usd_per_month ? (
                  <span className="text-xs text-text-secondary font-mono ml-1">/mo</span>
                ) : null}
              </div>
              <div className="text-[10px] text-text-secondary font-mono mt-0.5">
                {typeof t.seats === 'number' ? `${t.seats} seat${t.seats > 1 ? 's' : ''}` : t.seats}
              </div>
              <ul className="mt-4 space-y-1.5">
                {t.features.map((f) => (
                  <li key={f} className="flex items-start gap-1.5 text-xs">
                    <CheckCircle2 className="w-3 h-3 mt-0.5 text-accent-green flex-shrink-0" />
                    <span className="font-mono text-[10px]">{f}</span>
                  </li>
                ))}
              </ul>
              <button
                className={`mt-4 w-full py-2 rounded-md text-xs font-medium ${
                  t.name === 'community' ? 'bg-bg-secondary text-text-secondary'
                  : 'bg-accent-blue text-white hover:bg-accent-blue/90'
                }`}
                disabled={t.name === 'community'}
              >
                {t.name === 'community' ? 'Current — free forever' : `Subscribe to ${t.display}`}
                {t.name !== 'community' && <ArrowRight className="inline w-3 h-3 ml-1" />}
              </button>
            </div>
          ))}
        </div>
        <p className="text-[10px] text-text-secondary mt-2 text-center flex items-center justify-center gap-1.5">
          <Lock className="w-3 h-3" /> Subscriptions go live once Stripe is funded.
          Webhook receiver is already deployed at <span className="font-mono">/api/agent-studio/billing/webhook</span>.
        </p>
      </section>
    </div>
  )
}
