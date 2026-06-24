import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ShieldCheck, FileSearch, FileCheck2, ArrowRight,
  CheckCircle2, Lock, Sparkles, Loader2,
} from 'lucide-react'
import PageGuide from '../../../components/PageGuide'
import { createCheckout, fetchActivity, getStoredApiKey } from '../api'
import type { ActivityRollup } from '../api'
import { useAgentStudioState } from '../../../hooks/useAgentStudioState'
import AccessBanner from '../components/AccessBanner'

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
  const [email, setEmail] = useAgentStudioState<string>('portal', 'email', '')
  const [pending, setPending] = useState<'pro' | 'enterprise' | null>(null)
  const [stagingNote, setStagingNote] = useState<string | null>(null)
  const [activity, setActivity] = useAgentStudioState<ActivityRollup | null>('portal', 'activity', null)

  useEffect(() => {
    Promise.all([
      fetch(`${API}/api/agent-studio/sku-catalog`).then((r) => r.json()),
      fetch(`${API}/api/agent-studio/entitlement/tiers`).then((r) => r.json()),
    ])
      .then(([s, t]) => { setSkus(s.skus || []); setTiers(t.tiers || []) })
      .catch((e) => setErr(String(e)))

    if (getStoredApiKey()) {
      fetchActivity(3).then(setActivity).catch(() => { /* unauthed → leave blank */ })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const subscribe = async (tier: 'pro' | 'enterprise') => {
    setErr(null)
    setStagingNote(null)
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setErr('Enter a valid work email above before subscribing.')
      return
    }
    setPending(tier)
    try {
      const sess = await createCheckout(email, tier, 14)
      if (sess.mode === 'error') {
        setErr(sess.error || 'Checkout failed.')
      } else if (sess.url) {
        if (sess.mode === 'staging') {
          setStagingNote(
            `Staging mode — Stripe is not funded. You'll be redirected to the account ` +
            `console with a synthetic session_id; no card will be charged.`,
          )
          setTimeout(() => { window.location.href = sess.url! }, 1200)
        } else {
          window.location.href = sess.url
        }
      }
    } catch (e) {
      setErr(String(e))
    } finally {
      setPending(null)
    }
  }

  return (
    <div className="space-y-6">
      <AccessBanner />
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
          <Link to="/agent-studio/quickstart"
                className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-accent-blue text-white text-sm font-medium hover:bg-accent-blue/90">
            <Sparkles className="w-4 h-4" /> Browse 13 agent templates
          </Link>
          <Link to="/agent-scanner"
                className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-bg-card border border-bg-card text-sm hover:bg-bg-secondary/60">
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

      <PageGuide
        title="How to use Agent Studio Portal"
        steps={[
          { title: 'Start with the free scanner', desc: 'Top-right CTA → 12 OWASP-Agentic + MCP-framing checks in <500 ms. The conversion wedge — every scan finding maps to a SKU.' },
          { title: 'Read the 5-SKU catalog', desc: 'Agent Lab (PoC) → Agent Factory (production) → Agent Red Team (security) → Continuous Defense (retainer) → Secure-by-Design (flywheel bundle).' },
          { title: 'Compare the 3 SaaS tiers', desc: 'Community is free forever (read-only UAV + basic scanner). Pro adds API + dossier generation. Enterprise adds air-gap, SSO/SCIM, dedicated SE.' },
          { title: 'Sample dossier', desc: 'Top-right CTA → /dossier?vertical=agent_studio — generates a paper-ready assurance pack with the venture-plan SKUs, OWASP coverage, ISO 42001 mapping.' },
          { title: 'Subscribe', desc: 'Buttons go live the moment Stripe is funded — webhook endpoint already deployed at /api/agent-studio/billing/webhook.' },
        ]}
        tip="Print theme + Cmd-P of this page = a paper-ready commercial one-pager. Useful for investor / customer hand-offs."
      />

      {activity && (
        <section className="bg-bg-card rounded-xl p-5">
          <h2 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-accent-green" /> Pick up where you left off
            <button onClick={() => fetchActivity(3).then(setActivity).catch(() => {})}
                    className="ml-auto text-[10px] font-mono text-text-secondary hover:text-accent-blue">
              refresh
            </button>
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
            <ActivityCol title="Evals" link="/agent-studio/eval" empty="no eval runs yet">
              {activity.eval_runs.slice(0, 3).map((r) => (
                <div key={r.run_id} className="font-mono text-[11px] truncate">
                  <span className={
                    r.overall_verdict === 'pass' ? 'text-accent-green' :
                    r.overall_verdict === 'warn' ? 'text-accent-amber' : 'text-accent-red'
                  }>● </span>
                  {r.agent_name} <span className="text-text-secondary">({(r.overall_score*100).toFixed(0)}%)</span>
                </div>
              ))}
            </ActivityCol>
            <ActivityCol title="Red-team" link="/agent-studio/red-team" empty="no red-team runs yet">
              {activity.red_team_runs.slice(0, 3).map((r) => (
                <div key={r.run_id} className="font-mono text-[11px] truncate">
                  <span className={r.n_findings > 0 ? 'text-accent-red' : 'text-accent-green'}>● </span>
                  {r.target_name} <span className="text-text-secondary">({r.n_findings} findings)</span>
                </div>
              ))}
            </ActivityCol>
            <ActivityCol title="Supply chain" link="/agent-studio/supply-chain" empty="no scans yet">
              {activity.supply_chain_scans.slice(0, 3).map((s) => (
                <div key={s.scan_id} className="font-mono text-[11px] truncate">
                  <span className={
                    s.risk_level === 'safe' || s.risk_level === 'low' ? 'text-accent-green' :
                    s.risk_level === 'medium' ? 'text-accent-amber' : 'text-accent-red'
                  }>● </span>
                  {s.model_id} <span className="text-text-secondary">({s.risk_level})</span>
                </div>
              ))}
            </ActivityCol>
            <ActivityCol title="Sessions" link="/agent-studio/quickstart" empty="no test sessions yet">
              {activity.sessions.slice(0, 3).map((s) => (
                <Link key={s.session_id} to={`/agent-studio/build/${s.template_id}`}
                      className="font-mono text-[11px] truncate hover:text-accent-blue block">
                  <span className={s.aborted ? 'text-accent-red' : 'text-accent-blue'}>● </span>
                  {s.template_id} <span className="text-text-secondary">({s.n_messages} msgs)</span>
                </Link>
              ))}
            </ActivityCol>
          </div>
          <p className="mt-2 text-[10px] text-text-secondary">
            The SOC Copilot can probe these directly — try
            <code className="mx-1">"show me my last red-team run"</code> or
            <code className="mx-1">"summarise agent-studio activity"</code>.
          </p>
        </section>
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

        <div className="flex flex-wrap items-center gap-2 mb-3 text-xs">
          <label className="font-mono text-text-secondary">Work email:</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@company.com"
            className="px-2 py-1.5 rounded-md bg-bg-card border border-bg-card/40 text-xs w-72"
          />
          <Link to="/agent-studio/account"
                className="text-[11px] text-accent-blue underline underline-offset-2">
            Already a customer? Open the account console →
          </Link>
        </div>

        {stagingNote && (
          <div className="p-3 mb-3 bg-accent-orange/10 border border-accent-orange/30 rounded-md text-xs text-accent-orange">
            {stagingNote}
          </div>
        )}

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
                className={`mt-4 w-full py-2 rounded-md text-xs font-medium inline-flex items-center justify-center gap-1.5 ${
                  t.name === 'community' ? 'bg-bg-secondary text-text-secondary'
                  : 'bg-accent-blue text-white hover:bg-accent-blue/90 disabled:opacity-50'
                }`}
                disabled={t.name === 'community' || pending !== null}
                onClick={() => {
                  if (t.name === 'pro' || t.name === 'enterprise') subscribe(t.name)
                }}
              >
                {t.name === 'community' ? (
                  'Current — free forever'
                ) : pending === t.name ? (
                  <><Loader2 className="w-3 h-3 animate-spin" /> Creating checkout…</>
                ) : (
                  <>Subscribe to {t.display} <ArrowRight className="w-3 h-3" /></>
                )}
              </button>
            </div>
          ))}
        </div>
        <p className="text-[10px] text-text-secondary mt-2 text-center flex items-center justify-center gap-1.5">
          <Lock className="w-3 h-3" /> Staging mode runs without charging while Stripe is funded —
          webhook receiver is deployed at <span className="font-mono">/api/agent-studio/billing/webhook</span>.
        </p>
      </section>
    </div>
  )
}

function ActivityCol({ title, link, empty, children }: {
  title: string; link: string; empty: string; children: React.ReactNode
}) {
  const arr = Array.isArray(children) ? children : [children]
  const isEmpty = arr.filter(Boolean).length === 0
  return (
    <div className="bg-bg-secondary/40 border border-bg-card/40 rounded-md p-2">
      <Link to={link} className="text-[10px] font-mono uppercase text-text-secondary hover:text-accent-blue">
        {title} →
      </Link>
      <div className="mt-1 space-y-0.5">
        {isEmpty ? (
          <div className="text-[10px] text-text-secondary italic">{empty}</div>
        ) : children}
      </div>
    </div>
  )
}
