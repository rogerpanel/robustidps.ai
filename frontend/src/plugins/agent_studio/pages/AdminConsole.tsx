import { useEffect, useState } from 'react'
import {
  ShieldCheck, KeyRound, AlertCircle, CheckCircle2, Loader2, Copy,
  Plus, Trash2, RefreshCw, LogOut, Building2,
} from 'lucide-react'
import PageGuide from '../../../components/PageGuide'
import {
  adminWhoami, adminCreateGrant, adminListGrants, adminRevokeGrant,
  adminListCustomers, getStoredAdminToken, setStoredAdminToken,
} from '../api'
import type { AdminGrant, AdminGrantStats, Customer } from '../api'

const PAYMENT_RAILS: { id: string; label: string }[] = [
  { id: 'wire', label: 'Bank wire (SWIFT / SEPA)' },
  { id: 'crypto', label: 'Crypto (BTC / USDT / etc.)' },
  { id: 'yoomoney', label: 'YooMoney (RU)' },
  { id: 'qiwi', label: 'QIWI (RU)' },
  { id: 'sbp', label: 'SBP / Faster Payments (RU)' },
  { id: 'bank_card_offshore', label: 'Bank card (offshore)' },
  { id: 'comp', label: 'Complimentary (no charge)' },
  { id: 'sponsorship', label: 'Sponsored / academic' },
  { id: 'other', label: 'Other (see note)' },
]

export default function AdminConsole() {
  const [token, setToken] = useState(getStoredAdminToken() || '')
  const [authed, setAuthed] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  // Grants
  const [grants, setGrants] = useState<AdminGrant[]>([])
  const [stats, setStats] = useState<AdminGrantStats | null>(null)
  const [includeRevoked, setIncludeRevoked] = useState(true)
  const [customers, setCustomers] = useState<Customer[]>([])

  // New-grant form
  const [email, setEmail] = useState('')
  const [tier, setTier] = useState<'pro' | 'enterprise'>('pro')
  const [months, setMonths] = useState(12)
  const [rail, setRail] = useState('comp')
  const [note, setNote] = useState('')
  const [grantedBy, setGrantedBy] = useState('admin')
  const [issued, setIssued] = useState<{
    grant_id: string; customer_id: string; api_key: string
    email: string; tier: string; expires_at: string | null
    welcome_message: string
  } | null>(null)

  const authenticate = async () => {
    setErr(null); setBusy(true)
    try {
      setStoredAdminToken(token || null)
      await adminWhoami()
      setAuthed(true)
      await reload()
    } catch (e) {
      setErr(String(e))
      setAuthed(false)
    } finally { setBusy(false) }
  }

  const reload = async () => {
    setErr(null)
    try {
      const g = await adminListGrants(includeRevoked)
      setGrants(g.grants); setStats(g.stats)
      const c = await adminListCustomers()
      setCustomers(c.customers)
    } catch (e) { setErr(String(e)) }
  }

  const logout = () => {
    setStoredAdminToken(null); setToken(''); setAuthed(false)
    setGrants([]); setCustomers([]); setStats(null); setIssued(null)
  }

  const createGrant = async () => {
    setErr(null); setBusy(true); setIssued(null)
    try {
      const r = await adminCreateGrant({
        email, tier, months, payment_rail: rail,
        note: note || undefined, granted_by: grantedBy,
      })
      setIssued(r)
      setEmail(''); setNote('')
      await reload()
    } catch (e) {
      setErr(String(e))
    } finally { setBusy(false) }
  }

  const revoke = async (grant_id: string) => {
    if (!confirm(`Revoke ${grant_id}? All API keys for this customer will be invalidated.`)) return
    setBusy(true); setErr(null)
    try {
      await adminRevokeGrant(grant_id)
      await reload()
    } catch (e) { setErr(String(e)) } finally { setBusy(false) }
  }

  useEffect(() => {
    if (token) authenticate().catch(() => {})
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => { if (authed) reload().catch(() => {}) }, [includeRevoked, authed])

  // ── Login screen ─────────────────────────────────────────────────────
  if (!authed) {
    return (
      <div className="space-y-6 max-w-md mx-auto">
        <section className="text-center py-4">
          <h1 className="text-2xl font-display font-bold inline-flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-accent-red" /> Admin Console
          </h1>
          <p className="text-xs text-text-secondary mt-2">
            Side-channel licensing for users who can't (or won't) pay via Stripe.
          </p>
        </section>

        <div className="bg-bg-card rounded-xl p-5 space-y-3">
          <label className="block text-xs font-mono text-text-secondary">
            ROBUSTIDPS_ADMIN_TOKEN
          </label>
          <input
            type="password" value={token} onChange={(e) => setToken(e.target.value)}
            placeholder="paste admin token"
            className="w-full px-3 py-2 rounded-md bg-bg-secondary border border-bg-card/40 text-sm font-mono"
          />
          <button onClick={authenticate} disabled={busy || !token}
                  className="w-full py-2 rounded-md bg-accent-red text-white text-sm font-medium hover:bg-accent-red/90 disabled:opacity-50 inline-flex items-center justify-center gap-1.5">
            {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
            Authenticate
          </button>
          {err && (
            <div className="p-2 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red inline-flex items-center gap-1.5">
              <AlertCircle className="w-3 h-3" /> {err}
            </div>
          )}
          <p className="text-[10px] font-mono text-text-secondary">
            Set <code>ROBUSTIDPS_ADMIN_TOKEN</code> on the backend (env var) before this page works.
          </p>
        </div>
      </div>
    )
  }

  // ── Authenticated ────────────────────────────────────────────────────
  return (
    <div className="space-y-6">
      <section className="flex items-end justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-2xl font-display font-bold inline-flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-accent-red" /> Admin Console
          </h1>
          <p className="text-xs text-text-secondary mt-1">
            Issue licences via wire / crypto / YooMoney / QIWI / SBP / sponsorship —
            no Stripe touch. Each grant creates a customer + initial API key.
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={reload} className="px-2 py-1.5 rounded bg-bg-card border border-bg-card/40 text-xs inline-flex items-center gap-1">
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
          <button onClick={logout} className="px-2 py-1.5 rounded bg-bg-card border border-bg-card/40 text-xs inline-flex items-center gap-1">
            <LogOut className="w-3 h-3" /> Clear token
          </button>
        </div>
      </section>

      <PageGuide
        title="When to grant a licence here"
        steps={[
          { title: 'Sanctioned regions', desc: 'Stripe / most western processors do not operate in Russia, Crimea, Iran, North Korea, parts of Syria. Use the matching payment_rail (yoomoney / qiwi / sbp / crypto / wire).' },
          { title: 'Enterprise wire', desc: 'Enterprise tier prepaid by bank wire — rail=wire, months=12, note=PO number.' },
          { title: 'Sponsorships / academic', desc: 'rail=sponsorship or comp; months=0 = perpetual (use sparingly).' },
          { title: 'Send the API key', desc: 'Plaintext key is shown ONCE on this page. Send it to the customer over the same out-of-band channel they used to pay.' },
        ]}
        tip="Every grant is logged to weights/agent_studio_admin_grants.json with rail + note for audit."
      />

      {stats && (
        <section className="grid grid-cols-2 md:grid-cols-5 gap-2">
          <Stat label="active grants" value={String(stats.n_active)} tone="green" />
          <Stat label="revoked" value={String(stats.n_revoked)} tone="dim" />
          <Stat label="customers" value={String(customers.length)} />
          <Stat label="by tier"
                value={Object.entries(stats.by_tier).map(([k,v]) => `${k}:${v}`).join(' ') || '—'} />
          <Stat label="top rail"
                value={Object.entries(stats.by_payment_rail).sort((a,b) => b[1]-a[1])[0]?.join('=') || '—'} />
        </section>
      )}

      <section className="bg-bg-card rounded-xl p-5 space-y-3">
        <h2 className="text-sm font-semibold inline-flex items-center gap-1.5">
          <Plus className="w-4 h-4 text-accent-green" /> Issue new grant
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <Field label="Email">
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)}
                   className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs" />
          </Field>
          <Field label="Tier">
            <select value={tier} onChange={(e) => setTier(e.target.value as 'pro' | 'enterprise')}
                    className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs">
              <option value="pro">Pro</option>
              <option value="enterprise">Enterprise</option>
            </select>
          </Field>
          <Field label="Months (0 = perpetual)">
            <input type="number" value={months} min={0} max={120}
                   onChange={(e) => setMonths(Math.max(0, parseInt(e.target.value || '0', 10)))}
                   className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs" />
          </Field>
          <Field label="Payment rail">
            <select value={rail} onChange={(e) => setRail(e.target.value)}
                    className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs">
              {PAYMENT_RAILS.map((r) => (
                <option key={r.id} value={r.id}>{r.label}</option>
              ))}
            </select>
          </Field>
          <Field label="Note (PO / wire ref / crypto tx)" full>
            <input type="text" value={note} onChange={(e) => setNote(e.target.value)}
                   placeholder="PO-1234 · wire 2026-06-22 EUR 3,588 · trial complete"
                   className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs" />
          </Field>
          <Field label="Granted by (your handle)" full>
            <input type="text" value={grantedBy} onChange={(e) => setGrantedBy(e.target.value)}
                   className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs" />
          </Field>
        </div>
        <button onClick={createGrant} disabled={busy || !email}
                className="w-full py-2 rounded-md bg-accent-green text-white text-sm font-medium hover:bg-accent-green/90 disabled:opacity-50 inline-flex items-center justify-center gap-1.5">
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <KeyRound className="w-3.5 h-3.5" />}
          Issue grant + initial API key
        </button>

        {issued && (
          <div className="p-3 bg-accent-green/10 border border-accent-green/30 rounded-md space-y-2">
            <div className="text-xs font-semibold text-accent-green inline-flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" /> {issued.welcome_message}
            </div>
            <div className="text-[10px] font-mono text-text-secondary">
              grant_id={issued.grant_id} · customer_id={issued.customer_id} · tier={issued.tier}
              {issued.expires_at && <> · expires {issued.expires_at}</>}
            </div>
            <div className="px-2 py-1.5 rounded bg-bg-secondary border border-accent-green/30 text-xs font-mono break-all flex items-center justify-between gap-2">
              <span>{issued.api_key}</span>
              <button onClick={() => navigator.clipboard?.writeText(issued.api_key)}
                      className="p-1 hover:text-accent-blue"><Copy className="w-3 h-3" /></button>
            </div>
            <div className="text-[10px] font-mono text-accent-amber">
              Send this key to the customer over the same channel they paid. It cannot be shown again.
            </div>
          </div>
        )}
      </section>

      <section className="bg-bg-card rounded-xl p-5">
        <div className="flex items-end justify-between gap-3 mb-3">
          <h2 className="text-sm font-semibold inline-flex items-center gap-1.5">
            <Building2 className="w-4 h-4 text-accent-blue" /> Grants
          </h2>
          <label className="text-[10px] font-mono text-text-secondary inline-flex items-center gap-1">
            <input type="checkbox" checked={includeRevoked}
                   onChange={(e) => setIncludeRevoked(e.target.checked)} />
            include revoked
          </label>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-[11px] font-mono">
            <thead className="text-text-secondary uppercase text-[10px]">
              <tr className="text-left">
                <th className="pb-1.5">grant_id</th>
                <th>email</th>
                <th>tier</th>
                <th>rail</th>
                <th>months</th>
                <th>granted</th>
                <th>expires</th>
                <th>note</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {grants.length === 0 && (
                <tr><td colSpan={9} className="py-3 text-center text-text-secondary italic">No grants yet.</td></tr>
              )}
              {grants.map((g) => (
                <tr key={g.grant_id} className={`border-t border-bg-card/30 ${g.revoked_at ? 'opacity-50' : ''}`}>
                  <td className="py-1.5">{g.grant_id}</td>
                  <td>{g.email}</td>
                  <td><span className="text-accent-blue">{g.tier}</span></td>
                  <td>{g.payment_rail}</td>
                  <td>{g.months || '∞'}</td>
                  <td>{g.granted_at.slice(0, 10)}</td>
                  <td>{g.expires_at || '—'}</td>
                  <td className="max-w-[180px] truncate" title={g.note}>{g.note || '—'}</td>
                  <td>
                    {g.revoked_at ? (
                      <span className="text-accent-red text-[10px]">revoked</span>
                    ) : (
                      <button onClick={() => revoke(g.grant_id)}
                              className="p-1 rounded hover:bg-accent-red/10 text-accent-red"
                              title="Revoke">
                        <Trash2 className="w-3 h-3" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="bg-bg-card rounded-xl p-5">
        <h2 className="text-sm font-semibold inline-flex items-center gap-1.5 mb-3">
          <KeyRound className="w-4 h-4 text-accent-orange" /> Customer directory
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-[11px] font-mono">
            <thead className="text-text-secondary uppercase text-[10px]">
              <tr className="text-left">
                <th className="pb-1.5">customer_id</th>
                <th>email</th>
                <th>tier</th>
                <th>created</th>
                <th>trial ends</th>
                <th>keys</th>
              </tr>
            </thead>
            <tbody>
              {customers.length === 0 && (
                <tr><td colSpan={6} className="py-3 text-center text-text-secondary italic">No customers yet.</td></tr>
              )}
              {customers.map((c) => (
                <tr key={c.customer_id} className="border-t border-bg-card/30">
                  <td className="py-1.5">{c.customer_id}</td>
                  <td>{c.email}</td>
                  <td><span className="text-accent-blue">{c.tier}</span></td>
                  <td>{c.created_at.slice(0, 10)}</td>
                  <td>{c.trial_ends_at || '—'}</td>
                  <td>
                    {c.api_keys.length} ({c.api_keys.filter((k) => !k.revoked).length} active)
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {err && (
        <div className="p-3 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red inline-flex items-center gap-1.5">
          <AlertCircle className="w-3 h-3" /> {err}
        </div>
      )}
    </div>
  )
}

function Field({ label, children, full }: { label: string; children: React.ReactNode; full?: boolean }) {
  return (
    <div className={full ? 'md:col-span-2' : ''}>
      <label className="block text-[10px] font-mono text-text-secondary mb-1">{label}</label>
      {children}
    </div>
  )
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: 'green' | 'dim' }) {
  const cls = tone === 'green' ? 'text-accent-green' : tone === 'dim' ? 'text-text-secondary' : 'text-text-primary'
  return (
    <div className="bg-bg-card border border-bg-card/40 rounded p-2">
      <div className="text-[9px] font-mono uppercase text-text-secondary">{label}</div>
      <div className={`text-sm font-mono font-semibold ${cls} truncate`}>{value}</div>
    </div>
  )
}
