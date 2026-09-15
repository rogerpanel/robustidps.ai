import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import {
  KeyRound, ShieldCheck, ArrowRight, Loader2, AlertCircle, CheckCircle2,
  Copy, Trash2, RefreshCw, Sparkles,
} from 'lucide-react'
import PageGuide from '../../../components/PageGuide'
import {
  completeCheckout, fetchCustomer, issueApiKey, revokeApiKey,
} from '../api'
import type { Customer, CheckoutCompleteResult } from '../api'
import { useAgentStudioState } from '../../../hooks/useAgentStudioState'
import AccessBanner from '../components/AccessBanner'

/**
 * Stripe success URL target for the Agent Studio commerce sprint.
 *
 *   /agent-studio/account?session_id=cs_...   → first-time fulfilment
 *   /agent-studio/account?customer_id=cust_…  → returning console
 */
export default function AccountConsole() {
  const [params] = useSearchParams()
  const sessionId = params.get('session_id')
  const presetCustomer = params.get('customer_id')

  const [email, setEmail] = useAgentStudioState<string>('account', 'email', '')
  const [tier, setTier] = useAgentStudioState<'pro' | 'enterprise'>('account', 'tier', 'pro')
  const [customer, setCustomer] = useAgentStudioState<Customer | null>('account', 'customer', null)
  const [welcome, setWelcome] = useState<CheckoutCompleteResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [newKeyLabel, setNewKeyLabel] = useAgentStudioState<string>('account', 'keyLabel', 'ci-token')
  const [newKey, setNewKey] = useState<{ key_id: string; api_key: string } | null>(null)
  const [lastCustomerId, setLastCustomerId] = useAgentStudioState<string | null>('account', 'lastCustomerId', null)

  const reload = async (cid?: string) => {
    if (!cid) return
    try {
      const c = await fetchCustomer(cid)
      setCustomer(c)
      setLastCustomerId(c.customer_id)
    } catch (e) {
      setErr(String(e))
    }
  }

  useEffect(() => {
    const cid = presetCustomer || lastCustomerId
    if (cid) reload(cid)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [presetCustomer])

  const fulfill = async () => {
    if (!sessionId || !email) {
      setErr('Session ID and email are required.')
      return
    }
    setBusy(true); setErr(null)
    try {
      const res = await completeCheckout(sessionId, email, tier)
      setWelcome(res)
      await reload(res.customer_id)
    } catch (e) {
      setErr(String(e))
    } finally { setBusy(false) }
  }

  const handleIssueKey = async () => {
    if (!customer) return
    setBusy(true); setErr(null)
    try {
      const res = await issueApiKey(customer.customer_id, newKeyLabel || 'unnamed')
      setNewKey({ key_id: res.key_id, api_key: res.api_key })
      await reload(customer.customer_id)
    } catch (e) {
      setErr(String(e))
    } finally { setBusy(false) }
  }

  const handleRevoke = async (key_id: string) => {
    if (!customer) return
    setBusy(true); setErr(null)
    try {
      await revokeApiKey(customer.customer_id, key_id)
      await reload(customer.customer_id)
    } catch (e) {
      setErr(String(e))
    } finally { setBusy(false) }
  }

  const copy = (text: string) => navigator.clipboard?.writeText(text)

  // ── First-time fulfilment flow ──────────────────────────────────────
  if (sessionId && !welcome && !customer) {
    return (
      <div className="space-y-6 max-w-2xl mx-auto">
      <AccessBanner />
        <section className="text-center py-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-accent-green/10 text-accent-green text-xs font-mono mb-3">
            <CheckCircle2 className="w-3 h-3" /> Checkout complete
          </div>
          <h1 className="text-2xl font-display font-bold">Activate your Agent Studio account</h1>
          <p className="text-sm text-text-secondary mt-2">
            Confirm the email + tier from your subscription so we can issue your initial API key.
          </p>
          <p className="text-[10px] font-mono text-text-secondary mt-1">
            session_id: {sessionId.slice(0, 32)}…
          </p>
        </section>

        <div className="bg-bg-card rounded-xl p-5 space-y-3">
          <label className="block text-xs font-mono text-text-secondary">Email</label>
          <input
            type="email" value={email} onChange={(e) => setEmail(e.target.value)}
            placeholder="you@company.com"
            className="w-full px-3 py-2 rounded-md bg-bg-secondary border border-bg-card/40 text-sm"
          />
          <label className="block text-xs font-mono text-text-secondary mt-3">Tier</label>
          <select
            value={tier} onChange={(e) => setTier(e.target.value as 'pro' | 'enterprise')}
            className="w-full px-3 py-2 rounded-md bg-bg-secondary border border-bg-card/40 text-sm"
          >
            <option value="pro">Pro — $299/mo</option>
            <option value="enterprise">Enterprise — contact</option>
          </select>
          <button
            disabled={busy || !email}
            onClick={fulfill}
            className="mt-3 w-full py-2 rounded-md bg-accent-blue text-white text-sm font-medium hover:bg-accent-blue/90 disabled:opacity-50 inline-flex items-center justify-center gap-1.5"
          >
            {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
            Activate & issue API key
          </button>
          {err && (
            <div className="p-2 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red inline-flex items-center gap-1.5">
              <AlertCircle className="w-3 h-3" /> {err}
            </div>
          )}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <section className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-display font-bold">Account console</h1>
          <p className="text-sm text-text-secondary mt-1">
            Manage your Agent Studio subscription, API keys, and trial state.
          </p>
        </div>
        <Link to="/agent-studio"
              className="text-xs text-accent-blue underline underline-offset-2 inline-flex items-center gap-1">
          ← Back to portal
        </Link>
      </section>

      <PageGuide
        title="What you can do here"
        steps={[
          { title: 'Save your API key', desc: 'The plaintext key is shown ONCE on issuance — only its SHA-256 hash + 14-char prefix are stored server-side.' },
          { title: 'Issue more keys', desc: 'Per-CI keys, per-environment keys, per-teammate keys. Each one is independently revokable.' },
          { title: 'Revoke a key', desc: 'Click the trash icon. Calls /api/agent-studio/api-keys/revoke. Effective immediately.' },
          { title: 'Use the key', desc: 'Add `Authorization: Bearer rids_live_…` to your requests, or pass it to MambaGuardClient(api_key=…) in the SDK.' },
        ]}
      />

      {welcome && (
        <div className="bg-accent-green/10 border border-accent-green/30 rounded-xl p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="text-sm font-semibold text-accent-green inline-flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" /> {welcome.welcome_message}
              </div>
              <div className="text-[10px] font-mono text-text-secondary mt-1">
                Save this key now — it cannot be shown again.
              </div>
              <div className="mt-2 px-3 py-2 rounded bg-bg-secondary border border-accent-green/30 text-xs font-mono break-all flex items-center justify-between gap-2">
                <span>{welcome.api_key}</span>
                <button onClick={() => copy(welcome.api_key)}
                        className="p-1 hover:text-accent-blue" title="Copy">
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {!customer && !sessionId && (
        <div className="bg-bg-card rounded-xl p-5 space-y-3">
          <label className="block text-xs font-mono text-text-secondary">Look up customer</label>
          <div className="flex gap-2">
            <input
              type="text" placeholder="cust_…"
              className="flex-1 px-3 py-2 rounded-md bg-bg-secondary border border-bg-card/40 text-sm"
              onKeyDown={(e) => {
                if (e.key === 'Enter') reload((e.target as HTMLInputElement).value)
              }}
            />
            <Link to="/agent-studio"
                  className="px-3 py-2 rounded-md bg-accent-blue text-white text-xs font-medium inline-flex items-center gap-1">
              Or subscribe <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
        </div>
      )}

      {customer && (
        <>
          <section className="bg-bg-card rounded-xl p-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <div className="text-[10px] font-mono uppercase text-text-secondary">Customer</div>
                <div className="text-lg font-semibold">{customer.email}</div>
                <div className="text-[11px] font-mono text-text-secondary mt-0.5">
                  {customer.customer_id} · tier <span className="text-accent-blue">{customer.tier}</span>
                  {customer.trial_ends_at && (
                    <> · trial ends {customer.trial_ends_at}</>
                  )}
                </div>
              </div>
              <button onClick={() => reload(customer.customer_id)}
                      className="px-2 py-1 rounded bg-bg-secondary text-xs inline-flex items-center gap-1">
                <RefreshCw className="w-3 h-3" /> Refresh
              </button>
            </div>
            <div className="text-[10px] font-mono text-text-secondary mt-3">
              stripe_customer_id: {customer.stripe_customer_id || '— (staging mode)'}<br />
              stripe_subscription_id: {customer.stripe_subscription_id || '— (staging mode)'}
            </div>
          </section>

          <section className="bg-bg-card rounded-xl p-5">
            <h2 className="text-sm font-semibold mb-3 inline-flex items-center gap-1.5">
              <KeyRound className="w-4 h-4 text-accent-orange" /> API keys
            </h2>

            <div className="flex items-end gap-2 mb-4">
              <div className="flex-1">
                <label className="block text-[10px] font-mono text-text-secondary mb-1">New key label</label>
                <input
                  type="text" value={newKeyLabel}
                  onChange={(e) => setNewKeyLabel(e.target.value)}
                  placeholder="ci-token"
                  className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs"
                />
              </div>
              <button onClick={handleIssueKey} disabled={busy}
                      className="px-3 py-1.5 rounded bg-accent-blue text-white text-xs font-medium hover:bg-accent-blue/90 disabled:opacity-50 inline-flex items-center gap-1.5">
                {busy ? <Loader2 className="w-3 h-3 animate-spin" /> : <KeyRound className="w-3 h-3" />}
                Issue key
              </button>
            </div>

            {newKey && (
              <div className="mb-3 p-3 rounded bg-accent-green/10 border border-accent-green/30">
                <div className="text-[11px] font-semibold text-accent-green mb-1">
                  New API key — saved nowhere. Copy now.
                </div>
                <div className="px-2 py-1.5 rounded bg-bg-secondary text-xs font-mono break-all flex items-center justify-between gap-2">
                  <span>{newKey.api_key}</span>
                  <button onClick={() => copy(newKey.api_key)}
                          className="p-1 hover:text-accent-blue"><Copy className="w-3 h-3" /></button>
                </div>
              </div>
            )}

            <div className="space-y-2">
              {customer.api_keys.length === 0 && (
                <div className="text-xs text-text-secondary font-mono">No keys yet.</div>
              )}
              {customer.api_keys.map((k) => (
                <div key={k.id} className={`flex items-center justify-between gap-2 px-3 py-2 rounded border ${
                  k.revoked ? 'bg-bg-secondary/50 border-bg-card/30 opacity-60' : 'bg-bg-secondary border-bg-card/40'
                }`}>
                  <div className="min-w-0">
                    <div className="text-xs font-mono truncate">
                      <span className="text-accent-blue">{k.prefix}</span> · {k.label}
                      {k.revoked && <span className="ml-2 text-accent-red">[revoked]</span>}
                    </div>
                    <div className="text-[10px] text-text-secondary font-mono">
                      created {k.created_at} · last used {k.last_used_at || 'never'}
                    </div>
                  </div>
                  {!k.revoked && (
                    <button onClick={() => handleRevoke(k.id)} disabled={busy}
                            className="p-1.5 rounded hover:bg-accent-red/10 text-accent-red disabled:opacity-50"
                            title="Revoke">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </section>

          <section className="bg-bg-card rounded-xl p-5">
            <h2 className="text-sm font-semibold mb-2 inline-flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-accent-blue" /> Next steps
            </h2>
            <ul className="text-xs space-y-1.5 text-text-secondary">
              <li>→ <Link to="/agent-studio/eval" className="text-accent-blue underline">Run the eval harness</Link> against your agent spec.</li>
              <li>→ <Link to="/agent-studio/supply-chain" className="text-accent-blue underline">Scan your model supply chain</Link> for licence / CVE / format risks.</li>
              <li>→ <Link to="/agent-studio/red-team" className="text-accent-blue underline">Fire the red-team automation</Link> (Garak + deterministic harness).</li>
              <li>→ <Link to="/agent-studio/runtime" className="text-accent-blue underline">Wire runtime monitoring</Link> via OTel-GenAI traces.</li>
              <li>→ <Link to="/dossier?vertical=agent_studio" className="text-accent-blue underline">Generate your assurance dossier</Link>.</li>
            </ul>
          </section>
        </>
      )}

      {err && (
        <div className="p-3 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red inline-flex items-center gap-1.5">
          <AlertCircle className="w-3 h-3" /> {err}
        </div>
      )}
    </div>
  )
}
