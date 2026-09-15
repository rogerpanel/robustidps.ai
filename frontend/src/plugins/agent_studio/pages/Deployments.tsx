import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Cloud, Plus, Loader2, AlertCircle, RefreshCw, Trash2,
  CheckCircle2, AlertTriangle, Activity, Rocket,
} from 'lucide-react'
import PageGuide from '../../../components/PageGuide'
import {
  listDeployments, registerDeployment, retireDeployment, getStoredApiKey,
} from '../api'
import type {
  DeploymentRecord, DeploymentStats, CloudId, DeploymentTier,
} from '../api'
import { useAgentStudioState } from '../../../hooks/useAgentStudioState'
import AccessBanner from '../components/AccessBanner'

const CLOUDS: { id: CloudId; label: string }[] = [
  { id: 'aws', label: 'AWS' },        { id: 'gcp', label: 'GCP' },
  { id: 'azure', label: 'Azure' },    { id: 'fly', label: 'Fly.io' },
  { id: 'modal', label: 'Modal' },    { id: 'vercel', label: 'Vercel' },
  { id: 'k8s_self', label: 'Self-hosted k8s' },
  { id: 'docker_self', label: 'Self-hosted Docker' },
  { id: 'bare_metal', label: 'Bare metal' },
  { id: 'other', label: 'Other' },
]

const STATUS_TONE: Record<string, string> = {
  healthy:  'bg-accent-green/10 text-accent-green border-accent-green/30',
  degraded: 'bg-accent-amber/10 text-accent-amber border-accent-amber/30',
  stale:    'bg-bg-secondary text-text-secondary border-bg-card/40',
  retired:  'bg-bg-secondary/40 text-text-secondary/60 border-bg-card/30',
}

const STATUS_ICON: Record<string, typeof CheckCircle2> = {
  healthy:  CheckCircle2,
  degraded: AlertTriangle,
  stale:    Activity,
  retired:  Trash2,
}

export default function Deployments() {
  const [deps, setDeps] = useAgentStudioState<DeploymentRecord[]>('deploy', 'list', [])
  const [stats, setStats] = useAgentStudioState<DeploymentStats | null>('deploy', 'stats', null)
  const [includeRetired, setIncludeRetired] = useAgentStudioState<boolean>('deploy', 'includeRetired', false)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [showForm, setShowForm] = useState(false)

  // Form state (persisted so accidental nav doesn't lose work)
  const [name, setName] = useAgentStudioState<string>('deploy', 'fName', '')
  const [templateId, setTemplateId] = useAgentStudioState<string>('deploy', 'fTemplate', 'soc_triage')
  const [runtimeAgentId, setRuntimeAgentId] = useAgentStudioState<string>('deploy', 'fAgentId', '')
  const [cloud, setCloud] = useAgentStudioState<CloudId>('deploy', 'fCloud', 'other')
  const [region, setRegion] = useAgentStudioState<string>('deploy', 'fRegion', '')
  const [tier, setTier] = useAgentStudioState<DeploymentTier>('deploy', 'fTier', 'dev')
  const [url, setUrl] = useAgentStudioState<string>('deploy', 'fUrl', '')
  const [gitSha, setGitSha] = useAgentStudioState<string>('deploy', 'fGitSha', '')
  const [note, setNote] = useAgentStudioState<string>('deploy', 'fNote', '')

  const reload = async () => {
    if (!getStoredApiKey()) {
      setErr('API key required — open the Account console to issue one.')
      return
    }
    setErr(null); setBusy(true)
    try {
      const r = await listDeployments(includeRetired)
      setDeps(r.deployments); setStats(r.stats)
    } catch (e) {
      setErr(String(e))
    } finally { setBusy(false) }
  }

  useEffect(() => { reload() }, [includeRetired])  // eslint-disable-line

  const submitRegister = async () => {
    if (!name || !templateId || !runtimeAgentId) {
      setErr('name, template_id, and runtime_agent_id are required.')
      return
    }
    setBusy(true); setErr(null)
    try {
      await registerDeployment({
        template_id: templateId, name, runtime_agent_id: runtimeAgentId,
        cloud, region, tier,
        url: url || null, git_sha: gitSha || null,
        note,
      })
      setShowForm(false)
      setName(''); setRuntimeAgentId(''); setUrl(''); setGitSha(''); setNote('')
      await reload()
    } catch (e) {
      setErr(String(e))
    } finally { setBusy(false) }
  }

  const doRetire = async (id: string, dname: string) => {
    if (!confirm(`Retire deployment "${dname}"? It will be marked retired_at=now and excluded from active stats.`)) return
    setBusy(true); setErr(null)
    try {
      await retireDeployment(id)
      await reload()
    } catch (e) { setErr(String(e)) } finally { setBusy(false) }
  }

  return (
    <div className="space-y-5">
      <AccessBanner />
      <header className="flex items-end justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-2xl font-display font-bold inline-flex items-center gap-2">
            <Cloud className="w-5 h-5 text-accent-blue" /> Deployments
          </h1>
          <p className="text-xs text-text-secondary mt-1 max-w-3xl">
            Where your agents are running. Each registered deployment cross-references
            the runtime_agent_id used by its MambaGuardClient so the status / block-rate /
            latency telemetry flows in automatically.
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={reload} disabled={busy}
                  className="px-2 py-1.5 rounded bg-bg-card border border-bg-card/40 text-xs inline-flex items-center gap-1">
            {busy ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
            Refresh
          </button>
          <button onClick={() => setShowForm(!showForm)}
                  className="px-3 py-1.5 rounded bg-accent-blue text-white text-xs font-medium hover:bg-accent-blue/90 inline-flex items-center gap-1.5">
            <Plus className="w-3 h-3" /> Register
          </button>
        </div>
      </header>

      <PageGuide
        title="How to use the Deployments registry"
        steps={[
          { title: 'Wire your agent', desc: 'Your deployed agent runs MambaGuardClient with an agent_id of your choosing — that ID is your runtime_agent_id. Each verdict POST shows up under that ID in /agent-studio/runtime.' },
          { title: 'Register the deployment', desc: 'Click Register, fill in template_id + name + the runtime_agent_id you chose, plus cloud + region + tier metadata for your records.' },
          { title: 'Status colour-coding', desc: 'healthy (green) = block_rate < 5%. degraded (amber) = block_rate ≥ 5% or warn-tier verdicts visible. stale (grey) = no recent events. retired (faded) = manually marked end-of-life.' },
          { title: 'SOC Copilot follow-up', desc: 'Ask "list my deployments" or "why is the prod deployment degraded?" — the Copilot will pull from this page + the linked runtime snapshot.' },
        ]}
        tip="Multi-tenant isolation lands with the Postgres sprint; for now every deployment record carries customer_id and the API filters by the calling key's customer."
      />

      {stats && (
        <section className="grid grid-cols-2 md:grid-cols-5 gap-2">
          <Stat label="active" value={String(stats.n_active)} tone="green" />
          <Stat label="retired" value={String(stats.n_retired)} tone="dim" />
          <Stat label="healthy" value={String(stats.by_status.healthy || 0)} tone="green" />
          <Stat label="degraded" value={String(stats.by_status.degraded || 0)} tone="amber" />
          <Stat label="stale" value={String(stats.by_status.stale || 0)} tone="dim" />
        </section>
      )}

      {showForm && (
        <section className="bg-bg-card rounded-xl p-5 space-y-3">
          <h2 className="text-sm font-semibold inline-flex items-center gap-1.5">
            <Plus className="w-4 h-4 text-accent-green" /> Register a deployment
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <Field label="Name (human)">
              <input value={name} onChange={(e) => setName(e.target.value)}
                     placeholder="soc-triage-prod-eu"
                     className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs" />
            </Field>
            <Field label="Template">
              <input value={templateId} onChange={(e) => setTemplateId(e.target.value)}
                     placeholder="soc_triage"
                     className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs font-mono" />
            </Field>
            <Field label="Runtime agent_id (matches your MambaGuardClient)">
              <input value={runtimeAgentId} onChange={(e) => setRuntimeAgentId(e.target.value)}
                     placeholder="prod-eu-soc-triage-001"
                     className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs font-mono" />
            </Field>
            <Field label="Cloud">
              <select value={cloud} onChange={(e) => setCloud(e.target.value as CloudId)}
                      className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs">
                {CLOUDS.map((c) => <option key={c.id} value={c.id}>{c.label}</option>)}
              </select>
            </Field>
            <Field label="Region">
              <input value={region} onChange={(e) => setRegion(e.target.value)}
                     placeholder="eu-central-1"
                     className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs" />
            </Field>
            <Field label="Tier">
              <select value={tier} onChange={(e) => setTier(e.target.value as DeploymentTier)}
                      className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs">
                <option value="dev">dev</option>
                <option value="staging">staging</option>
                <option value="production">production</option>
              </select>
            </Field>
            <Field label="URL (optional)" full>
              <input value={url} onChange={(e) => setUrl(e.target.value)}
                     placeholder="https://agent.example.com or k8s://cluster/ns/pod"
                     className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs font-mono" />
            </Field>
            <Field label="Git sha (optional)">
              <input value={gitSha} onChange={(e) => setGitSha(e.target.value)}
                     placeholder="abc1234"
                     className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs font-mono" />
            </Field>
            <Field label="Note (optional)" full>
              <input value={note} onChange={(e) => setNote(e.target.value)}
                     className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs" />
            </Field>
          </div>
          <div className="flex gap-2">
            <button onClick={() => setShowForm(false)}
                    className="px-3 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs">
              Cancel
            </button>
            <button onClick={submitRegister} disabled={busy}
                    className="px-3 py-1.5 rounded bg-accent-blue text-white text-xs font-medium hover:bg-accent-blue/90 disabled:opacity-50 inline-flex items-center gap-1.5">
              {busy ? <Loader2 className="w-3 h-3 animate-spin" /> : <Rocket className="w-3 h-3" />}
              Register
            </button>
          </div>
        </section>
      )}

      {err && (
        <div className="p-3 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red inline-flex items-center gap-1.5">
          <AlertCircle className="w-3 h-3" /> {err}
        </div>
      )}

      <section className="flex items-center gap-3">
        <label className="text-[11px] font-mono text-text-secondary inline-flex items-center gap-1">
          <input type="checkbox" checked={includeRetired}
                 onChange={(e) => setIncludeRetired(e.target.checked)} />
          include retired
        </label>
      </section>

      {deps.length === 0 ? (
        <section className="bg-bg-card rounded-xl p-6 text-center">
          <Cloud className="w-8 h-8 text-text-secondary mx-auto mb-2" />
          <p className="text-xs text-text-secondary">
            No deployments registered yet. Click <strong>Register</strong> to add your first.
          </p>
        </section>
      ) : (
        <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {deps.map((d) => {
            const Icon = STATUS_ICON[d.status] || Activity
            return (
              <div key={d.deployment_id}
                   className={`border rounded-xl p-4 ${STATUS_TONE[d.status]}`}>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="min-w-0">
                    <div className="text-sm font-semibold truncate">{d.name}</div>
                    <div className="text-[10px] font-mono text-text-secondary truncate">
                      {d.template_id} · {d.cloud}{d.region ? `:${d.region}` : ''}
                    </div>
                  </div>
                  <span className="text-[9px] font-mono uppercase inline-flex items-center gap-1">
                    <Icon className="w-3 h-3" /> {d.status}
                  </span>
                </div>
                <div className="text-[10px] font-mono text-text-secondary mb-2 space-y-0.5">
                  <div>tier: <span className="text-text-primary">{d.tier}</span></div>
                  <div>runtime_agent_id: <span className="text-text-primary">{d.runtime_agent_id}</span></div>
                  {d.url && <div className="truncate">url: <span className="text-text-primary">{d.url}</span></div>}
                  {d.git_sha && <div>sha: <span className="text-text-primary">{d.git_sha}</span></div>}
                </div>
                {d.telemetry ? (
                  <div className="grid grid-cols-2 gap-2 text-[10px] mt-2 pt-2 border-t border-bg-card/40">
                    <Cell label="block" value={`${(d.telemetry.block_rate*100).toFixed(1)}%`}
                          tone={d.telemetry.block_rate >= 0.2 ? 'red' :
                                d.telemetry.block_rate >= 0.05 ? 'amber' : 'green'} />
                    <Cell label="warn" value={`${(d.telemetry.warn_rate*100).toFixed(1)}%`} tone="amber" />
                    <Cell label="p50"
                          value={d.telemetry.p50_latency_ms !== null ? `${d.telemetry.p50_latency_ms.toFixed(0)} ms` : '—'} />
                    <Cell label="p95"
                          value={d.telemetry.p95_latency_ms !== null ? `${d.telemetry.p95_latency_ms.toFixed(0)} ms` : '—'} />
                  </div>
                ) : (
                  <div className="text-[10px] text-text-secondary italic mt-2 pt-2 border-t border-bg-card/40">
                    No telemetry yet — POST verdicts to /api/agent-studio/runtime/ingest with
                    agent_id="{d.runtime_agent_id}".
                  </div>
                )}
                <div className="flex items-center justify-between mt-2 pt-2 border-t border-bg-card/40">
                  <Link to={`/agent-studio/runtime`}
                        className="text-[10px] font-mono text-accent-blue hover:underline">
                    Live monitor →
                  </Link>
                  {!d.retired_at && (
                    <button onClick={() => doRetire(d.deployment_id, d.name)}
                            className="p-1 rounded hover:bg-accent-red/10 text-accent-red"
                            title="Retire">
                      <Trash2 className="w-3 h-3" />
                    </button>
                  )}
                </div>
              </div>
            )
          })}
        </section>
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

function Stat({ label, value, tone }: { label: string; value: string; tone?: 'green' | 'amber' | 'dim' }) {
  const cls = tone === 'green' ? 'text-accent-green'
            : tone === 'amber' ? 'text-accent-amber'
            : tone === 'dim'   ? 'text-text-secondary' : 'text-text-primary'
  return (
    <div className="bg-bg-card border border-bg-card/40 rounded p-2">
      <div className="text-[9px] font-mono uppercase text-text-secondary">{label}</div>
      <div className={`text-sm font-mono font-semibold ${cls}`}>{value}</div>
    </div>
  )
}

function Cell({ label, value, tone }: { label: string; value: string; tone?: 'green' | 'amber' | 'red' }) {
  const cls = tone === 'red' ? 'text-accent-red'
            : tone === 'amber' ? 'text-accent-amber'
            : tone === 'green' ? 'text-accent-green' : ''
  return (
    <div>
      <div className="text-[9px] font-mono uppercase text-text-secondary">{label}</div>
      <div className={`font-mono font-semibold ${cls}`}>{value}</div>
    </div>
  )
}
