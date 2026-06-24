import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  CheckCircle2, Circle, Loader2, AlertCircle, Play, Copy, Send,
  Wrench, Server, Sparkles, Rocket, FlaskConical, Swords,
  Lock,
} from 'lucide-react'
import PageGuide from '../../../components/PageGuide'
import {
  fetchTemplate, createSession, sendSessionMessage, fetchSession,
  fetchSessionLLMInfo, getStoredApiKey, setStoredApiKey,
} from '../api'
import type {
  AgentTemplate, SessionDetail, IntegrationSnippet, SessionLLMInfo,
} from '../api'
import { useAgentStudioState } from '../../../hooks/useAgentStudioState'
import PlatformModelPicker from '../components/PlatformModelPicker'
import SideSuggestions from '../components/SideSuggestions'
import WorkspaceBar from '../components/WorkspaceBar'
import AccessBanner from '../components/AccessBanner'

type Step = 1 | 2 | 3 | 4

export default function BuildWizard() {
  const { templateId = 'blank' } = useParams()
  const ns = `build:${templateId}`
  const [tpl, setTpl] = useState<AgentTemplate | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [step, setStep] = useAgentStudioState<Step>(ns, 'step', 1)

  // Step 1
  const [specJson, setSpecJson] = useAgentStudioState<string>(ns, 'specJson', '')

  // Step 2
  const [envJson, setEnvJson] = useAgentStudioState<string>(ns, 'envJson', '')

  // Step 3
  const [apiKey, setApiKey] = useState(getStoredApiKey() || '')
  const [sessionId, setSessionId] = useAgentStudioState<string | null>(ns, 'sessionId', null)
  const [session, setSession] = useState<SessionDetail | null>(null)
  const [creating, setCreating] = useState(false)
  const [chatInput, setChatInput] = useAgentStudioState<string>(ns, 'chatInput', '')
  const [sending, setSending] = useState(false)
  const [chatErr, setChatErr] = useState<string | null>(null)

  // Step 4
  const [snippetIdx, setSnippetIdx] = useAgentStudioState<number>(ns, 'snippetIdx', 0)

  // Step 3 — LLM provider badge (cached across nav)
  const [llmInfo, setLlmInfo] = useAgentStudioState<SessionLLMInfo | null>('build', 'llmInfo', null)
  useEffect(() => {
    fetchSessionLLMInfo().then(setLlmInfo).catch(() => { /* leave previous */ })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    fetchTemplate(templateId)
      .then((t) => {
        setTpl(t)
        // Only seed from the template if the user hasn't edited yet
        if (!specJson) setSpecJson(JSON.stringify(t.spec, null, 2))
        if (!envJson) setEnvJson(JSON.stringify(t.environment, null, 2))
        if (!chatInput) setChatInput(t.test_inputs?.[0] || 'ping')
      })
      .catch((e) => setErr(String(e)))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [templateId])

  // Restore prior session detail if we have a session_id stored
  useEffect(() => {
    if (!sessionId || session) return
    fetchSession(sessionId)
      .then((s) => setSession(s))
      .catch(() => setSessionId(null))   // session expired / not ours
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId])

  const stepDone: Record<Step, boolean> = useMemo(() => ({
    1: Boolean(specJson && tryParse(specJson)),
    2: Boolean(envJson && tryParse(envJson)),
    3: Boolean(session && !session.aborted),
    4: false,
  }), [specJson, envJson, session])

  const startSession = async () => {
    if (!apiKey) { setChatErr('Paste your API key first.'); return }
    setStoredApiKey(apiKey)
    setCreating(true); setChatErr(null)
    try {
      const s = await createSession(templateId)
      setSession(s)
      setSessionId(s.session_id)
      setStep(3)
    } catch (e) {
      setChatErr(String(e))
    } finally { setCreating(false) }
  }

  const resetSession = () => {
    setSession(null)
    setSessionId(null)
  }

  const send = async () => {
    if (!session || !chatInput.trim()) return
    setSending(true); setChatErr(null)
    try {
      await sendSessionMessage(session.session_id, chatInput)
      const fresh = await fetchSession(session.session_id)
      setSession(fresh)
      setChatInput('')
    } catch (e) {
      setChatErr(String(e))
    } finally { setSending(false) }
  }

  if (err) {
    return (
      <div className="p-3 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red">
        {err}
      </div>
    )
  }
  if (!tpl) {
    return <div className="text-xs text-text-secondary">Loading template…</div>
  }

  return (
    <div className="space-y-5">
      <AccessBanner />
      <header className="flex items-end justify-between gap-3 flex-wrap">
        <div>
          <div className="flex items-center gap-2">
            <Link to="/agent-studio/quickstart"
                  className="text-xs text-accent-blue underline">← Templates</Link>
            <span className="text-[10px] font-mono text-text-secondary">
              tier {tpl.tier} · {tpl.category}
            </span>
          </div>
          <h1 className="text-2xl font-display font-bold mt-1">
            Build: <span className="text-accent-blue">{tpl.name}</span>
          </h1>
          <p className="text-xs text-text-secondary mt-1 max-w-3xl">{tpl.summary}</p>
        </div>
      </header>

      <Stepper step={step} setStep={setStep} done={stepDone} />

      <WorkspaceBar
        templateId={templateId}
        getState={() => ({
          step, specJson, envJson, sessionId, chatInput, snippetIdx,
        })}
        onLoad={(state) => {
          const s = state as {
            step?: Step; specJson?: string; envJson?: string
            sessionId?: string | null; chatInput?: string; snippetIdx?: number
          }
          if (typeof s.step === 'number')   setStep(s.step as Step)
          if (typeof s.specJson === 'string') setSpecJson(s.specJson)
          if (typeof s.envJson === 'string')  setEnvJson(s.envJson)
          if (s.sessionId !== undefined)      setSessionId(s.sessionId ?? null)
          if (typeof s.chatInput === 'string') setChatInput(s.chatInput)
          if (typeof s.snippetIdx === 'number') setSnippetIdx(s.snippetIdx)
        }}
      />

      <div className="grid grid-cols-1 lg:grid-cols-[1fr_18rem] gap-4">
        <div className="space-y-4 min-w-0">

      {/* Step 1 — Create agent (Express ↔ JSON) */}
      {step === 1 && (
        <Step1CreateAgent
          ns={ns}
          tpl={tpl}
          specJson={specJson}
          setSpecJson={setSpecJson}
          onNext={() => setStep(2)}
        />
      )}

      {/* Step 2 — Configure environment */}
      {step === 2 && (
        <section className="space-y-3">
          <PageGuide
            title="Step 2 · Configure the environment"
            steps={[
              { title: 'Network policy', desc: 'outbound_blocked (max safety) → allowlist (per-domain) → outbound_open (broad). Default per tier.' },
              { title: 'MCP servers', desc: 'Each MCP server is a permission grant. policy: read_only (safe) | read_write | write_audited.' },
              { title: 'Secrets vs env_vars', desc: 'Secrets are pulled from a secret store at runtime, never baked into the image. ROBUSTIDPS_API_KEY is always required.' },
            ]}
          />
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            <div className="bg-bg-card rounded-xl p-4">
              <label className="text-[10px] font-mono uppercase text-text-secondary">Environment (JSON)</label>
              <textarea
                value={envJson} onChange={(e) => setEnvJson(e.target.value)}
                spellCheck={false}
                className="mt-1 w-full h-80 bg-bg-secondary border border-bg-card/60 rounded-md p-2 text-xs font-mono"
              />
              {!tryParse(envJson) && (
                <div className="mt-1 text-[10px] text-accent-red">⚠ JSON does not parse.</div>
              )}
            </div>
            <div className="bg-bg-card rounded-xl p-4 space-y-3 text-xs">
              <h3 className="text-sm font-semibold inline-flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-accent-orange" /> Summary
              </h3>
              <Row label="runtime" value={tpl.environment.runtime} />
              <Row label="network" value={tpl.environment.network_policy} tone={
                tpl.environment.network_policy === 'outbound_open' ? 'amber' :
                tpl.environment.network_policy === 'outbound_blocked' ? 'green' : 'blue'
              } />
              {tpl.environment.network_allowlist.length > 0 && (
                <Row label="allowlist" value={tpl.environment.network_allowlist.join(', ')} />
              )}
              <div>
                <div className="text-[10px] font-mono uppercase text-text-secondary mb-1">packages</div>
                <div className="flex flex-wrap gap-1">
                  {tpl.environment.packages.map((p) => (
                    <span key={p} className="text-[10px] font-mono bg-bg-secondary px-1.5 py-0.5 rounded">{p}</span>
                  ))}
                </div>
              </div>
              <div>
                <div className="text-[10px] font-mono uppercase text-text-secondary mb-1">
                  MCP servers ({tpl.environment.mcp_servers.length})
                </div>
                {tpl.environment.mcp_servers.length === 0 && (
                  <div className="text-[10px] text-text-secondary italic">none</div>
                )}
                {tpl.environment.mcp_servers.map((m) => (
                  <div key={m.name} className="border border-bg-card/40 rounded p-1.5 mb-1 text-[10px]">
                    <div className="font-semibold">{m.name}</div>
                    <div className="font-mono opacity-70">{m.url}</div>
                    <div className="inline-block mt-0.5 px-1 py-0.5 rounded bg-bg-secondary text-[9px] font-mono">
                      policy: {m.policy}
                    </div>
                  </div>
                ))}
              </div>
              <div>
                <div className="text-[10px] font-mono uppercase text-text-secondary mb-1">env_vars</div>
                <div className="flex flex-wrap gap-1">
                  {tpl.environment.env_vars.map((e) => (
                    <span key={e} className="text-[10px] font-mono bg-bg-secondary px-1.5 py-0.5 rounded">{e}</span>
                  ))}
                </div>
              </div>
              <div>
                <div className="text-[10px] font-mono uppercase text-text-secondary mb-1 inline-flex items-center gap-1">
                  <Lock className="w-3 h-3" /> secrets
                </div>
                <div className="flex flex-wrap gap-1">
                  {tpl.environment.secrets.map((s) => (
                    <span key={s} className="text-[10px] font-mono bg-accent-red/10 text-accent-red px-1.5 py-0.5 rounded">{s}</span>
                  ))}
                </div>
              </div>
            </div>
          </div>
          <div className="flex gap-2">
            <button onClick={() => setStep(1)}
                    className="px-3 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs">
              ← Back
            </button>
            <div className="flex-1" />
            <button onClick={() => setStep(3)}
                    className="px-4 py-1.5 rounded bg-accent-blue text-white text-xs font-medium hover:bg-accent-blue/90">
              Next: Start session →
            </button>
          </div>
        </section>
      )}

      {/* Step 3 — Start session */}
      {step === 3 && (
        <section className="space-y-3">
          <PageGuide
            title="Step 3 · Test session"
            steps={[
              { title: 'Provide API key', desc: 'Required to start a session. Stored in localStorage; clears when you log out of the Account Console.' },
              { title: 'Send a probe', desc: 'Each message runs through the Aegis scanner pre- and post-response. Block-tier verdicts halt the turn and surface the finding codes.' },
              { title: 'Replay test_inputs', desc: 'The template ships canonical probes — pick from the dropdown to seed the input box.' },
            ]}
            tip="Sessions are sandboxed + deterministic. Real LLM dispatch happens in your deployed agent — this view exists to prove the verdict envelopes flow."
          />
          {llmInfo && (
            <div className={`text-[10px] font-mono px-3 py-1.5 rounded border inline-flex items-center gap-2 ${
              llmInfo.provider === 'synthetic_fallback'
                ? 'bg-bg-secondary text-text-secondary border-bg-card/40'
                : 'bg-accent-green/10 text-accent-green border-accent-green/30'
            }`}>
              {llmInfo.provider === 'synthetic_fallback' ? (
                <>● synthetic dispatcher (no LLM provider key set){llmInfo.reason ? ` · ${llmInfo.reason}` : ''}</>
              ) : (
                <>● live LLM dispatch · provider={llmInfo.provider} · model={llmInfo.model}</>
              )}
            </div>
          )}

          {!session && (
            <div className="bg-bg-card rounded-xl p-4 space-y-2">
              <label className="text-[10px] font-mono uppercase text-text-secondary">API key</label>
              <input
                type="password" value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="rids_live_…"
                className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs font-mono"
              />
              <button onClick={startSession} disabled={creating || !apiKey}
                      className="w-full py-2 rounded bg-accent-blue text-white text-xs font-medium hover:bg-accent-blue/90 disabled:opacity-50 inline-flex items-center justify-center gap-1.5">
                {creating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                Start session
              </button>
              {chatErr && (
                <div className="p-2 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red inline-flex items-center gap-1.5">
                  <AlertCircle className="w-3 h-3" /> {chatErr}
                </div>
              )}
            </div>
          )}

          {session && (
            <div className="bg-bg-card rounded-xl p-4 space-y-3">
              <div className="text-[10px] font-mono text-text-secondary flex items-center gap-2">
                <span>
                  session_id: <span className="text-text-primary">{session.session_id}</span> ·
                  template: {session.template_id} · {session.history.length} messages
                </span>
                {session.aborted && (
                  <span className="text-accent-red">ABORTED (system prompt blocked)</span>
                )}
                <button onClick={resetSession}
                        className="ml-auto px-2 py-0.5 rounded bg-bg-secondary border border-bg-card/40 hover:border-accent-red/40 text-[10px]">
                  Reset (start new)
                </button>
              </div>

              <div className="border border-bg-card/40 rounded-md p-2 max-h-96 overflow-y-auto space-y-1.5">
                {session.history.length === 0 && (
                  <div className="text-xs text-text-secondary italic">No messages yet — send your first probe.</div>
                )}
                {session.history.map((m, i) => <Bubble key={i} m={m} />)}
              </div>

              <div className="flex items-end gap-2">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <label className="text-[10px] font-mono uppercase text-text-secondary">Input</label>
                    {tpl.test_inputs.length > 0 && (
                      <select
                        onChange={(e) => setChatInput(e.target.value)}
                        defaultValue=""
                        className="text-[10px] bg-bg-secondary border border-bg-card/40 rounded px-1 py-0.5">
                        <option value="" disabled>Pick a test input…</option>
                        {tpl.test_inputs.map((t) => (
                          <option key={t} value={t}>{t.slice(0, 60)}{t.length > 60 ? '…' : ''}</option>
                        ))}
                      </select>
                    )}
                  </div>
                  <textarea
                    value={chatInput} onChange={(e) => setChatInput(e.target.value)}
                    rows={2}
                    className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs font-mono"
                  />
                </div>
                <button onClick={send} disabled={sending || !chatInput.trim() || session.aborted}
                        className="px-3 py-2 rounded bg-accent-blue text-white text-xs font-medium hover:bg-accent-blue/90 disabled:opacity-50 inline-flex items-center gap-1">
                  {sending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Send className="w-3 h-3" />}
                  Send
                </button>
              </div>
              {chatErr && (
                <div className="p-2 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red inline-flex items-center gap-1.5">
                  <AlertCircle className="w-3 h-3" /> {chatErr}
                </div>
              )}
            </div>
          )}

          <div className="flex gap-2">
            <button onClick={() => setStep(2)}
                    className="px-3 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs">
              ← Back
            </button>
            <div className="flex-1" />
            <button onClick={() => setStep(4)}
                    className="px-4 py-1.5 rounded bg-accent-blue text-white text-xs font-medium hover:bg-accent-blue/90">
              Next: Integrate →
            </button>
          </div>
        </section>
      )}

      {/* Step 4 — Integrate */}
      {step === 4 && (
        <section className="space-y-3">
          <PageGuide
            title="Step 4 · Integrate + ship"
            steps={[
              { title: 'Copy a snippet', desc: 'Three integration paths: Python (your framework of choice + Aegis), cURL (any HTTP client), Kubernetes (manifest stub).' },
              { title: 'Wire your secrets', desc: 'Set ROBUSTIDPS_API_KEY from your secret manager — never bake it into the image.' },
              { title: 'Promote to CI', desc: 'Add `pytest --aegis-fail-on-warn` to your pipeline; the CI gate fails on warn-or-block verdicts.' },
              { title: 'Generate the dossier', desc: 'After your first production traffic, regenerate the assurance dossier at /dossier?vertical=agent_studio for the auditor.' },
            ]}
          />
          <div className="flex gap-1 mb-2">
            {tpl.integration_snippets.map((s, i) => (
              <button key={i} onClick={() => setSnippetIdx(i)}
                      className={`px-3 py-1.5 rounded text-xs font-mono ${
                        snippetIdx === i ? 'bg-accent-blue text-white' : 'bg-bg-card text-text-secondary hover:text-text-primary'
                      }`}>
                {s.language} · {s.framework}
              </button>
            ))}
          </div>
          {tpl.integration_snippets[snippetIdx] && (
            <SnippetView snippet={tpl.integration_snippets[snippetIdx]} />
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
            <Link to="/dossier?vertical=agent_studio"
                  className="bg-bg-card rounded-xl p-4 hover:border-accent-blue/40 border border-transparent">
              <div className="text-sm font-semibold inline-flex items-center gap-1.5">
                <Rocket className="w-4 h-4 text-accent-blue" /> Generate assurance dossier
              </div>
              <div className="text-[11px] text-text-secondary mt-1">
                Five-SKU coverage + OWASP Agentic + ATLAS chain + CycloneDX-AI SBOM,
                Print theme → Cmd-P → auditor-ready PDF.
              </div>
            </Link>
            <Link to="/agent-studio/account"
                  className="bg-bg-card rounded-xl p-4 hover:border-accent-blue/40 border border-transparent">
              <div className="text-sm font-semibold inline-flex items-center gap-1.5">
                <Wrench className="w-4 h-4 text-accent-orange" /> Manage keys + tier
              </div>
              <div className="text-[11px] text-text-secondary mt-1">
                Account Console — issue per-CI keys, revoke leaked ones, check trial expiry.
              </div>
            </Link>
          </div>

          <div className="flex gap-2 mt-2">
            <button onClick={() => setStep(3)}
                    className="px-3 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs">
              ← Back
            </button>
            <div className="flex-1" />
            <Link to="/agent-studio/quickstart"
                  className="px-4 py-1.5 rounded bg-accent-green text-white text-xs font-medium hover:bg-accent-green/90 inline-flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" /> Done — pick another template
            </Link>
          </div>
        </section>
      )}

        </div>
        <SideSuggestions templateId={templateId} step={step} category={tpl.category} />
      </div>
    </div>
  )
}

// ── Step 1 component: Express ↔ JSON ───────────────────────────────────

type ExpressForm = {
  name: string
  purpose: string
  allowedTools: Record<string, boolean>
  network: 'blocked' | 'allowlist' | 'open'
  memory: 'none' | 'session' | 'long_term'
  onCritical: 'refuse' | 'warn' | 'escalate'
}

function expressToSpec(prev: Record<string, unknown>, f: ExpressForm): Record<string, unknown> {
  const tools = Object.entries(f.allowedTools)
    .filter(([, on]) => on)
    .map(([name]) => {
      const existing = ((prev.tools as Array<Record<string, unknown>>) || [])
        .find((t) => t.name === name)
      return existing || { name }
    })
  const guardrails: string[] = []
  if (f.onCritical === 'refuse')   guardrails.push('On critical input: refuse politely and do not act.')
  if (f.onCritical === 'warn')     guardrails.push('On critical input: surface a warning to the user but continue.')
  if (f.onCritical === 'escalate') guardrails.push('On critical input: escalate to a human reviewer and pause.')
  if (f.network === 'blocked')     guardrails.push('No outbound network calls except those baked into the listed tools.')
  if (f.network === 'allowlist')   guardrails.push('Outbound calls limited to the configured allowlist; refuse anything else.')
  return {
    ...prev,
    name: f.name || 'my-agent',
    system_prompt: `${f.purpose.trim()}\n\n${guardrails.join(' ')}`.trim(),
    tools,
    memory: f.memory,
    scope: f.network === 'open' ? 'loose' : 'strict',
  }
}

function specToExpress(spec: Record<string, unknown>): ExpressForm {
  const allTools = ((spec.tools as Array<Record<string, unknown>>) || [])
  const allowed: Record<string, boolean> = {}
  for (const t of allTools) {
    if (typeof t.name === 'string') allowed[t.name] = true
  }
  const sp = String(spec.system_prompt || '')
  const lower = sp.toLowerCase()
  return {
    name: String(spec.name || ''),
    // First sentence as the user-facing "purpose" — keeps the guardrails out.
    purpose: sp.split(/(?<=[.!?])\s+/)[0] || sp,
    allowedTools: allowed,
    network: lower.includes('no outbound network') ? 'blocked'
           : lower.includes('allowlist') ? 'allowlist' : 'open',
    memory: (['none', 'session', 'long_term'] as const)
      .find((m) => m === spec.memory) || 'session',
    onCritical: lower.includes('escalate') ? 'escalate'
              : lower.includes('warning') || lower.includes('warn') ? 'warn'
              : 'refuse',
  }
}

function Step1CreateAgent({ ns, tpl, specJson, setSpecJson, onNext }: {
  ns: string
  tpl: import('../api').AgentTemplate
  specJson: string
  setSpecJson: (v: string) => void
  onNext: () => void
}) {
  const [mode, setMode] = useAgentStudioState<'express' | 'json'>(ns, 'createMode', 'express')
  const currentSpec = (() => {
    try { return JSON.parse(specJson) as Record<string, unknown> } catch { return tpl.spec }
  })()
  const form = specToExpress(currentSpec)

  const update = (patch: Partial<ExpressForm>) => {
    const next = { ...form, ...patch }
    const nextSpec = expressToSpec(currentSpec, next)
    setSpecJson(JSON.stringify(nextSpec, null, 2))
  }

  const toggleTool = (name: string) =>
    update({ allowedTools: { ...form.allowedTools, [name]: !form.allowedTools[name] } })

  // Pool of tools: union of template tools + already-set tools.
  const toolPool = Array.from(new Set([
    ...((tpl.spec.tools as Array<Record<string, unknown>>) || [])
      .map((t) => String(t.name)),
    ...Object.keys(form.allowedTools),
  ]))

  // Platform models attached as special tools — kept in spec.platform_models
  // as a list of {id, role} entries. The wizard exposes them via the
  // PlatformModelPicker; the Express form treats them as opaque tools.
  const platformModels = (currentSpec.platform_models as Array<{ id: string; role?: string }> | undefined)
    || []
  const selectedPlatformModels = platformModels.map((m) => m.id)

  const setPlatformModels = (ids: string[]) => {
    const next = {
      ...currentSpec,
      platform_models: ids.map((id) => {
        const existing = platformModels.find((m) => m.id === id)
        return existing || { id, role: 'tool' }
      }),
    }
    setSpecJson(JSON.stringify(next, null, 2))
  }

  return (
    <section className="space-y-3">
      <PageGuide
        title="Step 1 · Create the agent"
        steps={mode === 'express' ? [
          { title: 'Name + purpose', desc: 'Plain-English sentence describing what the agent does. The wizard turns this into the system_prompt with the appropriate guardrails.' },
          { title: 'Pick allowed tools', desc: 'Each checkbox grants a permission. Fewer ticks = safer. The Aegis scanner re-runs on every change.' },
          { title: 'Set network + memory + critical-input behaviour', desc: 'Three dropdowns translate to system_prompt clauses and the runtime\'s scope = strict|loose flag.' },
          { title: 'Flip to JSON anytime', desc: 'Switch the Express / JSON tab to inspect what the wizard generated — engineers can tweak directly, then come back.' },
        ] : [
          { title: 'Edit the system prompt', desc: 'Tighten scope, add guardrails, name the refused behaviours explicitly. The Aegis scanner will check every change.' },
          { title: 'Curate tools', desc: 'Fewer = safer. Each tool name is a permission grant. Side-effects (write / network / exec) raise the supply-chain risk score.' },
          { title: 'Pin a model', desc: 'Default is gpt-4o-latest; pin to a hashed model id in production for reproducibility.' },
        ]}
      />

      <div className="flex items-center gap-1 bg-bg-card rounded-md p-1 w-fit">
        {(['express', 'json'] as const).map((m) => (
          <button key={m} onClick={() => setMode(m)}
                  className={`px-3 py-1 rounded text-[11px] font-mono ${
                    mode === m ? 'bg-accent-blue text-white' : 'text-text-secondary hover:text-text-primary'
                  }`}>
            {m === 'express' ? '🧭  Express (no-code)' : '⚙  JSON (engineer)'}
          </button>
        ))}
      </div>

      {mode === 'express' ? (
        <div className="bg-bg-card rounded-xl p-4 space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="block text-[10px] font-mono text-text-secondary mb-1">Agent name</label>
              <input
                type="text" value={form.name} onChange={(e) => update({ name: e.target.value })}
                placeholder="my-traffic-monitor"
                className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs font-mono"
              />
            </div>
            <div>
              <label className="block text-[10px] font-mono text-text-secondary mb-1">Memory</label>
              <select value={form.memory}
                      onChange={(e) => update({ memory: e.target.value as ExpressForm['memory'] })}
                      className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs">
                <option value="none">None (forgetful — safest)</option>
                <option value="session">Session-only (forgets after the run)</option>
                <option value="long_term">Long-term (persists across runs)</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-[10px] font-mono text-text-secondary mb-1">
              What is the agent for? (plain English)
            </label>
            <textarea
              value={form.purpose} onChange={(e) => update({ purpose: e.target.value })}
              rows={3}
              placeholder="e.g. 'Watches network flows for anomalies, scores severity, and opens tickets on critical traffic — never blocks directly, always asks a human.'"
              className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs"
            />
          </div>

          <div>
            <label className="block text-[10px] font-mono text-text-secondary mb-1">
              Allowed tools ({Object.values(form.allowedTools).filter(Boolean).length} of {toolPool.length})
            </label>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-1">
              {toolPool.map((name) => (
                <label key={name}
                       className="flex items-center gap-2 text-xs px-2 py-1 rounded bg-bg-secondary border border-bg-card/40 hover:border-accent-blue/40 cursor-pointer">
                  <input type="checkbox"
                         checked={!!form.allowedTools[name]}
                         onChange={() => toggleTool(name)} />
                  <span className="font-mono">{name}</span>
                </label>
              ))}
              {toolPool.length === 0 && (
                <div className="text-[10px] text-text-secondary italic">
                  No tools in the template — flip to JSON to add some.
                </div>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="block text-[10px] font-mono text-text-secondary mb-1">Network access</label>
              <select value={form.network}
                      onChange={(e) => update({ network: e.target.value as ExpressForm['network'] })}
                      className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs">
                <option value="blocked">No internet (safest)</option>
                <option value="allowlist">Allowlist only (recommended)</option>
                <option value="open">Open (development only)</option>
              </select>
            </div>
            <div>
              <label className="block text-[10px] font-mono text-text-secondary mb-1">On critical input</label>
              <select value={form.onCritical}
                      onChange={(e) => update({ onCritical: e.target.value as ExpressForm['onCritical'] })}
                      className="w-full px-2 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs">
                <option value="refuse">Refuse + log (safest)</option>
                <option value="warn">Warn user, continue</option>
                <option value="escalate">Escalate to human, pause</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-[10px] font-mono uppercase text-text-secondary mb-1">
              Platform models — RobustIDPS detection / response models as special tools
            </label>
            <PlatformModelPicker
              templateId={tpl.id}
              selected={selectedPlatformModels}
              onChange={setPlatformModels}
            />
          </div>

          <details className="text-[10px] font-mono text-text-secondary">
            <summary className="cursor-pointer hover:text-accent-blue">
              Preview generated spec
            </summary>
            <pre className="mt-2 p-2 bg-bg-secondary rounded border border-bg-card/40 overflow-x-auto max-h-48">{specJson}</pre>
          </details>
        </div>
      ) : (
        <div className="bg-bg-card rounded-xl p-4">
          <label className="text-[10px] font-mono uppercase text-text-secondary">Agent spec (JSON)</label>
          <textarea
            value={specJson} onChange={(e) => setSpecJson(e.target.value)}
            spellCheck={false}
            className="mt-1 w-full h-72 bg-bg-secondary border border-bg-card/60 rounded-md p-2 text-xs font-mono"
          />
          {!tryParse(specJson) && (
            <div className="mt-1 text-[10px] text-accent-red">⚠ JSON does not parse.</div>
          )}
          <div className="mt-3">
            <label className="block text-[10px] font-mono uppercase text-text-secondary mb-1">
              Platform models (mirrors spec.platform_models[])
            </label>
            <PlatformModelPicker
              templateId={tpl.id}
              selected={selectedPlatformModels}
              onChange={setPlatformModels}
            />
          </div>
        </div>
      )}

      <div className="flex gap-2">
        <Link to="/agent-studio/eval"
              onClick={() => sessionStorage.setItem('agentstudio_template_spec', specJson)}
              className="px-3 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs inline-flex items-center gap-1">
          <FlaskConical className="w-3 h-3" /> Send to Eval Harness
        </Link>
        <Link to="/agent-studio/red-team"
              onClick={() => sessionStorage.setItem('agentstudio_template_spec', specJson)}
              className="px-3 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-xs inline-flex items-center gap-1">
          <Swords className="w-3 h-3" /> Send to Red Team
        </Link>
        <div className="flex-1" />
        <button onClick={onNext}
                className="px-4 py-1.5 rounded bg-accent-blue text-white text-xs font-medium hover:bg-accent-blue/90">
          Next: Configure environment →
        </button>
      </div>
    </section>
  )
}


function tryParse(s: string): boolean {
  try { JSON.parse(s); return true } catch { return false }
}

function Stepper({ step, setStep, done }: {
  step: Step; setStep: (s: Step) => void; done: Record<Step, boolean>
}) {
  const STEPS: { n: Step; label: string }[] = [
    { n: 1, label: 'Create agent' },
    { n: 2, label: 'Configure environment' },
    { n: 3, label: 'Start session' },
    { n: 4, label: 'Integrate' },
  ]
  return (
    <ol className="flex items-center gap-1 flex-wrap">
      {STEPS.map((s, i) => (
        <li key={s.n} className="flex items-center gap-1">
          <button onClick={() => setStep(s.n)}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium ${
                    step === s.n ? 'bg-accent-blue text-white'
                    : done[s.n] ? 'bg-accent-green/10 text-accent-green border border-accent-green/30'
                    : 'bg-bg-card text-text-secondary hover:text-text-primary'
                  }`}>
            {done[s.n] ? <CheckCircle2 className="w-3 h-3" /> : <Circle className="w-3 h-3" />}
            {s.n}. {s.label}
          </button>
          {i < STEPS.length - 1 && <span className="text-text-secondary px-1">→</span>}
        </li>
      ))}
    </ol>
  )
}

function Row({ label, value, tone }: { label: string; value: string; tone?: 'amber' | 'green' | 'blue' }) {
  const cls = tone === 'amber' ? 'text-accent-amber'
            : tone === 'green' ? 'text-accent-green'
            : tone === 'blue'  ? 'text-accent-blue' : ''
  return (
    <div className="flex gap-2 text-[11px]">
      <span className="text-text-secondary font-mono uppercase w-24">{label}</span>
      <span className={`font-mono ${cls}`}>{value}</span>
    </div>
  )
}

function Bubble({ m }: { m: import('../api').SessionMessage }) {
  const tone = m.decision === 'block' ? 'bg-accent-red/10 border-accent-red/30'
             : m.decision === 'warn'  ? 'bg-accent-amber/10 border-accent-amber/30'
             :                          'bg-bg-secondary border-bg-card/40'
  const roleLabel = m.role === 'user' ? 'USER'
                  : m.role === 'agent' ? 'AGENT' : 'SYSTEM'
  const llm = (m as unknown as { llm_meta?: { provider: string; model: string; n_in: number; n_out: number } }).llm_meta
  return (
    <div className={`border rounded px-2 py-1.5 ${tone}`}>
      <div className="flex items-center justify-between text-[9px] font-mono uppercase text-text-secondary mb-0.5">
        <span>{roleLabel} · {m.ts}</span>
        <span className={
          m.decision === 'block' ? 'text-accent-red'
          : m.decision === 'warn' ? 'text-accent-amber'
          : 'text-accent-green'
        }>{m.decision}  ({m.n_findings})</span>
      </div>
      <div className="text-xs whitespace-pre-wrap">{m.text}</div>
      {m.findings.length > 0 && (
        <div className="mt-1 flex flex-wrap gap-1">
          {m.findings.slice(0, 4).map((f) => (
            <span key={f.code} className="text-[9px] font-mono bg-bg-card px-1 py-0.5 rounded">
              [{f.severity}] {f.code}
            </span>
          ))}
        </div>
      )}
      {llm && (
        <div className="mt-1 text-[9px] font-mono text-text-secondary">
          ● {llm.provider}/{llm.model} · in:{llm.n_in} out:{llm.n_out}
        </div>
      )}
    </div>
  )
}

function SnippetView({ snippet }: { snippet: IntegrationSnippet }) {
  const copy = () => navigator.clipboard?.writeText(snippet.code)
  return (
    <div className="bg-bg-card rounded-xl">
      <div className="flex items-center justify-between px-3 py-2 border-b border-bg-card/40">
        <div className="text-[10px] font-mono uppercase text-text-secondary">
          {snippet.language} · {snippet.framework}
        </div>
        <button onClick={copy}
                className="px-2 py-1 rounded bg-bg-secondary text-[10px] inline-flex items-center gap-1 hover:bg-accent-blue/10">
          <Copy className="w-3 h-3" /> Copy
        </button>
      </div>
      <pre className="text-[11px] font-mono p-3 overflow-x-auto max-h-96 whitespace-pre">{snippet.code}</pre>
    </div>
  )
}
