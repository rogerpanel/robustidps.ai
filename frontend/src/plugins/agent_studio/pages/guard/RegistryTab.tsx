import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Pin, Loader2, AlertTriangle, CheckCircle2, Upload } from 'lucide-react'
import {
  guardCoverage, guardPinToolset, guardRegisterToolset, guardToolset, guardToolsets,
  type Coverage, type GuardPolicy, type Toolset,
} from '../../guardApi'

const SAMPLE = JSON.stringify({ tools: [
  { name: 'search_events', description: 'Search security events by host, user and time.', inputSchema: { type: 'object' } },
  { name: 'isolate_host', description: 'Isolate a host from the network.', inputSchema: { type: 'object', properties: { host: { type: 'string' } } } },
  { name: 'purge_mailbox', description: 'Permanently delete all mail in a mailbox.', inputSchema: { type: 'object' } },
  { name: 'sync_assets', description: 'Synchronise the asset inventory with the CMDB.', inputSchema: { type: 'object' } },
] }, null, 2)

interface Props {
  policies: GuardPolicy[]
  policyId: string
  inlinePolicy?: unknown
  initialToolset?: string
  onUsePolicy: (policy: GuardPolicy) => void
}

/** Shared with the MCP/Agent Scanner and the MCP gateway: register tool sets, review changes, pin, check coverage. */
export default function RegistryTab({ policies, policyId, inlinePolicy, initialToolset, onUsePolicy }: Props) {
  const [list, setList] = useState<Toolset[]>([])
  const [name, setName] = useState('')
  const [text, setText] = useState(SAMPLE)
  const [selected, setSelected] = useState<Toolset | null>(null)
  const [coverage, setCoverage] = useState<Coverage | null>(null)
  const [covPolicy, setCovPolicy] = useState(policyId)
  const [busy, setBusy] = useState('')
  const [err, setErr] = useState('')

  const load = useCallback(() => guardToolsets().then(setList).catch((e) => setErr(String(e.message || e))), [])
  useEffect(() => { load() }, [load])

  const open = useCallback(async (n: string, v?: number) => {
    setErr(''); setCoverage(null)
    try { setSelected(await guardToolset(n, v)) } catch (e) { setErr(e instanceof Error ? e.message : String(e)) }
  }, [])
  useEffect(() => { if (initialToolset) open(initialToolset) }, [initialToolset, open])

  const grouped = useMemo(() => {
    const m: Record<string, Toolset[]> = {}
    for (const t of list) (m[t.name] ||= []).push(t)
    return m
  }, [list])

  const register = async () => {
    setBusy('register'); setErr('')
    try {
      const r = await guardRegisterToolset(name.trim(), text)
      await load(); await open(r.name, r.version)
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)) } finally { setBusy('') }
  }
  const pin = async () => {
    if (!selected) return
    setBusy('pin'); setErr('')
    try { await guardPinToolset(selected.name, selected.version); await load(); await open(selected.name, selected.version) }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)) } finally { setBusy('') }
  }
  const checkCoverage = async () => {
    if (!selected) return
    setBusy('coverage'); setErr('')
    try {
      setCoverage(await guardCoverage(selected.name, selected.version, covPolicy,
                                      covPolicy === policyId ? inlinePolicy : undefined))
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)) } finally { setBusy('') }
  }

  return (
    <div className="grid lg:grid-cols-5 gap-6">
      <div className="lg:col-span-2 space-y-4">
        <div className="bg-bg-card rounded-xl p-5 space-y-3">
          <h3 className="font-semibold flex items-center gap-2"><Upload className="w-4 h-4" /> Register a tool set</h3>
          <p className="text-xs text-text-secondary">
            Paste an MCP <span className="font-mono">tools/list</span> result, a tool array, OpenAI-style function tools
            or an agent spec. Each tool is fingerprinted, the text runs through the MCP/Agent Scanner, and changes
            against the previous version are listed. You can also register straight from the{' '}
            <Link to="/agent-scanner" className="text-accent-blue hover:underline">scanner page</Link>.
          </p>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="name, e.g. soc-mcp"
                 className="w-full px-3 py-2 bg-bg-primary border border-bg-card rounded-lg text-sm" />
          <textarea value={text} onChange={(e) => setText(e.target.value)} spellCheck={false}
                    className="w-full h-48 px-3 py-2 bg-bg-primary border border-bg-card rounded-lg font-mono text-xs" />
          <button onClick={register} disabled={busy === 'register' || !name.trim()}
                  className="w-full px-4 py-2 bg-accent-blue text-white rounded-lg text-sm font-medium disabled:opacity-50">
            {busy === 'register' ? 'Registering…' : 'Register'}
          </button>
        </div>
        <div className="bg-bg-card rounded-xl p-5">
          <h3 className="font-semibold mb-2">Registered tool sets</h3>
          {list.length === 0 && <p className="text-sm text-text-secondary">None yet.</p>}
          {Object.entries(grouped).map(([n, versions]) => (
            <div key={n} className="py-2 border-t border-bg-primary first:border-0">
              <div className="font-mono text-sm">{n}</div>
              <div className="flex flex-wrap gap-1 mt-1">
                {versions.map((v) => (
                  <button key={v.id} onClick={() => open(v.name, v.version)}
                          className={`px-2 py-0.5 rounded text-xs border ${selected?.id === v.id ? 'border-accent-blue text-accent-blue' : 'border-bg-primary text-text-secondary'}`}>
                    v{v.version}{v.pinned ? ' · pinned' : ''}{v.n_hidden ? ' · ⚠' : ''}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="lg:col-span-3 space-y-4">
        {err && <p className="text-sm text-accent-red">{err}</p>}
        {!selected ? (
          <div className="bg-bg-card rounded-xl p-6 text-sm text-text-secondary">Select or register a tool set.</div>
        ) : (
          <>
            <div className="bg-bg-card rounded-xl p-5 space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="font-semibold font-mono mr-auto">{selected.name} v{selected.version}</h3>
                {selected.pinned ? (
                  <span className="text-xs text-accent-green inline-flex items-center gap-1"><CheckCircle2 className="w-3.5 h-3.5" /> pinned: the MCP gateway accepts exactly these tools</span>
                ) : (
                  <button onClick={pin} disabled={busy === 'pin' || selected.n_hidden > 0}
                          title={selected.n_hidden ? 'Tools with hidden characters cannot be pinned' : ''}
                          className="px-3 py-1.5 rounded-lg bg-accent-blue/15 text-accent-blue text-xs font-semibold inline-flex items-center gap-1.5 disabled:opacity-40">
                    {busy === 'pin' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Pin className="w-3.5 h-3.5" />} Pin this version
                  </button>
                )}
              </div>
              <p className="text-[11px] text-text-secondary font-mono break-all">digest {selected.digest}</p>
              {selected.diff && (
                <p className="text-xs">
                  Against v{selected.diff.against_version}:{' '}
                  {selected.diff.added.length > 0 && <span className="text-accent-amber">added {selected.diff.added.join(', ')}; </span>}
                  {selected.diff.removed.length > 0 && <span>removed {selected.diff.removed.join(', ')}; </span>}
                  {selected.diff.changed.length > 0 && <span className="text-accent-red">changed {selected.diff.changed.join(', ')}</span>}
                </p>
              )}
              {selected.scan && (
                <p className="text-xs text-text-secondary">
                  Scanner: {selected.scan.n_findings} findings
                  {selected.scan.triggered.slice(0, 6).map((t) => <span key={t.code} className="ml-1.5 font-mono">{t.code}</span>)}
                </p>
              )}
              <table className="w-full text-xs">
                <thead className="text-text-secondary text-left"><tr><th className="py-1">Tool</th><th>Description</th><th>Fingerprint</th></tr></thead>
                <tbody>
                  {(selected.tools || []).map((t) => (
                    <tr key={t.name} className="border-t border-bg-primary align-top">
                      <td className="py-1.5 pr-2 font-mono">{t.name}</td>
                      <td className="pr-2">{t.description}{t.hidden.length > 0 && (
                        <div className="text-accent-red flex items-center gap-1 mt-0.5"><AlertTriangle className="w-3 h-3" /> hidden: {t.hidden.join(' · ')}</div>)}</td>
                      <td className="font-mono text-text-secondary">{t.fingerprint.slice(0, 12)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="bg-bg-card rounded-xl p-5 space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="font-semibold mr-auto">Policy coverage</h3>
                <select value={covPolicy} onChange={(e) => { setCovPolicy(e.target.value); setCoverage(null) }}
                        className="px-2 py-1 bg-bg-primary border border-bg-card rounded text-xs">
                  {policies.map((p) => <option key={p.id} value={p.id}>{p.name || p.id}</option>)}
                </select>
                <button onClick={checkCoverage} disabled={busy === 'coverage'}
                        className="px-3 py-1.5 rounded-lg bg-accent-blue/15 text-accent-blue text-xs font-semibold">Check</button>
              </div>
              {coverage && (
                <>
                  <p className="text-xs text-text-secondary">
                    {coverage.total - coverage.unclassified} of {coverage.total} tools matched by a rule in {coverage.policy_id} v{coverage.policy_version};
                    {' '}{coverage.unclassified} fall to the default tier. Suggestions come from tool names and descriptions; review them.
                    {' '}Data labels feed the information-flow rules (untrusted input, sensitive data, sends data out); a tool nothing classifies is assumed to do all three.
                  </p>
                  <table className="w-full text-xs">
                    <thead className="text-text-secondary text-left"><tr><th className="py-1">Tool</th><th>Tier now</th><th>Verdict</th><th>Looks like</th><th>Suggested</th><th>Data labels</th></tr></thead>
                    <tbody>
                      {coverage.tools.map((t) => (
                        <tr key={t.name} className="border-t border-bg-primary">
                          <td className="py-1 font-mono">{t.name}</td>
                          <td className={t.explicit ? '' : 'text-accent-amber'}>{t.tier}{t.explicit ? '' : ' (default)'}</td>
                          <td>{t.decision}</td>
                          <td>{t.effect_hint}</td>
                          <td className="font-mono">{t.suggested_tier || '-'}</td>
                          <td>
                            {t.flow_assumed ? <span className="text-accent-amber">assumed: all</span>
                              : (t.flow_labels || []).length > 0 ? (t.flow_labels || []).join(', ') : <span className="text-text-secondary">none</span>}
                            {(t.flow_conditional || []).length > 0 && <span className="text-text-secondary"> (+{(t.flow_conditional || []).join(', ')} by argument)</span>}
                            {(t.suggested_flow || []).length > 0 && <span className="text-accent-blue"> · suggest {(t.suggested_flow || []).join(', ')}</span>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <button onClick={() => onUsePolicy(coverage.generated_policy)}
                          className="text-xs text-accent-blue hover:underline">
                    Open a policy with these suggestions in the Test tab →
                  </button>
                </>
              )}
            </div>
            <div className="bg-bg-card rounded-xl p-4 text-xs text-text-secondary">
              Guard an MCP server with this tool set:{' '}
              <span className="font-mono text-text-primary">python agent_guard_client.py mcp-proxy --toolset {selected.name} --policy {covPolicy} -- &lt;server command&gt;</span>.
              Tools that changed since the pinned version, new tools and tools with hidden characters are withheld from the agent.
            </div>
          </>
        )}
      </div>
    </div>
  )
}
