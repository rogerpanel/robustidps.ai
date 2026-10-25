import { useEffect, useMemo, useState } from 'react'
import { Save, Loader2, CheckCircle2 } from 'lucide-react'
import { guardEnvironment, guardSaveEnvironment, guardValidateEnvironment } from '../../guardApi'

interface Asset { name: string; kind?: string; ip?: string; role?: string; group?: string | null; dependents?: number; available?: boolean; services?: { name: string; group?: string | null; dependents?: number }[] }

/** The asset inventory behind the predictive layer: what containment would take down, and what must stay up. */
export default function EnvironmentTab() {
  const [text, setText] = useState('')
  const [version, setVersion] = useState(0)
  const [example, setExample] = useState<Record<string, unknown> | null>(null)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    guardEnvironment().then((r) => {
      setVersion(r.version); setExample(r.example)
      setText(JSON.stringify(r.environment ?? { groups: {}, assets: [] }, null, 2))
    }).catch((e) => setMsg({ ok: false, text: String(e.message || e) }))
  }, [])

  const parsed = useMemo(() => { try { return JSON.parse(text) as { groups?: Record<string, { min_available?: number }>; assets?: Asset[] } } catch { return null } }, [text])

  const validate = async () => {
    try {
      const r = await guardValidateEnvironment(JSON.parse(text))
      setMsg(r.valid ? { ok: true, text: `Valid: ${r.assets} assets, ${r.groups} groups.` } : { ok: false, text: r.errors.join('; ') })
    } catch (e) { setMsg({ ok: false, text: e instanceof Error ? e.message : 'Not valid JSON' }) }
  }
  const save = async () => {
    setBusy(true); setMsg(null)
    try {
      const r = await guardSaveEnvironment(JSON.parse(text))
      setVersion(r.version); setMsg({ ok: true, text: `Saved as version ${r.version} (${r.assets} assets). Checks use it from now on.` })
    } catch (e) { setMsg({ ok: false, text: e instanceof Error ? e.message : String(e) }) } finally { setBusy(false) }
  }

  return (
    <div className="grid lg:grid-cols-5 gap-6">
      <div className="lg:col-span-3 bg-bg-card rounded-xl p-5 space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <h3 className="font-semibold mr-auto">Asset inventory {version ? `(version ${version})` : '(none saved)'}</h3>
          {example && (
            <button onClick={() => { setText(JSON.stringify(example, null, 2)); setMsg({ ok: true, text: 'Example loaded. Edit it to match your environment, then save.' }) }}
                    className="text-xs text-accent-blue hover:underline">Load example</button>
          )}
          <button onClick={validate} className="px-3 py-1.5 bg-accent-blue/15 text-accent-blue rounded-lg text-xs font-medium">Validate</button>
          <button onClick={save} disabled={busy || !parsed}
                  className="px-3 py-1.5 bg-accent-blue text-white rounded-lg text-xs font-medium inline-flex items-center gap-1.5 disabled:opacity-50">
            {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />} Save
          </button>
        </div>
        <p className="text-xs text-text-secondary">
          With an inventory, the SOC policy predicts what each containment action would take down before it runs. It denies
          actions that would leave a redundancy group below its minimum or cut off more dependents than the policy allows
          (100 per action, 250 per session), and it routes targets missing from the inventory to a person. Only you
          maintain this list; names an attacker chooses in telemetry do not change it. Saving requires a signed-in person
          and is recorded in the evidence ledger.
        </p>
        <textarea value={text} onChange={(e) => { setText(e.target.value); setMsg(null) }} spellCheck={false}
                  className="w-full h-[28rem] px-3 py-2 bg-bg-primary border border-bg-card rounded-lg font-mono text-xs" />
        {msg && <p className={`text-xs ${msg.ok ? 'text-accent-green' : 'text-accent-red'}`}>{msg.ok && <CheckCircle2 className="w-3.5 h-3.5 inline mr-1" />}{msg.text}</p>}
      </div>
      <div className="lg:col-span-2 space-y-4">
        <div className="bg-bg-card rounded-xl p-5">
          <h4 className="text-sm font-semibold mb-2">Redundancy groups</h4>
          {!parsed?.groups || Object.keys(parsed.groups).length === 0 ? <p className="text-xs text-text-secondary">None.</p> : (
            <table className="w-full text-xs"><tbody>
              {Object.entries(parsed.groups).map(([g, v]) => {
                const members = (parsed.assets || []).filter((a) => a.group === g).length
                  + (parsed.assets || []).flatMap((a) => a.services || []).filter((s) => s.group === g).length
                return <tr key={g} className="border-t border-bg-primary"><td className="py-1 font-mono">{g}</td><td>{members} members</td><td>keep ≥ {v.min_available ?? 1}</td></tr>
              })}
            </tbody></table>
          )}
        </div>
        <div className="bg-bg-card rounded-xl p-5">
          <h4 className="text-sm font-semibold mb-2">Assets ({parsed?.assets?.length ?? 0})</h4>
          <div className="max-h-96 overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="text-text-secondary text-left"><tr><th className="py-1">Name</th><th>Kind</th><th>Role</th><th>Dependents</th></tr></thead>
              <tbody>
                {(parsed?.assets || []).map((a) => (
                  <tr key={a.name} className={`border-t border-bg-primary ${a.available === false ? 'opacity-50' : ''}`}>
                    <td className="py-1 font-mono">{a.name}</td><td>{a.kind || 'host'}</td><td>{a.role}{a.group ? ` · ${a.group}` : ''}</td><td>{a.dependents ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}
