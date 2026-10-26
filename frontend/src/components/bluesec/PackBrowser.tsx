import { useMemo, useState } from 'react'
import { unzipSync, strFromU8 } from 'fflate'
import { Package, Download, FolderOpen, Loader2, Eye, EyeOff, Search, AlertTriangle, FileDown } from 'lucide-react'
import { downloadCsv } from './csv'

export const PUBLISHED_PACK = '/downloads/robustidps-bluesec-pack.zip'
const FORMAT = 'robustidps-bluesec-pack/1'
const MAX_PACK_BYTES = 60 * 1024 * 1024

interface ManifestTask {
  id: string; platform: string; verdict: string; attack: string; title: string
  source: string; source_dataset: string; source_url: string; entities: number; relations: number
}
interface Manifest { format: string; name: string; created: string; tasks: ManifestTask[] }
type Obj = Record<string, unknown>
interface PackTask {
  id: string; platform: string; alert: Obj; optimal_calls: number
  graph: { entities: Record<string, Obj>; relations: Record<string, Obj & { type: string; source: string; target: string }> }
}
interface Answer { id: string; verdict: string; attack: string; core: string[]; acceptable: string[]; evidence_fields: Record<string, string[]> }
interface Pack { manifest: Manifest; tasks: Record<string, PackTask>; answers: Record<string, Answer>; origin: string }

// Packs are untrusted input: only the expected JSON members are parsed, sizes are capped,
// and values are rendered as text (React escapes them).
function parsePack(bytes: Uint8Array, origin: string): Pack {
  if (bytes.byteLength > MAX_PACK_BYTES) throw new Error('Pack is larger than 60 MB.')
  const files = unzipSync(bytes, { filter: f => f.name.endsWith('.json') && f.originalSize < MAX_PACK_BYTES })
  const read = (name: string) => {
    if (!files[name]) throw new Error(`Pack is missing ${name}.`)
    return JSON.parse(strFromU8(files[name]))
  }
  const manifest = read('manifest.json') as Manifest
  if (manifest.format !== FORMAT) throw new Error('Not a RobustIDPS BlueSec practice pack.')
  const tasks: Record<string, PackTask> = {}
  const answers: Record<string, Answer> = {}
  for (const t of manifest.tasks.slice(0, 1000)) {
    tasks[t.id] = read(`tasks/${t.id}.json`)
    if (files[`answers/${t.id}.json`]) answers[t.id] = read(`answers/${t.id}.json`)
  }
  return { manifest, tasks, answers, origin }
}

function label(e: Obj | undefined): string {
  if (!e) return ''
  const v = e.command_line ?? e.path ?? e.destination_ip ?? e.query_name ?? e.name ?? e.hostname ?? e.image ?? ''
  return String(v).slice(0, 140)
}

function TaskView({ task, answer, showAnswers }: { task: PackTask; answer?: Answer; showAnswers: boolean }) {
  const [query, setQuery] = useState('')
  const [focus, setFocus] = useState<string>(() => String((task.alert.trigger_entities as string[] | undefined)?.[0] ?? ''))
  const ents = task.graph.entities
  const rels = task.graph.relations
  const counts = useMemo(() => {
    const e: Record<string, number> = {}
    const r: Record<string, number> = {}
    Object.values(ents).forEach(x => { e[String(x.type)] = (e[String(x.type)] || 0) + 1 })
    Object.values(rels).forEach(x => { r[x.type] = (r[x.type] || 0) + 1 })
    return { e: Object.entries(e).sort((a, b) => b[1] - a[1]), r: Object.entries(r).sort((a, b) => b[1] - a[1]) }
  }, [ents, rels])
  const hits = useMemo(() => {
    const q = query.trim().toLowerCase()
    const all = Object.entries(ents)
    return (q ? all.filter(([id, e]) => id.toLowerCase().includes(q) || JSON.stringify(e).toLowerCase().includes(q)) : all).slice(0, 80)
  }, [ents, query])
  const focused = ents[focus]
  const links = useMemo(() => Object.entries(rels).filter(([, r]) => r.source === focus || r.target === focus).slice(0, 60), [rels, focus])
  const core = new Set(showAnswers && answer ? answer.core : [])

  return (
    <div className="space-y-3">
      <div className="grid md:grid-cols-2 gap-3">
        <div>
          <div className="text-[10px] uppercase tracking-wide text-text-secondary mb-1">Alert</div>
          <pre className="text-[11px] bg-bg-primary rounded p-2 overflow-auto max-h-56 whitespace-pre-wrap break-all">{JSON.stringify(task.alert, null, 2)}</pre>
        </div>
        <div className="space-y-2">
          <div className="text-[10px] uppercase tracking-wide text-text-secondary">Graph: {Object.keys(ents).length} entities, {Object.keys(rels).length} relations</div>
          <div className="flex flex-wrap gap-1">{counts.e.map(([k, n]) => <span key={k} className="px-1.5 py-0.5 rounded bg-bg-primary text-[11px]">{k} <b>{n}</b></span>)}</div>
          <div className="flex flex-wrap gap-1">{counts.r.map(([k, n]) => <span key={k} className="px-1.5 py-0.5 rounded bg-bg-primary text-[11px] text-text-secondary">{k} <b className="text-text-primary">{n}</b></span>)}</div>
          {showAnswers && answer && (
            <div className="rounded-lg border border-bg-card p-2 text-xs space-y-1">
              <div>Expected verdict: <b className={answer.verdict === 'malicious' ? 'text-accent-red' : 'text-accent-green'}>{answer.verdict}</b> · ATT&CK {answer.attack}</div>
              <div className="text-text-secondary">{answer.verdict === 'malicious' ? 'Core entities a complete response names' : 'Anchors that prove legitimacy'}:</div>
              <div className="flex flex-wrap gap-1">
                {answer.core.map(id => (
                  <button key={id} onClick={() => setFocus(id)} className="px-1.5 py-0.5 rounded bg-bg-primary font-mono text-[11px] hover:text-accent-blue" title={label(ents[id] ?? rels[id])}>{id}</button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="grid md:grid-cols-2 gap-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Search className="w-3.5 h-3.5 text-text-secondary" />
            <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search entities (id, path, command line, IP…)"
              className="flex-1 bg-bg-primary border border-bg-card rounded px-2 py-1 text-xs" />
          </div>
          <ul className="max-h-72 overflow-auto text-xs divide-y divide-bg-card">
            {hits.map(([id, e]) => (
              <li key={id}>
                <button onClick={() => setFocus(id)} className={`w-full text-left px-1.5 py-1 hover:bg-bg-primary ${focus === id ? 'bg-bg-primary' : ''}`}>
                  <span className={`font-mono ${core.has(id) ? 'text-accent-amber' : ''}`}>{id}</span>
                  <span className="text-text-secondary"> · {String(e.type)}</span>
                  <div className="text-text-secondary truncate">{label(e)}</div>
                </button>
              </li>
            ))}
          </ul>
        </div>
        <div>
          {focused ? (
            <div className="space-y-2">
              <div className="text-xs"><span className="font-mono">{focus}</span> <span className="text-text-secondary">· {String(focused.type)}</span></div>
              <table className="w-full text-[11px]"><tbody>
                {Object.entries(focused).filter(([k]) => k !== 'type').map(([k, v]) => (
                  <tr key={k} className="border-t border-bg-card"><td className="pr-2 py-0.5 text-text-secondary align-top whitespace-nowrap">{k}</td><td className="font-mono break-all">{String(v)}</td></tr>
                ))}
              </tbody></table>
              <div className="text-[10px] uppercase tracking-wide text-text-secondary">Relations ({links.length}{links.length === 60 ? '+' : ''})</div>
              <ul className="max-h-40 overflow-auto text-[11px] space-y-0.5">
                {links.map(([rid, r]) => {
                  const other = r.source === focus ? r.target : r.source
                  return (
                    <li key={rid}>
                      <span className="text-text-secondary">{r.source === focus ? '→' : '←'} {r.type}</span>{' '}
                      <button onClick={() => setFocus(other)} className="font-mono hover:text-accent-blue">{other}</button>
                      <span className="text-text-secondary"> {label(ents[other]).slice(0, 60)}</span>
                    </li>
                  )
                })}
              </ul>
            </div>
          ) : <p className="text-xs text-text-secondary">Select an entity to see its properties and relations.</p>}
        </div>
      </div>
    </div>
  )
}

export default function PackBrowser() {
  const [pack, setPack] = useState<Pack | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [open, setOpen] = useState('')
  const [showAnswers, setShowAnswers] = useState(false)

  const load = async (get: () => Promise<Uint8Array>, origin: string) => {
    setLoading(true); setError('')
    try { setPack(parsePack(await get(), origin)); setOpen('') } catch (e) { setError((e as Error).message) } finally { setLoading(false) }
  }
  const openPublished = () => load(async () => {
    const r = await fetch(PUBLISHED_PACK)
    if (!r.ok) throw new Error(`Could not download the pack (HTTP ${r.status}).`)
    return new Uint8Array(await r.arrayBuffer())
  }, 'published pack')
  const openFile = (f: File | undefined) => f && load(async () => new Uint8Array(await f.arrayBuffer()), f.name)

  const exportTasks = () => {
    if (!pack) return
    const head = ['task', 'platform', 'title', 'entities', 'relations', 'source', 'source_dataset', 'source_url']
    downloadCsv('bluesec-pack-tasks', [showAnswers ? [...head, 'expected_verdict', 'attack'] : head,
      ...pack.manifest.tasks.map(t => {
        const row = [t.id, t.platform, t.title, t.entities, t.relations, t.source, t.source_dataset, t.source_url]
        return showAnswers ? [...row, t.verdict, t.attack] : row
      })])
  }

  const stats = pack ? {
    windows: pack.manifest.tasks.filter(t => t.platform === 'windows').length,
    linux: pack.manifest.tasks.filter(t => t.platform === 'linux').length,
  } : null

  return (
    <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="font-semibold flex items-center gap-2 mr-auto"><Package className="w-4 h-4" /> Practice pack</h2>
        <a href={PUBLISHED_PACK} download className="text-xs px-2.5 py-1.5 rounded bg-bg-primary border border-bg-card hover:border-accent-blue flex items-center gap-1">
          <Download className="w-3.5 h-3.5" /> Download pack (.zip)
        </a>
        <button onClick={openPublished} disabled={loading} className="text-xs px-2.5 py-1.5 rounded bg-bg-primary border border-bg-card hover:border-accent-blue flex items-center gap-1 disabled:opacity-40">
          {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Package className="w-3.5 h-3.5" />} Browse published pack
        </button>
        <label className="text-xs px-2.5 py-1.5 rounded bg-bg-primary border border-bg-card hover:border-accent-blue flex items-center gap-1 cursor-pointer">
          <FolderOpen className="w-3.5 h-3.5" /> Open a pack file
          <input type="file" accept=".zip,application/zip" className="hidden" onChange={e => openFile(e.target.files?.[0])} />
        </label>
      </div>
      <p className="text-xs text-text-secondary max-w-4xl">
        Investigation tasks built from public attack telemetry: Windows recordings from OTRF Security-Datasets (MIT) and
        Linux recordings from Splunk attack_data (Apache-2.0), each as an alert plus an evidence graph, with ground truth
        kept apart. Run it with <span className="font-mono">python -m bluesec1_agent.robust.cli --pack robustidps-bluesec-pack.zip</span>,
        then add the run above.
      </p>
      {error && <p className="text-xs text-accent-red flex gap-1.5"><AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />{error}</p>}
      {pack && stats && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-3 text-xs text-text-secondary">
            <span><b className="text-text-primary">{pack.manifest.tasks.length}</b> tasks · {stats.windows} Windows · {stats.linux} Linux · from {pack.origin} · built {pack.manifest.created.slice(0, 10)}</span>
            <button onClick={() => setShowAnswers(!showAnswers)} className="ml-auto flex items-center gap-1 hover:text-text-primary">
              {showAnswers ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />} {showAnswers ? 'Hide' : 'Show'} answers
            </button>
            <button onClick={exportTasks} className="flex items-center gap-1 hover:text-text-primary"><FileDown className="w-3.5 h-3.5" /> Task list CSV</button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-left text-xs text-text-secondary">
                <th className="font-normal py-1.5">Task</th><th className="font-normal">Platform</th>{showAnswers && <th className="font-normal">ATT&CK</th>}
                <th className="font-normal">Alert</th><th className="font-normal text-right pr-3">Graph</th>
                {showAnswers && <th className="font-normal">Answer</th>}<th className="font-normal">Source</th>
              </tr></thead>
              <tbody>
                {pack.manifest.tasks.map(t => (
                  <tr key={t.id} onClick={() => setOpen(open === t.id ? '' : t.id)} className={`border-t border-bg-card cursor-pointer hover:bg-bg-primary/50 ${open === t.id ? 'bg-bg-primary/70' : ''}`}>
                    <td className="py-1.5 pr-2 font-mono text-xs">{t.id}</td>
                    <td className="text-xs pr-2">{t.platform}</td>
                    {showAnswers && <td className="text-xs pr-2">{t.attack}</td>}
                    <td className="text-xs pr-2">{t.title}</td>
                    <td className="text-xs text-right tabular-nums pr-3">{t.entities}/{t.relations}</td>
                    {showAnswers && <td className={`text-xs pr-2 ${t.verdict === 'malicious' ? 'text-accent-red' : 'text-accent-green'}`}>{t.verdict}</td>}
                    <td className="text-xs"><a href={t.source_url} target="_blank" rel="noreferrer noopener" onClick={e => e.stopPropagation()} className="text-accent-blue hover:underline">{t.source.split(' ')[0]}</a></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {open && pack.tasks[open] && (
            <TaskView key={open} task={pack.tasks[open]} answer={pack.answers[open]} showAnswers={showAnswers} />
          )}
        </div>
      )}
    </div>
  )
}
