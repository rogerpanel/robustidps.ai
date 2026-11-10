import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Cloud, RefreshCw, Trash2, Download, Upload, ArrowRight,
  Archive, AlertCircle, Loader2, ShieldCheck, FolderOpen,
} from 'lucide-react'
import PageGuide from '../../../components/PageGuide'
import {
  listWorkspaces, deleteWorkspace, archiveWorkspace,
  exportWorkspaceUrl, importWorkspace, adminListWorkspaces,
} from '../api'
import type { WorkspaceRecord, WorkspaceStats } from '../api'
import { useAgentStudioState } from '../../../hooks/useAgentStudioState'
import { getUser } from '../../../utils/auth'
import AccessBanner from '../components/AccessBanner'

export default function Workspaces() {
  const user = getUser()
  const isAdmin = user?.role === 'admin'

  const [items, setItems] = useAgentStudioState<WorkspaceRecord[]>('ws', 'items', [])
  const [stats, setStats] = useAgentStudioState<WorkspaceStats | null>('ws', 'stats', null)
  const [includeArchived, setIncludeArchived] = useAgentStudioState<boolean>('ws', 'archived', false)
  const [adminMode, setAdminMode] = useAgentStudioState<boolean>('ws', 'admin', false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [msg, setMsg] = useState<string | null>(null)

  const refresh = async () => {
    setBusy(true); setErr(null)
    try {
      if (isAdmin && adminMode) {
        const r = await adminListWorkspaces(includeArchived)
        setItems(r.workspaces); setStats(r.stats)
      } else {
        const r = await listWorkspaces({ include_archived: includeArchived })
        setItems(r.workspaces); setStats(r.stats || null)
      }
    } catch (e) {
      setErr(String(e))
    } finally { setBusy(false) }
  }

  useEffect(() => { refresh() /* eslint-disable-line */ }, [includeArchived, adminMode])

  const onArchive = async (id: string, name: string) => {
    if (!confirm(`Archive "${name}"? It can be restored from the archived list.`)) return
    await archiveWorkspace(id).catch((e) => setErr(String(e)))
    setMsg(`Archived: ${name}`); setTimeout(() => setMsg(null), 3000)
    await refresh()
  }

  const onDelete = async (id: string, name: string) => {
    if (!confirm(`HARD DELETE "${name}"? This cannot be undone.`)) return
    await deleteWorkspace(id).catch((e) => setErr(String(e)))
    setMsg(`Deleted: ${name}`); setTimeout(() => setMsg(null), 3000)
    await refresh()
  }

  const onImport = async () => {
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = 'application/json,.json'
    input.onchange = async () => {
      const f = input.files?.[0]
      if (!f) return
      try {
        const payload = JSON.parse(await f.text())
        await importWorkspace(payload)
        setMsg('Imported.'); setTimeout(() => setMsg(null), 3000)
        await refresh()
      } catch (e) { setErr(String(e)) }
    }
    input.click()
  }

  return (
    <div className="space-y-5">
      <AccessBanner />
      <header className="flex items-end justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-2xl font-display font-bold inline-flex items-center gap-2">
            <Cloud className="w-5 h-5 text-accent-blue" /> Workspaces
            {isAdmin && adminMode && (
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-accent-green/15 text-accent-green border border-accent-green/30">
                admin · all users
              </span>
            )}
          </h1>
          <p className="text-xs text-text-secondary mt-1 max-w-3xl">
            Your saved BuildWizard sessions, per template. Resume from where
            you left off, export to a JSON file you can keep offline, or
            import work shared by a teammate. Strict per-user isolation —
            only you (and platform admins) can see yours.
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={refresh} disabled={busy}
                  className="px-2 py-1.5 rounded bg-bg-card border border-bg-card/40 text-xs inline-flex items-center gap-1">
            {busy ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
            Refresh
          </button>
          <button onClick={onImport}
                  className="px-3 py-1.5 rounded bg-accent-blue text-white text-xs font-medium hover:bg-accent-blue/90 inline-flex items-center gap-1.5">
            <Upload className="w-3 h-3" /> Import from JSON
          </button>
        </div>
      </header>

      <PageGuide
        title="How to use Workspaces"
        steps={[
          { title: 'Auto-saved while you build', desc: 'Use the Save button on the BuildWizard toolbar to persist your in-progress agent. State follows your identity, not your browser — open the same workspace from another device after sign-in.' },
          { title: 'Resume from anywhere', desc: 'Click any saved workspace to jump back into its BuildWizard. The same step, spec, environment, and snippet tab restore.' },
          { title: 'Export for archive / handoff', desc: 'Download the workspace as JSON; archive it on disk or share it. Re-import resets the owner to whoever uploads.' },
          { title: 'Archive vs Delete', desc: 'Archive is a soft delete (recoverable via "show archived"); Delete is permanent.' },
          { title: 'Admin override', desc: 'Platform admins can flip the "Admin · all users" toggle to see and manage every user\'s workspace.' },
        ]}
        tip="Demo-mode visitors cannot save — the API returns 403. Either sign in as a platform user or paste an API key from /agent-studio/account."
      />

      <section className="flex items-center gap-3 flex-wrap">
        <label className="text-[11px] font-mono text-text-secondary inline-flex items-center gap-1">
          <input type="checkbox" checked={includeArchived}
                 onChange={(e) => setIncludeArchived(e.target.checked)} />
          show archived
        </label>
        {isAdmin && (
          <label className="text-[11px] font-mono text-accent-green inline-flex items-center gap-1">
            <input type="checkbox" checked={adminMode}
                   onChange={(e) => setAdminMode(e.target.checked)} />
            <ShieldCheck className="w-3 h-3" /> admin: every user's workspaces
          </label>
        )}
        {stats && (
          <span className="ml-auto text-[10px] font-mono text-text-secondary">
            {stats.n_active} active · {stats.n_archived} archived
            {adminMode && stats.by_owner && (
              <> · {Object.keys(stats.by_owner).length} distinct owners</>
            )}
          </span>
        )}
      </section>

      {err && (
        <div className="p-3 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red inline-flex items-center gap-1.5">
          <AlertCircle className="w-3 h-3" /> {err}
        </div>
      )}
      {msg && (
        <div className="p-2 bg-accent-green/10 border border-accent-green/30 rounded-md text-xs text-accent-green">
          {msg}
        </div>
      )}

      {items.length === 0 ? (
        <section className="bg-bg-card rounded-xl p-6 text-center">
          <FolderOpen className="w-8 h-8 text-text-secondary mx-auto mb-2" />
          <p className="text-xs text-text-secondary">
            No workspaces yet. Open <Link to="/agent-studio/quickstart" className="text-accent-blue underline">the Quickstart</Link>,
            build an agent, then click <strong>Save</strong> in the toolbar.
          </p>
        </section>
      ) : (
        <section className="overflow-x-auto">
          <table className="w-full text-[11px] font-mono">
            <thead className="text-text-secondary uppercase text-[10px]">
              <tr className="text-left">
                <th className="pb-1.5">name</th>
                <th>template</th>
                {adminMode && <th>owner</th>}
                <th>updated</th>
                <th>state</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((w) => (
                <tr key={w.workspace_id}
                    className={`border-t border-bg-card/30 ${w.archived_at ? 'opacity-50' : ''}`}>
                  <td className="py-1.5">
                    <Link to={`/agent-studio/build/${w.template_id}`}
                          onClick={() => {
                            // Pre-stamp the BuildWizard's active workspace
                            // so the bar loads it.
                            try {
                              localStorage.setItem(
                                `rids:as:wsbar:${w.template_id}:activeId`,
                                JSON.stringify(w.workspace_id))
                              localStorage.setItem(
                                `rids:as:wsbar:${w.template_id}:activeName`,
                                JSON.stringify(w.name))
                            } catch { /* */ }
                          }}
                          className="text-accent-blue hover:underline inline-flex items-center gap-1">
                      {w.name} <ArrowRight className="w-3 h-3" />
                    </Link>
                    {w.archived_at && (
                      <span className="ml-2 text-accent-red text-[10px]">archived</span>
                    )}
                  </td>
                  <td>{w.template_id}</td>
                  {adminMode && (
                    <td className="truncate max-w-[12rem]" title={w.owner_email}>
                      {w.owner_email}
                    </td>
                  )}
                  <td>{w.updated_at?.slice(0, 16) || '—'}</td>
                  <td className="text-text-secondary">
                    step {(w.state as { step?: number })?.step ?? '?'} · {Object.keys(w.state || {}).length} keys
                  </td>
                  <td className="text-right whitespace-nowrap">
                    <a href={exportWorkspaceUrl(w.workspace_id)}
                       target="_blank" rel="noreferrer"
                       className="inline-block p-1 hover:text-accent-blue"
                       title="Export as JSON">
                      <Download className="w-3 h-3" />
                    </a>
                    {!w.archived_at && (
                      <button onClick={() => onArchive(w.workspace_id, w.name)}
                              className="inline-block p-1 hover:text-accent-amber"
                              title="Archive (soft delete)">
                        <Archive className="w-3 h-3" />
                      </button>
                    )}
                    <button onClick={() => onDelete(w.workspace_id, w.name)}
                            className="inline-block p-1 hover:text-accent-red"
                            title="Delete (hard)">
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  )
}
