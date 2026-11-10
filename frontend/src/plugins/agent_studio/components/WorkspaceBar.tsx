import { useEffect, useState } from 'react'
import {
  Save, Download, Upload, Trash2, FolderOpen, RefreshCw,
  Loader2, CheckCircle2, AlertCircle, Cloud,
} from 'lucide-react'
import {
  saveWorkspace, listWorkspaces, fetchWorkspace, exportWorkspaceUrl,
  importWorkspace, deleteWorkspace,
} from '../api'
import type { WorkspaceRecord } from '../api'
import { useAgentStudioState } from '../../../hooks/useAgentStudioState'

/**
 * Workspace toolbar for the BuildWizard.
 *
 * - Save/Save-As: pack the wizard's persisted state into spec.platform
 *   under the user's identity.
 * - Load: resume from any saved workspace for this template_id.
 * - Export: download the workspace as a JSON file the user can keep.
 * - Import: upload a JSON file (caller becomes the owner regardless).
 * - Delete: hard delete (owner-only).
 *
 * `getState()` collects whatever the parent considers the canonical
 * snapshot — passed in so the bar stays agnostic about wizard
 * internals. `onLoad(state)` is called when the user picks a workspace.
 */
export default function WorkspaceBar({
  templateId, getState, onLoad,
}: {
  templateId: string
  getState: () => Record<string, unknown>
  onLoad: (state: Record<string, unknown>) => void
}) {
  const ns = `wsbar:${templateId}`
  const [activeId, setActiveId] = useAgentStudioState<string | null>(ns, 'activeId', null)
  const [activeName, setActiveName] = useAgentStudioState<string>(ns, 'activeName', '')
  const [items, setItems] = useState<WorkspaceRecord[]>([])
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ tone: 'ok' | 'err'; text: string } | null>(null)
  const [open, setOpen] = useState(false)

  const refresh = async () => {
    setBusy(true)
    try {
      const r = await listWorkspaces({ template_id: templateId })
      setItems(r.workspaces)
    } catch (e) {
      setMsg({ tone: 'err', text: String(e) })
    } finally { setBusy(false) }
  }

  useEffect(() => { refresh() /* eslint-disable-line */ }, [templateId])

  const flash = (tone: 'ok' | 'err', text: string) => {
    setMsg({ tone, text })
    setTimeout(() => setMsg(null), 3500)
  }

  const onSave = async (forceNew = false) => {
    const name = forceNew
      ? prompt('Save as — name for the new workspace:', activeName || `${templateId}-${new Date().toISOString().slice(0,10)}`) || ''
      : (activeName || templateId)
    if (!name) return
    setBusy(true)
    try {
      const r = await saveWorkspace({
        workspace_id: forceNew ? null : activeId,
        template_id: templateId, name, state: getState(),
      })
      setActiveId(r.workspace_id)
      setActiveName(r.name)
      flash('ok', `Saved: ${r.name}`)
      await refresh()
    } catch (e) {
      flash('err', String(e))
    } finally { setBusy(false) }
  }

  const onLoadPick = async (id: string) => {
    setBusy(true)
    try {
      const r = await fetchWorkspace(id)
      onLoad(r.state)
      setActiveId(r.workspace_id)
      setActiveName(r.name)
      setOpen(false)
      flash('ok', `Loaded: ${r.name}`)
    } catch (e) {
      flash('err', String(e))
    } finally { setBusy(false) }
  }

  const onDelete = async (id: string, name: string) => {
    if (!confirm(`Delete workspace "${name}"? This cannot be undone.`)) return
    setBusy(true)
    try {
      await deleteWorkspace(id)
      if (activeId === id) { setActiveId(null); setActiveName('') }
      await refresh()
      flash('ok', `Deleted: ${name}`)
    } catch (e) {
      flash('err', String(e))
    } finally { setBusy(false) }
  }

  const onExport = () => {
    if (!activeId) {
      flash('err', 'Save the workspace first, then export.')
      return
    }
    window.open(exportWorkspaceUrl(activeId), '_blank')
  }

  const onImport = async () => {
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = 'application/json,.json'
    input.onchange = async () => {
      const file = input.files?.[0]
      if (!file) return
      setBusy(true)
      try {
        const text = await file.text()
        const payload = JSON.parse(text)
        const r = await importWorkspace(payload)
        setActiveId(r.workspace_id)
        setActiveName(r.name)
        onLoad(r.state)
        await refresh()
        flash('ok', `Imported: ${r.name}`)
      } catch (e) {
        flash('err', String(e))
      } finally { setBusy(false) }
    }
    input.click()
  }

  return (
    <div className="bg-bg-card border border-bg-card/40 rounded-md px-3 py-2 text-xs">
      <div className="flex items-center gap-2 flex-wrap">
        <Cloud className="w-3.5 h-3.5 text-accent-blue" />
        <span className="font-mono text-text-secondary">workspace:</span>
        {activeId ? (
          <span className="font-mono text-accent-blue truncate max-w-[14rem]">{activeName}</span>
        ) : (
          <span className="font-mono text-text-secondary italic">unsaved (local-only)</span>
        )}

        <button onClick={() => onSave(false)} disabled={busy}
                className="ml-2 px-2 py-1 rounded bg-accent-blue text-white text-[11px] inline-flex items-center gap-1 disabled:opacity-50"
                title="Save (overwrites the active workspace)">
          {busy ? <Loader2 className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
          Save
        </button>
        <button onClick={() => onSave(true)} disabled={busy}
                className="px-2 py-1 rounded bg-bg-secondary border border-bg-card/40 text-[11px] inline-flex items-center gap-1 disabled:opacity-50">
          Save as…
        </button>
        <button onClick={() => setOpen(!open)}
                className="px-2 py-1 rounded bg-bg-secondary border border-bg-card/40 text-[11px] inline-flex items-center gap-1">
          <FolderOpen className="w-3 h-3" /> Load ({items.length})
        </button>
        <button onClick={refresh} disabled={busy}
                className="px-2 py-1 rounded bg-bg-secondary border border-bg-card/40 text-[11px] inline-flex items-center gap-1">
          <RefreshCw className="w-3 h-3" />
        </button>
        <span className="flex-1" />
        <button onClick={onExport} disabled={!activeId}
                className="px-2 py-1 rounded bg-bg-secondary border border-bg-card/40 text-[11px] inline-flex items-center gap-1 disabled:opacity-40"
                title="Download workspace as JSON">
          <Download className="w-3 h-3" /> Export
        </button>
        <button onClick={onImport}
                className="px-2 py-1 rounded bg-bg-secondary border border-bg-card/40 text-[11px] inline-flex items-center gap-1">
          <Upload className="w-3 h-3" /> Import
        </button>
      </div>

      {open && items.length > 0 && (
        <div className="mt-2 border-t border-bg-card/40 pt-2 max-h-56 overflow-y-auto space-y-1">
          {items.map((w) => (
            <div key={w.workspace_id}
                 className={`flex items-center gap-2 px-2 py-1 rounded ${
                   w.workspace_id === activeId ? 'bg-accent-blue/10' : 'hover:bg-bg-secondary/50'
                 }`}>
              <button onClick={() => onLoadPick(w.workspace_id)}
                      className="flex-1 text-left truncate font-mono text-[11px] hover:text-accent-blue">
                {w.name}
                <span className="text-text-secondary ml-2 text-[10px]">
                  {w.updated_at?.slice(0, 16)}
                </span>
              </button>
              <button onClick={() => onDelete(w.workspace_id, w.name)}
                      className="p-1 rounded hover:bg-accent-red/10 text-accent-red"
                      title="Delete">
                <Trash2 className="w-3 h-3" />
              </button>
            </div>
          ))}
        </div>
      )}
      {open && items.length === 0 && (
        <div className="mt-2 text-[10px] text-text-secondary italic">
          No saved workspaces yet for this template — Save to create one.
        </div>
      )}

      {msg && (
        <div className={`mt-2 text-[10px] inline-flex items-center gap-1 ${
          msg.tone === 'ok' ? 'text-accent-green' : 'text-accent-red'
        }`}>
          {msg.tone === 'ok' ? <CheckCircle2 className="w-3 h-3" /> : <AlertCircle className="w-3 h-3" />}
          {msg.text}
        </div>
      )}
    </div>
  )
}
