import { useCallback, useEffect, useState } from 'react'
import { ShieldCheck, ShieldAlert, Download, RefreshCw } from 'lucide-react'
import {
  guardEvidence, guardExportEvidence, guardVerifyEvidence,
  type EvidenceRecord, type EvidenceVerification,
} from '../../guardApi'

const KINDS = ['', 'guard_decision', 'approval', 'toolset_register', 'toolset_pin', 'toolset_drift', 'evaluation', 'session_reset']

/** The hash-chained ledger behind the dossier's runtime-safety section. */
export default function EvidenceTab() {
  const [records, setRecords] = useState<EvidenceRecord[]>([])
  const [verification, setVerification] = useState<EvidenceVerification | null>(null)
  const [kind, setKind] = useState('')
  const [err, setErr] = useState('')

  const load = useCallback(() => {
    setErr('')
    guardEvidence(kind || undefined).then(setRecords).catch((e) => setErr(String(e.message || e)))
    guardVerifyEvidence().then(setVerification).catch(() => setVerification(null))
  }, [kind])
  useEffect(() => { load() }, [load])

  const exportAll = async () => {
    const data = await guardExportEvidence()
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }))
    const a = document.createElement('a')
    a.href = url; a.download = `agent-guard-evidence-${(verification?.head || 'ledger').slice(0, 12)}.json`; a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-4">
      <div className="bg-bg-card rounded-xl p-5 flex flex-wrap items-center gap-4">
        {verification && (verification.valid ? (
          <div className="flex items-center gap-2 text-accent-green"><ShieldCheck className="w-6 h-6" />
            <div><div className="font-semibold">Chain verified</div>
              <div className="text-xs text-text-secondary">{verification.records} records; every hash recomputed</div></div></div>
        ) : (
          <div className="flex items-center gap-2 text-accent-red"><ShieldAlert className="w-6 h-6" />
            <div><div className="font-semibold">Chain broken at record {verification.broken_at}</div>
              <div className="text-xs">{(verification.problems || []).join('; ')}</div></div></div>
        ))}
        <div className="text-xs font-mono text-text-secondary break-all flex-1 min-w-64">head {verification?.head}</div>
        <select value={kind} onChange={(e) => setKind(e.target.value)} className="px-2 py-1 bg-bg-primary border border-bg-card rounded text-xs">
          {KINDS.map((k) => <option key={k} value={k}>{k || 'all kinds'}</option>)}
        </select>
        <button onClick={load} title="Refresh" className="text-text-secondary hover:text-text-primary"><RefreshCw className="w-4 h-4" /></button>
        <button onClick={exportAll} className="text-xs text-accent-blue inline-flex items-center gap-1"><Download className="w-3.5 h-3.5" /> Export with payloads</button>
      </div>
      <p className="text-xs text-text-secondary">
        Each record's hash covers its content and the previous hash, so changing or removing an earlier record breaks
        every later one. Denials, approval requests, modifications, approvals, tool registrations, pins, drift and
        evaluations are recorded; allowed calls are only counted in the session log. The head hash is quoted in the
        Assurance Dossier.
      </p>
      {err && <p className="text-sm text-accent-red">{err}</p>}
      <div className="bg-bg-card rounded-xl p-4 overflow-x-auto">
        {records.length === 0 ? <p className="text-sm text-text-secondary">No records yet.</p> : (
          <table className="w-full text-xs">
            <thead className="text-text-secondary text-left"><tr><th className="py-1">#</th><th>Time</th><th>Kind</th><th>Summary</th><th>Hash</th></tr></thead>
            <tbody>
              {records.map((r) => (
                <tr key={r.seq} className="border-t border-bg-primary">
                  <td className="py-1 font-mono">{r.seq}</td>
                  <td className="text-text-secondary whitespace-nowrap">{new Date(r.created_at).toLocaleString()}</td>
                  <td className="font-mono">{r.kind}</td>
                  <td>{r.summary}</td>
                  <td className="font-mono text-text-secondary">{r.hash.slice(0, 12)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
