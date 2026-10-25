import { useEffect, useState } from 'react'
import { Gauge, Save, Loader2 } from 'lucide-react'
import { guardDeferral, guardSaveDeferral, type DeferralCalibration, type DeferralSettings } from '../../guardApi'

const MODE_TEXT: Record<DeferralSettings['mode'], string> = {
  off: 'Off: every request goes to a person.',
  shadow: 'Shadow: every request still goes to a person; each one records whether it would have been auto-approved.',
  auto: 'Auto: routine requests under the threshold are approved without a person; the rest come here.',
}

/** Calibrated deferral: learn from past decisions which requests a person really needs to see. */
export default function DeferralPanel() {
  const [settings, setSettings] = useState<DeferralSettings | null>(null)
  const [cal, setCal] = useState<DeferralCalibration | null>(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)

  useEffect(() => {
    guardDeferral().then((r) => { setSettings(r.settings); setCal(r.calibration) }).catch((e) => setMsg({ ok: false, text: String(e.message || e) }))
  }, [])

  const save = async () => {
    if (!settings) return
    setBusy(true); setMsg(null)
    try {
      const r = await guardSaveDeferral(settings)
      setSettings(r.settings); setCal(r.calibration); setMsg({ ok: true, text: 'Saved (recorded in the evidence ledger).' })
    } catch (e) { setMsg({ ok: false, text: e instanceof Error ? e.message : String(e) }) } finally { setBusy(false) }
  }

  if (!settings) return null
  return (
    <div className="bg-bg-card rounded-xl p-4 space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <h3 className="font-semibold text-sm flex items-center gap-2 mr-auto"><Gauge className="w-4 h-4 text-accent-blue" /> Calibrated deferral</h3>
        <select value={settings.mode} onChange={(e) => setSettings({ ...settings, mode: e.target.value as DeferralSettings['mode'] })}
                className="px-2 py-1 bg-bg-primary border border-bg-card rounded text-xs">
          <option value="off">off</option><option value="shadow">shadow</option><option value="auto">auto</option>
        </select>
        <label className="text-xs text-text-secondary">max wrong
          <input type="number" step="0.01" min="0.01" max="0.4" value={settings.alpha}
                 onChange={(e) => setSettings({ ...settings, alpha: Number(e.target.value) })}
                 className="ml-1 w-16 px-1 py-0.5 bg-bg-primary border border-bg-card rounded" />
        </label>
        <label className="text-xs text-text-secondary">confidence
          <select value={settings.delta} onChange={(e) => setSettings({ ...settings, delta: Number(e.target.value) })}
                  className="ml-1 px-1 py-0.5 bg-bg-primary border border-bg-card rounded">
            <option value={0.1}>90%</option><option value={0.05}>95%</option><option value={0.01}>99%</option>
          </select>
        </label>
        <button onClick={save} disabled={busy}
                className="px-3 py-1.5 bg-accent-blue text-white rounded-lg text-xs font-medium inline-flex items-center gap-1.5 disabled:opacity-50">
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />} Save
        </button>
      </div>
      <p className="text-xs text-text-secondary">{MODE_TEXT[settings.mode]}</p>
      {cal && (
        <p className={`text-xs ${cal.ready ? 'text-accent-green' : 'text-text-secondary'}`}>
          {cal.ready
            ? `Calibrated on ${cal.n} decided requests: requests with risk score ≤ ${cal.threshold} would be auto-approved (${Math.round(cal.auto_share * 100)}% of past ones). Guarantee: with ${Math.round((1 - cal.delta) * 100)}% confidence, at most ${Math.round(cal.alpha * 100)}% of auto-approved requests are ones a person would deny.`
            : `Not calibrated: ${cal.reason}.`}
        </p>
      )}
      <p className="text-[11px] text-text-secondary">
        Never auto-approved, whatever the score: refusals, irreversible or unclassified actions, hidden characters,
        unsafe or unknown predicted effects, and sessions that already had refusals. Start with shadow mode to see how it
        would decide before switching to auto.
      </p>
      {msg && <p className={`text-xs ${msg.ok ? 'text-accent-green' : 'text-accent-red'}`}>{msg.text}</p>}
    </div>
  )
}
