import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Plane, Play, Pause, RotateCcw, Upload, Download, AlertCircle, Loader2,
} from 'lucide-react'
import PageGuide from '../../../components/PageGuide'
import {
  fleetReset, fleetStep, fleetUpload, fleetSamplePackUrl,
} from '../api'
import type { FleetUAV, FleetSnapshot } from '../api'

const ATTACK_CHOICES: { id: string; label: string; color: string }[] = [
  { id: 'none',        label: 'none',         color: '#94A3B8' },
  { id: 'fgsm',        label: 'FGSM',         color: '#F97316' },
  { id: 'pgd',         label: 'PGD',          color: '#EF4444' },
  { id: 'cw',          label: 'C&W',          color: '#EC4899' },
  { id: 'deepfool',    label: 'DeepFool',     color: '#F59E0B' },
  { id: 'gaussian',    label: 'Gaussian',     color: '#3B82F6' },
  { id: 'spoof_gnss',  label: 'GNSS spoof',   color: '#DC2626' },
  { id: 'jam_link',    label: 'Jam link',     color: '#7C2D12' },
  { id: 'label_flip',  label: 'Label flip',   color: '#A855F7' },
]

const DEFENSE_COLOR: Record<string, string> = {
  no_def:    '#DC2626',
  caf_cnn:   '#F59E0B',
  seq2seq:   '#0F8B8D',
  framework: '#1D4ED8',
}

function sessionFromStorage(): string {
  const existing = sessionStorage.getItem('uav_fleet_session')
  if (existing) return existing
  const fresh = `live-${Math.random().toString(36).slice(2, 10)}`
  sessionStorage.setItem('uav_fleet_session', fresh)
  return fresh
}

export default function FleetDemo() {
  const [sessionId, setSessionId] = useState<string>(sessionFromStorage)
  const [nUavs, setNUavs] = useState(3)
  const [snapshot, setSnapshot] = useState<FleetSnapshot | null>(null)
  const [running, setRunning] = useState(false)
  const [jsDb, setJsDb] = useState(10)
  const [perUavAttack, setPerUavAttack] = useState<Record<string, string>>({})
  const [err, setErr] = useState<string | null>(null)
  const [uploadInfo, setUploadInfo] = useState<string | null>(null)
  const tickRef = useRef<number | null>(null)

  const doReset = useCallback(async (n: number) => {
    setErr(null)
    try {
      const r = await fleetReset({ session_id: sessionId, n_uavs: n })
      setSnapshot({
        session_id: r.session_id, js_db: jsDb, fleet_mcr: 1.0,
        n_completed: 0, n_in_flight: r.n_uavs, n_failed: 0,
        uavs: r.uavs,
      })
      setPerUavAttack({})
    } catch (e) {
      setErr(String(e))
    }
  }, [sessionId, jsDb])

  useEffect(() => { doReset(nUavs) }, [doReset, nUavs])

  const doStep = useCallback(async () => {
    try {
      const r = await fleetStep({
        session_id: sessionId, per_uav_attack: perUavAttack,
        js_db: jsDb, dt_s: 1.0,
      })
      setSnapshot(r)
    } catch (e) {
      setErr(String(e))
    }
  }, [sessionId, perUavAttack, jsDb])

  useEffect(() => {
    if (!running) return
    tickRef.current = window.setInterval(doStep, 1000)
    return () => { if (tickRef.current) window.clearInterval(tickRef.current) }
  }, [running, doStep])

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setRunning(false); setErr(null); setUploadInfo(null)
    try {
      const r = await fleetUpload(file)
      setSessionId(r.session_id)
      sessionStorage.setItem('uav_fleet_session', r.session_id)
      setSnapshot({
        session_id: r.session_id, js_db: jsDb, fleet_mcr: 1.0,
        n_completed: 0, n_in_flight: r.n_uavs, n_failed: 0,
        uavs: r.uavs,
      })
      setPerUavAttack({})
      setUploadInfo(`Loaded ${r.n_uavs} UAVs from ${file.name}`)
    } catch (e) {
      setErr(String(e))
    }
  }

  const uavs = snapshot?.uavs ?? []

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-display font-bold flex items-center gap-2">
            <Plane className="w-5 h-5 text-accent-blue" /> Live Fleet Demo
          </h1>
          <p className="text-xs text-text-secondary mt-1 max-w-3xl">
            Multi-UAV simulator — inject attacks per-UAV, watch detection + fallback react in real time.
            Upload your own fleet bundle (or download the sample pack to see the schema). Steps run at 1 Hz.
          </p>
        </div>
        <div className="flex flex-col gap-1 text-[10px] font-mono text-text-secondary text-right">
          <span>session: <span className="text-text-primary">{sessionId}</span></span>
          <span>{snapshot?.n_completed ?? 0} done · {snapshot?.n_in_flight ?? 0} flying · {snapshot?.n_failed ?? 0} failed</span>
        </div>
      </div>

      <PageGuide
        title="How to use the Live Fleet Demo"
        steps={[
          { title: 'Choose fleet size', desc: 'Default 3 UAVs; up to 12. Each has its own kind (delivery/patrol/search) + defense config.' },
          { title: 'Adjust ambient J/S', desc: 'Slider sets the global jamming-to-signal ratio every UAV faces. Higher = harder for all defenses.' },
          { title: 'Pick a per-UAV attack', desc: 'Each tile has a dropdown — pick none, FGSM, PGD, CW, DeepFool, GNSS spoof, link jam, label flip, or Gaussian noise.' },
          { title: 'Play', desc: 'Step the simulator at 1 Hz. Watch the autopilot mode flip (nominal → gnss_degraded → rtl) and the MCR adjust per UAV.' },
          { title: 'Upload your own bundle', desc: 'Download the sample pack first to see the schema, then re-upload your edited version for a custom fleet.' },
        ]}
        tip="The defense config defaults to 'framework' (M1+M4+M6+M7). Try setting one UAV to 'no_def' and another to 'framework' under the same C&W attack — watch the framework hold and the no-def UAV's MCR collapse."
      />

      {/* Controls */}
      <div className="bg-bg-card rounded-xl p-4 flex flex-wrap items-center gap-3">
        <button onClick={() => setRunning(!running)} disabled={!snapshot}
                className={`flex items-center gap-1.5 px-3 py-2 rounded-md text-xs font-medium ${
                  running ? 'bg-accent-amber text-white' : 'bg-accent-blue text-white hover:bg-accent-blue/90'
                } disabled:opacity-50`}>
          {running ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
          {running ? 'Pause' : 'Play (1 Hz)'}
        </button>

        <button onClick={() => { setRunning(false); doReset(nUavs); setUploadInfo(null) }}
                className="flex items-center gap-1.5 px-3 py-2 rounded-md text-xs font-medium bg-bg-secondary border border-bg-card/40 hover:border-accent-blue/40">
          <RotateCcw className="w-3.5 h-3.5" /> Reset fleet
        </button>

        <div className="flex items-center gap-2 text-xs">
          <label className="text-text-secondary">Fleet size</label>
          <select value={nUavs} onChange={(e) => setNUavs(parseInt(e.target.value, 10))}
                  className="bg-bg-secondary border border-bg-card/60 rounded px-2 py-1 text-xs font-mono">
            {[3, 5, 8, 12].map((n) => <option key={n} value={n}>{n}</option>)}
          </select>
        </div>

        <div className="flex items-center gap-2 flex-1 min-w-[200px]">
          <label className="text-xs text-text-secondary font-mono">J/S</label>
          <input type="range" min={0} max={40} value={jsDb} onChange={(e) => setJsDb(parseInt(e.target.value, 10))}
                 className="flex-1 accent-accent-orange" />
          <span className="text-xs font-mono w-12 text-right">{jsDb} dB</span>
        </div>

        <a href={fleetSamplePackUrl()} download
           className="flex items-center gap-1.5 px-3 py-2 rounded-md text-xs font-medium bg-bg-secondary border border-bg-card/40 hover:border-accent-blue/40">
          <Download className="w-3.5 h-3.5" /> Sample pack
        </a>

        <label className="flex items-center gap-1.5 px-3 py-2 rounded-md text-xs font-medium bg-accent-orange/15 text-accent-orange border border-accent-orange/30 hover:bg-accent-orange/25 cursor-pointer">
          <Upload className="w-3.5 h-3.5" /> Upload fleet
          <input type="file" accept=".json,application/json" onChange={handleUpload} className="hidden" />
        </label>
      </div>

      {uploadInfo && (
        <div className="px-3 py-1.5 bg-accent-green/10 border border-accent-green/30 rounded-md text-xs text-accent-green font-mono">
          {uploadInfo}
        </div>
      )}
      {err && (
        <div className="px-3 py-2 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red flex items-center gap-2">
          <AlertCircle className="w-3.5 h-3.5" />{err}
        </div>
      )}

      {/* Aggregate fleet MCR */}
      {snapshot && (
        <div className="bg-bg-card rounded-xl p-4">
          <div className="flex items-baseline justify-between mb-1">
            <h2 className="text-sm font-semibold">Aggregate fleet MCR</h2>
            <span className={`text-2xl font-display font-bold ${
              snapshot.fleet_mcr >= 0.90 ? 'text-accent-green' :
              snapshot.fleet_mcr >= 0.80 ? 'text-accent-amber' : 'text-accent-red'
            }`}>
              {(snapshot.fleet_mcr * 100).toFixed(1)}%
            </span>
          </div>
          <div className="h-2 bg-bg-secondary rounded overflow-hidden">
            <div className="h-full bg-accent-blue transition-all"
                 style={{ width: `${snapshot.fleet_mcr * 100}%` }} />
          </div>
          <p className="text-[10px] text-text-secondary mt-1">
            DO-326A operational floor is MCR ≥ 0.90.
            {' '}{snapshot.n_completed} completed · {snapshot.n_in_flight} in flight · {snapshot.n_failed} failed
          </p>
        </div>
      )}

      {/* Per-UAV grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {uavs.map((u) => (
          <UAVCard key={u.uav_id} uav={u}
                   attack={perUavAttack[u.uav_id] ?? 'none'}
                   onAttackChange={(a) => setPerUavAttack({ ...perUavAttack, [u.uav_id]: a })} />
        ))}
      </div>
    </div>
  )
}

function UAVCard({ uav, attack, onAttackChange }: {
  uav: FleetUAV; attack: string; onAttackChange: (a: string) => void
}) {
  const modeColor = uav.autopilot_mode === 'nominal' ? 'text-accent-green'
                  : uav.autopilot_mode === 'gnss_degraded' ? 'text-accent-amber'
                  : 'text-accent-red'
  const completedBadge = uav.completed === true ? 'bg-accent-green/15 text-accent-green border-accent-green/30'
                       : uav.completed === false ? 'bg-accent-red/15 text-accent-red border-accent-red/30'
                       : 'bg-bg-secondary text-text-secondary border-bg-card/40'
  const completedLabel = uav.completed === true ? 'done' : uav.completed === false ? 'failed' : 'flying'

  return (
    <div className={`bg-bg-card rounded-xl p-3 border-t-2`}
         style={{ borderTopColor: DEFENSE_COLOR[uav.defense] ?? '#1D4ED8' }}>
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-1.5">
          <Plane className="w-3.5 h-3.5 text-accent-blue" />
          <span className="text-sm font-semibold">{uav.uav_id}</span>
          <span className="text-[9px] font-mono text-text-secondary">· {uav.kind}</span>
        </div>
        <span className={`text-[9px] font-mono uppercase px-1.5 py-0.5 rounded border ${completedBadge}`}>
          {completedLabel}
        </span>
      </div>

      <div className="text-[10px] font-mono text-text-secondary mb-2">
        defense: <span className="text-text-primary">{uav.defense}</span>
      </div>

      <div className="space-y-1.5">
        <Meter label="mission" value={uav.mission_progress_pct} color="#3B82F6" />
        <Meter label="battery" value={uav.battery_pct} color={uav.battery_pct < 30 ? '#DC2626' : '#22C55E'} />
        <Meter label="link"    value={uav.link_quality_pct} color={uav.link_quality_pct < 30 ? '#DC2626' : '#22C55E'} />
        <Meter label="spoof" value={uav.gnss_spoof_confidence * 100}
               color={uav.gnss_spoof_confidence > 0.5 ? '#DC2626' : '#94A3B8'} reverse />
      </div>

      <div className="mt-2 flex items-center justify-between text-[10px] font-mono">
        <span className="text-text-secondary">autopilot:</span>
        <span className={modeColor}>{uav.autopilot_mode}</span>
      </div>

      <div className="mt-2 pt-2 border-t border-bg-card/40">
        <label className="text-[10px] text-text-secondary block mb-1">inject attack</label>
        <select value={attack} onChange={(e) => onAttackChange(e.target.value)}
                disabled={uav.completed !== null}
                className="w-full bg-bg-secondary border border-bg-card/60 rounded px-2 py-1 text-xs font-mono disabled:opacity-50">
          {ATTACK_CHOICES.map((a) => (
            <option key={a.id} value={a.id}>{a.label}</option>
          ))}
        </select>
        {uav.last_attack !== 'none' && (
          <div className="mt-1 flex items-center gap-1.5 text-[10px] font-mono">
            <span className="text-text-secondary">last:</span>
            <span style={{ color: ATTACK_CHOICES.find((c) => c.id === uav.last_attack)?.color }}>
              {uav.last_attack}
            </span>
            <span className={`ml-auto ${uav.attack_caught ? 'text-accent-green' : 'text-accent-red'}`}>
              {uav.attack_caught ? '✓ caught' : '✗ missed'}
            </span>
          </div>
        )}
      </div>
    </div>
  )
}

function Meter({ label, value, color, reverse = false }: {
  label: string; value: number; color: string; reverse?: boolean
}) {
  const pct = Math.max(0, Math.min(100, value))
  return (
    <div>
      <div className="flex items-center justify-between text-[9px] font-mono text-text-secondary">
        <span>{label}</span>
        <span className="text-text-primary">{pct.toFixed(0)}%</span>
      </div>
      <div className={`h-1 bg-bg-secondary rounded overflow-hidden ${reverse ? '' : ''}`}>
        <div className="h-full transition-all" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
    </div>
  )
}
