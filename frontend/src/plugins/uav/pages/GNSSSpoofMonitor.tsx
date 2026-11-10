import { useEffect, useMemo, useState, useCallback } from 'react'
import { Radar, RefreshCw, Sliders, Shuffle, Loader2, Antenna, AlertTriangle } from 'lucide-react'
import PageGuide from '../../../components/PageGuide'
import ExportMenu from '../../../components/ExportMenu'
import SkyPlotGNSS from '../components/SkyPlotGNSS'
import DatasetSelector from '../components/DatasetSelector'
import { fetchGNSS } from '../api'
import type { GNSSResponse, GNSSQuery } from '../api'

const DEFAULT_QUERY: GNSSQuery = {
  seed: 0,               // pinned seed → reproducible, "Resample" bumps it
  receiver_model: 'gp_software',
  jamming_db: 0,
  n_spoofed: 2,
  spoof_threshold: 0.5,
}

const RECEIVER_FALLBACK = [
  { id: 'gp_software',      label: 'GP-software',        nominal_cno: 45, jam_rejection_db:  0, pvt_collapse_js_db: 22 },
  { id: 'ublox_f9p_sim',    label: 'u-blox F9P (sim)',   nominal_cno: 47, jam_rejection_db:  8, pvt_collapse_js_db: 28 },
  { id: 'novatel_oem7_sim', label: 'NovAtel OEM7 (sim)', nominal_cno: 49, jam_rejection_db: 12, pvt_collapse_js_db: 32 },
]

export default function GNSSSpoofMonitor() {
  const [data, setData] = useState<GNSSResponse | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [query, setQuery] = useState<GNSSQuery>(DEFAULT_QUERY)
  const [showLabels, setShowLabels] = useState(true)
  const [sortKey, setSortKey] = useState<'sv' | 'cno' | 'conf'>('conf')

  const load = useCallback(async (q: GNSSQuery) => {
    setLoading(true); setErr(null)
    try {
      const r = await fetchGNSS(q)
      setData(r)
    } catch (e) {
      setErr(String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load(query) }, [load, query])

  const receivers = data?.receiver_catalog ?? RECEIVER_FALLBACK
  const activeReceiver = receivers.find((r) => r.id === query.receiver_model) ?? receivers[0]

  const resample = () => setQuery((q) => ({ ...q, seed: Math.floor(Math.random() * 1_000_000_000) }))
  const reset = () => setQuery(DEFAULT_QUERY)
  const set = <K extends keyof GNSSQuery>(k: K, v: GNSSQuery[K]) => setQuery((q) => ({ ...q, [k]: v }))

  const sortedSats = useMemo(() => {
    if (!data) return []
    const s = [...data.satellites]
    if (sortKey === 'sv')   s.sort((a, b) => a.sv.localeCompare(b.sv))
    if (sortKey === 'cno')  s.sort((a, b) => b.cno_db_hz - a.cno_db_hz)
    if (sortKey === 'conf') s.sort((a, b) => b.spoof_confidence - a.spoof_confidence)
    return s
  }, [data, sortKey])

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-display font-bold flex items-center gap-2">
            <Radar className="w-5 h-5 text-accent-blue" /> GNSS Spoof Monitor
          </h1>
          <p className="text-xs text-text-secondary mt-1 max-w-4xl">
            Chapter 6 §6.5.2 — constellation-and-receiver as graph G<sub>t</sub><sup>GNSS</sup>.
            M1 CT-TGNN flags coherent edge-dynamics inconsistencies typical of overlapped-power spoofing
            (TEXBAT scenarios 1, 3, 8). M6 UC-HGP gates the autopilot into GNSS-degraded mode.
            Every control below is <b>live</b> — the physics recomputes on the server per selection.
          </p>
        </div>
        <div className="flex gap-2 items-center">
          <button
            onClick={resample}
            disabled={loading}
            className="text-xs flex items-center gap-1 px-3 py-1.5 rounded-md bg-accent-blue/10 border border-accent-blue/30 text-accent-blue hover:bg-accent-blue/20 disabled:opacity-50"
          >
            {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Shuffle className="w-3.5 h-3.5" />}
            Resample
          </button>
          <button
            onClick={() => load(query)}
            disabled={loading}
            className="text-xs flex items-center gap-1 px-3 py-1.5 rounded-md bg-bg-card border border-bg-card hover:border-accent-blue/40 disabled:opacity-50"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
          <ExportMenu filename="uav-gnss-spoof" />
        </div>
      </div>

      <PageGuide
        title="How to use GNSS Spoof Monitor"
        steps={[
          { title: 'Read the sky plot', desc: 'Each circle is a visible satellite; radius scales with C/N₀ signal strength; red outline = spoof confidence above the threshold you set below.' },
          { title: 'Pick a receiver front-end', desc: 'GP-software (worst case, no rejection), u-blox F9P (8 dB jam-rejection), NovAtel OEM7 (12 dB, best). The nominal C/N₀ and the J/S level at which the PVT collapses change per receiver.' },
          { title: 'Dial the jammer', desc: 'Slide J/S from 0–40 dB. Watch the sky-plot C/N₀ ring shrink and the fleet-disagreement figure climb. When J/S ≥ the receiver\'s PVT-collapse dB, the mode flips to GNSS-degraded even without any spoofed sat.' },
          { title: 'Vary spoofed satellite count', desc: '0 (clean sky), 1 (needle in a haystack), 2 (published TEXBAT default {G03,G05}), up to 8 (whole-sky spoof). Combined with J/S, this drives the graph M1 CT-TGNN sees.' },
          { title: 'Tune spoof-confidence threshold', desc: 'The framework flags a satellite when spoof_confidence ≥ threshold. Lower it and false positives appear; raise it and true spoofs slip through — same operating-curve exercise the paper reports.' },
          { title: 'Resample vs. Refresh', desc: 'Resample = new random seed (fresh statistical sample of the same physics). Refresh = re-run with the same seed (should return identical numbers — reproducibility check).' },
        ]}
        tip="The CAF-CNN baseline operates per-satellite — it misses coordinated spoofs on subsets. M1 CT-TGNN integrates the constellation graph dynamics, which is why it catches them."
      />

      <DatasetSelector page="/uav/gnss" />

      {/* CONTROL PANEL --------------------------------------------------- */}
      <div className="bg-bg-card rounded-xl p-4 space-y-3">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <Sliders className="w-4 h-4 text-accent-blue" /> Controls
          <span className="ml-auto text-[10px] font-mono text-text-secondary">
            seed = {data?.controls?.seed ?? query.seed ?? '—'} · reproducible per exact settings
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Receiver model */}
          <div>
            <label className="flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-text-secondary mb-1">
              <Antenna className="w-3 h-3" /> Receiver front-end
            </label>
            <select
              value={query.receiver_model}
              onChange={(e) => set('receiver_model', e.target.value)}
              className="w-full bg-bg-secondary border border-bg-card rounded px-2 py-1.5 text-xs font-mono"
            >
              {receivers.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.label} — rej {r.jam_rejection_db} dB · collapse {r.pvt_collapse_js_db} dB
                </option>
              ))}
            </select>
            {activeReceiver && (
              <p className="text-[10px] text-text-secondary mt-1">
                Nominal C/N₀ {activeReceiver.nominal_cno} dB-Hz · loses PVT above {activeReceiver.pvt_collapse_js_db} dB J/S.
              </p>
            )}
          </div>

          {/* Jamming slider */}
          <div>
            <label className="flex items-center justify-between text-[11px] uppercase tracking-wider text-text-secondary mb-1">
              <span>Jamming J/S</span>
              <span className="font-mono normal-case tracking-normal text-text-primary">{Number(query.jamming_db ?? 0).toFixed(0)} dB</span>
            </label>
            <input
              type="range" min={0} max={40} step={1}
              value={Number(query.jamming_db ?? 0)}
              onChange={(e) => set('jamming_db', Number(e.target.value))}
              className="w-full accent-accent-blue"
            />
            <p className="text-[10px] text-text-secondary mt-1">
              Effective J/S (after receiver rejection) ={' '}
              <span className="font-mono text-text-primary">
                {data?.controls?.effective_js_db?.toFixed(1) ?? '—'} dB
              </span>
            </p>
          </div>

          {/* Spoofed sat count */}
          <div>
            <label className="flex items-center justify-between text-[11px] uppercase tracking-wider text-text-secondary mb-1">
              <span>Spoofed satellites</span>
              <span className="font-mono normal-case tracking-normal text-text-primary">{query.n_spoofed ?? 0} / 8</span>
            </label>
            <input
              type="range" min={0} max={8} step={1}
              value={Number(query.n_spoofed ?? 0)}
              onChange={(e) => set('n_spoofed', Number(e.target.value))}
              className="w-full accent-accent-orange"
            />
            <p className="text-[10px] text-text-secondary mt-1">
              0 = clean sky · 2 = TEXBAT baseline · 8 = whole-sky spoof
            </p>
          </div>

          {/* Confidence threshold */}
          <div>
            <label className="flex items-center justify-between text-[11px] uppercase tracking-wider text-text-secondary mb-1">
              <span>Spoof-conf. threshold</span>
              <span className="font-mono normal-case tracking-normal text-text-primary">{Number(query.spoof_threshold ?? 0.5).toFixed(2)}</span>
            </label>
            <input
              type="range" min={0.05} max={0.95} step={0.05}
              value={Number(query.spoof_threshold ?? 0.5)}
              onChange={(e) => set('spoof_threshold', Number(e.target.value))}
              className="w-full accent-accent-red"
            />
            <p className="text-[10px] text-text-secondary mt-1">
              Framework flags SV when M1 conf ≥ threshold
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 pt-2 border-t border-bg-card/40">
          <label className="text-[11px] text-text-secondary flex items-center gap-1.5 cursor-pointer">
            <input
              type="checkbox" checked={showLabels}
              onChange={(e) => setShowLabels(e.target.checked)}
              className="accent-accent-blue"
            />
            Show SV labels on sky plot
          </label>
          <button
            onClick={reset}
            className="text-[11px] text-text-secondary hover:text-accent-red ml-auto"
          >
            Reset to defaults
          </button>
        </div>

        {data?.controls?.pvt_collapsed && (
          <div className="flex items-center gap-2 text-xs text-accent-red bg-accent-red/10 border border-accent-red/30 rounded px-3 py-2">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            PVT collapsed — J/S {Number(query.jamming_db ?? 0).toFixed(0)} dB ≥ receiver PVT-collapse threshold
            ({data.controls.pvt_collapse_js_db} dB). Mode forced to GNSS-degraded regardless of spoof activity.
          </div>
        )}
      </div>

      {err && (
        <div className="p-3 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red">
          {err}
        </div>
      )}

      {!data ? (
        <div className="text-text-secondary text-sm">Loading…</div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-bg-card rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-sm font-semibold">Sky plot</h2>
              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                  data.mode === 'nominal'
                    ? 'bg-accent-green/10 text-accent-green'
                    : 'bg-accent-red/10 text-accent-red'
                }`}
              >
                {data.mode}
              </span>
            </div>
            <SkyPlotGNSS satellites={data.satellites} showLabels={showLabels} />
            <p className="text-[10px] text-text-secondary mt-2">
              Radius ∝ C/N₀ · red = flagged spoofed · dashed outline = M1 spoof-confidence above {Number(query.spoof_threshold ?? 0.5).toFixed(2)}
            </p>
          </div>

          <div className="bg-bg-card rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-sm font-semibold">Per-SV detail</h2>
              <div className="flex items-center gap-1 text-[10px]">
                <span className="text-text-secondary mr-1">sort</span>
                {(['sv', 'cno', 'conf'] as const).map((k) => (
                  <button
                    key={k} onClick={() => setSortKey(k)}
                    className={`px-2 py-0.5 rounded font-mono ${
                      sortKey === k
                        ? 'bg-accent-blue/15 text-accent-blue'
                        : 'text-text-secondary hover:text-text-primary'
                    }`}
                  >
                    {k === 'sv' ? 'SV' : k === 'cno' ? 'C/N₀' : 'conf'}
                  </button>
                ))}
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs font-mono">
                <thead className="text-text-secondary text-[10px] uppercase tracking-wider border-b border-bg-card/50">
                  <tr>
                    <th className="text-left py-1 pr-2">SV</th>
                    <th className="text-right py-1 pr-2">Az</th>
                    <th className="text-right py-1 pr-2">El</th>
                    <th className="text-right py-1 pr-2">C/N₀</th>
                    <th className="text-right py-1 pr-2">Spoof conf.</th>
                    <th className="text-center py-1">Flag</th>
                  </tr>
                </thead>
                <tbody>
                  {sortedSats.map((s) => (
                    <tr key={s.sv} className={s.spoofed ? 'bg-accent-red/5' : ''}>
                      <td className="py-1 pr-2 font-semibold">{s.sv}</td>
                      <td className="py-1 pr-2 text-right">{s.azimuth_deg}°</td>
                      <td className="py-1 pr-2 text-right">{s.elevation_deg}°</td>
                      <td className="py-1 pr-2 text-right">{s.cno_db_hz.toFixed(1)}</td>
                      <td
                        className={`py-1 pr-2 text-right ${
                          s.flagged ?? s.spoofed ? 'text-accent-red font-semibold' : ''
                        }`}
                      >
                        {s.spoof_confidence.toFixed(3)}
                      </td>
                      <td className="py-1 text-center">{s.flagged ?? s.spoofed ? '⚠' : '·'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="mt-3 pt-3 border-t border-bg-card/40 text-xs space-y-1.5 font-mono">
              <div className="flex justify-between">
                <span className="text-text-secondary">satellites flagged / spoofed</span>
                <span className="font-semibold">
                  {data.n_flagged_satellites ?? '—'} / {data.n_spoofed_satellites ?? '—'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-text-secondary">cross-droneport fleet disagreement</span>
                <span className="font-semibold">{data.fleet_disagreement.toFixed(3)}</span>
              </div>
              {data.fallback && (
                <div className="flex justify-between">
                  <span className="text-text-secondary">M6 fallback mode</span>
                  <span className="font-semibold text-accent-orange">{data.fallback}</span>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
