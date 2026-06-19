import { useEffect, useState } from 'react'
import { Radar, RefreshCw } from 'lucide-react'
import PageGuide from '../../../components/PageGuide'
import SkyPlotGNSS from '../components/SkyPlotGNSS'
import DatasetSelector from '../components/DatasetSelector'
import { fetchGNSS } from '../api'
import type { GNSSResponse } from '../api'

export default function GNSSSpoofMonitor() {
  const [data, setData] = useState<GNSSResponse | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const load = () => fetchGNSS().then(setData).catch((e) => setErr(String(e)))
  useEffect(() => { load() }, [])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-display font-bold flex items-center gap-2">
            <Radar className="w-5 h-5 text-accent-blue" /> GNSS Spoof Monitor
          </h1>
          <p className="text-xs text-text-secondary mt-1">
            Chapter 6 §6.5.2 — constellation-and-receiver as graph G<sub>t</sub><sup>GNSS</sup>.
            M1 CT-TGNN flags coherent edge-dynamics inconsistencies typical of overlapped-power spoofing
            (TEXBAT scenarios 1, 3, 8). M6 UC-HGP gates the autopilot into GNSS-degraded mode.
          </p>
        </div>
        <button onClick={load} className="text-xs flex items-center gap-1 text-accent-blue hover:text-accent-orange">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      <PageGuide
        title="How to use GNSS Spoof Monitor"
        steps={[
          { title: 'Read the sky plot', desc: 'Each circle is a visible satellite; radius scales with C/N₀ signal strength; red outline = spoof confidence above 0.5.' },
          { title: 'Scan the per-SV table', desc: 'Right panel lists every satellite with azimuth, elevation, C/N₀, and spoof confidence. Spoofed rows are highlighted red.' },
          { title: 'Watch fleet disagreement', desc: 'Cross-droneport disagreement score — high values mean different droneports see different fixes, a M2 FedLLM-API signal of regional spoofing.' },
          { title: 'Check autopilot mode', desc: 'When the framework crosses the M6 UC-HGP uncertainty threshold, mode flips from "nominal" to "GNSS-degraded" and the fallback (INS + visual odometry) activates.' },
          { title: 'Refresh to resample', desc: 'Each visit recomputes — useful to show the panel that spoofed satellites cluster (not random false positives).' },
        ]}
        tip="The CAF-CNN baseline operates per-satellite — it misses coordinated spoofs on subsets. M1 CT-TGNN integrates the constellation graph dynamics, which is why it catches them."
      />

      <DatasetSelector page="/uav/gnss" />

      {err && <div className="p-3 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red">{err}</div>}
      {!data ? <div className="text-text-secondary text-sm">Loading…</div> : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-bg-card rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-sm font-semibold">Sky plot</h2>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                data.mode === 'nominal' ? 'bg-accent-green/10 text-accent-green' : 'bg-accent-red/10 text-accent-red'
              }`}>{data.mode}</span>
            </div>
            <SkyPlotGNSS satellites={data.satellites} />
            <p className="text-[10px] text-text-secondary mt-2">
              Radius ∝ C/N₀ · red = flagged spoofed · dashed outline = M1 spoof-confidence above 0.5
            </p>
          </div>

          <div className="bg-bg-card rounded-xl p-4">
            <h2 className="text-sm font-semibold mb-2">Per-SV detail</h2>
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
                  {data.satellites.map((s) => (
                    <tr key={s.sv} className={s.spoofed ? 'bg-accent-red/5' : ''}>
                      <td className="py-1 pr-2 font-semibold">{s.sv}</td>
                      <td className="py-1 pr-2 text-right">{s.azimuth_deg}°</td>
                      <td className="py-1 pr-2 text-right">{s.elevation_deg}°</td>
                      <td className="py-1 pr-2 text-right">{s.cno_db_hz}</td>
                      <td className={`py-1 pr-2 text-right ${s.spoofed ? 'text-accent-red font-semibold' : ''}`}>
                        {s.spoof_confidence.toFixed(3)}
                      </td>
                      <td className="py-1 text-center">{s.spoofed ? '⚠' : '·'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="mt-3 pt-3 border-t border-bg-card/40 text-xs space-y-1.5 font-mono">
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
