import { useEffect, useState, useCallback } from 'react'
import { Activity } from 'lucide-react'

const API = import.meta.env.VITE_API_URL || ''

interface PointResult {
  mcr: number
  ci_low: number
  ci_high: number
  above_do_326a: boolean
  label: string
  color: string
}

interface Snapshot {
  js_db: number
  do_326a_threshold: number
  points: Record<string, PointResult>
}

export default function JSOperatingPoint() {
  const [js, setJs] = useState(20)
  const [snap, setSnap] = useState<Snapshot | null>(null)
  const [loading, setLoading] = useState(false)

  const fetchPoint = useCallback(async (jsDb: number) => {
    setLoading(true)
    try {
      const r = await fetch(`${API}/api/uav/ew-bench/operating-point?js_db=${jsDb}`)
      if (r.ok) setSnap(await r.json())
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchPoint(20) }, [fetchPoint])

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newJs = parseInt(e.target.value, 10)
    setJs(newJs)
    fetchPoint(newJs)
  }

  return (
    <div className="bg-bg-card rounded-xl p-4">
      <h2 className="text-sm font-semibold mb-2 flex items-center gap-1.5">
        <Activity className="w-3.5 h-3.5 text-accent-orange" /> Operating point — drag to query
      </h2>
      <p className="text-[10px] text-text-secondary mb-3">
        Set the jamming-to-signal ratio and see how each configuration responds at that operating point.
        DO-326A floor is MCR ≥ 0.90.
      </p>

      <div className="flex items-center gap-3 mb-3">
        <label className="text-xs text-text-secondary font-mono flex-shrink-0">J/S</label>
        <input
          type="range" min={0} max={40} step={1} value={js}
          onChange={handleChange}
          className="flex-1 accent-accent-orange"
        />
        <span className="text-sm font-mono text-text-primary w-14 text-right">
          {js} dB
        </span>
      </div>

      {snap && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2">
          {Object.entries(snap.points).map(([key, p]) => (
            <div key={key}
                 className={`border rounded-md p-2 ${p.above_do_326a
                   ? 'border-accent-green/30 bg-accent-green/5'
                   : 'border-accent-red/30 bg-accent-red/5'}`}>
              <div className="flex items-center gap-1.5 mb-1">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: p.color }} />
                <span className="text-[10px] font-mono text-text-secondary uppercase truncate">{key}</span>
              </div>
              <div className="text-lg font-display font-bold">
                {(p.mcr * 100).toFixed(1)}%
              </div>
              <div className="text-[9px] font-mono text-text-secondary">
                ±{((p.ci_high - p.ci_low) * 50).toFixed(1)} (95% CI)
              </div>
              <div className={`text-[10px] font-mono mt-1 ${
                p.above_do_326a ? 'text-accent-green' : 'text-accent-red'
              }`}>
                {p.above_do_326a ? '✓ DO-326A pass' : '✗ below DO-326A'}
              </div>
            </div>
          ))}
        </div>
      )}
      {loading && <div className="text-[10px] text-text-secondary mt-2">Sampling…</div>}
    </div>
  )
}
