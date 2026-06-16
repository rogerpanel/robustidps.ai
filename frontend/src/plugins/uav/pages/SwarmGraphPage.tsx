import { useEffect, useState } from 'react'
import { Network } from 'lucide-react'
import SwarmGraphAnimated from '../components/SwarmGraphAnimated'
import { fetchSwarmSnapshot } from '../api'
import type { SwarmSnapshot } from '../api'

export default function SwarmGraphPage() {
  const [snaps, setSnaps] = useState<SwarmSnapshot[]>([])
  const [err, setErr] = useState<string | null>(null)
  useEffect(() => { fetchSwarmSnapshot().then((d) => setSnaps(d.snapshots)).catch((e) => setErr(String(e))) }, [])

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-display font-bold flex items-center gap-2">
          <Network className="w-5 h-5 text-accent-blue" /> Swarm Graph Gₜ
        </h1>
        <p className="text-xs text-text-secondary mt-1">
          Chapter 6 §6.3 — the UAV swarm as a continuous-time dynamic graph integrated by M1 CT-TGNN.
          Three time slices: clean topology, jamming event (loss of u₂–u₃ and u₃–p links), intruder insertion
          (false-neighbour hostile edges to u₂ and u₃).
        </p>
      </div>

      {err && <div className="p-3 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red">{err}</div>}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {snaps.map((s) => (
          <div key={s.t} className="bg-bg-card rounded-xl p-4">
            <SwarmGraphAnimated snapshots={[s]} autoplay={false} />
          </div>
        ))}
      </div>

      {snaps.length > 0 && (
        <div className="bg-bg-card rounded-xl p-4">
          <h2 className="text-sm font-semibold mb-2">Animated trajectory</h2>
          <SwarmGraphAnimated snapshots={snaps} autoplay intervalMs={1800} />
          <p className="text-[10px] text-text-secondary mt-2">
            Edge legend — green: trusted radio link · orange dashed: jammed · red dashed: hostile false neighbour.
            M1 CT-TGNN integrates dh<sub>v</sub>/dt across the entire trajectory rather than discretising at frame boundaries.
          </p>
        </div>
      )}
    </div>
  )
}
