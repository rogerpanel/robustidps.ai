import { useEffect, useState } from 'react'
import { Network, Layers } from 'lucide-react'
import PageGuide from '../../../components/PageGuide'
import ExportMenu from '../../../components/ExportMenu'
import SwarmGraphAnimated from '../components/SwarmGraphAnimated'
import DatasetSelector from '../components/DatasetSelector'
import { fetchSwarmSnapshot } from '../api'
import type { SwarmSnapshot } from '../api'

type ViewMode = 't1' | 't2' | 't3' | 't4' | 'all'

const MODE_META: Record<ViewMode, { label: string; hint: string }> = {
  t1:  { label: 't1 — clean',              hint: 'Baseline topology, no attack surface' },
  t2:  { label: 't2 — jamming',            hint: 'Loss of u₂–u₃ and u₃–p links' },
  t3:  { label: 't3 — intruder',           hint: 'Hostile false-neighbour edges to u₂ and u₃' },
  t4:  { label: 't4 — combined view',      hint: 'All three overlaid — jamming + intruder + trusted core' },
  all: { label: 'compare all four',        hint: 'Side-by-side grid — pick a slice to zoom' },
}

export default function SwarmGraphPage() {
  const [snaps, setSnaps] = useState<SwarmSnapshot[]>([])
  const [err, setErr] = useState<string | null>(null)
  const [mode, setMode] = useState<ViewMode>('all')

  useEffect(() => {
    fetchSwarmSnapshot()
      .then((d) => setSnaps(d.snapshots))
      .catch((e) => setErr(String(e)))
  }, [])

  const pickSlice = (t: number): SwarmSnapshot | null =>
    snaps.find((s) => Math.round(s.t) === t) ?? null

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-display font-bold flex items-center gap-2">
            <Network className="w-5 h-5 text-accent-blue" /> Swarm Graph Gₜ
          </h1>
          <p className="text-xs text-text-secondary mt-1 max-w-4xl">
            Chapter 6 §6.3 — the UAV swarm as a continuous-time dynamic graph integrated by M1 CT-TGNN.
            Four time slices: <b>t1</b> clean topology, <b>t2</b> jamming event (loss of u₂–u₃ and u₃–p links),
            <b>t3</b> intruder insertion (false-neighbour hostile edges to u₂ and u₃), and the new
            <b> t4 combined view</b> — all three states superimposed on the intruder-augmented topology.
          </p>
        </div>
        <ExportMenu filename="uav-swarm-graph" />
      </div>

      <PageGuide
        title="How to use Swarm Graph"
        steps={[
          { title: 'Pick a view mode', desc: 'Segmented control below — inspect one slice (t1..t4) or compare all four side-by-side.' },
          { title: 'Read the three published slices', desc: 't1 = clean topology; t2 = jamming (orange dashed = jammed link); t3 = intruder (red dashed = hostile edge).' },
          { title: 'The new t4 overlay', desc: 't4 superimposes t1 + t2 + t3 on the intruder-augmented node set so you can see the full attack surface in one panel — how the framework must handle jammed AND hostile edges simultaneously.' },
          { title: 'Watch the animation', desc: 'The animated panel loops through all four slices — shows how the framework adapts as the topology degrades and then converges.' },
          { title: 'Node legend', desc: 'Green circles = trusted UAV; blue square = droneport; red circle = intruder UAV.' },
          { title: 'Edge legend', desc: 'Solid green = trusted radio link; orange dashed = jammed; red dashed = hostile.' },
          { title: 'Connect to M1 / M7', desc: 'M1 CT-TGNN integrates dh_v/dt across this trajectory; M7 FedGTD re-weights its Stackelberg policy at each topology change.' },
        ]}
        tip="The t4 combined view is what the Phase-D EW-Bench harness actually feeds M1 CT-TGNN — you can see why per-satellite baselines (CAF-CNN) miss coordinated multi-vector attacks."
      />

      <DatasetSelector page="/uav/swarm" />

      {/* Segmented control ----------------------------------------------- */}
      <div className="bg-bg-card/50 rounded-lg p-1.5 inline-flex flex-wrap gap-1">
        {(['t1', 't2', 't3', 't4', 'all'] as ViewMode[]).map((m) => (
          <button
            key={m}
            onClick={() => setMode(m)}
            title={MODE_META[m].hint}
            className={`text-xs px-3 py-1.5 rounded-md transition-colors inline-flex items-center gap-1.5 ${
              mode === m
                ? 'bg-accent-blue text-white'
                : 'text-text-secondary hover:text-text-primary hover:bg-bg-card'
            }`}
          >
            {m === 'all' && <Layers className="w-3 h-3" />}
            {MODE_META[m].label}
          </button>
        ))}
      </div>

      {err && (
        <div className="p-3 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red">
          {err}
        </div>
      )}

      {/* Panel grid ------------------------------------------------------- */}
      {mode === 'all' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          {snaps.map((s) => (
            <div key={s.t} className="bg-bg-card rounded-xl p-4 space-y-2">
              <SwarmGraphAnimated snapshots={[s]} autoplay={false} />
              {s.description && (
                <p className="text-[10px] text-text-secondary italic">{s.description}</p>
              )}
            </div>
          ))}
        </div>
      ) : (
        (() => {
          const t = mode === 't1' ? 1 : mode === 't2' ? 2 : mode === 't3' ? 3 : 4
          const single = pickSlice(t)
          return single ? (
            <div className="bg-bg-card rounded-xl p-5 max-w-3xl">
              <SwarmGraphAnimated snapshots={[single]} autoplay={false} />
              {single.description && (
                <p className="text-[11px] text-text-secondary italic mt-3">{single.description}</p>
              )}
            </div>
          ) : (
            <div className="text-text-secondary text-sm">Loading…</div>
          )
        })()
      )}

      {snaps.length > 0 && (
        <div className="bg-bg-card rounded-xl p-4">
          <h2 className="text-sm font-semibold mb-2">Animated trajectory</h2>
          <SwarmGraphAnimated snapshots={snaps} autoplay intervalMs={1800} />
          <p className="text-[10px] text-text-secondary mt-2">
            Edge legend — green: trusted radio link · orange dashed: jammed · red dashed: hostile false neighbour.
            M1 CT-TGNN integrates dh<sub>v</sub>/dt across the entire trajectory rather than discretising at frame boundaries.
            The loop now includes t4, the combined-view snapshot that superimposes all attack vectors.
          </p>
        </div>
      )}
    </div>
  )
}
