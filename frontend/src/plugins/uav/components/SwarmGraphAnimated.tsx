import { useEffect, useState } from 'react'
import type { SwarmSnapshot } from '../api'

interface Props { snapshots: SwarmSnapshot[]; autoplay?: boolean; intervalMs?: number }

const POS: Record<string, { x: number; y: number }> = {
  u1: { x: 60,  y: 60  },
  u2: { x: 160, y: 30  },
  u3: { x: 260, y: 60  },
  p:  { x: 160, y: 160 },
  b:  { x: 200, y: 90  },
}

const EDGE_COLOR: Record<string, string> = {
  trust:   'rgb(var(--color-accent-green))',
  jammed:  'rgb(var(--color-accent-orange))',
  hostile: 'rgb(var(--color-accent-red))',
}

export default function SwarmGraphAnimated({ snapshots, autoplay = true, intervalMs = 1800 }: Props) {
  const [idx, setIdx] = useState(0)
  useEffect(() => {
    if (!autoplay) return
    const id = setInterval(() => setIdx((i) => (i + 1) % snapshots.length), intervalMs)
    return () => clearInterval(id)
  }, [autoplay, intervalMs, snapshots.length])

  const snap = snapshots[idx]
  if (!snap) return null

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-xs">
        <span className="font-mono text-text-secondary">{snap.label}</span>
        <div className="flex gap-1">
          {snapshots.map((_, i) => (
            <button
              key={i} onClick={() => setIdx(i)}
              className={`w-2 h-2 rounded-full transition-colors ${i === idx ? 'bg-accent-blue' : 'bg-bg-card hover:bg-text-secondary/40'}`}
              aria-label={`Time slice ${i + 1}`}
            />
          ))}
        </div>
      </div>
      <svg viewBox="0 0 320 200" className="w-full bg-bg-secondary/40 rounded-md border border-bg-card/50">
        {snap.edges.map((e, i) => {
          const a = POS[e.src]; const b = POS[e.dst]; if (!a || !b) return null
          return (
            <line
              key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
              stroke={EDGE_COLOR[e.kind]}
              strokeWidth={e.kind === 'trust' ? 1.5 : 2}
              strokeDasharray={e.kind === 'trust' ? undefined : '4 3'}
              opacity={e.kind === 'trust' ? 0.8 : 0.95}
            />
          )
        })}
        {snap.nodes.map((n) => {
          const p = POS[n.id]; if (!p) return null
          const fill = n.kind === 'intruder' ? 'rgb(var(--color-accent-red))'
                     : n.kind === 'droneport' ? 'rgb(var(--color-accent-blue))'
                     : 'rgb(var(--color-accent-green))'
          return (
            <g key={n.id}>
              {n.kind === 'droneport' ? (
                <rect x={p.x - 10} y={p.y - 10} width={20} height={20} fill={fill} rx={3} />
              ) : (
                <circle cx={p.x} cy={p.y} r={9} fill={fill} />
              )}
              <text x={p.x} y={p.y - 14} textAnchor="middle"
                    fontSize="9" fill="rgb(var(--color-text-secondary))">{n.label}</text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}
