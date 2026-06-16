import type { SatelliteFix } from '../api'

interface Props { satellites: SatelliteFix[]; size?: number }

export default function SkyPlotGNSS({ satellites, size = 240 }: Props) {
  const cx = size / 2, cy = size / 2, R = size / 2 - 14

  const toXY = (azDeg: number, elDeg: number) => {
    const r = R * (1 - elDeg / 90)
    const azRad = (azDeg - 90) * Math.PI / 180
    return { x: cx + r * Math.cos(azRad), y: cy + r * Math.sin(azRad) }
  }

  return (
    <svg viewBox={`0 0 ${size} ${size}`} className="w-full max-w-[280px] bg-bg-secondary/40 rounded-md border border-bg-card/50">
      {[0.33, 0.67, 1.0].map((f, i) => (
        <circle key={i} cx={cx} cy={cy} r={R * f} fill="none"
                stroke="rgb(var(--color-bg-card))" strokeWidth={0.6} />
      ))}
      <line x1={cx} y1={cy - R} x2={cx} y2={cy + R} stroke="rgb(var(--color-bg-card))" strokeWidth={0.6} />
      <line x1={cx - R} y1={cy} x2={cx + R} y2={cy} stroke="rgb(var(--color-bg-card))" strokeWidth={0.6} />
      <text x={cx} y={cy - R - 3} fontSize="9" textAnchor="middle" fill="rgb(var(--color-text-secondary))">N</text>
      <text x={cx + R + 6} y={cy + 3} fontSize="9" fill="rgb(var(--color-text-secondary))">E</text>
      <text x={cx} y={cy + R + 10} fontSize="9" textAnchor="middle" fill="rgb(var(--color-text-secondary))">S</text>
      <text x={cx - R - 10} y={cy + 3} fontSize="9" fill="rgb(var(--color-text-secondary))">W</text>
      {satellites.map((s) => {
        const { x, y } = toXY(s.azimuth_deg, s.elevation_deg)
        const r = 4 + s.cno_db_hz / 18
        const fill = s.spoofed ? 'rgb(var(--color-accent-red))' : 'rgb(var(--color-accent-blue))'
        return (
          <g key={s.sv}>
            <circle cx={x} cy={y} r={r} fill={fill} fillOpacity={0.85} />
            <text x={x} y={y - r - 2} fontSize="8" textAnchor="middle"
                  fill="rgb(var(--color-text-primary))">{s.sv}</text>
            {s.spoofed && (
              <circle cx={x} cy={y} r={r + 3} fill="none"
                      stroke="rgb(var(--color-accent-red))" strokeWidth={1} strokeDasharray="2 2" />
            )}
          </g>
        )
      })}
    </svg>
  )
}
