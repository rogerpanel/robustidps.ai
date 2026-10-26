import {
  ComposedChart, Line, Area, XAxis, YAxis, Tooltip, Legend,
  ResponsiveContainer, ReferenceLine, CartesianGrid,
} from 'recharts'
import type { MCRCurve } from '../api'

interface Props {
  curves: MCRCurve[]
  threshold: number
  thresholdLabel: string
  height?: number
}

export default function MCRJSChart({ curves, threshold, thresholdLabel, height = 320 }: Props) {
  const grid = curves[0]?.points.map((_, i) => {
    const row: Record<string, number> = { js_db: curves[0].points[i].js_db }
    curves.forEach((c) => {
      row[c.config_key] = c.points[i].mcr
      row[`${c.config_key}_lo`] = c.points[i].ci_low
      row[`${c.config_key}_hi`] = c.points[i].ci_high
    })
    return row
  }) ?? []

  return (
    <ResponsiveContainer width="100%" height={height}>
      <ComposedChart data={grid} margin={{ top: 12, right: 20, bottom: 28, left: 4 }}>
        <CartesianGrid stroke="rgb(var(--color-bg-card) / 0.5)" strokeDasharray="3 4" />
        <XAxis
          dataKey="js_db" type="number" domain={[0, 40]}
          tick={{ fontSize: 11, fill: 'rgb(var(--color-text-secondary))' }}
          label={{ value: 'Jamming-to-Signal Ratio  J/S  (dB)', position: 'insideBottom', offset: -16,
                   fill: 'rgb(var(--color-text-secondary))', fontSize: 11 }}
        />
        <YAxis
          domain={[0, 1.02]} tick={{ fontSize: 11, fill: 'rgb(var(--color-text-secondary))' }}
          label={{ value: 'Mission-Completion-Rate', angle: -90, position: 'insideLeft',
                   fill: 'rgb(var(--color-text-secondary))', fontSize: 11 }}
        />
        <Tooltip
          contentStyle={{ background: 'rgb(var(--color-bg-card))', border: '1px solid rgb(var(--color-bg-card))', borderRadius: 6, fontSize: 11 }}
          formatter={(v: number) => (typeof v === 'number' ? v.toFixed(3) : v)}
          labelFormatter={(v) => `J/S = ${v} dB`}
        />
        <Legend verticalAlign="top" wrapperStyle={{ fontSize: 11, paddingBottom: 6 }} />
        <ReferenceLine
          y={threshold} stroke="rgb(var(--color-accent-orange))" strokeDasharray="6 3"
          label={{ value: `${thresholdLabel}: ${threshold.toFixed(2)}`, position: 'insideTopRight',
                   fill: 'rgb(var(--color-accent-orange))', fontSize: 10 }}
        />
        {curves.map((c) => (
          <Area
            key={`${c.config_key}_ci`} type="monotone"
            dataKey={`${c.config_key}_hi`} stroke="none" fill={c.color} fillOpacity={0.06}
            legendType="none" name={`${c.label} CI`}
          />
        ))}
        {curves.map((c) => (
          <Line
            key={c.config_key} type="monotone" dataKey={c.config_key} name={c.label}
            stroke={c.color} strokeWidth={2.2} dot={{ r: 2.5 }} activeDot={{ r: 4 }}
          />
        ))}
      </ComposedChart>
    </ResponsiveContainer>
  )
}
