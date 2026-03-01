import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

interface Props {
  confidences: number[]
}

export default function ConfidenceHistogram({ confidences }: Props) {
  // Build 10-bin histogram
  const bins = Array.from({ length: 10 }, (_, i) => ({
    range: `${(i * 10).toFixed(0)}-${((i + 1) * 10).toFixed(0)}%`,
    count: 0,
  }))

  for (const c of confidences) {
    const idx = Math.min(Math.floor(c * 10), 9)
    bins[idx].count++
  }

  return (
    <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
      <h3 className="text-sm font-medium text-text-secondary mb-4">Confidence Distribution</h3>
      <ResponsiveContainer width="100%" height={280}>
        <BarChart data={bins}>
          <XAxis
            dataKey="range"
            tick={{ fill: '#94A3B8', fontSize: 10 }}
            axisLine={{ stroke: '#334155' }}
          />
          <YAxis
            tick={{ fill: '#94A3B8', fontSize: 10 }}
            axisLine={{ stroke: '#334155' }}
          />
          <Tooltip
            contentStyle={{
              background: '#1E293B',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#F8FAFC',
              fontSize: '12px',
            }}
          />
          <Bar dataKey="count" fill="#3B82F6" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
