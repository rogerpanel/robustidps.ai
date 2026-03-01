import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  ReferenceLine,
} from 'recharts'

interface AblationEntry {
  accuracy: number
  accuracy_drop: number
  disabled: number[]
}

interface Props {
  data: Record<string, AblationEntry>
}

export default function AblationChart({ data }: Props) {
  const entries = Object.entries(data).map(([name, v]) => ({
    name: name.length > 22 ? name.slice(0, 20) + '...' : name,
    fullName: name,
    accuracy: +(v.accuracy * 100).toFixed(2),
    drop: +(v.accuracy_drop * 100).toFixed(2),
    isFull: name === 'Full System',
  }))

  return (
    <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
      <h3 className="text-sm font-medium text-text-secondary mb-4">
        Ablation Study — Accuracy by Configuration
      </h3>
      <ResponsiveContainer width="100%" height={380}>
        <BarChart data={entries} layout="vertical" margin={{ left: 140 }}>
          <XAxis
            type="number"
            domain={[0, 100]}
            tick={{ fill: '#94A3B8', fontSize: 11 }}
            axisLine={{ stroke: '#334155' }}
            tickFormatter={(v) => `${v}%`}
          />
          <YAxis
            type="category"
            dataKey="name"
            tick={{ fill: '#94A3B8', fontSize: 11 }}
            axisLine={{ stroke: '#334155' }}
            width={135}
          />
          <Tooltip
            contentStyle={{
              background: '#1E293B',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#F8FAFC',
              fontSize: '12px',
            }}
            formatter={(value: number, _name: string, entry: { payload: typeof entries[0] }) => [
              `${value.toFixed(2)}%  (drop: -${entry.payload.drop.toFixed(2)}%)`,
              'Accuracy',
            ]}
          />
          <ReferenceLine x={entries[0]?.accuracy} stroke="#3B82F6" strokeDasharray="3 3" />
          <Bar dataKey="accuracy" radius={[0, 4, 4, 0]}>
            {entries.map((e, i) => (
              <Cell key={i} fill={e.isFull ? '#3B82F6' : '#EF4444'} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
