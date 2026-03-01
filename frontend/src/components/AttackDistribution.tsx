import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts'

const COLORS = [
  '#3B82F6', '#EF4444', '#F59E0B', '#22C55E', '#A855F7',
  '#F97316', '#06B6D4', '#EC4899', '#8B5CF6', '#14B8A6',
  '#6366F1', '#D946EF', '#0EA5E9',
]

interface Props {
  data: Record<string, number>
}

export default function AttackDistribution({ data }: Props) {
  const entries = Object.entries(data)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)

  return (
    <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
      <h3 className="text-sm font-medium text-text-secondary mb-4">Attack Distribution</h3>
      <ResponsiveContainer width="100%" height={280}>
        <PieChart>
          <Pie
            data={entries}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            innerRadius={55}
            outerRadius={100}
            paddingAngle={2}
            stroke="none"
          >
            {entries.map((_, i) => (
              <Cell key={i} fill={COLORS[i % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: '#1E293B',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#F8FAFC',
              fontSize: '12px',
            }}
          />
          <Legend
            wrapperStyle={{ fontSize: '11px', color: '#94A3B8' }}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )
}
