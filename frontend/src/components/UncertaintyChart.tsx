import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'

interface Flow {
  flow_id: number
  epistemic_uncertainty: number
  aleatoric_uncertainty: number
  label_predicted: string
}

interface Props {
  predictions: Flow[]
  maxBars?: number
}

export default function UncertaintyChart({ predictions, maxBars = 40 }: Props) {
  const data = predictions.slice(0, maxBars).map((p) => ({
    id: p.flow_id,
    epi: +p.epistemic_uncertainty.toFixed(4),
    ale: +p.aleatoric_uncertainty.toFixed(4),
    label: p.label_predicted,
  }))

  return (
    <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
      <h3 className="text-sm font-medium text-text-secondary mb-4">
        Uncertainty Decomposition (first {maxBars} flows)
      </h3>
      <ResponsiveContainer width="100%" height={260}>
        <BarChart data={data}>
          <XAxis
            dataKey="id"
            tick={{ fill: '#94A3B8', fontSize: 9 }}
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
          <Legend wrapperStyle={{ fontSize: '11px', color: '#94A3B8' }} />
          <Bar dataKey="epi" stackId="u" fill="#A855F7" name="Epistemic" />
          <Bar dataKey="ale" stackId="u" fill="#3B82F6" name="Aleatoric" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
