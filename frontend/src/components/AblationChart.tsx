import { useState } from 'react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  ReferenceLine,
  LineChart,
  Line,
  CartesianGrid,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
} from 'recharts'
import type { AblationEntry, PairwiseEntry, IncrementalEntry } from '../hooks/useAblation'

interface Props {
  data: Record<string, AblationEntry>
  pairwise: Record<string, PairwiseEntry>
  incremental: IncrementalEntry[]
  branchNames: string[]
}

type MetricKey = 'accuracy' | 'precision' | 'recall' | 'f1'
type ViewTab = 'drop' | 'metrics' | 'radar' | 'pairwise' | 'incremental'

const METRIC_LABELS: Record<MetricKey, string> = {
  accuracy: 'Accuracy',
  precision: 'Precision',
  recall: 'Recall',
  f1: 'F1 Score',
}

const TAB_LABELS: Record<ViewTab, string> = {
  drop: 'Accuracy Drop',
  metrics: 'Multi-Metric',
  radar: 'Radar',
  pairwise: 'Pairwise Interactions',
  incremental: 'Incremental Build-up',
}

export default function AblationChart({ data, pairwise, incremental, branchNames }: Props) {
  const [activeTab, setActiveTab] = useState<ViewTab>('drop')
  const [selectedMetric, setSelectedMetric] = useState<MetricKey>('accuracy')

  const entries = Object.entries(data).map(([name, v]) => ({
    name: name.length > 24 ? name.slice(0, 22) + '...' : name,
    fullName: name,
    accuracy: +(v.accuracy * 100).toFixed(2),
    precision: +(v.precision * 100).toFixed(2),
    recall: +(v.recall * 100).toFixed(2),
    f1: +(v.f1 * 100).toFixed(2),
    drop: +(v.accuracy_drop * 100).toFixed(2),
    isFull: name === 'Full System',
  }))

  const fullAcc = entries.find((e) => e.isFull)?.accuracy ?? 100

  // Build pairwise grid data
  const pairEntries = Object.values(pairwise)
  const hasPairwise = pairEntries.length > 0
  const hasIncremental = incremental.length > 0

  // Available tabs
  const tabs: ViewTab[] = ['drop', 'metrics', 'radar']
  if (hasPairwise) tabs.push('pairwise')
  if (hasIncremental) tabs.push('incremental')

  return (
    <div className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
      {/* Tab bar */}
      <div className="flex border-b border-bg-card px-2 pt-2 gap-1 overflow-x-auto">
        {tabs.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-xs font-medium rounded-t-lg transition-colors whitespace-nowrap ${
              activeTab === tab
                ? 'bg-bg-card text-text-primary border-b-2 border-accent-blue'
                : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            {TAB_LABELS[tab]}
          </button>
        ))}
      </div>

      <div className="p-5">
        {/* ── Accuracy Drop Chart ───────────────────────────────────── */}
        {activeTab === 'drop' && (
          <>
            <h3 className="text-sm font-medium text-text-secondary mb-4">
              Ablation Study — Accuracy by Configuration
            </h3>
            <ResponsiveContainer width="100%" height={380}>
              <BarChart data={entries} layout="vertical" margin={{ left: 150 }}>
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
                  width={145}
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
                <ReferenceLine x={fullAcc} stroke="#3B82F6" strokeDasharray="3 3" />
                <Bar dataKey="accuracy" radius={[0, 4, 4, 0]}>
                  {entries.map((e, i) => (
                    <Cell key={i} fill={e.isFull ? '#3B82F6' : '#EF4444'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </>
        )}

        {/* ── Multi-Metric Comparison ──────────────────────────────── */}
        {activeTab === 'metrics' && (
          <>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-medium text-text-secondary">
                Multi-Metric Comparison
              </h3>
              <div className="flex gap-1">
                {(Object.keys(METRIC_LABELS) as MetricKey[]).map((m) => (
                  <button
                    key={m}
                    onClick={() => setSelectedMetric(m)}
                    className={`px-3 py-1 text-xs rounded-lg transition-colors ${
                      selectedMetric === m
                        ? 'bg-accent-blue/20 text-accent-blue'
                        : 'text-text-secondary hover:text-text-primary'
                    }`}
                  >
                    {METRIC_LABELS[m]}
                  </button>
                ))}
              </div>
            </div>
            <ResponsiveContainer width="100%" height={380}>
              <BarChart data={entries} layout="vertical" margin={{ left: 150 }}>
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
                  width={145}
                />
                <Tooltip
                  contentStyle={{
                    background: '#1E293B',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    color: '#F8FAFC',
                    fontSize: '12px',
                  }}
                  formatter={(value: number) => [`${value.toFixed(2)}%`, METRIC_LABELS[selectedMetric]]}
                />
                <Bar dataKey={selectedMetric} radius={[0, 4, 4, 0]}>
                  {entries.map((e, i) => (
                    <Cell
                      key={i}
                      fill={
                        e.isFull
                          ? '#3B82F6'
                          : selectedMetric === 'precision'
                          ? '#8B5CF6'
                          : selectedMetric === 'recall'
                          ? '#10B981'
                          : selectedMetric === 'f1'
                          ? '#F59E0B'
                          : '#EF4444'
                      }
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </>
        )}

        {/* ── Radar Chart ──────────────────────────────────────────── */}
        {activeTab === 'radar' && (
          <>
            <h3 className="text-sm font-medium text-text-secondary mb-4">
              Method Contribution Radar — Metric Retention When Removed
            </h3>
            <ResponsiveContainer width="100%" height={400}>
              <RadarChart
                data={entries.filter((e) => !e.isFull).map((e) => ({
                  method: e.name,
                  accuracy: e.accuracy,
                  precision: e.precision,
                  recall: e.recall,
                  f1: e.f1,
                }))}
              >
                <PolarGrid stroke="#334155" />
                <PolarAngleAxis
                  dataKey="method"
                  tick={{ fill: '#94A3B8', fontSize: 10 }}
                />
                <PolarRadiusAxis
                  domain={[0, 100]}
                  tick={{ fill: '#64748B', fontSize: 9 }}
                  axisLine={false}
                />
                <Radar name="Accuracy" dataKey="accuracy" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.15} />
                <Radar name="Precision" dataKey="precision" stroke="#8B5CF6" fill="#8B5CF6" fillOpacity={0.1} />
                <Radar name="Recall" dataKey="recall" stroke="#10B981" fill="#10B981" fillOpacity={0.1} />
                <Radar name="F1" dataKey="f1" stroke="#F59E0B" fill="#F59E0B" fillOpacity={0.1} />
                <Tooltip
                  contentStyle={{
                    background: '#1E293B',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    color: '#F8FAFC',
                    fontSize: '12px',
                  }}
                />
              </RadarChart>
            </ResponsiveContainer>
            <div className="flex justify-center gap-4 mt-2">
              {[
                { label: 'Accuracy', color: '#3B82F6' },
                { label: 'Precision', color: '#8B5CF6' },
                { label: 'Recall', color: '#10B981' },
                { label: 'F1', color: '#F59E0B' },
              ].map((l) => (
                <div key={l.label} className="flex items-center gap-1.5 text-xs text-text-secondary">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ background: l.color }} />
                  {l.label}
                </div>
              ))}
            </div>
          </>
        )}

        {/* ── Pairwise Interaction Heatmap ─────────────────────────── */}
        {activeTab === 'pairwise' && hasPairwise && (
          <>
            <h3 className="text-sm font-medium text-text-secondary mb-2">
              Pairwise Branch Interaction Matrix
            </h3>
            <p className="text-xs text-text-secondary mb-4">
              Green = synergistic (removing both hurts more than expected).
              Red = redundant (overlapping contributions).
            </p>
            <div className="overflow-x-auto">
              <table className="text-xs">
                <thead>
                  <tr>
                    <th className="p-2" />
                    {branchNames.map((n, i) => (
                      <th key={i} className="p-2 text-text-secondary font-normal whitespace-nowrap max-w-[80px] truncate" title={n}>
                        M{i + 1}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {branchNames.map((rowName, ri) => (
                    <tr key={ri}>
                      <td className="p-2 text-text-secondary font-medium whitespace-nowrap">
                        <span className="font-mono mr-1">M{ri + 1}</span>
                        {rowName.length > 18 ? rowName.slice(0, 16) + '...' : rowName}
                      </td>
                      {branchNames.map((_colName, ci) => {
                        if (ri === ci) {
                          return (
                            <td key={ci} className="p-2">
                              <div className="w-12 h-8 rounded bg-bg-card/50 flex items-center justify-center text-text-secondary">
                                —
                              </div>
                            </td>
                          )
                        }
                        const key = ri < ci ? `${ri}-${ci}` : `${ci}-${ri}`
                        const entry = pairwise[key]
                        if (!entry) {
                          return (
                            <td key={ci} className="p-2">
                              <div className="w-12 h-8 rounded bg-bg-card/30" />
                            </td>
                          )
                        }
                        const val = entry.interaction
                        const intensity = Math.min(Math.abs(val) * 500, 1)
                        const bg =
                          val > 0
                            ? `rgba(16, 185, 129, ${intensity * 0.4})`
                            : `rgba(239, 68, 68, ${intensity * 0.4})`
                        const textColor = val > 0 ? '#10B981' : '#EF4444'
                        return (
                          <td key={ci} className="p-2">
                            <div
                              className="w-12 h-8 rounded flex items-center justify-center font-mono text-[10px]"
                              style={{ background: bg, color: textColor }}
                              title={`${entry.name_i} + ${entry.name_j}: interaction=${(val * 100).toFixed(2)}%`}
                            >
                              {val > 0 ? '+' : ''}
                              {(val * 100).toFixed(1)}
                            </div>
                          </td>
                        )
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}

        {/* ── Incremental Build-up Chart ───────────────────────────── */}
        {activeTab === 'incremental' && hasIncremental && (
          <>
            <h3 className="text-sm font-medium text-text-secondary mb-2">
              Incremental Method Addition
            </h3>
            <p className="text-xs text-text-secondary mb-4">
              Methods added one at a time (most impactful first), showing cumulative accuracy gain.
            </p>
            <ResponsiveContainer width="100%" height={380}>
              <LineChart
                data={incremental.map((e) => ({
                  ...e,
                  accuracy: +(e.accuracy * 100).toFixed(2),
                  gain: +(e.gain * 100).toFixed(2),
                  label: e.label.length > 20 ? e.label.slice(0, 18) + '...' : e.label,
                }))}
                margin={{ left: 10, right: 20 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis
                  dataKey="label"
                  tick={{ fill: '#94A3B8', fontSize: 9 }}
                  angle={-30}
                  textAnchor="end"
                  height={80}
                />
                <YAxis
                  domain={[0, 100]}
                  tick={{ fill: '#94A3B8', fontSize: 11 }}
                  tickFormatter={(v) => `${v}%`}
                />
                <Tooltip
                  contentStyle={{
                    background: '#1E293B',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    color: '#F8FAFC',
                    fontSize: '12px',
                  }}
                  formatter={(value: number, name: string) => [
                    `${value.toFixed(2)}%`,
                    name === 'accuracy' ? 'Cumulative Accuracy' : 'Step Gain',
                  ]}
                />
                <Line
                  type="monotone"
                  dataKey="accuracy"
                  stroke="#3B82F6"
                  strokeWidth={2}
                  dot={{ fill: '#3B82F6', r: 4 }}
                  activeDot={{ r: 6 }}
                />
                <Line
                  type="monotone"
                  dataKey="gain"
                  stroke="#10B981"
                  strokeWidth={1.5}
                  strokeDasharray="5 5"
                  dot={{ fill: '#10B981', r: 3 }}
                />
              </LineChart>
            </ResponsiveContainer>
            <div className="flex justify-center gap-6 mt-2">
              <div className="flex items-center gap-1.5 text-xs text-text-secondary">
                <span className="w-4 h-0.5 bg-blue-500 inline-block" />
                Cumulative Accuracy
              </div>
              <div className="flex items-center gap-1.5 text-xs text-text-secondary">
                <span className="w-4 h-0.5 bg-green-500 inline-block border-dashed" style={{ borderTop: '1.5px dashed #10B981', background: 'transparent' }} />
                Step Gain
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
