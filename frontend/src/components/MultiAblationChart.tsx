import { useState, useMemo } from 'react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  LineChart,
  Line,
  CartesianGrid,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
} from 'recharts'
import type { MultiAblationData } from '../hooks/useMultiAblation'

interface Props {
  data: MultiAblationData
}

type ViewTab =
  | 'heatmap'
  | 'branch_stability'
  | 'model_comparison'
  | 'cross_drop'
  | 'dataset_sensitivity'
  | 'incremental_compare'

const TAB_LABELS: Record<ViewTab, string> = {
  heatmap: 'Robustness Heatmap',
  branch_stability: 'Branch Stability',
  model_comparison: 'Model Comparison',
  cross_drop: 'Cross-Dataset Drops',
  dataset_sensitivity: 'Dataset Sensitivity',
  incremental_compare: 'Incremental Compare',
}

const MODEL_COLORS = ['#3B82F6', '#8B5CF6', '#10B981', '#F59E0B', '#EF4444', '#EC4899']
const DATASET_COLORS = ['#06B6D4', '#F97316', '#84CC16', '#E879F9']

const TOOLTIP_STYLE = {
  background: '#1E293B',
  border: '1px solid #334155',
  borderRadius: '8px',
  color: '#F8FAFC',
  fontSize: '12px',
}

export default function MultiAblationChart({ data }: Props) {
  const [activeTab, setActiveTab] = useState<ViewTab>('heatmap')
  const [selectedModel, setSelectedModel] = useState<string>(data.model_names[0] || '')
  const [selectedDataset, setSelectedDataset] = useState<string>(data.dataset_names[0] || '')

  const tabs: ViewTab[] = useMemo(() => {
    const t: ViewTab[] = ['heatmap']
    if (Object.keys(data.cross_dataset_stability).length > 0) t.push('branch_stability')
    if (data.model_names.length > 1) t.push('model_comparison')
    t.push('cross_drop')
    if (data.dataset_names.length > 1) t.push('dataset_sensitivity')
    // Show incremental compare if at least one run has incremental data
    const hasIncremental = Object.values(data.ablation_matrix).some(
      (r) => r.incremental && r.incremental.length > 0,
    )
    if (hasIncremental && data.dataset_names.length > 1) t.push('incremental_compare')
    return t
  }, [data])

  /* ── Derived data ───────────────────────────────────────────────── */

  // Heatmap: model × dataset bar chart
  const heatmapBarData = useMemo(() => {
    return data.dataset_names.map((ds) => {
      const entry: Record<string, string | number> = { dataset: ds }
      data.model_names.forEach((m) => {
        const cell = data.robustness_heatmap.find(
          (h) => h.model === m && h.dataset === ds,
        )
        entry[`${m}_acc`] = cell ? +(cell.full_accuracy * 100).toFixed(1) : 0
        entry[`${m}_rob`] = cell ? +(cell.robustness_score * 100).toFixed(1) : 0
      })
      return entry
    })
  }, [data])

  // Branch stability for selected model
  const stabilityData = useMemo(() => {
    const stab = data.cross_dataset_stability[selectedModel]
    if (!stab) return []
    return Object.entries(stab.branches).map(([bname, info]) => ({
      branch: bname.length > 20 ? bname.slice(0, 18) + '...' : bname,
      fullName: bname,
      meanDrop: +(info.mean_drop * 100).toFixed(2),
      stability: +(info.stability_score * 100).toFixed(1),
      ...Object.fromEntries(
        Object.entries(info.drops_per_dataset).map(([ds, d]) => [
          ds,
          +(d * 100).toFixed(2),
        ]),
      ),
    }))
  }, [data, selectedModel])

  // Cross-dataset drop comparison: grouped bar per branch, one bar per dataset
  const crossDropData = useMemo(() => {
    const stab = data.cross_dataset_stability[selectedModel]
    if (!stab) {
      // Fallback: single dataset, show branch drops directly
      const key = `${selectedModel}|${data.dataset_names[0]}`
      const run = data.ablation_matrix[key]
      if (!run) return []
      return Object.entries(run.ablation)
        .filter(([k]) => k !== 'Full System' && k !== 'Custom')
        .map(([name, v]) => ({
          branch: name.length > 18 ? name.slice(0, 16) + '...' : name,
          [data.dataset_names[0]]: +(v.accuracy_drop * 100).toFixed(2),
        }))
    }
    return Object.entries(stab.branches).map(([bname, info]) => ({
      branch: bname.length > 18 ? bname.slice(0, 16) + '...' : bname,
      ...Object.fromEntries(
        Object.entries(info.drops_per_dataset).map(([ds, d]) => [
          ds,
          +(d * 100).toFixed(2),
        ]),
      ),
    }))
  }, [data, selectedModel])

  // Model comparison for selected dataset
  const modelComparisonData = useMemo(() => {
    const cmp = data.cross_model_comparison[selectedDataset]
    if (!cmp) return []
    return Object.entries(cmp.models).map(([mn, m]) => ({
      model: mn,
      accuracy: +(m.full_accuracy * 100).toFixed(2),
      precision: +(m.full_precision * 100).toFixed(2),
      recall: +(m.full_recall * 100).toFixed(2),
      f1: +(m.full_f1 * 100).toFixed(2),
      avgDrop: +(m.avg_branch_drop * 100).toFixed(2),
      robustness: +(m.robustness_score * 100).toFixed(1),
    }))
  }, [data, selectedDataset])

  // Dataset sensitivity
  const sensitivityData = useMemo(() => {
    return Object.entries(data.dataset_sensitivity).map(([ds, info]) => ({
      dataset: ds.length > 20 ? ds.slice(0, 18) + '...' : ds,
      fullName: ds,
      meanAccuracy: +(info.mean_accuracy * 100).toFixed(2),
      sensitivity: +(info.sensitivity_score * 100).toFixed(2),
      ...Object.fromEntries(
        Object.entries(info.model_accuracies).map(([mn, a]) => [
          mn,
          +(a * 100).toFixed(2),
        ]),
      ),
    }))
  }, [data])

  // Incremental comparison across datasets for selected model
  const incrementalCompareData = useMemo(() => {
    const runs: { dataset: string; incremental: { step: number; label: string; accuracy: number }[] }[] = []
    data.dataset_names.forEach((ds) => {
      const key = `${selectedModel}|${ds}`
      const run = data.ablation_matrix[key]
      if (run?.incremental?.length) {
        runs.push({
          dataset: ds,
          incremental: run.incremental.map((e) => ({
            step: e.step,
            label: e.label,
            accuracy: +(e.accuracy * 100).toFixed(2),
          })),
        })
      }
    })
    if (runs.length === 0) return []
    // Merge by step
    const maxSteps = Math.max(...runs.map((r) => r.incremental.length))
    const merged = []
    for (let i = 0; i < maxSteps; i++) {
      const entry: Record<string, string | number> = {
        step: i,
        label: runs[0]?.incremental[i]?.label || `Step ${i}`,
      }
      runs.forEach((r) => {
        entry[r.dataset] = r.incremental[i]?.accuracy ?? 0
      })
      merged.push(entry)
    }
    return merged
  }, [data, selectedModel])

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
        {/* ── Robustness Heatmap ────────────────────────────────────── */}
        {activeTab === 'heatmap' && (
          <>
            <h3 className="text-sm font-medium text-text-secondary mb-2">
              Model × Dataset Robustness Heatmap
            </h3>
            <p className="text-xs text-text-secondary mb-4">
              Full system accuracy and robustness score (1 - avg branch drop) per model across datasets.
            </p>
            {/* Heatmap grid */}
            <div className="overflow-x-auto mb-6">
              <table className="text-xs w-full">
                <thead>
                  <tr className="text-text-secondary">
                    <th className="p-2 text-left">Model \ Dataset</th>
                    {data.dataset_names.map((ds) => (
                      <th key={ds} className="p-2 text-center whitespace-nowrap" title={ds}>
                        {ds.length > 20 ? ds.slice(0, 18) + '...' : ds}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.model_names.map((mn) => (
                    <tr key={mn} className="border-t border-bg-card/30">
                      <td className="p-2 font-medium text-text-primary">{mn}</td>
                      {data.dataset_names.map((ds) => {
                        const cell = data.robustness_heatmap.find(
                          (h) => h.model === mn && h.dataset === ds,
                        )
                        const acc = cell ? cell.full_accuracy : 0
                        const rob = cell ? cell.robustness_score : 0
                        const intensity = Math.min(rob, 1)
                        const bg =
                          rob >= 0.95
                            ? `rgba(16, 185, 129, ${intensity * 0.35})`
                            : rob >= 0.85
                            ? `rgba(245, 158, 11, ${intensity * 0.3})`
                            : `rgba(239, 68, 68, ${Math.max(0.1, (1 - intensity) * 0.4)})`
                        const textColor = rob >= 0.95 ? '#10B981' : rob >= 0.85 ? '#F59E0B' : '#EF4444'
                        return (
                          <td key={ds} className="p-2 text-center">
                            <div
                              className="rounded-lg px-3 py-2 inline-block min-w-[100px]"
                              style={{ background: bg }}
                            >
                              <div className="font-mono font-semibold" style={{ color: textColor }}>
                                {(acc * 100).toFixed(1)}%
                              </div>
                              <div className="text-[10px] text-text-secondary mt-0.5">
                                rob: {(rob * 100).toFixed(1)}%
                              </div>
                            </div>
                          </td>
                        )
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Grouped bar chart */}
            <h4 className="text-xs font-medium text-text-secondary mb-3">Accuracy by Model × Dataset</h4>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={heatmapBarData} margin={{ left: 10, bottom: 30 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis
                  dataKey="dataset"
                  tick={{ fill: '#94A3B8', fontSize: 10 }}
                  angle={-15}
                  textAnchor="end"
                  height={60}
                />
                <YAxis
                  domain={[0, 100]}
                  tick={{ fill: '#94A3B8', fontSize: 11 }}
                  tickFormatter={(v) => `${v}%`}
                />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                {data.model_names.map((mn, i) => (
                  <Bar
                    key={mn}
                    dataKey={`${mn}_acc`}
                    name={`${mn} Accuracy`}
                    fill={MODEL_COLORS[i % MODEL_COLORS.length]}
                    radius={[2, 2, 0, 0]}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
            <div className="flex justify-center gap-4 mt-2 flex-wrap">
              {data.model_names.map((mn, i) => (
                <div key={mn} className="flex items-center gap-1.5 text-xs text-text-secondary">
                  <span
                    className="w-2.5 h-2.5 rounded-full"
                    style={{ background: MODEL_COLORS[i % MODEL_COLORS.length] }}
                  />
                  {mn}
                </div>
              ))}
            </div>
          </>
        )}

        {/* ── Branch Stability ──────────────────────────────────────── */}
        {activeTab === 'branch_stability' && (
          <>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-medium text-text-secondary">
                  Branch Importance Stability Across Datasets
                </h3>
                <p className="text-xs text-text-secondary mt-1">
                  How consistently each branch impacts accuracy across different datasets.
                  High stability = branch importance is consistent regardless of data.
                </p>
              </div>
              {data.model_names.length > 1 && (
                <div className="flex gap-1">
                  {data.model_names.map((mn) => (
                    <button
                      key={mn}
                      onClick={() => setSelectedModel(mn)}
                      className={`px-3 py-1 text-xs rounded-lg transition-colors ${
                        selectedModel === mn
                          ? 'bg-accent-blue/20 text-accent-blue'
                          : 'text-text-secondary hover:text-text-primary'
                      }`}
                    >
                      {mn}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {stabilityData.length > 0 ? (
              <>
                {/* Stability bar chart */}
                <ResponsiveContainer width="100%" height={350}>
                  <BarChart data={stabilityData} layout="vertical" margin={{ left: 150 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis
                      type="number"
                      domain={[0, 100]}
                      tick={{ fill: '#94A3B8', fontSize: 11 }}
                      tickFormatter={(v) => `${v}%`}
                    />
                    <YAxis
                      type="category"
                      dataKey="branch"
                      tick={{ fill: '#94A3B8', fontSize: 10 }}
                      width={145}
                    />
                    <Tooltip
                      contentStyle={TOOLTIP_STYLE}
                      formatter={(value: number, name: string) => [
                        `${value.toFixed(2)}%`,
                        name === 'stability' ? 'Stability Score' : `Drop (${name})`,
                      ]}
                    />
                    <Bar dataKey="stability" name="Stability Score" radius={[0, 4, 4, 0]}>
                      {stabilityData.map((e, i) => (
                        <Cell
                          key={i}
                          fill={
                            e.stability >= 80
                              ? '#10B981'
                              : e.stability >= 50
                              ? '#F59E0B'
                              : '#EF4444'
                          }
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>

                {/* Summary cards */}
                {data.cross_dataset_stability[selectedModel] && (
                  <div className="grid grid-cols-2 gap-3 mt-4">
                    <div className="bg-bg-card/30 rounded-lg p-3 border border-accent-green/20">
                      <div className="text-[10px] text-text-secondary uppercase tracking-wider mb-1">
                        Most Stable Branch
                      </div>
                      <div className="text-sm font-medium text-accent-green">
                        {data.cross_dataset_stability[selectedModel].most_stable || 'N/A'}
                      </div>
                      <div className="text-[10px] text-text-secondary mt-0.5">
                        Consistent importance across all datasets
                      </div>
                    </div>
                    <div className="bg-bg-card/30 rounded-lg p-3 border border-accent-red/20">
                      <div className="text-[10px] text-text-secondary uppercase tracking-wider mb-1">
                        Least Stable Branch
                      </div>
                      <div className="text-sm font-medium text-accent-red">
                        {data.cross_dataset_stability[selectedModel].least_stable || 'N/A'}
                      </div>
                      <div className="text-[10px] text-text-secondary mt-0.5">
                        Importance varies most across datasets
                      </div>
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="text-center py-12 text-text-secondary text-sm">
                Branch stability requires at least 2 datasets with a multi-branch model.
              </div>
            )}
          </>
        )}

        {/* ── Model Comparison ─────────────────────────────────────── */}
        {activeTab === 'model_comparison' && (
          <>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-medium text-text-secondary">
                  Cross-Model Robustness Comparison
                </h3>
                <p className="text-xs text-text-secondary mt-1">
                  Compare how different models perform and degrade across ablation on the selected dataset.
                </p>
              </div>
              {data.dataset_names.length > 1 && (
                <div className="flex gap-1">
                  {data.dataset_names.map((ds) => (
                    <button
                      key={ds}
                      onClick={() => setSelectedDataset(ds)}
                      className={`px-3 py-1 text-xs rounded-lg transition-colors ${
                        selectedDataset === ds
                          ? 'bg-accent-blue/20 text-accent-blue'
                          : 'text-text-secondary hover:text-text-primary'
                      }`}
                    >
                      {ds.length > 15 ? ds.slice(0, 13) + '...' : ds}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {modelComparisonData.length > 0 ? (
              <>
                {/* Radar comparison */}
                <ResponsiveContainer width="100%" height={380}>
                  <RadarChart data={modelComparisonData}>
                    <PolarGrid stroke="#334155" />
                    <PolarAngleAxis dataKey="model" tick={{ fill: '#94A3B8', fontSize: 11 }} />
                    <PolarRadiusAxis domain={[0, 100]} tick={{ fill: '#64748B', fontSize: 9 }} axisLine={false} />
                    <Radar name="Accuracy" dataKey="accuracy" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.15} />
                    <Radar name="Precision" dataKey="precision" stroke="#8B5CF6" fill="#8B5CF6" fillOpacity={0.1} />
                    <Radar name="Recall" dataKey="recall" stroke="#10B981" fill="#10B981" fillOpacity={0.1} />
                    <Radar name="F1" dataKey="f1" stroke="#F59E0B" fill="#F59E0B" fillOpacity={0.1} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
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

                {/* Robustness ranking */}
                {data.cross_model_comparison[selectedDataset] && (
                  <div className="mt-6">
                    <h4 className="text-xs font-medium text-text-secondary mb-3 uppercase tracking-wider">
                      Robustness Ranking
                    </h4>
                    <div className="space-y-2">
                      {data.cross_model_comparison[selectedDataset].ranking.map((mn, i) => {
                        const m = data.cross_model_comparison[selectedDataset].models[mn]
                        return (
                          <div
                            key={mn}
                            className="flex items-center gap-3 bg-bg-card/30 rounded-lg px-4 py-2.5"
                          >
                            <span
                              className={`text-xs font-bold w-6 h-6 rounded-full flex items-center justify-center ${
                                i === 0
                                  ? 'bg-accent-green/20 text-accent-green'
                                  : i === data.model_names.length - 1
                                  ? 'bg-accent-red/20 text-accent-red'
                                  : 'bg-accent-amber/20 text-accent-amber'
                              }`}
                            >
                              #{i + 1}
                            </span>
                            <span className="text-sm font-medium text-text-primary flex-1">{mn}</span>
                            <div className="flex gap-4 text-xs">
                              <span className="text-text-secondary">
                                Acc: <span className="font-mono text-accent-blue">{(m.full_accuracy * 100).toFixed(1)}%</span>
                              </span>
                              <span className="text-text-secondary">
                                Avg Drop: <span className="font-mono text-accent-red">{(m.avg_branch_drop * 100).toFixed(2)}%</span>
                              </span>
                              <span className="text-text-secondary">
                                Rob: <span className="font-mono text-accent-green">{(m.robustness_score * 100).toFixed(1)}%</span>
                              </span>
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}

                {/* Deprecation/Appreciation Analysis */}
                {data.dataset_names.length > 1 && data.model_names.length > 0 && (
                  <div className="mt-6">
                    <h4 className="text-xs font-medium text-text-secondary mb-3 uppercase tracking-wider">
                      Model Deprecation / Appreciation Across Datasets
                    </h4>
                    <p className="text-xs text-text-secondary mb-3">
                      Shows how each model's accuracy changes across datasets. Positive delta = appreciation, negative = deprecation.
                    </p>
                    <div className="overflow-x-auto">
                      <table className="text-xs w-full">
                        <thead>
                          <tr className="text-text-secondary border-b border-bg-card">
                            <th className="p-2 text-left">Model</th>
                            {data.dataset_names.map((ds) => (
                              <th key={ds} className="p-2 text-center">
                                {ds.length > 15 ? ds.slice(0, 13) + '...' : ds}
                              </th>
                            ))}
                            <th className="p-2 text-center">Delta (Max-Min)</th>
                            <th className="p-2 text-center">Trend</th>
                          </tr>
                        </thead>
                        <tbody>
                          {data.model_names.map((mn) => {
                            const accs = data.dataset_names.map((ds) => {
                              const cmp = data.cross_model_comparison[ds]
                              return cmp?.models[mn]?.full_accuracy ?? 0
                            })
                            const maxAcc = Math.max(...accs)
                            const minAcc = Math.min(...accs)
                            const delta = maxAcc - minAcc
                            const trend =
                              accs.length >= 2
                                ? accs[accs.length - 1] - accs[0] > 0.001
                                  ? 'appreciation'
                                  : accs[accs.length - 1] - accs[0] < -0.001
                                  ? 'deprecation'
                                  : 'stable'
                                : 'stable'
                            return (
                              <tr key={mn} className="border-t border-bg-card/30">
                                <td className="p-2 font-medium">{mn}</td>
                                {accs.map((acc, j) => (
                                  <td key={j} className="p-2 text-center font-mono">
                                    {(acc * 100).toFixed(1)}%
                                  </td>
                                ))}
                                <td
                                  className={`p-2 text-center font-mono font-semibold ${
                                    delta > 0.05 ? 'text-accent-red' : delta > 0.02 ? 'text-accent-amber' : 'text-accent-green'
                                  }`}
                                >
                                  {(delta * 100).toFixed(2)}%
                                </td>
                                <td className="p-2 text-center">
                                  <span
                                    className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium ${
                                      trend === 'appreciation'
                                        ? 'bg-accent-green/15 text-accent-green'
                                        : trend === 'deprecation'
                                        ? 'bg-accent-red/15 text-accent-red'
                                        : 'bg-accent-blue/15 text-accent-blue'
                                    }`}
                                  >
                                    {trend === 'appreciation' ? '+ Improving' : trend === 'deprecation' ? '- Degrading' : '= Stable'}
                                  </span>
                                </td>
                              </tr>
                            )
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="text-center py-12 text-text-secondary text-sm">
                Model comparison requires at least 2 models.
              </div>
            )}
          </>
        )}

        {/* ── Cross-Dataset Accuracy Drops ─────────────────────────── */}
        {activeTab === 'cross_drop' && (
          <>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-medium text-text-secondary">
                  Branch Accuracy Drop Across Datasets
                </h3>
                <p className="text-xs text-text-secondary mt-1">
                  Compare which branches cause the most damage on different datasets.
                  Dataset-dependent branches may reveal data distribution sensitivity.
                </p>
              </div>
              {data.model_names.length > 1 && (
                <div className="flex gap-1">
                  {data.model_names.map((mn) => (
                    <button
                      key={mn}
                      onClick={() => setSelectedModel(mn)}
                      className={`px-3 py-1 text-xs rounded-lg transition-colors ${
                        selectedModel === mn
                          ? 'bg-accent-blue/20 text-accent-blue'
                          : 'text-text-secondary hover:text-text-primary'
                      }`}
                    >
                      {mn}
                    </button>
                  ))}
                </div>
              )}
            </div>
            <ResponsiveContainer width="100%" height={380}>
              <BarChart data={crossDropData} layout="vertical" margin={{ left: 140 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis
                  type="number"
                  tick={{ fill: '#94A3B8', fontSize: 11 }}
                  tickFormatter={(v) => `${v}%`}
                />
                <YAxis
                  type="category"
                  dataKey="branch"
                  tick={{ fill: '#94A3B8', fontSize: 10 }}
                  width={135}
                />
                <Tooltip
                  contentStyle={TOOLTIP_STYLE}
                  formatter={(value: number, name: string) => [`${value.toFixed(2)}%`, name]}
                />
                {data.dataset_names.map((ds, i) => (
                  <Bar
                    key={ds}
                    dataKey={ds}
                    name={ds}
                    fill={DATASET_COLORS[i % DATASET_COLORS.length]}
                    radius={[0, 3, 3, 0]}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
            <div className="flex justify-center gap-4 mt-2 flex-wrap">
              {data.dataset_names.map((ds, i) => (
                <div key={ds} className="flex items-center gap-1.5 text-xs text-text-secondary">
                  <span
                    className="w-2.5 h-2.5 rounded-full"
                    style={{ background: DATASET_COLORS[i % DATASET_COLORS.length] }}
                  />
                  {ds}
                </div>
              ))}
            </div>
          </>
        )}

        {/* ── Dataset Sensitivity ──────────────────────────────────── */}
        {activeTab === 'dataset_sensitivity' && (
          <>
            <h3 className="text-sm font-medium text-text-secondary mb-2">
              Dataset Sensitivity Analysis
            </h3>
            <p className="text-xs text-text-secondary mb-4">
              How much model performance varies across datasets. Higher sensitivity = models disagree more on this data.
            </p>
            <ResponsiveContainer width="100%" height={350}>
              <BarChart data={sensitivityData} margin={{ left: 10, bottom: 30 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis
                  dataKey="dataset"
                  tick={{ fill: '#94A3B8', fontSize: 10 }}
                  angle={-15}
                  textAnchor="end"
                  height={60}
                />
                <YAxis
                  domain={[0, 100]}
                  tick={{ fill: '#94A3B8', fontSize: 11 }}
                  tickFormatter={(v) => `${v}%`}
                />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                {data.model_names.map((mn, i) => (
                  <Bar
                    key={mn}
                    dataKey={mn}
                    name={mn}
                    fill={MODEL_COLORS[i % MODEL_COLORS.length]}
                    radius={[2, 2, 0, 0]}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
            <div className="flex justify-center gap-4 mt-2 flex-wrap">
              {data.model_names.map((mn, i) => (
                <div key={mn} className="flex items-center gap-1.5 text-xs text-text-secondary">
                  <span
                    className="w-2.5 h-2.5 rounded-full"
                    style={{ background: MODEL_COLORS[i % MODEL_COLORS.length] }}
                  />
                  {mn}
                </div>
              ))}
            </div>

            {/* Sensitivity summary table */}
            <div className="mt-6 overflow-x-auto">
              <table className="text-xs w-full">
                <thead>
                  <tr className="text-text-secondary border-b border-bg-card">
                    <th className="p-2 text-left">Dataset</th>
                    <th className="p-2 text-right">Mean Accuracy</th>
                    <th className="p-2 text-right">Sensitivity</th>
                    <th className="p-2 text-center">Assessment</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(data.dataset_sensitivity).map(([ds, info]) => (
                    <tr key={ds} className="border-t border-bg-card/30">
                      <td className="p-2 font-medium">{ds}</td>
                      <td className="p-2 text-right font-mono">{(info.mean_accuracy * 100).toFixed(2)}%</td>
                      <td className="p-2 text-right font-mono">{(info.sensitivity_score * 100).toFixed(3)}%</td>
                      <td className="p-2 text-center">
                        <span
                          className={`inline-flex px-2 py-0.5 rounded-full text-[10px] font-medium ${
                            info.sensitivity_score < 0.02
                              ? 'bg-accent-green/15 text-accent-green'
                              : info.sensitivity_score < 0.05
                              ? 'bg-accent-amber/15 text-accent-amber'
                              : 'bg-accent-red/15 text-accent-red'
                          }`}
                        >
                          {info.sensitivity_score < 0.02 ? 'Low' : info.sensitivity_score < 0.05 ? 'Medium' : 'High'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}

        {/* ── Incremental Comparison ───────────────────────────────── */}
        {activeTab === 'incremental_compare' && (
          <>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-medium text-text-secondary">
                  Incremental Build-up Comparison Across Datasets
                </h3>
                <p className="text-xs text-text-secondary mt-1">
                  How cumulative accuracy grows as branches are added, compared side-by-side per dataset.
                </p>
              </div>
              {data.model_names.length > 1 && (
                <div className="flex gap-1">
                  {data.model_names.map((mn) => (
                    <button
                      key={mn}
                      onClick={() => setSelectedModel(mn)}
                      className={`px-3 py-1 text-xs rounded-lg transition-colors ${
                        selectedModel === mn
                          ? 'bg-accent-blue/20 text-accent-blue'
                          : 'text-text-secondary hover:text-text-primary'
                      }`}
                    >
                      {mn}
                    </button>
                  ))}
                </div>
              )}
            </div>
            {incrementalCompareData.length > 0 ? (
              <>
                <ResponsiveContainer width="100%" height={380}>
                  <LineChart data={incrementalCompareData} margin={{ left: 10, right: 20 }}>
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
                      contentStyle={TOOLTIP_STYLE}
                      formatter={(value: number, name: string) => [`${value.toFixed(2)}%`, name]}
                    />
                    {data.dataset_names.map((ds, i) => (
                      <Line
                        key={ds}
                        type="monotone"
                        dataKey={ds}
                        stroke={DATASET_COLORS[i % DATASET_COLORS.length]}
                        strokeWidth={2}
                        dot={{ fill: DATASET_COLORS[i % DATASET_COLORS.length], r: 4 }}
                        activeDot={{ r: 6 }}
                      />
                    ))}
                  </LineChart>
                </ResponsiveContainer>
                <div className="flex justify-center gap-4 mt-2 flex-wrap">
                  {data.dataset_names.map((ds, i) => (
                    <div key={ds} className="flex items-center gap-1.5 text-xs text-text-secondary">
                      <span
                        className="w-4 h-0.5 inline-block"
                        style={{ background: DATASET_COLORS[i % DATASET_COLORS.length] }}
                      />
                      {ds}
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="text-center py-12 text-text-secondary text-sm">
                Incremental data not available for this model-dataset combination.
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
