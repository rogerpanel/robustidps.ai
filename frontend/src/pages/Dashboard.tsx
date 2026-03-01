import { useEffect, useState } from 'react'
import { Activity, ShieldAlert, ShieldCheck, Gauge } from 'lucide-react'
import StatCard from '../components/StatCard'
import AttackDistribution from '../components/AttackDistribution'
import ConfidenceHistogram from '../components/ConfidenceHistogram'
import { SAMPLE_RESULTS } from '../utils/api'

interface Results {
  n_flows: number
  n_threats: number
  n_benign: number
  ece: number
  predictions: Array<{
    flow_id: number
    src_ip: string
    dst_ip: string
    label_predicted: string
    confidence: number
    severity: string
  }>
  attack_distribution: Record<string, number>
}

export default function Dashboard() {
  const [data, setData] = useState<Results | null>(null)

  useEffect(() => {
    const stored = localStorage.getItem('robustidps_results')
    if (stored) {
      try {
        setData(JSON.parse(stored))
      } catch {
        setData(SAMPLE_RESULTS as unknown as Results)
      }
    } else {
      setData(SAMPLE_RESULTS as unknown as Results)
    }
  }, [])

  if (!data) return null

  const benignPct = data.n_flows > 0 ? ((data.n_benign / data.n_flows) * 100).toFixed(1) : '0'
  const confidences = data.predictions?.map((p) => p.confidence) ?? []

  const SEV_COLOR: Record<string, string> = {
    benign: 'text-accent-blue',
    low: 'text-accent-green',
    medium: 'text-accent-amber',
    high: 'text-accent-orange',
    critical: 'text-accent-red',
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-display font-bold">Dashboard</h1>

      <div className="grid grid-cols-4 gap-4">
        <StatCard
          label="Total Flows"
          value={data.n_flows.toLocaleString()}
          icon={Activity}
          color="text-accent-blue"
        />
        <StatCard
          label="Threats Detected"
          value={data.n_threats.toLocaleString()}
          icon={ShieldAlert}
          color="text-accent-red"
          sub={`${((data.n_threats / Math.max(data.n_flows, 1)) * 100).toFixed(1)}% of total`}
        />
        <StatCard
          label="Benign Traffic"
          value={`${benignPct}%`}
          icon={ShieldCheck}
          color="text-accent-green"
        />
        <StatCard
          label="ECE Score"
          value={data.ece.toFixed(3)}
          icon={Gauge}
          color="text-accent-purple"
          sub="Expected Calibration Error"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <AttackDistribution data={data.attack_distribution} />
        <ConfidenceHistogram confidences={confidences} />
      </div>

      {/* Recent detections */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h3 className="text-sm font-medium text-text-secondary mb-4">Recent Detections</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-text-secondary text-xs">
                <th className="px-3 py-2 text-left">#</th>
                <th className="px-3 py-2 text-left">Src IP</th>
                <th className="px-3 py-2 text-left">Dst IP</th>
                <th className="px-3 py-2 text-left">Label</th>
                <th className="px-3 py-2 text-left">Confidence</th>
                <th className="px-3 py-2 text-left">Severity</th>
              </tr>
            </thead>
            <tbody>
              {(data.predictions?.slice(0, 20) ?? []).map((p) => (
                <tr key={p.flow_id} className="border-t border-bg-card/50 hover:bg-bg-card/20">
                  <td className="px-3 py-2 font-mono text-text-secondary">{p.flow_id}</td>
                  <td className="px-3 py-2 font-mono">{p.src_ip}</td>
                  <td className="px-3 py-2 font-mono">{p.dst_ip}</td>
                  <td className="px-3 py-2">{p.label_predicted}</td>
                  <td className="px-3 py-2 font-mono">{(p.confidence * 100).toFixed(1)}%</td>
                  <td className="px-3 py-2">
                    <span className={`font-medium text-xs ${SEV_COLOR[p.severity] || 'text-text-secondary'}`}>
                      {p.severity}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
