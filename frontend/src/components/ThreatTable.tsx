import { useState, useMemo } from 'react'
import { Search, ArrowUpDown } from 'lucide-react'

interface Flow {
  flow_id: number
  src_ip: string
  dst_ip: string
  label_predicted: string
  label_true: string | null
  confidence: number
  severity: string
  epistemic_uncertainty: number
  aleatoric_uncertainty: number
  total_uncertainty: number
}

const SEV_COLOR: Record<string, string> = {
  benign: 'bg-accent-blue/10 text-accent-blue',
  low: 'bg-accent-green/10 text-accent-green',
  medium: 'bg-accent-amber/10 text-accent-amber',
  high: 'bg-accent-orange/10 text-accent-orange',
  critical: 'bg-accent-red/10 text-accent-red',
}

interface Props {
  predictions: Flow[]
}

type SortKey = keyof Flow

export default function ThreatTable({ predictions }: Props) {
  const [query, setQuery] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('flow_id')
  const [sortAsc, setSortAsc] = useState(true)

  const filtered = useMemo(() => {
    const q = query.toLowerCase()
    let data = predictions.filter(
      (r) =>
        r.label_predicted.toLowerCase().includes(q) ||
        r.src_ip.includes(q) ||
        r.dst_ip.includes(q) ||
        r.severity.includes(q),
    )
    data.sort((a, b) => {
      const av = a[sortKey]
      const bv = b[sortKey]
      if (av == null || bv == null) return 0
      if (av < bv) return sortAsc ? -1 : 1
      if (av > bv) return sortAsc ? 1 : -1
      return 0
    })
    return data
  }, [predictions, query, sortKey, sortAsc])

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortAsc(!sortAsc)
    else {
      setSortKey(key)
      setSortAsc(true)
    }
  }

  const TH = ({ k, children }: { k: SortKey; children: React.ReactNode }) => (
    <th
      className="px-3 py-2 text-left text-xs font-medium text-text-secondary cursor-pointer select-none whitespace-nowrap"
      onClick={() => toggleSort(k)}
    >
      <span className="inline-flex items-center gap-1">
        {children}
        <ArrowUpDown className="w-3 h-3" />
      </span>
    </th>
  )

  return (
    <div className="space-y-3">
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-secondary" />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search by IP, label, severity..."
          className="w-full bg-bg-card/50 border border-bg-card rounded-lg pl-9 pr-4 py-2 text-sm text-text-primary placeholder:text-text-secondary focus:outline-none focus:border-accent-blue"
        />
      </div>

      <div className="overflow-x-auto rounded-lg border border-bg-card">
        <table className="w-full text-sm">
          <thead className="bg-bg-card/40">
            <tr>
              <TH k="flow_id">#</TH>
              <TH k="src_ip">Src IP</TH>
              <TH k="dst_ip">Dst IP</TH>
              <TH k="label_predicted">Label</TH>
              <TH k="confidence">Conf.</TH>
              <TH k="total_uncertainty">Uncert.</TH>
              <TH k="severity">Severity</TH>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 200).map((r) => (
              <tr
                key={r.flow_id}
                className={`border-t border-bg-card/50 hover:bg-bg-card/20 ${
                  r.severity === 'critical'
                    ? 'bg-accent-red/5'
                    : r.severity === 'benign'
                      ? 'bg-accent-blue/5'
                      : ''
                }`}
              >
                <td className="px-3 py-2 font-mono text-text-secondary">{r.flow_id}</td>
                <td className="px-3 py-2 font-mono">{r.src_ip}</td>
                <td className="px-3 py-2 font-mono">{r.dst_ip}</td>
                <td className="px-3 py-2 font-medium">{r.label_predicted}</td>
                <td className="px-3 py-2 font-mono">{(r.confidence * 100).toFixed(1)}%</td>
                <td className="px-3 py-2 font-mono">{r.total_uncertainty.toFixed(3)}</td>
                <td className="px-3 py-2">
                  <span
                    className={`px-2 py-0.5 rounded text-xs font-medium ${SEV_COLOR[r.severity] || 'bg-bg-card text-text-secondary'}`}
                  >
                    {r.severity}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length > 200 && (
          <div className="px-3 py-2 text-xs text-text-secondary text-center border-t border-bg-card">
            Showing first 200 of {filtered.length} flows
          </div>
        )}
      </div>
    </div>
  )
}
