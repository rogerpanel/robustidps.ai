import { useEffect, useState } from 'react'
import { Database, ExternalLink, Check, Clock, Lock } from 'lucide-react'

const API = import.meta.env.VITE_API_URL || ''

interface DatasetEntry {
  id: string
  name: string
  domain: string
  size_full: string
  tier: 'curated_50mb' | 'on_demand' | 'reference_only'
  source_url: string
  citation: string
  demo_subset_available: boolean
}

interface Props {
  page: string
  onSelect?: (datasetId: string) => void
  initialId?: string
}

export default function DatasetSelector({ page, onSelect, initialId }: Props) {
  const [datasets, setDatasets] = useState<DatasetEntry[]>([])
  const [selected, setSelected] = useState<string | null>(initialId ?? null)
  const [expanded, setExpanded] = useState(false)

  useEffect(() => {
    fetch(`${API}/api/uav/datasets/for-page/${page}`)
      .then((r) => r.json())
      .then((d) => {
        setDatasets(d.datasets || [])
        if (!selected && d.datasets?.length) {
          setSelected(d.datasets[0].id)
          onSelect?.(d.datasets[0].id)
        }
      })
      .catch(() => {})
  }, [page])

  const current = datasets.find((d) => d.id === selected)
  if (datasets.length === 0) return null

  return (
    <div className="bg-bg-card rounded-xl p-3 text-xs">
      <div className="flex items-center gap-2">
        <Database className="w-3.5 h-3.5 text-accent-blue" />
        <span className="text-text-secondary">Dataset:</span>
        <select
          value={selected ?? ''}
          onChange={(e) => { setSelected(e.target.value); onSelect?.(e.target.value) }}
          className="bg-bg-secondary border border-bg-card/60 rounded px-2 py-1 text-xs font-mono"
        >
          {datasets.map((d) => (
            <option key={d.id} value={d.id}>{d.name} — {d.size_full}</option>
          ))}
        </select>

        {current && <TierBadge tier={current.tier} subsetReady={current.demo_subset_available} />}

        <button
          onClick={() => setExpanded(!expanded)}
          className="ml-auto text-[10px] text-text-secondary hover:text-text-primary"
        >
          {expanded ? '▲ less' : '▼ more'}
        </button>
      </div>

      {expanded && current && (
        <div className="mt-2 pt-2 border-t border-bg-card/40 space-y-1 text-[11px]">
          <div className="text-text-secondary">
            <span className="font-mono">domain:</span> {current.domain}
          </div>
          <div className="text-text-secondary">
            <span className="font-mono">citation:</span> {current.citation}
          </div>
          <div className="text-text-secondary">
            <span className="font-mono">size (full):</span> {current.size_full}
          </div>
          <a href={current.source_url} target="_blank" rel="noreferrer"
             className="inline-flex items-center gap-1 text-accent-blue hover:text-accent-orange">
            source <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      )}
    </div>
  )
}

function TierBadge({ tier, subsetReady }: { tier: string; subsetReady: boolean }) {
  if (tier === 'curated_50mb' && subsetReady)
    return (
      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono bg-accent-green/10 text-accent-green border border-accent-green/30">
        <Check className="w-2.5 h-2.5" /> demo loaded
      </span>
    )
  if (tier === 'on_demand')
    return (
      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono bg-accent-amber/10 text-accent-amber border border-accent-amber/30">
        <Clock className="w-2.5 h-2.5" /> on-demand
      </span>
    )
  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono bg-bg-secondary text-text-secondary border border-bg-card/40">
      <Lock className="w-2.5 h-2.5" /> reference-only
    </span>
  )
}
