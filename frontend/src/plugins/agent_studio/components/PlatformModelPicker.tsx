import { useEffect, useMemo, useState } from 'react'
import { Cpu, CheckCircle2, ExternalLink, Loader2 } from 'lucide-react'
import { fetchPlatformModels, fetchPlatformModelRecs } from '../api'
import type { PlatformModel } from '../api'

const CATEGORY_TONE: Record<string, string> = {
  ensemble:        'bg-accent-blue/10 text-accent-blue border-accent-blue/30',
  temporal:        'bg-accent-purple/10 text-accent-purple border-accent-purple/30',
  federated:       'bg-accent-orange/10 text-accent-orange border-accent-orange/30',
  foundation:      'bg-accent-green/10 text-accent-green border-accent-green/30',
  clrl:            'bg-accent-amber/10 text-accent-amber border-accent-amber/30',
  certified:       'bg-accent-green/10 text-accent-green border-accent-green/30',
  self_supervised: 'bg-accent-blue/10 text-accent-blue border-accent-blue/30',
  pqc:             'bg-accent-red/10 text-accent-red border-accent-red/30',
  llm_protocol:    'bg-accent-purple/10 text-accent-purple border-accent-purple/30',
}

/**
 * Picker for the platform-side detection / response models that an
 * agent can attach as "special tools". Recommended set per template
 * is loaded from the backend; user can toggle on top of it.
 *
 * The selection is surfaced as `selected[]` to the parent so the
 * BuildWizard can fold it into spec.platform_models.
 */
export default function PlatformModelPicker({
  templateId, selected, onChange,
}: {
  templateId: string
  selected: string[]
  onChange: (next: string[]) => void
}) {
  const [models, setModels] = useState<PlatformModel[]>([])
  const [recommended, setRecommended] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState(true)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    setBusy(true)
    Promise.all([
      fetchPlatformModels(),
      fetchPlatformModelRecs(templateId).catch(() => ({ model_ids: [] as string[] })),
    ])
      .then(([all, rec]) => {
        setModels(all.models)
        setRecommended(new Set(rec.model_ids))
      })
      .catch((e) => setErr(String(e)))
      .finally(() => setBusy(false))
  }, [templateId])

  const sortedModels = useMemo(() => {
    return [...models].sort((a, b) => {
      const ar = recommended.has(a.id) ? 0 : 1
      const br = recommended.has(b.id) ? 0 : 1
      return ar - br || a.category.localeCompare(b.category) || a.name.localeCompare(b.name)
    })
  }, [models, recommended])

  const toggle = (id: string) => {
    const next = new Set(selected)
    next.has(id) ? next.delete(id) : next.add(id)
    onChange(Array.from(next))
  }

  const applyRecommended = () => onChange(Array.from(recommended))

  if (busy && models.length === 0) {
    return <div className="text-xs text-text-secondary inline-flex items-center gap-2">
      <Loader2 className="w-3 h-3 animate-spin" /> Loading platform model catalog…
    </div>
  }
  if (err) {
    return <div className="text-xs text-accent-red">Failed to load platform models: {err}</div>
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <div className="text-[10px] font-mono text-text-secondary">
          {selected.length} of {models.length} platform models attached
          {recommended.size > 0 && (
            <> · {recommended.size} recommended for this archetype</>
          )}
        </div>
        {recommended.size > 0 && (
          <button onClick={applyRecommended}
                  className="text-[10px] font-mono text-accent-blue hover:underline">
            ↻ apply recommended
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-80 overflow-y-auto">
        {sortedModels.map((m) => {
          const isSelected = selected.includes(m.id)
          const isRec = recommended.has(m.id)
          return (
            <label key={m.id}
                   className={`flex items-start gap-2 p-2 rounded border cursor-pointer text-xs
                     ${isSelected
                       ? 'bg-accent-blue/10 border-accent-blue/40'
                       : 'bg-bg-secondary border-bg-card/40 hover:border-accent-blue/30'}`}>
              <input type="checkbox" checked={isSelected}
                     onChange={() => toggle(m.id)}
                     className="mt-0.5" />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1.5 flex-wrap">
                  <Cpu className="w-3 h-3 shrink-0 text-text-secondary" />
                  <span className="font-mono text-[11px] truncate">{m.id}</span>
                  <span className={`text-[9px] font-mono uppercase px-1 py-0 rounded border
                    ${CATEGORY_TONE[m.category] || 'border-bg-card/40 text-text-secondary'}`}>
                    {m.category}
                  </span>
                  {isRec && (
                    <span className="text-[9px] font-mono text-accent-green inline-flex items-center gap-0.5">
                      <CheckCircle2 className="w-2.5 h-2.5" /> recommended
                    </span>
                  )}
                </div>
                <div className="text-[11px] mt-0.5 font-medium">{m.name}</div>
                <div className="text-[10px] text-text-secondary mt-0.5 line-clamp-2">
                  {m.description}
                </div>
                <div className="text-[9px] font-mono text-text-secondary mt-0.5 italic">
                  role: {m.role} · {m.role_blurb}
                </div>
                {m.paper && (
                  <div className="text-[9px] text-text-secondary mt-0.5 inline-flex items-center gap-0.5">
                    <ExternalLink className="w-2.5 h-2.5" />
                    <span className="truncate">{m.paper}</span>
                  </div>
                )}
              </div>
            </label>
          )
        })}
      </div>
    </div>
  )
}
