import { useEffect } from 'react'
import { Lightbulb, Loader2 } from 'lucide-react'
import { fetchBuildSuggestions } from '../api'
import { useAgentStudioState } from '../../../hooks/useAgentStudioState'

/**
 * Contextual side-tips that follow the user through the BuildWizard.
 *
 * Driven by `/build-suggestions/{template_id}?step=N`. The backend
 * picks tips per (step, category) — e.g. UAV mission planners get
 * different advice on Step 2 than network-ops engineers do.
 *
 * Persists per template + step so a user can read a tip, navigate away,
 * and come back to find it still there.
 */
export default function SideSuggestions({ templateId, step, category }: {
  templateId: string
  step: number
  category?: string
}) {
  const ns = `tips:${templateId}:${step}`
  const [tips, setTips] = useAgentStudioState<string[] | null>(ns, 'cached', null)
  const [busy, setBusy] = useAgentStudioState<boolean>(ns, 'loading', false)

  useEffect(() => {
    setBusy(true)
    fetchBuildSuggestions(templateId, step, category)
      .then((r) => setTips(r.tips))
      .catch(() => setTips([]))
      .finally(() => setBusy(false))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [templateId, step, category])

  if (!tips && !busy) return null

  return (
    <aside className="bg-accent-amber/5 border border-accent-amber/30 rounded-xl p-3 space-y-2">
      <div className="flex items-center gap-1.5 text-xs font-semibold text-accent-amber">
        <Lightbulb className="w-3.5 h-3.5" />
        Suggestions for step {step}
        {category && (
          <span className="text-[10px] font-mono opacity-70">· {category} archetype</span>
        )}
        {busy && <Loader2 className="w-3 h-3 animate-spin ml-auto" />}
      </div>
      {tips && tips.length === 0 && (
        <div className="text-[11px] text-text-secondary italic">
          No archetype-specific tips for this step.
        </div>
      )}
      <ul className="space-y-1.5">
        {(tips || []).map((tip, i) => (
          <li key={i} className="text-[11px] leading-snug flex gap-1.5">
            <span className="text-accent-amber font-mono">{i + 1}.</span>
            <span>{tip}</span>
          </li>
        ))}
      </ul>
    </aside>
  )
}
