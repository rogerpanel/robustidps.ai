import { useState } from 'react'
import { HelpCircle, X } from 'lucide-react'

interface Step {
  title: string
  desc: string
}

interface Props {
  title: string
  steps: Step[]
  tip?: string
}

export default function PageGuide({ title, steps, tip }: Props) {
  const [open, setOpen] = useState(true)

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="flex items-center gap-1.5 text-xs text-text-secondary hover:text-accent-blue transition-colors"
      >
        <HelpCircle className="w-3.5 h-3.5" /> How to use this page
      </button>
    )
  }

  return (
    <div className="bg-accent-blue/5 border border-accent-blue/20 rounded-xl p-4 relative">
      <button
        onClick={() => setOpen(false)}
        className="absolute top-3 right-3 text-text-secondary hover:text-text-primary"
      >
        <X className="w-4 h-4" />
      </button>
      <h4 className="text-xs font-semibold text-accent-blue mb-2 flex items-center gap-1.5">
        <HelpCircle className="w-3.5 h-3.5" /> {title}
      </h4>
      <ol className="space-y-1.5 text-xs text-text-secondary">
        {steps.map((step, i) => (
          <li key={i} className="flex gap-2">
            <span className="shrink-0 w-5 h-5 rounded-full bg-accent-blue/15 text-accent-blue flex items-center justify-center text-[10px] font-bold">
              {i + 1}
            </span>
            <span>
              <strong className="text-text-primary">{step.title}</strong> — {step.desc}
            </span>
          </li>
        ))}
      </ol>
      {tip && (
        <div className="mt-2 text-xs text-accent-blue/80 italic">{tip}</div>
      )}
    </div>
  )
}
