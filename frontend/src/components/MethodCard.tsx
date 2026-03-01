interface Props {
  index: number
  name: string
  description: string
  formalism: string
  gap: string
}

const COLORS = [
  'border-accent-blue',
  'border-accent-purple',
  'border-accent-green',
  'border-accent-amber',
  'border-accent-orange',
  'border-accent-red',
  'border-accent-blue',
]

export default function MethodCard({ index, name, description, formalism, gap }: Props) {
  return (
    <div className={`bg-bg-secondary rounded-xl p-5 border-l-4 ${COLORS[index % COLORS.length]} border border-bg-card`}>
      <div className="flex items-center gap-2 mb-2">
        <span className="text-xs font-mono bg-bg-card px-2 py-0.5 rounded text-text-secondary">
          M{index + 1}
        </span>
        <h3 className="text-sm font-display font-semibold">{name}</h3>
      </div>
      <p className="text-sm text-text-secondary mb-3">{description}</p>
      <div className="text-xs font-mono text-accent-purple bg-accent-purple/10 px-2 py-1 rounded mb-2">
        {formalism}
      </div>
      <p className="text-xs text-text-secondary">
        <span className="font-medium">Gap:</span> {gap}
      </p>
    </div>
  )
}
