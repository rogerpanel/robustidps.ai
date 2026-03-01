import type { LucideIcon } from 'lucide-react'

interface Props {
  label: string
  value: string | number
  icon: LucideIcon
  color?: string
  sub?: string
}

export default function StatCard({ label, value, icon: Icon, color = 'text-accent-blue', sub }: Props) {
  return (
    <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
      <div className="flex items-center justify-between mb-3">
        <span className="text-text-secondary text-sm">{label}</span>
        <Icon className={`w-5 h-5 ${color}`} />
      </div>
      <p className={`text-2xl font-display font-bold ${color}`}>{value}</p>
      {sub && <p className="text-xs text-text-secondary mt-1">{sub}</p>}
    </div>
  )
}
