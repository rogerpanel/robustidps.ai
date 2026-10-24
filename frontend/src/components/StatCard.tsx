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
    <div className="bg-bg-secondary rounded-xl p-3 md:p-5 border border-bg-card">
      <div className="flex items-center justify-between mb-2 md:mb-3">
        <span className="text-text-secondary text-xs md:text-sm">{label}</span>
        <Icon className={`w-4 h-4 md:w-5 md:h-5 ${color}`} />
      </div>
      <p className={`text-xl md:text-2xl font-display font-bold ${color}`}>{value}</p>
      {sub && <p className="text-xs text-text-secondary mt-1">{sub}</p>}
    </div>
  )
}
