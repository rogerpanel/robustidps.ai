import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  X,
  Loader2,
  CheckCircle2,
  AlertCircle,
  Clock,
  Trash2,
  ClipboardList,
} from 'lucide-react'
import { useNoticeBoard, type NoticeStatus } from '../hooks/useNoticeBoard'

const statusConfig: Record<NoticeStatus, { icon: typeof Loader2; color: string; label: string }> = {
  running:   { icon: Loader2,      color: 'text-accent-blue',   label: 'Running' },
  completed: { icon: CheckCircle2, color: 'text-accent-green',  label: 'Done' },
  pending:   { icon: Clock,        color: 'text-accent-amber',  label: 'Pending' },
  error:     { icon: AlertCircle,  color: 'text-accent-red',    label: 'Error' },
}

export default function NoticeBoard() {
  const { notices, removeNotice, clearAll } = useNoticeBoard()
  const navigate = useNavigate()

  // Auto-dismiss completed notices after 8 seconds
  useEffect(() => {
    const completedIds = notices
      .filter(n => n.status === 'completed')
      .map(n => n.id)

    if (completedIds.length === 0) return

    const timers = completedIds.map(id =>
      setTimeout(() => removeNotice(id), 8000)
    )

    return () => timers.forEach(clearTimeout)
  }, [notices, removeNotice])

  const runningCount = notices.filter((n) => n.status === 'running').length
  const pendingCount = notices.filter((n) => n.status === 'pending').length

  return (
    <div className="border-t border-bg-card flex flex-col max-h-[45%]">
      {/* Header */}
      <div className="px-3 pt-3 pb-2 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ClipboardList className="w-4 h-4 text-accent-blue" />
          <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary/70">
            Notice Board
          </span>
        </div>
        {notices.length > 0 && (
          <button
            onClick={clearAll}
            className="p-1 rounded text-text-secondary/40 hover:text-accent-red transition-colors"
            title="Clear all notices"
          >
            <Trash2 className="w-3 h-3" />
          </button>
        )}
      </div>

      {/* Summary counts */}
      {(runningCount > 0 || pendingCount > 0) && (
        <div className="px-3 pb-2 flex gap-3 text-[10px]">
          {runningCount > 0 && (
            <span className="flex items-center gap-1 text-accent-blue">
              <Loader2 className="w-3 h-3 animate-spin" />
              {runningCount} active
            </span>
          )}
          {pendingCount > 0 && (
            <span className="flex items-center gap-1 text-accent-amber">
              <Clock className="w-3 h-3" />
              {pendingCount} pending
            </span>
          )}
        </div>
      )}

      {/* Notice list */}
      <div className="flex-1 overflow-y-auto px-2 pb-2 space-y-1">
        {notices.length === 0 ? (
          <div className="px-2 py-4 text-center text-[11px] text-text-secondary/40">
            No activities yet
          </div>
        ) : (
          notices.map((notice) => {
            const cfg = statusConfig[notice.status]
            const Icon = cfg.icon
            return (
              <div
                key={notice.id}
                className={`group relative flex items-start gap-2 px-2 py-1.5 rounded-lg hover:bg-bg-card/50 transition-colors cursor-pointer${notice.status === 'completed' ? ' opacity-80' : ''}`}
                onClick={() => notice.page && navigate(notice.page)}
                title={notice.description || notice.title}
              >
                <Icon
                  className={`w-3.5 h-3.5 mt-0.5 shrink-0 ${cfg.color} ${
                    notice.status === 'running' ? 'animate-spin' : ''
                  }`}
                />
                <div className="flex-1 min-w-0">
                  <div className="text-[11px] font-medium text-text-primary truncate">
                    {notice.title}
                  </div>
                  {notice.description && (
                    <div className="text-[10px] text-text-secondary/60 truncate">
                      {notice.description}
                    </div>
                  )}
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    removeNotice(notice.id)
                  }}
                  className="opacity-0 group-hover:opacity-100 p-0.5 rounded text-text-secondary/40 hover:text-accent-red transition-all"
                  title="Dismiss"
                >
                  <X className="w-3 h-3" />
                </button>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
