import { createContext, useContext, useState, useCallback, type ReactNode } from 'react'
import { getUser } from '../utils/auth'

function _key(base: string): string {
  const u = getUser()
  return u ? `${base}::${u.email}` : base
}

export type NoticeStatus = 'running' | 'completed' | 'pending' | 'error'

export interface NoticeItem {
  id: string
  title: string
  description?: string
  status: NoticeStatus
  page?: string        // route to navigate to, e.g. '/xai'
  timestamp: number
}

interface NoticeBoardContextType {
  notices: NoticeItem[]
  addNotice: (notice: Omit<NoticeItem, 'id' | 'timestamp'>) => string
  updateNotice: (id: string, updates: Partial<Omit<NoticeItem, 'id'>>) => void
  removeNotice: (id: string) => void
  clearAll: () => void
}

const NoticeBoardContext = createContext<NoticeBoardContextType | null>(null)

const STORAGE_KEY = 'robustidps_notices'

export function NoticeBoardProvider({ children }: { children: ReactNode }) {
  const [notices, setNotices] = useState<NoticeItem[]>(() => {
    try {
      const cached = localStorage.getItem(_key(STORAGE_KEY))
      return cached ? JSON.parse(cached) : []
    } catch {
      return []
    }
  })

  const persist = (items: NoticeItem[]) => {
    try {
      localStorage.setItem(_key(STORAGE_KEY), JSON.stringify(items))
    } catch { /* quota exceeded */ }
  }

  const addNotice = useCallback((notice: Omit<NoticeItem, 'id' | 'timestamp'>): string => {
    const id = `notice_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`
    const newItem: NoticeItem = { ...notice, id, timestamp: Date.now() }
    setNotices((prev) => {
      const next = [newItem, ...prev]
      persist(next)
      return next
    })
    return id
  }, [])

  const updateNotice = useCallback((id: string, updates: Partial<Omit<NoticeItem, 'id'>>) => {
    setNotices((prev) => {
      const next = prev.map((n) => (n.id === id ? { ...n, ...updates } : n))
      persist(next)
      return next
    })
  }, [])

  const removeNotice = useCallback((id: string) => {
    setNotices((prev) => {
      const next = prev.filter((n) => n.id !== id)
      persist(next)
      return next
    })
  }, [])

  const clearAll = useCallback(() => {
    setNotices([])
    localStorage.removeItem(_key(STORAGE_KEY))
  }, [])

  return (
    <NoticeBoardContext.Provider value={{ notices, addNotice, updateNotice, removeNotice, clearAll }}>
      {children}
    </NoticeBoardContext.Provider>
  )
}

export function useNoticeBoard() {
  const ctx = useContext(NoticeBoardContext)
  if (!ctx) throw new Error('useNoticeBoard must be used within NoticeBoardProvider')
  return ctx
}
