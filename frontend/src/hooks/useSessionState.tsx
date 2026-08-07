/**
 * useSessionState — hook that syncs page state to/from the server session.
 *
 * On mount, loads persisted state from the server (if any).
 * On state changes, debounce-saves back to the server.
 * Listens for cross-tab state-sync events and updates local state.
 *
 * Usage:
 *   const { serverState, saveState, loaded } = useSessionState('live-monitor')
 *
 *   // On mount, check `serverState` and restore UI
 *   // When UI state changes, call saveState({ ... })
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import { savePageState, loadPageState } from '../utils/sessionManager'
import { isAuthenticated } from '../utils/auth'

interface UseSessionStateResult {
  serverState: Record<string, unknown> | null
  saveState: (state: Record<string, unknown>) => void
  loaded: boolean
}

export function useSessionState(page: string): UseSessionStateResult {
  const [serverState, setServerState] = useState<Record<string, unknown> | null>(null)
  const [loaded, setLoaded] = useState(false)
  const pageRef = useRef(page)
  pageRef.current = page

  // Load state from server on mount
  useEffect(() => {
    if (!isAuthenticated()) {
      setLoaded(true)
      return
    }

    let cancelled = false
    loadPageState(page).then((state) => {
      if (!cancelled) {
        setServerState(state)
        setLoaded(true)
      }
    })
    return () => { cancelled = true }
  }, [page])

  // Listen for cross-tab state updates
  useEffect(() => {
    const handler = (e: Event) => {
      const detail = (e as CustomEvent).detail
      if (detail?.page === pageRef.current) {
        setServerState(detail.state)
      }
    }
    window.addEventListener('robustidps-state-sync', handler)
    return () => window.removeEventListener('robustidps-state-sync', handler)
  }, [])

  const saveState = useCallback(
    (state: Record<string, unknown>) => {
      if (!isAuthenticated()) return
      savePageState(pageRef.current, state)
    },
    [],
  )

  return { serverState, saveState, loaded }
}
