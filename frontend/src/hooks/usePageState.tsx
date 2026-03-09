/**
 * usePageState — persistent in-memory state for page components.
 *
 * Works like useState but survives React Router navigations because
 * the state lives in a module-level Map rather than inside the
 * unmounted page component.
 *
 * Usage:
 *   const [file, setFile] = usePageState<File | null>('redteam', 'file', null)
 *
 * On logout clearAllPageState() is called automatically via sessionReset.
 */

import { useState, useCallback, useRef } from 'react'
import { registerSessionReset } from '../utils/sessionReset'
import { getUser } from '../utils/auth'

// Module-level store — persists across mounts/unmounts
const _store = new Map<string, any>()

/** Clear all persisted page state (called on logout). */
export function clearAllPageState(): void {
  _store.clear()
}

registerSessionReset(clearAllPageState)

function mk(page: string, key: string) {
  const u = getUser()
  const prefix = u ? `${u.email}::` : ''
  return `${prefix}${page}::${key}`
}

/**
 * Drop-in replacement for useState that persists across navigations.
 *
 * @param page  Unique page identifier, e.g. 'redteam'
 * @param key   State key within the page, e.g. 'file'
 * @param init  Default / initial value (used only if nothing stored yet)
 */
export function usePageState<T>(
  page: string,
  key: string,
  init: T,
): [T, (v: T | ((prev: T) => T)) => void] {
  const k = mk(page, key)

  // Seed the store on first call for this key
  const seeded = useRef(false)
  if (!seeded.current) {
    seeded.current = true
    if (!_store.has(k)) {
      _store.set(k, init)
    }
  }

  // Local tick state to trigger re-renders
  const [, setTick] = useState(0)

  const value: T = _store.has(k) ? _store.get(k) : init

  const setter = useCallback(
    (v: T | ((prev: T) => T)) => {
      const prev: T = _store.has(k) ? _store.get(k) : init
      const next = typeof v === 'function' ? (v as (p: T) => T)(prev) : v
      _store.set(k, next)
      setTick(t => t + 1)
    },
    [k, init],
  )

  return [value, setter]
}
