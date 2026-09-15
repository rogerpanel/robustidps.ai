/**
 * useAgentStudioState — persistent state for Agent Studio pages.
 *
 * Combines two layers:
 *   1. Module-level Map (instant in-memory) — survives React Router
 *      navigation (matches the platform's existing usePageState pattern).
 *   2. localStorage shim — survives hard reload + tab restart.
 *
 * Each Agent Studio page uses one namespace; the key inside the
 * namespace is the field name. Stored values are JSON-serialisable.
 *
 * Sample:
 *   const [text, setText]   = useAgentStudioState('redteam', 'targetSpec', SAMPLE)
 *   const [run,  setRun]    = useAgentStudioState<RedTeamRun | null>('redteam', 'lastRun', null)
 *
 * On logout / session reset, the persistent store clears via the
 * existing sessionReset registry.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { registerSessionReset } from '../utils/sessionReset'

const PREFIX = 'rids:as:'           // Agent Studio storage namespace
const VERSION_KEY = `${PREFIX}schema_version`
const SCHEMA_VERSION = '1'          // bump to invalidate stale entries

// In-memory layer — keeps things snappy and survives navigation
const _store = new Map<string, unknown>()

// Wipe any keys that pre-date the current schema version
;(function migrateOrClear() {
  if (typeof localStorage === 'undefined') return
  if (localStorage.getItem(VERSION_KEY) !== SCHEMA_VERSION) {
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const k = localStorage.key(i)
      if (k && k.startsWith(PREFIX)) localStorage.removeItem(k)
    }
    localStorage.setItem(VERSION_KEY, SCHEMA_VERSION)
  }
})()

export function clearAgentStudioState() {
  _store.clear()
  if (typeof localStorage !== 'undefined') {
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const k = localStorage.key(i)
      if (k && k.startsWith(PREFIX) && k !== VERSION_KEY) {
        localStorage.removeItem(k)
      }
    }
  }
}
registerSessionReset(clearAgentStudioState)

function mk(page: string, key: string) {
  return `${PREFIX}${page}:${key}`
}

function _readLS<T>(k: string, init: T): T {
  if (typeof localStorage === 'undefined') return init
  const raw = localStorage.getItem(k)
  if (raw === null) return init
  try { return JSON.parse(raw) as T } catch { return init }
}

function _writeLS(k: string, v: unknown) {
  if (typeof localStorage === 'undefined') return
  try { localStorage.setItem(k, JSON.stringify(v)) }
  catch { /* quota / private mode — silent */ }
}

/**
 * Drop-in replacement for useState that persists across navigation
 * AND hard reload (via localStorage). Scoped to the Agent Studio
 * namespace (`rids:as:<page>:<key>`).
 */
export function useAgentStudioState<T>(
  page: string,
  key: string,
  init: T,
): [T, (v: T | ((prev: T) => T)) => void] {
  const k = mk(page, key)

  // Seed in-memory store on first call (preferring localStorage)
  const seeded = useRef(false)
  if (!seeded.current) {
    seeded.current = true
    if (!_store.has(k)) {
      _store.set(k, _readLS(k, init))
    }
  }

  const [, setTick] = useState(0)
  const value: T = _store.has(k) ? (_store.get(k) as T) : init

  const setter = useCallback(
    (v: T | ((prev: T) => T)) => {
      const prev: T = _store.has(k) ? (_store.get(k) as T) : init
      const next = typeof v === 'function' ? (v as (p: T) => T)(prev) : v
      _store.set(k, next)
      _writeLS(k, next)
      setTick((t) => t + 1)
    },
    [k, init],
  )

  return [value, setter]
}

/**
 * Read a persisted Agent Studio value imperatively — useful when you
 * need to seed a UI from elsewhere (e.g. SOC Copilot deep-linking into
 * a page with a saved spec).
 */
export function readAgentStudioState<T>(page: string, key: string, fallback: T): T {
  const k = mk(page, key)
  if (_store.has(k)) return _store.get(k) as T
  return _readLS(k, fallback)
}

/**
 * Dump every persisted Agent Studio key so the SOC Copilot can offer
 * a "pick up where you left off" prompt from the client side.
 */
export function listAgentStudioState(): { key: string; value: unknown }[] {
  const out: { key: string; value: unknown }[] = []
  _store.forEach((v, k) => out.push({ key: k.slice(PREFIX.length), value: v }))
  return out
}
