/**
 * Session reset registry — ensures all module-level state is cleared on logout.
 *
 * Modules with persistent (closure-scoped) stores register a reset callback here.
 * When a user logs out, `resetAllSessions()` is called to wipe every registered
 * store plus any user-scoped localStorage keys, preventing data leakage between
 * different user sessions on the same browser.
 */

type ResetFn = () => void

const _resetCallbacks: ResetFn[] = []

/** Register a cleanup function to be called on logout / session reset. */
export function registerSessionReset(fn: ResetFn): void {
  if (!_resetCallbacks.includes(fn)) {
    _resetCallbacks.push(fn)
  }
}

/** Base keys in localStorage that hold user-scoped data and must be cleared on logout. */
const USER_SCOPED_BASE_KEYS = [
  'robustidps_results',
  'robustidps_job_id',
  'robustidps_file_name',
  'robustidps_source',
  'robustidps_ablation',
  'robustidps_notices',
]

/** sessionStorage keys that hold sensitive data and must be cleared on logout. */
const SESSION_SCOPED_KEYS = [
  'robustidps_copilot_api_key',
]

/** Call every registered reset callback and clear user-scoped localStorage. */
export function resetAllSessions(): void {
  // 1. Invoke all registered module-level store resets
  for (const fn of _resetCallbacks) {
    try { fn() } catch { /* don't let one failure prevent others */ }
  }

  // 2. Clear user-scoped localStorage keys (both legacy un-scoped and email-scoped)
  for (const key of USER_SCOPED_BASE_KEYS) {
    localStorage.removeItem(key)
  }
  // Clear any email-scoped keys (format: baseKey::email)
  const toRemove: string[] = []
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i)
    if (k && USER_SCOPED_BASE_KEYS.some(base => k.startsWith(base + '::'))) {
      toRemove.push(k)
    }
  }
  for (const k of toRemove) {
    localStorage.removeItem(k)
  }

  // 3. Clear sensitive sessionStorage keys (e.g. copilot API key)
  for (const key of SESSION_SCOPED_KEYS) {
    sessionStorage.removeItem(key)
  }
  // Also clear any legacy localStorage copy of the API key
  localStorage.removeItem('robustidps_copilot_api_key')
}
