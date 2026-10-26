/**
 * Session Manager — cross-tab/device session synchronization.
 *
 * Features:
 *   1. Server-side session tracking (session_id stored alongside JWT)
 *   2. Heartbeat to keep session alive + detect timeout
 *   3. BroadcastChannel for cross-tab communication (same browser)
 *   4. Page state sync (persist/restore UI state to server)
 *   5. Auto-logout on session expiry or server invalidation
 *   6. storage event listener for cross-tab logout in different browsers
 */

import { getToken, getUser, clearAuth, setAuth, type AuthUser } from './auth'
import { resetAllSessions } from './sessionReset'

const API = import.meta.env.VITE_API_URL || ''
const SESSION_ID_KEY = 'robustidps_session_id'
const HEARTBEAT_INTERVAL = 60_000 // 60 seconds
const STATE_SYNC_DEBOUNCE = 2_000 // debounce state saves

// ── Session ID management ──────────────────────────────────────────────

export function getSessionId(): string | null {
  return localStorage.getItem(SESSION_ID_KEY)
}

export function setSessionId(id: string): void {
  localStorage.setItem(SESSION_ID_KEY, id)
}

export function clearSessionId(): void {
  localStorage.removeItem(SESSION_ID_KEY)
}

// ── Headers with session ───────────────────────────────────────────────

export function sessionHeaders(): Record<string, string> {
  const headers: Record<string, string> = {}
  const token = getToken()
  if (token) headers['Authorization'] = `Bearer ${token}`
  const sid = getSessionId()
  if (sid) headers['X-Session-ID'] = sid
  return headers
}

// ── BroadcastChannel for cross-tab sync ────────────────────────────────

type SessionMessage =
  | { type: 'logout' }
  | { type: 'login'; token: string; user: AuthUser; sessionId: string }
  | { type: 'state-update'; page: string; state: Record<string, unknown> }
  | { type: 'heartbeat-response'; expiresAt: string }

let _channel: BroadcastChannel | null = null

function getChannel(): BroadcastChannel | null {
  if (_channel) return _channel
  if (typeof BroadcastChannel === 'undefined') return null
  try {
    _channel = new BroadcastChannel('robustidps-session')
    return _channel
  } catch {
    return null
  }
}

// ── Heartbeat ──────────────────────────────────────────────────────────

let _heartbeatTimer: ReturnType<typeof setInterval> | null = null
let _onSessionExpired: (() => void) | null = null

async function sendHeartbeat(): Promise<void> {
  const token = getToken()
  if (!token) return

  try {
    const res = await fetch(`${API}/api/sessions/heartbeat`, {
      method: 'POST',
      headers: sessionHeaders(),
    })

    if (res.status === 401) {
      // Token or session expired — force logout
      _onSessionExpired?.()
      return
    }

    if (res.ok) {
      const data = await res.json()
      // Update session ID if server created a new one
      if (data.session_id) {
        setSessionId(data.session_id)
      }
      // Broadcast heartbeat to other tabs
      getChannel()?.postMessage({
        type: 'heartbeat-response',
        expiresAt: data.expires_at,
      } satisfies SessionMessage)
    }
  } catch {
    // Network error — don't force logout, will retry next interval
  }
}

// ── Page State Sync ────────────────────────────────────────────────────

const _pendingSaves = new Map<string, ReturnType<typeof setTimeout>>()

export async function savePageState(page: string, state: Record<string, unknown>): Promise<void> {
  // Debounce to avoid spamming the server
  const existing = _pendingSaves.get(page)
  if (existing) clearTimeout(existing)

  _pendingSaves.set(
    page,
    setTimeout(async () => {
      _pendingSaves.delete(page)
      const token = getToken()
      if (!token) return

      try {
        await fetch(`${API}/api/sessions/state`, {
          method: 'PUT',
          headers: {
            ...sessionHeaders(),
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ page, state }),
        })

        // Notify other tabs of state update
        getChannel()?.postMessage({
          type: 'state-update',
          page,
          state,
        } satisfies SessionMessage)
      } catch {
        // Silently fail — state sync is best-effort
      }
    }, STATE_SYNC_DEBOUNCE),
  )
}

export async function loadPageState(page: string): Promise<Record<string, unknown> | null> {
  const token = getToken()
  if (!token) return null

  try {
    const res = await fetch(`${API}/api/sessions/state/${encodeURIComponent(page)}`, {
      headers: sessionHeaders(),
    })
    if (!res.ok) return null
    const data = await res.json()
    return data.state && Object.keys(data.state).length > 0 ? data.state : null
  } catch {
    return null
  }
}

// ── Session Lifecycle ──────────────────────────────────────────────────

export function startSession(onExpired: () => void): void {
  _onSessionExpired = onExpired

  // Start heartbeat
  if (_heartbeatTimer) clearInterval(_heartbeatTimer)
  sendHeartbeat() // immediate first heartbeat
  _heartbeatTimer = setInterval(sendHeartbeat, HEARTBEAT_INTERVAL)

  // Listen for cross-tab messages
  const ch = getChannel()
  if (ch) {
    ch.onmessage = (ev: MessageEvent<SessionMessage>) => {
      const msg = ev.data
      switch (msg.type) {
        case 'logout':
          // Another tab logged out — mirror it here
          stopSession()
          resetAllSessions()
          clearAuth()
          clearSessionId()
          _onSessionExpired?.()
          break
        case 'login':
          // Another tab logged in — update our local state
          setAuth(msg.token, msg.user)
          setSessionId(msg.sessionId)
          break
        case 'state-update':
          // Another tab updated page state — emit a custom event
          window.dispatchEvent(
            new CustomEvent('robustidps-state-sync', {
              detail: { page: msg.page, state: msg.state },
            }),
          )
          break
      }
    }
  }

  // Listen for localStorage changes from other tabs (fallback for browsers without BroadcastChannel)
  window.addEventListener('storage', _handleStorageEvent)
}

export function stopSession(): void {
  if (_heartbeatTimer) {
    clearInterval(_heartbeatTimer)
    _heartbeatTimer = null
  }
  _onSessionExpired = null

  // Clear pending state saves
  for (const timer of _pendingSaves.values()) {
    clearTimeout(timer)
  }
  _pendingSaves.clear()

  window.removeEventListener('storage', _handleStorageEvent)
}

function _handleStorageEvent(e: StorageEvent): void {
  // If token was removed in another tab, force logout here too
  if (e.key === 'robustidps_token' && e.newValue === null) {
    stopSession()
    _onSessionExpired?.()
  }
}

export function broadcastLogin(token: string, user: AuthUser, sessionId: string): void {
  getChannel()?.postMessage({
    type: 'login',
    token,
    user,
    sessionId,
  } satisfies SessionMessage)
}

export function broadcastLogout(): void {
  getChannel()?.postMessage({ type: 'logout' } satisfies SessionMessage)
}

export async function serverLogout(logoutAll = false): Promise<void> {
  const token = getToken()
  if (!token) return

  try {
    await fetch(`${API}/api/sessions/logout${logoutAll ? '?all=true' : ''}`, {
      method: 'POST',
      headers: sessionHeaders(),
    })
  } catch {
    // Best-effort
  }
}

// ── Active Sessions (for admin/profile views) ──────────────────────────

export interface ActiveSession {
  session_id: string
  device_label: string
  ip_address: string
  is_active: boolean
  last_heartbeat: string
  created_at: string
  expires_at: string
}

export async function getActiveSessions(): Promise<ActiveSession[]> {
  const token = getToken()
  if (!token) return []

  try {
    const res = await fetch(`${API}/api/sessions/active`, {
      headers: sessionHeaders(),
    })
    if (!res.ok) return []
    return await res.json()
  } catch {
    return []
  }
}
