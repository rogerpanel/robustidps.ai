/**
 * Anonymous visitor analytics — privacy-respecting, no PII.
 *
 * Tracks:
 * - Unique sessions (sessionStorage — dies on tab close)
 * - Return visitors (hashed visitor_id in localStorage)
 * - Page views and feature usage events
 * - Optional self-reported role (researcher / industry / student / other)
 *
 * All data is anonymous. No cookies, no fingerprinting, GDPR-friendly.
 */

// ── Session management ───────────────────────────────────────────────────

function generateId(): string {
  return crypto.randomUUID?.() ?? Math.random().toString(36).slice(2) + Date.now().toString(36)
}

export function getSessionId(): string {
  let id = sessionStorage.getItem('ridps_session_id')
  if (!id) {
    id = generateId()
    sessionStorage.setItem('ridps_session_id', id)
  }
  return id
}

export function getVisitorId(): string {
  let id = localStorage.getItem('ridps_visitor_id')
  if (!id) {
    id = generateId()
    localStorage.setItem('ridps_visitor_id', id)
  }
  return id
}

// ── Visitor role (optional, self-reported) ───────────────────────────────

export type VisitorRole = 'researcher' | 'industry' | 'student' | 'postdoc' | 'other' | null

export function getVisitorRole(): VisitorRole {
  return (localStorage.getItem('ridps_visitor_role') as VisitorRole) || null
}

export function setVisitorRole(role: VisitorRole): void {
  if (role) {
    localStorage.setItem('ridps_visitor_role', role)
  } else {
    localStorage.removeItem('ridps_visitor_role')
  }
}

// ── Event tracking ───────────────────────────────────────────────────────

type AnalyticsEvent = {
  event: string
  page?: string
  metadata?: Record<string, string | number | boolean>
}

const EVENT_QUEUE: AnalyticsEvent[] = []
let flushTimer: ReturnType<typeof setTimeout> | null = null

/**
 * Track an analytics event. Events are batched and flushed every 5 seconds
 * (or when the queue reaches 10 events) to minimize network overhead.
 */
export function trackEvent(event: string, metadata?: Record<string, string | number | boolean>): void {
  EVENT_QUEUE.push({
    event,
    page: window.location.pathname,
    metadata,
  })

  // Flush if queue is getting large
  if (EVENT_QUEUE.length >= 10) {
    flushEvents()
    return
  }

  // Otherwise debounce the flush
  if (flushTimer) clearTimeout(flushTimer)
  flushTimer = setTimeout(flushEvents, 5000)
}

/**
 * Track a page view. Call this on route changes.
 */
export function trackPageView(path: string): void {
  trackEvent('page_view', { path })
}

/**
 * Flush queued events to the backend.
 * Silently fails if backend is unavailable — analytics should never break the app.
 */
async function flushEvents(): Promise<void> {
  if (EVENT_QUEUE.length === 0) return

  const events = EVENT_QUEUE.splice(0, EVENT_QUEUE.length)
  if (flushTimer) {
    clearTimeout(flushTimer)
    flushTimer = null
  }

  const payload = {
    session_id: getSessionId(),
    visitor_id: getVisitorId(),
    visitor_role: getVisitorRole(),
    events,
    timestamp: new Date().toISOString(),
  }

  try {
    const base = import.meta.env.VITE_API_URL || ''
    await fetch(`${base}/api/analytics/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      // Use keepalive so events aren't lost on page unload
      keepalive: true,
    })
  } catch {
    // Silently fail — analytics should never disrupt the user experience
  }
}

// Flush remaining events on page unload
if (typeof window !== 'undefined') {
  window.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
      flushEvents()
    }
  })
}
