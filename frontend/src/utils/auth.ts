/**
 * Authentication utilities — JWT token management.
 */

const TOKEN_KEY = 'robustidps_token'
const USER_KEY = 'robustidps_user'

export interface AuthUser {
  id: number
  email: string
  full_name: string
  role: 'admin' | 'analyst' | 'viewer'
  organization: string
  use_case: string
  is_active: boolean
  created_at: string
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function getUser(): AuthUser | null {
  const raw = localStorage.getItem(USER_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw)
  } catch {
    return null
  }
}

export function setAuth(token: string, user: AuthUser): void {
  localStorage.setItem(TOKEN_KEY, token)
  localStorage.setItem(USER_KEY, JSON.stringify(user))
}

export function clearAuth(): void {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
}

export function isAuthenticated(): boolean {
  return !!getToken()
}

/**
 * Add Authorization header to fetch options.
 */
export function authHeaders(): Record<string, string> {
  const token = getToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}
