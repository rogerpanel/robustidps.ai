// Agent Guard (safety filter) API: /api/agent-guard/*
const API = import.meta.env.VITE_API_URL || ''

function headers(json = false): Record<string, string> {
  const h: Record<string, string> = json ? { 'Content-Type': 'application/json' } : {}
  const token = localStorage.getItem('robustidps_token') || localStorage.getItem('robustidps_api_key')
  if (token) h['Authorization'] = `Bearer ${token}`
  return h
}

async function call<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${API}/api/agent-guard${path}`, body === undefined
    ? { headers: headers() }
    : { method: 'POST', headers: headers(true), body: JSON.stringify(body) })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    const d = (data as { detail?: unknown }).detail
    const msg = typeof d === 'string' ? d
      : d && typeof d === 'object' && 'policy_errors' in d ? (d as { policy_errors: string[] }).policy_errors.join('; ')
      : `Error ${res.status}`
    throw new Error(msg)
  }
  return data as T
}

export type Verdict = 'allow' | 'modify' | 'ask' | 'deny'

export interface GuardFinding { rule_id: string; verdict: Verdict; reason: string }

export interface GuardDecision {
  decision: Verdict
  risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'UNKNOWN'
  reasons: string[]
  findings: GuardFinding[]
  modified_args: Record<string, unknown> | null
  canonical_tool: string
  tier: string
  hidden_characters: string[]
  session_calls: number
  policy_id: string
  policy_version: string
  filter_version: string
  latency_ms: number
}

export interface GuardLogEntry extends GuardDecision {
  t: number
  session_id: string
  tool_name: string
  args: Record<string, unknown>
}

export type GuardPolicy = Record<string, unknown> & { id: string; version: string; name: string; description: string }

export const guardInfo = () => call<{ filter_version: string; timeout_s: number }>('/info')
export const guardPolicies = () => call<GuardPolicy[]>('/policies')
export const guardValidate = (policy: unknown) => call<{ valid: boolean; errors: string[] }>('/policies/validate', { policy })
export const guardCheck = (body: {
  session_id: string; tool_name: string; args: Record<string, unknown>
  policy_id?: string; policy?: unknown; framework?: string
}) => call<GuardDecision>('/check', body)
export const guardDecisions = (sessionId: string) =>
  call<GuardLogEntry[]>(`/decisions?session_id=${encodeURIComponent(sessionId)}&limit=50`)
export const guardReset = (sessionId: string) =>
  call<{ reset: boolean }>(`/sessions/${encodeURIComponent(sessionId)}/reset`, {})
export const guardClientUrl = `${API}/api/agent-guard/client.py`
