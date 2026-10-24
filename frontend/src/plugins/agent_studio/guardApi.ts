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
      : Array.isArray(d) ? d.map((e: { loc?: unknown[]; msg?: string }) =>
          `${(e.loc || []).filter((x) => x !== 'body').join('.')}: ${e.msg}`).join('; ')
      : d && typeof d === 'object' && 'policy_errors' in d ? (d as { policy_errors: string[] }).policy_errors.join('; ')
      : d && typeof d === 'object' && 'suite_errors' in d ? (d as { suite_errors: string[] }).suite_errors.join('; ')
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
  call_key: string
  approval_id: string | null
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
  policy_id?: string; policy?: unknown; framework?: string; approval_id?: string
}) => call<GuardDecision>('/check', body)
export const guardDecisions = (sessionId: string) =>
  call<GuardLogEntry[]>(`/decisions?session_id=${encodeURIComponent(sessionId)}&limit=50`)
export const guardReset = (sessionId: string) =>
  call<{ reset: boolean }>(`/sessions/${encodeURIComponent(sessionId)}/reset`, {})
export const guardClientUrl = `${API}/api/agent-guard/client.py`
export const guardIntegrationUrl = (name: 'agentdojo' | 'inspect') => `${API}/api/agent-guard/integrations/${name}`

// ── approvals ─────────────────────────────────────────────────────────
export interface GuardApproval {
  id: string
  session_id: string
  status: 'pending' | 'approved' | 'denied' | 'used' | 'expired'
  created_at: string
  expires_at: string
  decided_at: string | null
  decided_by: string
  note: string
  request: { tool_name: string; args: Record<string, unknown>; policy_id: string; policy_version: string; agent_id: string; framework: string }
  preview: {
    tool: string; canonical_tool: string; args: Record<string, unknown>; tier: string; tier_description: string
    reversible: boolean | null; targets: { arg: string; value: string }[]; n_targets: number
    hidden_characters: string[]; reasons: string[]; risk: string; agent_id: string; framework: string; policy: string
  }
}
export const guardApprovals = (status?: string) =>
  call<GuardApproval[]>(`/approvals${status ? `?status=${status}` : ''}`)
export const guardDecideApproval = (id: string, decision: 'approve' | 'deny', note: string) =>
  call<GuardApproval>(`/approvals/${encodeURIComponent(id)}/decide`, { decision, note })

// ── tool registry ─────────────────────────────────────────────────────
export interface RegistryTool {
  name: string; description: string; input_schema: Record<string, unknown>; fingerprint: string; hidden: string[]
}
export interface Toolset {
  id: string; name: string; version: number; pinned: boolean; digest: string; created_at: string
  n_tools: number; n_hidden: number; unchanged?: boolean
  scan: { n_findings: number; severity_breakdown: Record<string, number>; triggered: { code: string; title: string; severity: string }[] } | null
  diff: { against_version: number; added: string[]; removed: string[]; changed: string[] } | null
  tools?: RegistryTool[]
}
export interface Coverage {
  policy_id: string; policy_version: string; total: number; unclassified: number
  tools: { name: string; tier: string; decision: string; explicit: boolean; effect_hint: string; suggested_tier: string | null; hidden: string[] }[]
  generated_policy: GuardPolicy
}
export const guardToolsets = () => call<Toolset[]>('/toolsets')
export const guardRegisterToolset = (name: string, text: string) => call<Toolset>('/toolsets', { name, text })
export const guardToolset = (name: string, version?: number) =>
  call<Toolset>(`/toolsets/${encodeURIComponent(name)}${version ? `?version=${version}` : ''}`)
export const guardPinToolset = (name: string, version: number) =>
  call<Toolset>(`/toolsets/${encodeURIComponent(name)}/pin?version=${version}`, {})
export const guardCoverage = (name: string, version: number, policy_id: string, policy?: unknown) =>
  call<Coverage>(`/toolsets/${encodeURIComponent(name)}/coverage`, { version, policy_id, policy })

// ── evaluation ────────────────────────────────────────────────────────
export interface SuiteCase { id: string; tool: string; args: Record<string, unknown>; expect: Verdict; group?: string | null }
export interface GuardSuite { id: string; version: string; policy_id: string; description: string; cases: SuiteCase[] }
export interface EvalResult {
  summary: {
    suite: string; policy: string; cases: number; exact_accuracy: number; stop_recall: number | null
    false_stop_rate: number | null; confusion: Record<string, number>; groups: number
    invariance_violations: string[]; mean_latency_ms: number
  }
  rows: { id: string; tool: string; group: string | null; expect: Verdict; got: Verdict; correct: boolean; rules: string[]; latency_ms: number }[]
  filter_version: string; suite_digest: string; policy_digest: string; result_digest: string
  evidence: { seq: number; hash: string }
  reproduction: { earlier_runs_same_inputs: number; all_match: boolean | null }
}
export const guardSuites = () => call<GuardSuite[]>('/suites')
export const guardEvaluate = (body: { suite_id?: string; suite?: unknown; policy_id?: string; policy?: unknown }) =>
  call<EvalResult>('/evaluate', body)

// ── evidence ledger ───────────────────────────────────────────────────
export interface EvidenceRecord { seq: number; created_at: string; kind: string; summary: string; payload_digest: string; prev_hash: string; hash: string }
export interface EvidenceVerification { valid: boolean; records: number; head: string; broken_at?: number; problems?: string[] }
export const guardEvidence = (kind?: string) => call<EvidenceRecord[]>(`/evidence?limit=200${kind ? `&kind=${kind}` : ''}`)
export const guardVerifyEvidence = () => call<EvidenceVerification>('/evidence/verify')
export const guardExportEvidence = () => call<Record<string, unknown>>('/evidence/export')

export interface CompareRow {
  name: string; kind: 'policy' | 'ablation' | 'baseline'
  exact_accuracy: number; stop_recall: number | null; false_stop_rate: number | null
  ci95: { exact_accuracy: [number, number] | null; stop_recall: [number, number] | null; false_stop_rate: [number, number] | null }
  verdicts_digest: string
}
export interface CompareResult {
  suite: string; policy: string; cases: number; table: CompareRow[]
  bootstrap: { resamples: number; seed: number }
  comparison_digest: string; note: string; evidence: { seq: number; hash: string }
}
export const guardCompare = (body: { suite_id?: string; suite?: unknown; policy_id?: string; policy?: unknown }) =>
  call<CompareResult>('/evaluate/compare', body)
