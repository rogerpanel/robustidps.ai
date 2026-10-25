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
  prediction: GuardPrediction | null
  deferral: GuardDeferral | null
  flow: GuardFlow | null
  actions: GuardTyped[] | null
  budget_charges: Record<string, number> | null
}

export interface GuardTyped {
  id: string; targets: string[]; n_targets: number | null; ports: number | null; probes: number | null
  rates: Record<string, number>; projected: boolean; dropped: string[]
}

export interface FlowSource { tool: string; call: number }
export interface GuardFlow {
  tool: string
  call_labels: string[]
  label_reasons: Record<string, string>
  unclassified: boolean
  session_before: Record<string, FlowSource>
  session_after: string[]
  rules: { id: string; verdict: Verdict }[]
}
export interface GuardSessionState {
  session_id: string; exists: boolean; calls: number; denied_attempts: number
  budget_used: Record<string, number>; unavailable: string[]; blast: number; labels: Record<string, FlowSource>
}

export interface GuardDeferral {
  mode: string; score: number | null; eligible: boolean; reason: string
  threshold?: number | null; alpha?: number; would_auto_approve?: boolean
}

export interface GuardPrediction {
  effect: string
  affected: { id: string; name: string; role: string; group: string | null; dependents: number }[]
  unknown: string[]
  blast_radius: number
  session_blast_radius: number
  groups: { group: string; members: number; remaining_after: number; min_available: number }[]
  safe: boolean
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
export const guardSession = (sessionId: string) =>
  call<GuardSessionState>(`/sessions/${encodeURIComponent(sessionId)}`)
export const guardReset = (sessionId: string) =>
  call<{ reset: boolean }>(`/sessions/${encodeURIComponent(sessionId)}/reset`, {})
export const guardClientUrl = `${API}/api/agent-guard/client.py`
export const guardIntegrationUrl = (name: 'agentdojo' | 'inspect' | 'selftest' | 'claude-sdk') => `${API}/api/agent-guard/integrations/${name}`
export const guardOpenHandsHooksUrl = (policy: string, approvalWait = 0) =>
  `${API}/api/agent-guard/integrations/openhands-hooks?policy=${encodeURIComponent(policy)}&approval_wait=${approvalWait}`

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
    prediction?: GuardPrediction | null
    deferral?: GuardDeferral | null
    flow?: GuardFlow | null
    actions?: GuardTyped[] | null
    budget_charges?: Record<string, number> | null
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
  tools: {
    name: string; tier: string; decision: string; explicit: boolean; effect_hint: string; suggested_tier: string | null; hidden: string[]
    flow_labels?: string[]; flow_conditional?: string[]; flow_assumed?: boolean; suggested_flow?: string[]
  }[]
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
export interface SuiteCase {
  id: string; tool: string; args: Record<string, unknown>; expect: Verdict; group?: string | null
  category?: string | null; context?: string | null; appropriate?: boolean | null
  session?: string | null; expect_rule?: string | null
}
export interface GuardSuite { id: string; version: string; policy_id: string; description: string; cases: SuiteCase[] }
export interface EvalResult {
  summary: {
    suite: string; policy: string; cases: number; exact_accuracy: number; stop_recall: number | null
    false_stop_rate: number | null; confusion: Record<string, number>; groups: number
    intervention_rate: number | null; repair_rate: number | null
    reason_accuracy: number | null; sessions: number
    invariance_violations: string[]; mean_latency_ms: number
    appropriateness: Record<'appropriate' | 'inappropriate', { n: number; let_through?: number; to_a_person?: number; denied?: number }> | null
    by_category: Record<string, { n: number; exact_accuracy: number }>
  }
  rows: {
    id: string; tool: string; group: string | null; session: string | null; expect: Verdict; got: Verdict; correct: boolean
    rules: string[]; expect_rule: string | null; reason_ok: boolean | null; latency_ms: number
  }[]
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
  intervention_rate: number | null; repair_rate: number | null; reason_accuracy: number | null
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

// ── environment model (predictive layer) ──────────────────────────────
export const guardEnvironment = () =>
  call<{ version: number; environment: Record<string, unknown> | null; example: Record<string, unknown> }>('/environment')
export const guardValidateEnvironment = (environment: unknown) =>
  call<{ valid: boolean; errors: string[]; assets?: number; groups?: number }>('/environment/validate', { environment })
export async function guardSaveEnvironment(environment: unknown) {
  const res = await fetch(`${API}/api/agent-guard/environment`, {
    method: 'PUT', headers: headers(true), body: JSON.stringify({ environment }),
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    const d = (data as { detail?: unknown }).detail
    throw new Error(typeof d === 'string' ? d
      : d && typeof d === 'object' && 'environment_errors' in d ? (d as { environment_errors: string[] }).environment_errors.join('; ')
      : `Error ${res.status}`)
  }
  return data as { version: number; assets: number; groups: number }
}

// ── calibrated deferral ──────────────────────────────────────────────
export interface DeferralSettings { mode: 'off' | 'shadow' | 'auto'; alpha: number; delta: number; min_samples: number }
export interface DeferralCalibration {
  n: number; alpha: number; delta: number; min_samples: number; denial_rate: number | null; method: string
  ready: boolean; threshold: number | null; auto_share: number; historical_miss_rate?: number; reason: string
}
export const guardDeferral = () => call<{ settings: DeferralSettings; calibration: DeferralCalibration }>('/deferral')
export async function guardSaveDeferral(settings: DeferralSettings) {
  const res = await fetch(`${API}/api/agent-guard/deferral`, { method: 'PUT', headers: headers(true), body: JSON.stringify(settings) })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(typeof (data as { detail?: unknown }).detail === 'string' ? (data as { detail: string }).detail : `Error ${res.status}`)
  return data as { settings: DeferralSettings; calibration: DeferralCalibration }
}
