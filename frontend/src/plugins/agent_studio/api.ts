const API = import.meta.env.VITE_API_URL || ''

// Identity is layered: a platform JWT (admin or tier-scoped user) wins
// when present; otherwise we fall back to the rids_live_… key the user
// pasted into the Account Console. The backend accepts whichever is
// useful — admin JWTs bypass tier checks entirely.
function _identityHeaders(): Record<string, string> {
  const headers: Record<string, string> = {}
  const platformToken = typeof localStorage !== 'undefined'
    ? localStorage.getItem('robustidps_token') : null
  const apiKey = typeof localStorage !== 'undefined'
    ? localStorage.getItem('robustidps_api_key') : null
  // Platform JWT takes precedence (admin would always want their session).
  const bearer = platformToken || apiKey
  if (bearer) headers['Authorization'] = `Bearer ${bearer}`
  return headers
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API}${path}`, { headers: _identityHeaders() })
  if (!res.ok) throw new Error(`${path} → ${res.status}`)
  return res.json()
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ..._identityHeaders() },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`${path} → ${res.status}`)
  return res.json()
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type InputKind = 'mcp_manifest' | 'tool_list' | 'system_prompt' | 'agent_card'

export interface ScanCheckResult {
  code: string
  title: string
  severity: Severity
  owasp_agentic: string | null
  triggered: boolean
  remediation: string
}

export interface ScanReport {
  input_kind: InputKind
  input_size_chars: number
  n_checks_run: number
  n_findings: number
  severity_breakdown: Partial<Record<Severity, number>>
  results: ScanCheckResult[]
}

export interface SKU {
  id: string
  name: string
  price_usd: string
  duration: string
  summary: string
}

export const runAgentScan = (b: { text: string; input_kind: InputKind }) =>
  postJson<ScanReport>('/api/agent-studio/scanner/run', b)

export const fetchScannerChecks = () =>
  getJson<{ checks: { code: string; title: string; severity: Severity; owasp_agentic: string | null; remediation: string }[] }>(
    '/api/agent-studio/scanner/checks'
  )

export const fetchSKUCatalog = () =>
  getJson<{ skus: SKU[] }>('/api/agent-studio/sku-catalog')

// ── Access info — surfaces which identity modes the server accepts ──

export interface AccessInfo {
  auth_disabled: boolean
  demo_mode: boolean
  admin_token_set: boolean
  sources_accepted: string[]
}
export const fetchAccessInfo = () =>
  getJson<AccessInfo>('/api/agent-studio/access-info')

// ── Eval Harness ─────────────────────────────────────────────────────

export interface EvalResult {
  eval_id: string; name: string; score: number
  verdict: 'pass' | 'warn' | 'fail'
  detail: string; n_probes: number; elapsed_ms: number
}
export interface EvalRun {
  run_id: string; agent_name: string; timestamp: string
  overall_score: number
  overall_verdict: 'pass' | 'warn' | 'fail'
  results: EvalResult[]
}
export const runAgentEval = (agent_spec: unknown) =>
  postJson<EvalRun>('/api/agent-studio/eval/run', { agent_spec })
export const fetchEvalHistory = () =>
  getJson<{ runs: EvalRun[] }>('/api/agent-studio/eval/history?limit=10')

// ── Red Team ─────────────────────────────────────────────────────────

export interface RedTeamProbeResult {
  code: string; owasp_agentic: string; atlas_tactic: string
  name: string; severity: Severity; triggered: boolean
  remediation: string
}
export interface RedTeamRun {
  run_id: string; target_name: string; timestamp: string
  n_probes: number; n_findings: number
  severity_breakdown: Partial<Record<Severity, number>>
  atlas_chain: string[]
  results: RedTeamProbeResult[]
}
export const runAgentRedTeam = (target_spec: unknown) =>
  postJson<RedTeamRun>('/api/agent-studio/red-team/run', { target_spec })
export const runAgentRedTeamGarak = (target_spec: unknown) =>
  postJson<RedTeamRun>('/api/agent-studio/red-team/garak', { target_spec })
export const fetchGarakInfo = () =>
  getJson<{ runner: 'garak_live' | 'garak_synthetic_fallback';
            version: string; hint?: string }>(
    '/api/agent-studio/red-team/garak/info')
export const fetchRedTeamCatalog = () =>
  getJson<{ n_probes: number; by_owasp_agentic: Record<string, string[]>;
            probes: { code: string; owasp_agentic: string; atlas_tactic: string;
                       name: string; severity: Severity; remediation: string }[] }>(
    '/api/agent-studio/red-team/catalog')

// ── Runtime Monitor ──────────────────────────────────────────────────

export interface RuntimeAgentSummary {
  agent_id: string; framework: string; window_size: number
  n_events: number; block_rate: number; warn_rate: number
  p50_latency_ms: number; p95_latency_ms: number
  top_findings: { code: string; count: number }[]
}
export interface RuntimeAlert {
  alert_id: string; ts_ms: number; agent_id: string; framework: string
  block_rate: number; window_size: number; trigger: string[]
  severity: string; message: string
}
export interface RuntimeSnapshot {
  n_agents: number
  agents: RuntimeAgentSummary[]
  recent_alerts: RuntimeAlert[]
}
export const fetchRuntimeSnapshot = () =>
  getJson<RuntimeSnapshot>('/api/agent-studio/runtime/snapshot')
export const seedRuntimeDemo = () =>
  postJson<RuntimeSnapshot>('/api/agent-studio/runtime/seed-demo', {})
export const resetRuntime = () =>
  postJson<{ reset: boolean }>('/api/agent-studio/runtime/reset', {})
export const ingestOTelSpan = (span: Record<string, unknown>) =>
  postJson<unknown>('/api/agent-studio/runtime/otel/spans', span)
export const ingestOTelTraces = (otlp: Record<string, unknown>) =>
  postJson<unknown>('/api/agent-studio/runtime/otel/traces', otlp)
export const fetchOTelInfo = () =>
  getJson<{ receiver: string; version: string; semconv_version: string;
            endpoints: string[]; supported_attributes: string[] }>(
    '/api/agent-studio/runtime/otel/info')

// ── Supply Chain Scan ────────────────────────────────────────────────

export interface FormatRisk { file_format: string; risk_level: string; rationale: string }
export interface ModelScan {
  scan_id: string; model_id: string; timestamp: string
  origin: string; licence: string; size_gb: number | null
  downloads: number | null; likes: number | null
  architecture: string; parent_models: string[]
  format_risks: FormatRisk[]
  cve_matches: { cve: string; severity: string; summary: string; affects: string }[]
  risk_score: number
  risk_level: 'safe' | 'low' | 'medium' | 'high' | 'critical'
  sbom_fragment: Record<string, unknown>
  rationale: string[]
}
export const scanModel = (model_id: string, spec: Record<string, unknown> = {}) =>
  postJson<ModelScan>('/api/agent-studio/supply-chain/scan', { model_id, spec })
export const scanModelLive = (model_id: string, spec: Record<string, unknown> = {}) =>
  postJson<ModelScan & { hf_enrichment_used: boolean }>(
    '/api/agent-studio/supply-chain/scan-live', { model_id, spec })
export const fetchHfInfo = () =>
  getJson<{ client: string; version: string; base_url: string;
            timeout_s: number; has_token: boolean; fallback: string }>(
    '/api/agent-studio/supply-chain/hf-info')

// ── Billing / Checkout ───────────────────────────────────────────────

export interface CheckoutSession {
  mode: 'live' | 'staging' | 'error'
  session_id?: string
  url?: string
  tier?: 'pro' | 'enterprise'
  email?: string
  trial_days?: number
  hint?: string
  error?: string
}
export interface CustomerApiKey {
  id: string; label: string; prefix: string
  created_at: string; last_used_at: string | null; revoked: boolean
}
export interface Customer {
  customer_id: string
  email: string
  tier: string
  created_at: string
  trial_ends_at: string | null
  api_keys: CustomerApiKey[]
  stripe_customer_id: string | null
  stripe_subscription_id: string | null
}
export interface CheckoutCompleteResult {
  customer_id: string; email: string; tier: string
  trial_ends_at: string
  api_key: string         // plaintext, shown ONCE
  api_key_id: string
  welcome_message: string
}

export const createCheckout = (email: string, tier: 'pro' | 'enterprise', trial_days = 14) =>
  postJson<CheckoutSession>('/api/agent-studio/billing/checkout',
    { email, tier, trial_days })

export const completeCheckout = (session_id: string, email: string, tier: 'pro' | 'enterprise') =>
  postJson<CheckoutCompleteResult>('/api/agent-studio/billing/checkout/complete',
    { session_id, email, tier })

export const fetchCustomer = (customer_id: string) =>
  getJson<Customer>(`/api/agent-studio/customers/${customer_id}`)

export const issueApiKey = (customer_id: string, label: string) =>
  postJson<{ api_key: string; key_id: string; label: string; customer_id: string }>(
    '/api/agent-studio/api-keys/issue', { customer_id, label })

export const revokeApiKey = (customer_id: string, key_id: string) =>
  postJson<{ ok: boolean; key_id?: string; revoked?: boolean; error?: string }>(
    '/api/agent-studio/api-keys/revoke', { customer_id, key_id })

// ── Quickstart templates ─────────────────────────────────────────────

export interface AgentEnvironment {
  runtime: string
  network_policy: 'outbound_open' | 'outbound_blocked' | 'allowlist'
  network_allowlist: string[]
  packages: string[]
  mcp_servers: { name: string; url: string; policy: string }[]
  env_vars: string[]
  secrets: string[]
}
export interface IntegrationSnippet {
  language: string
  framework: string
  code: string
}
export interface AgentTemplate {
  id: string
  name: string
  tier: 'A' | 'B' | 'C' | 'blank'
  category: string
  summary: string
  use_case: string
  frameworks: string[]
  spec: Record<string, unknown>
  recommended_skus: string[]
  notes: string
  environment: AgentEnvironment
  test_inputs: string[]
  integration_snippets: IntegrationSnippet[]
}
export interface TemplateStats {
  n_templates: number
  by_tier: Record<string, number>
  by_category: Record<string, number>
}

export const listTemplates = (tier?: 'A' | 'B' | 'C' | 'blank') =>
  getJson<{ templates: AgentTemplate[]; stats: TemplateStats }>(
    `/api/agent-studio/templates${tier ? `?tier=${tier}` : ''}`)

export const fetchTemplate = (id: string) =>
  getJson<AgentTemplate>(`/api/agent-studio/templates/${id}`)

// ── Sessions ─────────────────────────────────────────────────────────

export interface SessionMessage {
  role: 'user' | 'agent' | 'system'
  text: string
  ts: string
  decision: 'allow' | 'warn' | 'block'
  n_findings: number
  findings: { code: string; severity: string; title: string }[]
  llm_meta?: { provider: string; model: string; n_in: number; n_out: number } | null
}
export interface SessionDetail {
  session_id: string
  template_id: string
  customer_id: string
  created_at: string
  history: SessionMessage[]
  aborted: boolean
}
export interface SessionListItem {
  session_id: string
  template_id: string
  customer_id: string
  created_at: string
  n_messages: number
  aborted: boolean
}

function _authJson<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json', ..._identityHeaders(),
  }
  return fetch(`${API}${path}`, {
    method, headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  }).then(async (r) => {
    if (!r.ok) throw new Error(`${path} → ${r.status} ${await r.text()}`)
    return r.json() as Promise<T>
  })
}

export const createSession = (template_id: string, customer_id?: string) =>
  _authJson<SessionDetail>('POST', '/api/agent-studio/sessions', { template_id, customer_id })

export const fetchSession = (session_id: string) =>
  _authJson<SessionDetail>('GET', `/api/agent-studio/sessions/${session_id}`)

export const listSessions = (limit = 50) =>
  _authJson<{ sessions: SessionListItem[]; stats: Record<string, unknown> }>(
    'GET', `/api/agent-studio/sessions?limit=${limit}`)

export const sendSessionMessage = (session_id: string, input: string) =>
  _authJson<{
    decision: 'allow' | 'warn' | 'block'
    n_findings: number
    findings: { code: string; severity: string; title: string }[]
    agent_reply: string | null
    input_decision: 'allow' | 'warn' | 'block'
    input_n_findings: number
    blocked_on?: 'input' | 'output'
  }>('POST', `/api/agent-studio/sessions/${session_id}/messages`, { input })

// ── Activity rollup (drives the portal's "recent" panel + Copilot) ──

export interface ActivityRollup {
  customer_id: string | null
  eval_runs: { run_id: string; agent_name: string;
               overall_verdict: 'pass' | 'warn' | 'fail';
               overall_score: number; timestamp: string }[]
  red_team_runs: { run_id: string; target_name: string;
                   n_findings: number; timestamp: string;
                   severity_breakdown: Record<string, number>;
                   atlas_chain: string[] }[]
  supply_chain_scans: { scan_id: string; model_id: string;
                        risk_level: string; risk_score: number;
                        timestamp: string }[]
  sessions: SessionListItem[]
  session_stats: Record<string, unknown>
  runtime_snapshot: Record<string, unknown>
  billing_admin_stats: Record<string, unknown>
  deployments?: DeploymentRecord[]
  deployment_stats?: DeploymentStats
}

export const fetchActivity = (limit = 5) =>
  _authJson<ActivityRollup>('GET', `/api/agent-studio/activity?limit=${limit}`)

// ── LLM info (which provider sessions hit) ───────────────────────────

export interface SessionLLMInfo {
  provider: 'anthropic' | 'openai' | 'google' | 'deepseek' | 'synthetic_fallback'
  model?: string
  reason?: string
  configured_priority: string[]
  available: string[]
}

export const fetchSessionLLMInfo = () =>
  getJson<SessionLLMInfo>('/api/agent-studio/sessions/llm-info')

// ── Deployments ──────────────────────────────────────────────────────

export type DeploymentStatus = 'healthy' | 'degraded' | 'stale' | 'retired'
export type CloudId = 'aws' | 'gcp' | 'azure' | 'fly' | 'modal' | 'vercel'
  | 'k8s_self' | 'docker_self' | 'bare_metal' | 'other'
export type DeploymentTier = 'dev' | 'staging' | 'production'

export interface DeploymentTelemetry {
  block_rate: number; warn_rate: number
  p50_latency_ms: number | null; p95_latency_ms: number | null
  n_events: number; window_size: number
  top_findings: { code: string; count: number }[]
}
export interface DeploymentRecord {
  deployment_id: string
  customer_id: string
  template_id: string
  name: string
  runtime_agent_id: string
  cloud: CloudId
  region: string
  tier: DeploymentTier
  url: string | null
  git_sha: string | null
  deployed_at: string
  deployed_by: string
  note: string
  retired_at: string | null
  status: DeploymentStatus
  telemetry: DeploymentTelemetry | null
}
export interface DeploymentStats {
  n_total: number; n_active: number; n_retired: number
  by_status: Record<string, number>
  by_cloud: Record<string, number>
  by_tier: Record<string, number>
  by_template: Record<string, number>
}

export const listDeployments = (include_retired = false) =>
  _authJson<{ deployments: DeploymentRecord[]; stats: DeploymentStats }>(
    'GET', `/api/agent-studio/deployments?include_retired=${include_retired}`)

export const registerDeployment = (body: {
  template_id: string; name: string; runtime_agent_id: string
  cloud?: CloudId; region?: string; tier?: DeploymentTier
  url?: string | null; git_sha?: string | null
  deployed_by?: string; note?: string
}) =>
  _authJson<DeploymentRecord>('POST', '/api/agent-studio/deployments', body)

export const retireDeployment = (deployment_id: string) =>
  _authJson<{ ok: boolean; deployment_id: string; retired_at?: string; error?: string }>(
    'POST', `/api/agent-studio/deployments/${deployment_id}/retire`)

// ── Admin grants ─────────────────────────────────────────────────────

const ADMIN_TOKEN_KEY = 'robustidps_admin_token'
export const getStoredAdminToken = () =>
  typeof localStorage !== 'undefined' ? localStorage.getItem(ADMIN_TOKEN_KEY) : null
export const setStoredAdminToken = (t: string | null) => {
  if (typeof localStorage === 'undefined') return
  if (t) localStorage.setItem(ADMIN_TOKEN_KEY, t)
  else localStorage.removeItem(ADMIN_TOKEN_KEY)
}

async function adminRequest<T>(method: string, path: string, body?: unknown): Promise<T> {
  const token = getStoredAdminToken()
  if (!token) throw new Error('Admin token not set')
  const res = await fetch(`${API}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) throw new Error(`${path} → ${res.status} ${await res.text()}`)
  return res.json()
}

export interface AdminGrant {
  grant_id: string
  customer_id: string
  email: string
  tier: string
  months: number
  payment_rail: string
  granted_at: string
  granted_by: string
  expires_at: string | null
  note: string
  revoked_at: string | null
}
export interface AdminGrantStats {
  n_total: number; n_active: number; n_revoked: number
  by_payment_rail: Record<string, number>
  by_tier: Record<string, number>
}

export const adminWhoami = () =>
  adminRequest<{ role: string; ok: boolean }>('GET', '/api/agent-studio/admin/whoami')

export const adminCreateGrant = (body: {
  email: string; tier: 'pro' | 'enterprise'; months: number
  payment_rail: string; note?: string; granted_by?: string
}) =>
  adminRequest<{
    grant_id: string; customer_id: string; email: string
    tier: string; api_key: string; key_id: string
    expires_at: string | null; welcome_message: string
  }>('POST', '/api/agent-studio/admin/grants', body)

export const adminListGrants = (include_revoked = true) =>
  adminRequest<{ grants: AdminGrant[]; stats: AdminGrantStats }>(
    'GET', `/api/agent-studio/admin/grants?include_revoked=${include_revoked}`)

export const adminRevokeGrant = (grant_id: string) =>
  adminRequest<{ ok: boolean; grant_id?: string; revoked_at?: string; error?: string }>(
    'POST', `/api/agent-studio/admin/grants/${grant_id}/revoke`)

export const adminListCustomers = () =>
  adminRequest<{ customers: Customer[] }>('GET', '/api/agent-studio/customers')

const API_KEY_STORAGE = 'robustidps_api_key'
export const getStoredApiKey = () =>
  typeof localStorage !== 'undefined' ? localStorage.getItem(API_KEY_STORAGE) : null
export const setStoredApiKey = (k: string | null) => {
  if (typeof localStorage === 'undefined') return
  if (k) localStorage.setItem(API_KEY_STORAGE, k)
  else localStorage.removeItem(API_KEY_STORAGE)
}
