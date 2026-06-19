const API = import.meta.env.VITE_API_URL || ''

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API}${path}`)
  if (!res.ok) throw new Error(`${path} → ${res.status}`)
  return res.json()
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
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
