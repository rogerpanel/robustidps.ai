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
