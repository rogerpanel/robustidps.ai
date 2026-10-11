const API = import.meta.env.VITE_API_URL || ''

export type Vertical = 'uav' | 'agent_studio'
export type Audience = 'operator' | 'auditor' | 'investor'

export interface Dossier {
  dossier_id: string
  vertical: Vertical
  vertical_label: string
  audience: Audience
  generated_at: string
  commit: string
  subject: Record<string, unknown>
  operational_headline?: Record<string, unknown>
  certificates?: Record<string, unknown>
  attack_coverage: Record<string, unknown>
  industry_position?: Record<string, unknown>
  regulatory_mapping: Record<string, unknown>[]
  reproducibility: Record<string, unknown>
  scan_report?: Record<string, unknown> | null
}

export async function generateDossier(
  vertical: Vertical,
  audience: Audience = 'auditor',
  scan_report: unknown | null = null,
): Promise<Dossier> {
  const res = await fetch(`${API}/api/dossier/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ vertical, audience, scan_report }),
  })
  if (!res.ok) throw new Error(`/api/dossier/generate → ${res.status}`)
  return res.json()
}

export async function listVerticals(): Promise<{ id: Vertical; label: string; chapter: string }[]> {
  const res = await fetch(`${API}/api/dossier/verticals`)
  const data = await res.json()
  return data.verticals
}
