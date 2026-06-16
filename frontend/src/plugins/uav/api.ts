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

// ── Types ──────────────────────────────────────────────────────────────

export interface MCRPoint { js_db: number; mcr: number; ci_low: number; ci_high: number }
export interface MCRCurve {
  config_key: string
  label: string
  color: string
  points: MCRPoint[]
  do_326a_crossing_db: number | null
}
export interface BenchMeta {
  name: string
  description: string
  n_flights: number
  regulatory_threshold: { name: string; mcr: number }
  operational_target: { name: string; mcr_floor: number; js_db_max: number }
}
export interface OverviewResponse {
  benchmark: BenchMeta
  ew_curves: MCRCurve[]
  phase_a_metrics: Record<string, number | string>
  tiers: { name: string; budget_w: number | null; methods: string[] }[]
  edge_profile: {
    platform: string; latency_ms_per_frame: number; fps: number;
    ram_mib: number; cpu_pct_one_core: number;
  }
}
export interface SwarmNode { id: string; kind: 'uav' | 'droneport' | 'intruder'; label: string }
export interface SwarmEdge { src: string; dst: string; kind: 'trust' | 'jammed' | 'hostile' }
export interface SwarmSnapshot { t: number; label: string; nodes: SwarmNode[]; edges: SwarmEdge[] }
export interface SatelliteFix {
  sv: string; azimuth_deg: number; elevation_deg: number;
  cno_db_hz: number; spoof_confidence: number; spoofed: boolean
}
export interface GNSSResponse {
  satellites: SatelliteFix[]; fleet_disagreement: number;
  mode: string; fallback: string | null
}
export interface CertificateResponse {
  lipschitz_L_g: number; gronwall_radius: number; rs_certified_radius: number;
  rs_sigma: number; rs_alpha: number; rs_samples: number;
  horizon_T: number; epsilon_out: number; pac_bayes_bound: number;
  dp_epsilon: number; dp_delta: number;
  operational_interpretation: {
    js_db_floor: number; mcr_floor: number;
    regulatory_floor_mcr: number; regulatory_floor_label: string;
  }
}
export interface AttackResult {
  attack: string; epsilon: number; pgd_steps: number;
  true_label: number; clean_prediction: number; adversarial_prediction: number;
  fooled: boolean; l2_distortion: number; linf_distortion: number;
}
export interface MissionFinding { severity: string; code: string; message: string }
export interface MissionReview {
  verdict: 'approve' | 'block'; model: string; format: string;
  n_findings: number; findings: MissionFinding[]
}
export interface IndustryRow { id: string; label: string; scores: string[] }
export interface IndustryResponse { vendors: string[]; criteria: IndustryRow[] }
export interface RegulatoryEntry {
  jurisdiction: 'RU' | 'INT'; instrument: string; requirement: string;
  satisfied_by: string[]; evidence: string
}

// ── Endpoints ──────────────────────────────────────────────────────────

export const fetchUAVOverview     = () => getJson<OverviewResponse>('/api/uav/overview')
export const fetchEWCurves        = () => getJson<{ benchmark: BenchMeta; curves: MCRCurve[] }>('/api/uav/ew-bench/curves')
export const fetchSwarmSnapshot   = () => getJson<{ snapshots: SwarmSnapshot[] }>('/api/uav/swarm/snapshot')
export const fetchGNSS            = () => getJson<GNSSResponse>('/api/uav/gnss/sky')
export const fetchCertificates    = () => getJson<CertificateResponse>('/api/uav/certificates')
export const fetchIndustry        = () => getJson<IndustryResponse>('/api/uav/industry-comparison')
export const fetchRegulatory      = () => getJson<{ entries: RegulatoryEntry[] }>('/api/uav/regulatory')
export const runPerceptionAttack  = (b: { attack: 'fgsm' | 'pgd'; epsilon: number; pgd_steps: number; sample_index: number }) =>
  postJson<AttackResult>('/api/uav/perception/attack', b)
export const reviewMissionPlan    = (b: { plan_text: string; plan_format: 'plan' | 'json-ld' | 'owl' }) =>
  postJson<MissionReview>('/api/uav/mission-plan/review', b)
