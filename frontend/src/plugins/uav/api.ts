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
  ew_source?: 'phase_d_measured' | 'phase_a_chapter_anchored' | string
  phase_a_metrics: Record<string, number | string>
  tiers: { name: string; budget_w: number | null; methods: string[] }[]
  edge_profile: {
    platform: string; latency_ms_per_frame: number; fps: number;
    ram_mib: number; cpu_pct_one_core: number;
  }
}
export interface SwarmNode { id: string; kind: 'uav' | 'droneport' | 'intruder'; label: string }
export interface SwarmEdge { src: string; dst: string; kind: 'trust' | 'jammed' | 'hostile' }
export interface SwarmSnapshot {
  t: number; label: string; nodes: SwarmNode[]; edges: SwarmEdge[]
  description?: string
}
export interface SatelliteFix {
  sv: string; azimuth_deg: number; elevation_deg: number;
  cno_db_hz: number; spoof_confidence: number; spoofed: boolean
  flagged?: boolean
}
export interface ReceiverProfile {
  id: string; label: string;
  nominal_cno: number; jam_rejection_db: number; pvt_collapse_js_db: number
}
export interface GNSSControls {
  seed: number; receiver_model: string; receiver_label: string;
  jamming_db: number; effective_js_db: number;
  pvt_collapse_js_db: number; pvt_collapsed: boolean;
  spoof_threshold: number; n_spoofed_requested: number
}
export interface GNSSResponse {
  satellites: SatelliteFix[]; fleet_disagreement: number;
  mode: string; fallback: string | null;
  n_spoofed_satellites?: number; n_flagged_satellites?: number;
  controls?: GNSSControls; receiver_catalog?: ReceiverProfile[]
}
export interface GNSSQuery {
  seed?: number | null; receiver_model?: string;
  jamming_db?: number; n_spoofed?: number | null;
  spoof_threshold?: number
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
  attack: string
  true_label: number
  clean_prediction?: number
  clean_confidence?: number
  adversarial_prediction?: number
  adversarial_confidence?: number
  fooled?: boolean
  confidence_drop?: number
  l2_distortion?: number
  linf_distortion?: number
  epsilon?: number
  pgd_steps?: number
  is_training_time?: boolean
  label_flip_fraction?: number
  flipped_label?: number
  label_changed?: boolean
  hint?: string
}

export interface AttackCatalogEntry {
  id: string
  label: string
  kind: 'white_box' | 'black_box' | 'baseline' | 'training'
  desc: string
}

export interface FleetUAV {
  uav_id: string; kind: string; defense: string
  mission_progress_pct: number; battery_pct: number; link_quality_pct: number
  gnss_spoof_confidence: number; autopilot_mode: string
  position: [number, number, number]; last_attack: string
  attack_caught: boolean; completed: boolean | null; mcr_running: number
}

export interface FleetSnapshot {
  session_id: string; js_db: number; fleet_mcr: number
  n_completed: number; n_in_flight: number; n_failed: number
  uavs: FleetUAV[]
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
export const fetchGNSS            = (q: GNSSQuery = {}) => {
  const p = new URLSearchParams()
  if (q.seed != null) p.set('seed', String(q.seed))
  if (q.receiver_model) p.set('receiver_model', q.receiver_model)
  if (q.jamming_db != null) p.set('jamming_db', String(q.jamming_db))
  if (q.n_spoofed != null) p.set('n_spoofed', String(q.n_spoofed))
  if (q.spoof_threshold != null) p.set('spoof_threshold', String(q.spoof_threshold))
  const qs = p.toString()
  return getJson<GNSSResponse>('/api/uav/gnss/sky' + (qs ? '?' + qs : ''))
}
export const fetchCertificates    = () => getJson<CertificateResponse>('/api/uav/certificates')
export const fetchIndustry        = () => getJson<IndustryResponse>('/api/uav/industry-comparison')
export const fetchRegulatory      = () => getJson<{ entries: RegulatoryEntry[] }>('/api/uav/regulatory')
export const runPerceptionAttack = (b: Record<string, unknown>) =>
  postJson<AttackResult>('/api/uav/perception/attack', b)

export const fetchAttackCatalog = () =>
  getJson<{ attacks: AttackCatalogEntry[]; total: number }>('/api/uav/perception/attack-catalog')

export const fleetStep = (b: { session_id: string; per_uav_attack: Record<string, string>; js_db: number; dt_s: number }) =>
  postJson<FleetSnapshot>('/api/uav/fleet/step', b)

export const fleetReset = (b: { session_id: string; n_uavs: number }) =>
  postJson<{ session_id: string; n_uavs: number; uavs: FleetUAV[] }>('/api/uav/fleet/reset', b)

export const fleetSamplePackUrl = () => `${API}/api/uav/fleet/sample-pack`

export const fleetUpload = async (file: File): Promise<{ session_id: string; n_uavs: number; uav_ids: string[]; uavs: FleetUAV[] }> => {
  const form = new FormData()
  form.append('file', file)
  const res = await fetch(`${API}/api/uav/fleet/upload`, { method: 'POST', body: form })
  if (!res.ok) throw new Error(`/api/uav/fleet/upload → ${res.status}`)
  return res.json()
}
export const reviewMissionPlan    = (b: { plan_text: string; plan_format: 'plan' | 'json-ld' | 'owl' }) =>
  postJson<MissionReview>('/api/uav/mission-plan/review', b)
