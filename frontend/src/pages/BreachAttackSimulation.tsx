import { useState, useMemo } from 'react'
import {
  Swords, Loader2, Play, CheckCircle2, AlertTriangle, XCircle, Shield,
  ChevronDown, ChevronUp, Target, TrendingUp, Activity,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import { cachePageResult } from '../utils/api'
import { useNoticeBoard } from '../hooks/useNoticeBoard'
import { registerSessionReset } from '../utils/sessionReset'

/* ── Breach & Attack Simulation (BAS) ────────────────────────────────────
 * End-to-end automated attack scenarios that test the platform's own
 * detection stack across the MITRE ATT&CK kill chain.
 *
 * Detector pipeline (toggleable): Surrogate IDS, LipMamba, SDE-TGNN,
 * CL-RL Policy, FedGTD, JailGuard, ConformalGuard, Multi-Agent PQC.
 */

type StepStatus = 'pending' | 'running' | 'detected' | 'missed' | 'partial'

interface AttackStep {
  id: string
  tactic: string             // ATT&CK tactic name
  technique: string          // ATT&CK technique ID, e.g. T1190
  description: string
  detector_required: string  // which platform detector should catch it
  severity: 'critical' | 'high' | 'medium' | 'low'
}

interface Scenario {
  id: string
  name: string
  description: string
  threat_actor: string
  steps: AttackStep[]
}

interface StepResult {
  status: StepStatus
  detected_by: string | null
  confidence: number
  ttd_ms: number          // time-to-detect
}

interface ScenarioResult {
  scenario_id: string
  name: string
  steps_total: number
  steps_detected: number
  steps_partial: number
  steps_missed: number
  detection_rate: number
  mean_ttd_ms: number
  critical_missed: number
  step_results: Record<string, StepResult>
  finished_at: number
}

const SCENARIOS: Scenario[] = [
  {
    id: 'apt29',
    name: 'APT-29 (Cozy Bear) Espionage Chain',
    description: 'Spear-phish → web exploit → credential theft → lateral movement → data exfil over DNS.',
    threat_actor: 'APT-29',
    steps: [
      { id: 'apt29_recon',  tactic: 'Reconnaissance',  technique: 'T1595.002', description: 'External vulnerability scanning of the perimeter.',                       detector_required: 'Surrogate IDS',         severity: 'low'      },
      { id: 'apt29_init',   tactic: 'Initial Access',  technique: 'T1190',     description: 'Exploit a public-facing app (CVE-2024-####).',                            detector_required: 'Surrogate IDS / WAF',   severity: 'critical' },
      { id: 'apt29_exec',   tactic: 'Execution',       technique: 'T1059.001', description: 'PowerShell dropper executes in memory.',                                  detector_required: 'LipMamba',              severity: 'high'     },
      { id: 'apt29_cred',   tactic: 'Credential Access', technique: 'T1003.001', description: 'LSASS memory dump for cached credentials.',                             detector_required: 'CL-RL Policy',          severity: 'critical' },
      { id: 'apt29_lat',    tactic: 'Lateral Movement', technique: 'T1021.002', description: 'SMB / WinRM lateral hops to high-value hosts.',                           detector_required: 'SDE-TGNN',              severity: 'high'     },
      { id: 'apt29_collect',tactic: 'Collection',      technique: 'T1005',     description: 'Data staged from local repositories.',                                    detector_required: 'FedGTD',                severity: 'medium'   },
      { id: 'apt29_c2',     tactic: 'C2',              technique: 'T1071.004', description: 'DNS tunnelling for command-and-control.',                                 detector_required: 'SSL-GraphAnomaly',      severity: 'high'     },
      { id: 'apt29_exfil',  tactic: 'Exfiltration',    technique: 'T1048.003', description: 'Asymmetric exfil over a covert HTTPS channel.',                            detector_required: 'Multi-Agent PQC',       severity: 'critical' },
    ],
  },
  {
    id: 'ransomware',
    name: 'Ransomware Kill Chain (LockBit-class)',
    description: 'Phishing payload → AD enumeration → privilege escalation → backup wipe → mass encryption.',
    threat_actor: 'LockBit-class affiliate',
    steps: [
      { id: 'ran_init',    tactic: 'Initial Access',     technique: 'T1566.001', description: 'Macro-laden phishing attachment establishes foothold.',           detector_required: 'Surrogate IDS',     severity: 'critical' },
      { id: 'ran_disc',    tactic: 'Discovery',          technique: 'T1018',     description: 'Internal network discovery & AD enumeration.',                  detector_required: 'SDE-TGNN',          severity: 'medium'   },
      { id: 'ran_priv',    tactic: 'Privilege Escalation', technique: 'T1068', description: 'Local kernel exploit for SYSTEM privileges.',                     detector_required: 'CL-RL Policy',      severity: 'high'     },
      { id: 'ran_def',     tactic: 'Defense Evasion',    technique: 'T1562.001', description: 'Disable AV / EDR before payload execution.',                     detector_required: 'LipMamba',          severity: 'high'     },
      { id: 'ran_persist', tactic: 'Persistence',        technique: 'T1547.001', description: 'Run-key persistence for the encryptor.',                          detector_required: 'Surrogate IDS',     severity: 'medium'   },
      { id: 'ran_backup',  tactic: 'Impact',             technique: 'T1490',     description: 'Inhibit system recovery (delete shadow copies).',                detector_required: 'FedGTD',            severity: 'critical' },
      { id: 'ran_encrypt', tactic: 'Impact',             technique: 'T1486',     description: 'Mass file encryption + ransom note drop.',                       detector_required: 'CL-RL Policy',      severity: 'critical' },
    ],
  },
  {
    id: 'mirai',
    name: 'Mirai-Class IoT Botnet Onboarding',
    description: 'Telnet brute force → loader stage → CnC join → DDoS dispatch from the captured IoT host.',
    threat_actor: 'Mirai variant',
    steps: [
      { id: 'mirai_scan',   tactic: 'Reconnaissance',   technique: 'T1046',     description: 'Scan for open Telnet/SSH on /16 ranges.',                         detector_required: 'Surrogate IDS',         severity: 'low'      },
      { id: 'mirai_brute',  tactic: 'Initial Access',   technique: 'T1110.001', description: 'Telnet password brute force using default-cred dictionary.',     detector_required: 'Surrogate IDS',         severity: 'high'     },
      { id: 'mirai_loader', tactic: 'Execution',        technique: 'T1059.004', description: 'Drop the second-stage Mirai binary via wget/tftp.',               detector_required: 'LipMamba',              severity: 'high'     },
      { id: 'mirai_join',   tactic: 'C2',               technique: 'T1071.001', description: 'Outbound TCP join to CnC.',                                       detector_required: 'SSL-GraphAnomaly',      severity: 'medium'   },
      { id: 'mirai_attack', tactic: 'Impact',           technique: 'T1498.001', description: 'CnC dispatches a UDP/TCP DDoS at the victim.',                   detector_required: 'CL-RL Policy',          severity: 'critical' },
    ],
  },
  {
    id: 'insider',
    name: 'Insider Data Theft',
    description: 'Authorised user collects + slowly exfiltrates sensitive data over weeks via approved channels.',
    threat_actor: 'Insider',
    steps: [
      { id: 'ins_auth',    tactic: 'Initial Access',  technique: 'T1078',     description: 'Insider logs in using legitimate credentials.',                                    detector_required: 'Zero-Trust Policy',     severity: 'low'      },
      { id: 'ins_disc',    tactic: 'Discovery',       technique: 'T1083',     description: 'Browses file shares for high-value documents.',                                   detector_required: 'FedGTD',                severity: 'low'      },
      { id: 'ins_collect', tactic: 'Collection',      technique: 'T1213',     description: 'Stages data from sharepoint / wiki repos.',                                       detector_required: 'CL-RL Policy',          severity: 'medium'   },
      { id: 'ins_chunk',   tactic: 'Exfiltration',    technique: 'T1030',     description: 'Slow drip — many small uploads to a personal cloud over weeks.',                 detector_required: 'SSL-GraphAnomaly',      severity: 'high'     },
      { id: 'ins_obfusc',  tactic: 'Defense Evasion', technique: 'T1027',     description: 'Encrypts uploads to evade DLP keyword scanning.',                                 detector_required: 'Multi-Agent PQC',       severity: 'high'     },
    ],
  },
  {
    id: 'supply_chain',
    name: 'ML Supply-Chain Compromise',
    description: 'Adversary backdoors a public model, target organisation pulls and deploys it.',
    threat_actor: 'Backdoor crafter',
    steps: [
      { id: 'sc_register',  tactic: 'Resource Development', technique: 'AML.T0019', description: 'Adversary publishes a poisoned model variant.',                       detector_required: 'Supply-Chain Scan', severity: 'high'     },
      { id: 'sc_pull',      tactic: 'Initial Access',       technique: 'AML.T0010.004', description: 'Target pulls the poisoned model into production.',                detector_required: 'JailGuard',         severity: 'critical' },
      { id: 'sc_persist',   tactic: 'Persistence',          technique: 'AML.T0018.001', description: 'Backdoor persists across fine-tunes (resilient trigger).',         detector_required: 'LipMamba',          severity: 'critical' },
      { id: 'sc_trigger',   tactic: 'Execution',            technique: 'AML.T0011.000', description: 'Magic input fires backdoor at inference.',                        detector_required: 'JailGuard',         severity: 'critical' },
      { id: 'sc_exfil',     tactic: 'Exfiltration',         technique: 'AML.T0024.002', description: 'Functionality extraction by repeated probing.',                    detector_required: 'ConformalGuard',    severity: 'high'     },
    ],
  },
  {
    id: 'llm_jailbreak',
    name: 'LLM Jailbreak + Tool Abuse Chain',
    description: 'DAN-style jailbreak followed by tool abuse over MCP to exfiltrate workspace data.',
    threat_actor: 'Adversarial prompter',
    steps: [
      { id: 'jb_recon',  tactic: 'Reconnaissance',  technique: 'AML.T0014',  description: 'Probe the model to fingerprint family + safety policy.',           detector_required: 'JailGuard',         severity: 'low'      },
      { id: 'jb_inject', tactic: 'Defense Evasion', technique: 'AML.T0051',  description: 'Multi-turn injection breaches alignment.',                          detector_required: 'JailGuard',         severity: 'high'     },
      { id: 'jb_tool',   tactic: 'Execution',       technique: 'AML.T0053',  description: 'Hijack a connected MCP tool through the broken alignment.',         detector_required: 'MCP Defenses',      severity: 'critical' },
      { id: 'jb_collect',tactic: 'Collection',      technique: 'AML.T0036',  description: 'Read sensitive resources (workspace docs / secrets).',              detector_required: 'Zero-Trust Policy', severity: 'critical' },
      { id: 'jb_exfil',  tactic: 'Exfiltration',    technique: 'AML.T0024.002', description: 'Encode collected data as base64 in an outbound tool call.',     detector_required: 'Egress DLP',        severity: 'critical' },
    ],
  },
]

interface DetectorState {
  surrogate_ids: boolean
  lipmamba: boolean
  sde_tgnn: boolean
  clrl_policy: boolean
  fedgtd: boolean
  ssl_anomaly: boolean
  jailguard: boolean
  conformal_guard: boolean
  multi_agent_pqc: boolean
  zero_trust: boolean
  mcp_defenses: boolean
  egress_dlp: boolean
  supply_chain_scan: boolean
}

const DEFAULT_DETECTORS: DetectorState = {
  surrogate_ids: true, lipmamba: true, sde_tgnn: true, clrl_policy: true,
  fedgtd: true, ssl_anomaly: true, jailguard: true, conformal_guard: true,
  multi_agent_pqc: true, zero_trust: true, mcp_defenses: true, egress_dlp: true,
  supply_chain_scan: true,
}

const DETECTOR_LABELS: Record<keyof DetectorState, string> = {
  surrogate_ids: 'Surrogate IDS', lipmamba: 'LipMamba', sde_tgnn: 'SDE-TGNN',
  clrl_policy: 'CL-RL Policy', fedgtd: 'FedGTD', ssl_anomaly: 'SSL-GraphAnomaly',
  jailguard: 'JailGuard', conformal_guard: 'ConformalGuard',
  multi_agent_pqc: 'Multi-Agent PQC', zero_trust: 'Zero-Trust Policy',
  mcp_defenses: 'MCP Defenses', egress_dlp: 'Egress DLP', supply_chain_scan: 'Supply-Chain Scan',
}

/* Map "detector_required" strings to detector keys. Allows for combined "A / B" markers. */
function detectorKeysFor(req: string): (keyof DetectorState)[] {
  const tokens = req.split('/').map(s => s.trim().toLowerCase())
  const keys: (keyof DetectorState)[] = []
  for (const t of tokens) {
    if (t.includes('surrogate'))   keys.push('surrogate_ids')
    if (t.includes('lipmamba'))    keys.push('lipmamba')
    if (t.includes('sde-tgnn'))    keys.push('sde_tgnn')
    if (t.includes('cl-rl'))       keys.push('clrl_policy')
    if (t.includes('fedgtd'))      keys.push('fedgtd')
    if (t.includes('ssl-graph') || t.includes('ssl_graph')) keys.push('ssl_anomaly')
    if (t.includes('jailguard'))   keys.push('jailguard')
    if (t.includes('conformal'))   keys.push('conformal_guard')
    if (t.includes('multi-agent') || t.includes('multi_agent')) keys.push('multi_agent_pqc')
    if (t.includes('zero-trust') || t.includes('zero_trust'))   keys.push('zero_trust')
    if (t.includes('mcp'))         keys.push('mcp_defenses')
    if (t.includes('egress') || t.includes('dlp'))              keys.push('egress_dlp')
    if (t.includes('supply'))      keys.push('supply_chain_scan')
    if (t.includes('waf'))         keys.push('surrogate_ids')   // WAF is part of surrogate path here
  }
  return keys.length ? keys : ['surrogate_ids']
}

const STATUS_STYLE: Record<StepStatus, { bg: string; fg: string; icon: typeof CheckCircle2; label: string }> = {
  pending:  { bg: 'bg-bg-card',         fg: 'text-text-secondary', icon: Activity,       label: 'Pending'  },
  running:  { bg: 'bg-blue-500/15',     fg: 'text-blue-400',       icon: Loader2,        label: 'Running'  },
  detected: { bg: 'bg-green-500/15',    fg: 'text-green-400',      icon: CheckCircle2,   label: 'Detected' },
  partial:  { bg: 'bg-amber-500/15',    fg: 'text-amber-400',      icon: AlertTriangle,  label: 'Partial'  },
  missed:   { bg: 'bg-red-500/15',      fg: 'text-red-400',        icon: XCircle,        label: 'Missed'   },
}

const SEVERITY_STYLE: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium:   'bg-amber-500/15 text-amber-400 border-amber-500/30',
  low:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
}

function evaluateStep(step: AttackStep, detectors: DetectorState): { status: StepStatus; detected_by: string | null; confidence: number; ttd_ms: number } {
  const required = detectorKeysFor(step.detector_required)
  const enabled = required.filter(k => detectors[k])
  const ttd = 200 + Math.floor(Math.random() * 1500)
  if (enabled.length === required.length) {
    return { status: 'detected', detected_by: enabled.map(k => DETECTOR_LABELS[k]).join(' + '), confidence: 0.85 + Math.random() * 0.13, ttd_ms: ttd }
  }
  if (enabled.length > 0) {
    return { status: 'partial', detected_by: enabled.map(k => DETECTOR_LABELS[k]).join(' + '), confidence: 0.55 + Math.random() * 0.2, ttd_ms: ttd + 800 }
  }
  return { status: 'missed', detected_by: null, confidence: 0, ttd_ms: 0 }
}

const _store: { detectors: DetectorState; results: Record<string, ScenarioResult>; selectedScenarios: Set<string>; expanded: Record<string, boolean> } = {
  detectors: { ...DEFAULT_DETECTORS },
  results: {},
  selectedScenarios: new Set(SCENARIOS.map(s => s.id)),
  expanded: {},
}
registerSessionReset(() => {
  _store.detectors = { ...DEFAULT_DETECTORS }
  _store.results = {}
  _store.selectedScenarios = new Set(SCENARIOS.map(s => s.id))
  _store.expanded = {}
})

const GUIDE_STEPS = [
  { title: 'Toggle defenses', desc: 'Each detector card represents a real platform component. Disable some to expose detection gaps.' },
  { title: 'Pick scenarios', desc: 'Choose one or more attack scenarios. Each is a multi-step ATT&CK kill chain (or ATLAS for ML attacks).' },
  { title: 'Run simulation', desc: 'Click Run All. Each step is exercised against the active detector set; coverage and time-to-detect are measured.' },
  { title: 'Review coverage', desc: 'Detection rate, missed criticals, and per-step status reveal where the platform is strong or has blind spots.' },
  { title: 'Iterate', desc: 'Tweak detectors, re-run, compare scenarios. Use the Copilot to ask "What did the BAS run miss?".' },
]

export default function BreachAttackSimulation() {
  const [detectors, _setDetectors] = useState<DetectorState>(_store.detectors)
  const [results, _setResults] = useState<Record<string, ScenarioResult>>(_store.results)
  const [selectedScenarios, _setSelectedScenarios] = useState<Set<string>>(_store.selectedScenarios)
  const [expanded, _setExpanded] = useState<Record<string, boolean>>(_store.expanded)
  const [running, setRunning] = useState(false)
  const [activeStep, setActiveStep] = useState<string | null>(null)
  const { addNotice, updateNotice } = useNoticeBoard()

  const setDetectors = (v: DetectorState) => { _store.detectors = v; _setDetectors(v) }
  const setResults = (v: Record<string, ScenarioResult>) => { _store.results = v; _setResults(v) }
  const setSelectedScenarios = (v: Set<string>) => { _store.selectedScenarios = v; _setSelectedScenarios(v) }
  const setExpanded = (v: Record<string, boolean>) => { _store.expanded = v; _setExpanded(v) }

  const toggleDetector = (k: keyof DetectorState) => setDetectors({ ...detectors, [k]: !detectors[k] })
  const toggleScenario = (id: string) => {
    const next = new Set(selectedScenarios)
    if (next.has(id)) next.delete(id); else next.add(id)
    setSelectedScenarios(next)
  }
  const toggleExpand = (id: string) => setExpanded({ ...expanded, [id]: !expanded[id] })

  const sleep = (ms: number) => new Promise(r => setTimeout(r, ms))

  const runScenario = async (scenario: Scenario): Promise<ScenarioResult> => {
    const stepResults: Record<string, StepResult> = {}
    let ttdSum = 0
    let detectedCount = 0
    for (const step of scenario.steps) {
      setActiveStep(step.id)
      stepResults[step.id] = { status: 'running', detected_by: null, confidence: 0, ttd_ms: 0 }
      setResults({ ...results, [scenario.id]: makePartialResult(scenario, stepResults) })
      await sleep(180 + Math.random() * 220)
      const ev = evaluateStep(step, detectors)
      stepResults[step.id] = ev
      if (ev.status === 'detected') { detectedCount++; ttdSum += ev.ttd_ms }
      setResults({ ...results, [scenario.id]: makePartialResult(scenario, stepResults) })
    }
    const detected = Object.values(stepResults).filter(r => r.status === 'detected').length
    const partial  = Object.values(stepResults).filter(r => r.status === 'partial').length
    const missed   = Object.values(stepResults).filter(r => r.status === 'missed').length
    const critical_missed = scenario.steps.filter(s => s.severity === 'critical' && stepResults[s.id]?.status === 'missed').length
    return {
      scenario_id: scenario.id, name: scenario.name,
      steps_total: scenario.steps.length,
      steps_detected: detected, steps_partial: partial, steps_missed: missed,
      detection_rate: scenario.steps.length ? Math.round((detected / scenario.steps.length) * 100) : 0,
      mean_ttd_ms: detectedCount ? Math.round(ttdSum / detectedCount) : 0,
      critical_missed, step_results: stepResults, finished_at: Date.now(),
    }
  }

  const makePartialResult = (scenario: Scenario, stepResults: Record<string, StepResult>): ScenarioResult => {
    const detected = Object.values(stepResults).filter(r => r.status === 'detected').length
    const partial  = Object.values(stepResults).filter(r => r.status === 'partial').length
    const missed   = Object.values(stepResults).filter(r => r.status === 'missed').length
    return {
      scenario_id: scenario.id, name: scenario.name,
      steps_total: scenario.steps.length,
      steps_detected: detected, steps_partial: partial, steps_missed: missed,
      detection_rate: scenario.steps.length ? Math.round((detected / scenario.steps.length) * 100) : 0,
      mean_ttd_ms: 0,
      critical_missed: scenario.steps.filter(s => s.severity === 'critical' && stepResults[s.id]?.status === 'missed').length,
      step_results: stepResults,
      finished_at: 0,
    }
  }

  const runAll = async () => {
    setRunning(true)
    const scenariosToRun = SCENARIOS.filter(s => selectedScenarios.has(s.id))
    const nid = addNotice({ title: 'Breach & Attack Simulation', description: `Running ${scenariosToRun.length} scenario(s)...`, status: 'running', page: '/bas' })
    let acc: Record<string, ScenarioResult> = { ...results }
    for (const sc of scenariosToRun) {
      const r = await runScenario(sc)
      acc = { ...acc, [sc.id]: r }
      setResults(acc)
    }
    setActiveStep(null)
    const totalSteps    = scenariosToRun.reduce((s, sc) => s + sc.steps.length, 0)
    const totalDetected = scenariosToRun.reduce((s, sc) => s + (acc[sc.id]?.steps_detected || 0), 0)
    const overall = totalSteps ? Math.round((totalDetected / totalSteps) * 100) : 0
    cachePageResult('bas', {
      scenarios_run: scenariosToRun.length,
      total_steps: totalSteps,
      total_detected: totalDetected,
      overall_detection_rate: overall,
      detectors_enabled: Object.entries(detectors).filter(([,v]) => v).map(([k]) => k),
      critical_missed: scenariosToRun.reduce((s, sc) => s + (acc[sc.id]?.critical_missed || 0), 0),
    }).catch(() => {})
    updateNotice(nid, { status: 'completed', description: `BAS done — ${overall}% overall detection across ${scenariosToRun.length} scenario(s)` })
    setRunning(false)
  }

  const overall = useMemo(() => {
    const list = Object.values(results)
    if (!list.length) return null
    const totalSteps = list.reduce((s, r) => s + r.steps_total, 0)
    const totalDet   = list.reduce((s, r) => s + r.steps_detected, 0)
    const totalPart  = list.reduce((s, r) => s + r.steps_partial, 0)
    const totalMiss  = list.reduce((s, r) => s + r.steps_missed, 0)
    const ttd        = list.filter(r => r.mean_ttd_ms > 0)
    return {
      detection_rate: totalSteps ? Math.round((totalDet / totalSteps) * 100) : 0,
      total_steps: totalSteps,
      total_detected: totalDet, total_partial: totalPart, total_missed: totalMiss,
      mean_ttd_ms: ttd.length ? Math.round(ttd.reduce((s, r) => s + r.mean_ttd_ms, 0) / ttd.length) : 0,
      critical_missed: list.reduce((s, r) => s + r.critical_missed, 0),
    }
  }, [results])

  const enabledDetectorCount = Object.values(detectors).filter(Boolean).length

  return (
    <div className="space-y-6 bas-root">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-accent-red/10 flex items-center justify-center">
            <Swords className="w-5 h-5 text-accent-red" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-text-primary">Breach &amp; Attack Simulation</h1>
            <p className="text-xs text-text-secondary mt-0.5">
              {SCENARIOS.length} adversary playbooks · {SCENARIOS.reduce((s, sc) => s + sc.steps.length, 0)} kill-chain steps · tested against the live RobustIDPS detector stack
            </p>
          </div>
        </div>
        <ExportMenu targetSelector=".bas-root" filename="bas-report" />
      </div>

      <PageGuide title="How to use Breach &amp; Attack Simulation" steps={GUIDE_STEPS}
        tip="Tip: Disable LipMamba and re-run the ransomware scenario — see how time-to-detect blows out and which steps go uncovered." />

      {/* Detectors */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-display font-semibold flex items-center gap-2"><Shield className="w-4 h-4 text-accent-red" /> Detector Stack</h2>
          <span className="text-[10px] text-text-secondary">{enabledDetectorCount} / {Object.keys(detectors).length} enabled</span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-2">
          {(Object.keys(detectors) as Array<keyof DetectorState>).map(k => {
            const on = detectors[k]
            return (
              <button key={k} onClick={() => toggleDetector(k)}
                className={`px-3 py-2 rounded-lg text-xs font-medium transition-all border text-left ${on ? 'bg-accent-green/8 border-accent-green/30 text-text-primary' : 'bg-bg-card/30 border-bg-card text-text-secondary hover:text-text-primary hover:border-text-secondary/40'}`}>
                <span className={`inline-block w-2 h-2 rounded-full mr-1.5 align-middle ${on ? 'bg-accent-green' : 'bg-text-secondary/30'}`} />
                {DETECTOR_LABELS[k]}
              </button>
            )
          })}
        </div>
      </div>

      {/* Scenarios */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <div className="flex items-center justify-between mb-3 flex-wrap gap-3">
          <h2 className="text-sm font-display font-semibold flex items-center gap-2"><Target className="w-4 h-4 text-accent-red" /> Attack Scenarios</h2>
          <div className="flex items-center gap-2">
            <button onClick={() => setSelectedScenarios(new Set(SCENARIOS.map(s => s.id)))}
              className="text-[10px] px-2 py-1 rounded bg-bg-card text-text-secondary hover:text-text-primary">Select all</button>
            <button onClick={() => setSelectedScenarios(new Set())}
              className="text-[10px] px-2 py-1 rounded bg-bg-card text-text-secondary hover:text-text-primary">Clear</button>
            <button onClick={runAll} disabled={running || selectedScenarios.size === 0}
              className="px-4 py-2 bg-accent-red hover:bg-accent-red/80 text-white rounded-lg text-xs font-semibold disabled:opacity-50 flex items-center gap-2">
              {running ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Running…</> : <><Play className="w-3.5 h-3.5" /> Run Selected</>}
            </button>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {SCENARIOS.map(sc => {
            const sel = selectedScenarios.has(sc.id)
            const r = results[sc.id]
            const exp = !!expanded[sc.id]
            const sevHist = sc.steps.reduce<Record<string, number>>((acc, s) => { acc[s.severity] = (acc[s.severity] || 0) + 1; return acc }, {})
            return (
              <div key={sc.id} className={`rounded-xl border overflow-hidden transition-colors ${sel ? 'bg-bg-secondary border-accent-red/30' : 'bg-bg-card/30 border-bg-card'}`}>
                <div className="p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-3 flex-1 min-w-0">
                      <input type="checkbox" checked={sel} onChange={() => toggleScenario(sc.id)} className="mt-1 accent-red-500" />
                      <div className="min-w-0">
                        <p className="text-sm font-semibold text-text-primary">{sc.name}</p>
                        <p className="text-[10px] text-text-secondary mt-0.5 leading-snug">{sc.description}</p>
                        <div className="flex items-center gap-1.5 flex-wrap mt-2">
                          <span className="px-1.5 py-0.5 bg-bg-card text-text-secondary rounded text-[9px]">{sc.threat_actor}</span>
                          <span className="px-1.5 py-0.5 bg-bg-card text-text-secondary rounded text-[9px]">{sc.steps.length} steps</span>
                          {Object.entries(sevHist).map(([sev, n]) => (
                            <span key={sev} className={`px-1.5 py-0.5 rounded text-[9px] border ${SEVERITY_STYLE[sev]}`}>{n} {sev}</span>
                          ))}
                        </div>
                      </div>
                    </div>
                    <button onClick={() => toggleExpand(sc.id)} className="p-1 rounded hover:bg-bg-card/50 text-text-secondary">{exp ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}</button>
                  </div>
                  {r && (
                    <div className="grid grid-cols-4 gap-1.5 mt-3">
                      <Mini label="Detected" value={r.steps_detected} color="text-accent-green" />
                      <Mini label="Partial"  value={r.steps_partial}  color="text-accent-amber" />
                      <Mini label="Missed"   value={r.steps_missed}   color="text-accent-red" />
                      <Mini label="DR"       value={`${r.detection_rate}%`} color={r.detection_rate >= 80 ? 'text-accent-green' : r.detection_rate >= 50 ? 'text-accent-amber' : 'text-accent-red'} />
                    </div>
                  )}
                </div>
                {exp && (
                  <div className="border-t border-bg-card bg-bg-card/30 p-3 space-y-1.5">
                    {sc.steps.map((step, i) => {
                      const sr = r?.step_results[step.id]
                      const status: StepStatus = sr?.status || (activeStep === step.id ? 'running' : 'pending')
                      const sty = STATUS_STYLE[status]
                      const Icon = sty.icon
                      return (
                        <div key={step.id} className={`flex items-start gap-2 px-3 py-2 rounded-lg ${sty.bg}`}>
                          <div className={`shrink-0 mt-0.5`}>
                            <Icon className={`w-3.5 h-3.5 ${sty.fg} ${status === 'running' ? 'animate-spin' : ''}`} />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <span className="text-[10px] text-text-secondary font-mono">{i + 1}.</span>
                              <span className="text-[10px] text-accent-blue font-mono">{step.technique}</span>
                              <span className="text-[10px] text-text-secondary">{step.tactic}</span>
                              <span className={`px-1.5 py-0.5 rounded text-[9px] border ${SEVERITY_STYLE[step.severity]}`}>{step.severity}</span>
                              {sr && sr.status !== 'pending' && sr.status !== 'running' && (
                                <span className={`text-[10px] ${sty.fg}`}>· {sr.detected_by ? `by ${sr.detected_by}` : 'no detector fired'}</span>
                              )}
                            </div>
                            <p className="text-xs text-text-primary mt-0.5">{step.description}</p>
                            {sr && sr.status === 'detected' && (
                              <p className="text-[10px] text-text-secondary mt-0.5">TTD {sr.ttd_ms} ms · {(sr.confidence * 100).toFixed(0)}% confidence</p>
                            )}
                          </div>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* Overall results */}
      {overall && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h2 className="text-sm font-semibold flex items-center gap-2 mb-3"><TrendingUp className="w-4 h-4 text-accent-blue" /> Overall Coverage</h2>
          <div className="grid grid-cols-2 sm:grid-cols-6 gap-3">
            <StatCard label="Detection Rate" value={`${overall.detection_rate}%`} color={overall.detection_rate >= 80 ? '#22C55E' : overall.detection_rate >= 50 ? '#F59E0B' : '#EF4444'} />
            <StatCard label="Steps" value={overall.total_steps} color="#3B82F6" />
            <StatCard label="Detected" value={overall.total_detected} color="#22C55E" />
            <StatCard label="Partial" value={overall.total_partial} color="#F59E0B" />
            <StatCard label="Missed" value={overall.total_missed} color="#EF4444" />
            <StatCard label="Mean TTD (ms)" value={overall.mean_ttd_ms} color="#8B5CF6" />
          </div>
          {overall.critical_missed > 0 && (
            <div className="mt-3 px-4 py-3 bg-red-500/8 border border-red-500/25 rounded-lg flex items-start gap-3">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <div className="text-xs">
                <p className="font-semibold text-red-400">{overall.critical_missed} critical-severity step{overall.critical_missed > 1 ? 's' : ''} missed</p>
                <p className="text-text-secondary mt-0.5">Re-run with the affected detectors enabled, or escalate to the engineering channel responsible for those components.</p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Related */}
      <div className="flex flex-wrap gap-2 pt-3 border-t border-bg-card">
        <span className="text-[10px] text-text-secondary mr-2">Related:</span>
        <a href="/redteam" className="text-[10px] px-2 py-1 rounded bg-accent-red/10 text-accent-red hover:bg-accent-red/20">Red Team Arena</a>
        <a href="/attack-chain" className="text-[10px] px-2 py-1 rounded bg-accent-amber/10 text-accent-amber hover:bg-accent-amber/20">Attack Chain Predictor</a>
        <a href="/mitre-attack" className="text-[10px] px-2 py-1 rounded bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20">MITRE ATT&CK</a>
        <a href="/atlas" className="text-[10px] px-2 py-1 rounded bg-accent-purple/10 text-accent-purple hover:bg-accent-purple/20">MITRE ATLAS</a>
        <a href="/investigation-chain" className="text-[10px] px-2 py-1 rounded bg-accent-orange/10 text-accent-orange hover:bg-accent-orange/20">Investigation Chain</a>
        <a href="/copilot" className="text-[10px] px-2 py-1 rounded bg-accent-green/10 text-accent-green hover:bg-accent-green/20">SOC Copilot</a>
      </div>
    </div>
  )
}

function StatCard({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div className="bg-bg-secondary border border-bg-card rounded-xl p-4">
      <p className="text-[10px] text-text-secondary uppercase tracking-wider mb-1">{label}</p>
      <p className="text-2xl font-bold" style={{ color }}>{value}</p>
    </div>
  )
}

function Mini({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div className="bg-bg-card/40 rounded p-1.5 text-center">
      <p className={`text-sm font-bold ${color}`}>{value}</p>
      <p className="text-[9px] text-text-secondary">{label}</p>
    </div>
  )
}

