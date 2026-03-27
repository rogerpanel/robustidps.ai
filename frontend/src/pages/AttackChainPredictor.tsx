import { useState, useMemo } from 'react'
import {
  TrendingUp, ChevronRight, Shield, AlertTriangle, Target,
  Activity, Zap, BarChart3, Layers, ArrowRight,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'

/* ── Attack transition probability matrix ────────────────────────────── */
/* Domain knowledge from MITRE ATT&CK kill chain analysis (Markov model) */

const ATTACK_TRANSITIONS: Record<string, { next: string; probability: number; technique: string }[]> = {
  'Recon-PingSweep': [
    { next: 'Recon-PortScan', probability: 0.65, technique: 'T1046' },
    { next: 'Recon-OSScan', probability: 0.25, technique: 'T1082' },
    { next: 'Recon-HostDiscovery', probability: 0.10, technique: 'T1018' },
  ],
  'Recon-PortScan': [
    { next: 'BruteForce-SSH', probability: 0.35, technique: 'T1110.001' },
    { next: 'WebAttack-SQLi', probability: 0.25, technique: 'T1190' },
    { next: 'Recon-OSScan', probability: 0.20, technique: 'T1082' },
    { next: 'BruteForce-FTP', probability: 0.15, technique: 'T1110.001' },
    { next: 'WebAttack-XSS', probability: 0.05, technique: 'T1189' },
  ],
  'Recon-OSScan': [
    { next: 'WebAttack-SQLi', probability: 0.30, technique: 'T1190' },
    { next: 'BruteForce-SSH', probability: 0.30, technique: 'T1110.001' },
    { next: 'WebAttack-CmdInjection', probability: 0.25, technique: 'T1059' },
    { next: 'Spoofing-ARP', probability: 0.15, technique: 'T1557.002' },
  ],
  'BruteForce-SSH': [
    { next: 'Malware-Backdoor', probability: 0.40, technique: 'T1059.001' },
    { next: 'WebAttack-CmdInjection', probability: 0.30, technique: 'T1059' },
    { next: 'Spoofing-IP', probability: 0.15, technique: 'T1090' },
    { next: 'DDoS-TCP', probability: 0.15, technique: 'T1498.001' },
  ],
  'BruteForce-FTP': [
    { next: 'Malware-Backdoor', probability: 0.45, technique: 'T1059.001' },
    { next: 'WebAttack-CmdInjection', probability: 0.30, technique: 'T1059' },
    { next: 'Malware-Ransomware', probability: 0.25, technique: 'T1486' },
  ],
  'WebAttack-SQLi': [
    { next: 'WebAttack-CmdInjection', probability: 0.35, technique: 'T1059' },
    { next: 'Malware-Backdoor', probability: 0.30, technique: 'T1059.001' },
    { next: 'WebAttack-BrowserHijack', probability: 0.20, technique: 'T1185' },
    { next: 'Malware-Ransomware', probability: 0.15, technique: 'T1486' },
  ],
  'WebAttack-XSS': [
    { next: 'WebAttack-BrowserHijack', probability: 0.40, technique: 'T1185' },
    { next: 'Spoofing-DNS', probability: 0.30, technique: 'T1557.001' },
    { next: 'WebAttack-CmdInjection', probability: 0.30, technique: 'T1059' },
  ],
  'WebAttack-CmdInjection': [
    { next: 'Malware-Backdoor', probability: 0.45, technique: 'T1059.001' },
    { next: 'Malware-Ransomware', probability: 0.30, technique: 'T1486' },
    { next: 'DDoS-TCP', probability: 0.15, technique: 'T1498.001' },
    { next: 'Spoofing-IP', probability: 0.10, technique: 'T1090' },
  ],
  'Malware-Backdoor': [
    { next: 'Spoofing-IP', probability: 0.30, technique: 'T1090' },
    { next: 'DDoS-TCP', probability: 0.25, technique: 'T1498.001' },
    { next: 'Malware-Ransomware', probability: 0.25, technique: 'T1486' },
    { next: 'DNS-Spoofing', probability: 0.20, technique: 'T1071.004' },
  ],
  'Spoofing-ARP': [
    { next: 'Spoofing-DNS', probability: 0.40, technique: 'T1557.001' },
    { next: 'WebAttack-BrowserHijack', probability: 0.30, technique: 'T1185' },
    { next: 'BruteForce-HTTP', probability: 0.30, technique: 'T1110.001' },
  ],
  'Spoofing-DNS': [
    { next: 'WebAttack-SQLi', probability: 0.35, technique: 'T1190' },
    { next: 'Malware-Backdoor', probability: 0.35, technique: 'T1059.001' },
    { next: 'DNS-Spoofing', probability: 0.30, technique: 'T1071.004' },
  ],
  'Malware-Ransomware': [
    { next: 'DDoS-TCP', probability: 0.50, technique: 'T1498.001' },
    { next: 'DDoS-HTTP', probability: 0.30, technique: 'T1498.001' },
    { next: 'DNS-Spoofing', probability: 0.20, technique: 'T1071.004' },
  ],
  'Mirai-greeth': [
    { next: 'DDoS-TCP', probability: 0.40, technique: 'T1498.001' },
    { next: 'DDoS-UDP', probability: 0.30, technique: 'T1498.001' },
    { next: 'DDoS-HTTP', probability: 0.20, technique: 'T1498.001' },
    { next: 'Mirai-udpplain', probability: 0.10, technique: 'T1583.005' },
  ],
}

/* ── Severity map by attack family ───────────────────────────────────── */

const SEVERITY_MAP: Record<string, { level: string; color: string }> = {
  'Recon': { level: 'low', color: '#22C55E' },
  'BruteForce': { level: 'medium', color: '#F59E0B' },
  'Spoofing': { level: 'high', color: '#F97316' },
  'WebAttack': { level: 'high', color: '#F97316' },
  'Malware': { level: 'critical', color: '#EF4444' },
  'DDoS': { level: 'critical', color: '#EF4444' },
  'Mirai': { level: 'critical', color: '#EF4444' },
  'DNS': { level: 'high', color: '#F97316' },
}

/* ── Attack families for grouped selector ────────────────────────────── */

const ATTACK_FAMILIES: Record<string, string[]> = {
  Recon: ['Recon-PingSweep', 'Recon-PortScan', 'Recon-OSScan', 'Recon-HostDiscovery'],
  BruteForce: ['BruteForce-SSH', 'BruteForce-FTP', 'BruteForce-HTTP'],
  WebAttack: ['WebAttack-SQLi', 'WebAttack-XSS', 'WebAttack-CmdInjection', 'WebAttack-BrowserHijack'],
  Spoofing: ['Spoofing-ARP', 'Spoofing-DNS', 'Spoofing-IP'],
  Malware: ['Malware-Backdoor', 'Malware-Ransomware'],
  DDoS: ['DDoS-TCP', 'DDoS-UDP', 'DDoS-HTTP', 'DDoS-ICMP', 'DDoS-SYN', 'DDoS-SlowLoris', 'DDoS-RST-FIN', 'DDoS-PSH-ACK', 'DDoS-Fragmentation'],
  Mirai: ['Mirai-greeth', 'Mirai-greip', 'Mirai-udpplain'],
  DNS: ['DNS-Spoofing'],
}

const FAMILY_COLORS: Record<string, string> = {
  Recon: 'bg-green-500/15 text-green-400 border-green-500/30',
  BruteForce: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  WebAttack: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  Spoofing: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  Malware: 'bg-red-500/15 text-red-400 border-red-500/30',
  DDoS: 'bg-red-500/15 text-red-400 border-red-500/30',
  Mirai: 'bg-red-500/15 text-red-400 border-red-500/30',
  DNS: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
}

/* ── Recommended pre-emptive actions ─────────────────────────────────── */

const PREEMPTIVE_ACTIONS: Record<string, string[]> = {
  low: [
    'Enable verbose logging on perimeter devices',
    'Verify firewall rules block ICMP sweep responses',
  ],
  medium: [
    'Enforce account lockout policies (5 failed attempts)',
    'Enable MFA on all SSH/FTP-exposed services',
    'Deploy honeypots to detect lateral movement',
  ],
  high: [
    'Activate WAF rules for SQLi/XSS/CmdInjection signatures',
    'Enable ARP inspection and DNSSEC validation',
    'Isolate high-value assets behind micro-segmented VLANs',
    'Review and rotate all service account credentials',
  ],
  critical: [
    'Immediately isolate affected network segments',
    'Activate incident response runbook and notify SOC lead',
    'Enable full packet capture on egress points',
    'Block known C2 IP ranges at border firewall',
    'Verify offline backups are current and accessible',
  ],
}

/* ── Helpers ──────────────────────────────────────────────────────────── */

function getSeverity(attack: string): { level: string; color: string } {
  const family = attack.split('-')[0]
  return SEVERITY_MAP[family] ?? { level: 'medium', color: '#F59E0B' }
}

const SEVERITY_ORDER: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 }

function predictChain(startAttack: string, depth: number): { attack: string; probability: number; technique: string; cumProb: number }[] {
  const chain: { attack: string; probability: number; technique: string; cumProb: number }[] = []
  let current = startAttack
  let cumProb = 1.0
  for (let i = 0; i < depth; i++) {
    const transitions = ATTACK_TRANSITIONS[current]
    if (!transitions || transitions.length === 0) break
    const best = transitions[0] // highest probability first
    cumProb *= best.probability
    chain.push({ attack: best.next, probability: best.probability, technique: best.technique, cumProb })
    current = best.next
  }
  return chain
}

/* ── Guide steps ─────────────────────────────────────────────────────── */

const GUIDE_STEPS = [
  { title: 'Select Observed Attack', desc: 'Choose the attack class currently observed in your network from the grouped selector.' },
  { title: 'View Predictions', desc: 'See the most likely next 1-5 attacker moves predicted by the Markov transition model.' },
  { title: 'Trace Kill Chain', desc: 'Follow the chain visualization to understand attack progression and cumulative probability.' },
  { title: 'Plan Response', desc: 'Use the risk assessment and pre-emptive actions to prepare defenses before the attacker advances.' },
]

/* ── Component ───────────────────────────────────────────────────────── */

export default function AttackChainPredictor() {
  const [selectedAttack, setSelectedAttack] = useState<string>('Recon-PingSweep')
  const [predictionDepth, setPredictionDepth] = useState(3)
  const [showAlternatives, setShowAlternatives] = useState(true)

  /* Predicted chain */
  const chain = useMemo(() => predictChain(selectedAttack, predictionDepth), [selectedAttack, predictionDepth])

  /* Alternative next steps for the selected attack */
  const alternatives = useMemo(() => {
    const trans = ATTACK_TRANSITIONS[selectedAttack]
    return trans ? [...trans].sort((a, b) => b.probability - a.probability) : []
  }, [selectedAttack])

  /* Risk assessment */
  const riskAssessment = useMemo(() => {
    if (chain.length === 0) {
      const sev = getSeverity(selectedAttack)
      return { level: sev.level, color: sev.color, score: SEVERITY_ORDER[sev.level] * 25 }
    }
    const finalStep = chain[chain.length - 1]
    const sev = getSeverity(finalStep.attack)
    const score = Math.min(100, SEVERITY_ORDER[sev.level] * 25 + (1 - finalStep.cumProb) * 10)
    return { level: sev.level, color: sev.color, score: Math.round(score) }
  }, [chain, selectedAttack])

  /* Stats */
  const stats = useMemo(() => {
    const startingPoints = Object.keys(ATTACK_TRANSITIONS)
    let totalDepth = 0
    let maxRisk = { attack: '', score: 0 }

    for (const start of startingPoints) {
      const c = predictChain(start, 5)
      totalDepth += c.length
      if (c.length > 0) {
        const finalSev = getSeverity(c[c.length - 1].attack)
        const score = SEVERITY_ORDER[finalSev.level] * 25
        if (score > maxRisk.score) {
          maxRisk = { attack: start, score }
        }
      }
    }

    return {
      totalChains: startingPoints.length,
      avgDepth: (totalDepth / startingPoints.length).toFixed(1),
      highestRisk: maxRisk.attack,
    }
  }, [])

  const hasTransitions = ATTACK_TRANSITIONS[selectedAttack] !== undefined

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <TrendingUp className="w-6 h-6 text-accent-blue" />
            Attack Chain Predictor
          </h1>
          <p className="text-sm text-text-secondary mt-1">
            Predict the next 3-5 attacker moves using Markov transition analysis on MITRE ATT&CK kill chains
          </p>
        </div>
        <ExportMenu filename="attack-chain-prediction" />
      </div>

      <PageGuide
        title="How to use Attack Chain Predictor"
        steps={GUIDE_STEPS}
        tip="Start with a Recon attack to see the full kill chain unfold from reconnaissance to impact."
      />

      {/* Stats bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Chains Modeled', value: stats.totalChains, icon: Layers, color: 'text-accent-blue' },
          { label: 'Avg Chain Depth', value: stats.avgDepth, icon: Activity, color: 'text-accent-purple' },
          { label: 'Highest-Risk Start', value: stats.highestRisk, icon: AlertTriangle, color: 'text-red-400' },
          { label: 'Chain Risk Score', value: `${riskAssessment.score}/100`, icon: Shield, color: 'text-amber-400' },
        ].map(m => (
          <div key={m.label} className="bg-bg-card border border-bg-card rounded-xl p-4">
            <div className="flex items-center gap-2 text-xs text-text-secondary mb-1">
              <m.icon className={`w-3.5 h-3.5 ${m.color}`} />
              {m.label}
            </div>
            <div className="text-lg font-bold truncate">{m.value}</div>
          </div>
        ))}
      </div>

      {/* Observed Attack Selector */}
      <div className="bg-bg-card border border-bg-card rounded-xl p-5">
        <h2 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <Target className="w-4 h-4 text-accent-blue" />
          Observed Attack Selector
        </h2>
        <div className="space-y-3">
          {Object.entries(ATTACK_FAMILIES).map(([family, attacks]) => (
            <div key={family}>
              <div className="text-xs text-text-secondary font-medium mb-1.5 uppercase tracking-wider">{family}</div>
              <div className="flex flex-wrap gap-1.5">
                {attacks.map(attack => {
                  const isSelected = selectedAttack === attack
                  const hasChain = ATTACK_TRANSITIONS[attack] !== undefined
                  return (
                    <button
                      key={attack}
                      onClick={() => setSelectedAttack(attack)}
                      className={`px-2.5 py-1 text-xs rounded-lg border transition-all ${
                        isSelected
                          ? 'bg-accent-blue/20 text-accent-blue border-accent-blue/50 ring-1 ring-accent-blue/30'
                          : hasChain
                            ? `${FAMILY_COLORS[family]} hover:brightness-125 cursor-pointer`
                            : 'bg-bg-surface/50 text-text-secondary/50 border-bg-surface cursor-not-allowed'
                      }`}
                      disabled={!hasChain && !isSelected}
                      title={hasChain ? `Select ${attack}` : 'No transition data available'}
                    >
                      {attack.split('-').pop()}
                    </button>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Depth slider */}
      <div className="bg-bg-card border border-bg-card rounded-xl p-4 flex items-center gap-4">
        <label className="text-sm text-text-secondary whitespace-nowrap">Prediction Depth:</label>
        <input
          type="range"
          min={1}
          max={5}
          value={predictionDepth}
          onChange={e => setPredictionDepth(Number(e.target.value))}
          className="flex-1 accent-accent-blue"
        />
        <span className="text-sm font-mono font-bold text-accent-blue w-6 text-center">{predictionDepth}</span>
        <button
          onClick={() => setShowAlternatives(!showAlternatives)}
          className={`text-xs px-3 py-1 rounded-lg border transition-colors ${
            showAlternatives
              ? 'bg-accent-blue/15 text-accent-blue border-accent-blue/30'
              : 'bg-bg-surface text-text-secondary border-bg-surface'
          }`}
        >
          {showAlternatives ? 'Hide' : 'Show'} Alternatives
        </button>
      </div>

      {/* Prediction Chain Visualization */}
      <div className="bg-bg-card border border-bg-card rounded-xl p-5">
        <h2 className="text-sm font-semibold mb-4 flex items-center gap-2">
          <Zap className="w-4 h-4 text-amber-400" />
          Predicted Attack Chain
        </h2>

        {!hasTransitions ? (
          <div className="text-center py-8 text-text-secondary text-sm">
            No transition data available for <span className="font-mono text-text-primary">{selectedAttack}</span>.
            Select an attack with known chain transitions.
          </div>
        ) : (
          <div className="flex items-stretch gap-0 overflow-x-auto pb-2">
            {/* Starting observed attack */}
            <ChainNode
              label={selectedAttack}
              subtitle="Observed"
              severity={getSeverity(selectedAttack)}
              probability={null}
              cumProb={null}
              technique={null}
              isStart
            />

            {chain.map((step, i) => (
              <div key={i} className="flex items-stretch">
                <ChainArrow probability={step.probability} />
                <ChainNode
                  label={step.attack}
                  subtitle={`Step ${i + 1}`}
                  severity={getSeverity(step.attack)}
                  probability={step.probability}
                  cumProb={step.cumProb}
                  technique={step.technique}
                  isStart={false}
                />
              </div>
            ))}

            {chain.length === 0 && (
              <div className="flex items-center ml-4 text-sm text-text-secondary italic">
                Chain terminates — no further transitions defined
              </div>
            )}
          </div>
        )}
      </div>

      {/* Alternative Paths Panel */}
      {showAlternatives && hasTransitions && (
        <div className="bg-bg-card border border-bg-card rounded-xl p-5">
          <h2 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-accent-purple" />
            Alternative Next Moves from {selectedAttack}
          </h2>
          <div className="space-y-2">
            {alternatives.map((alt, i) => {
              const sev = getSeverity(alt.next)
              return (
                <div key={i} className="flex items-center gap-3">
                  <div className="w-44 text-xs font-mono truncate text-text-primary">{alt.next}</div>
                  <div className="flex-1 h-5 bg-bg-surface rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-500"
                      style={{
                        width: `${alt.probability * 100}%`,
                        backgroundColor: sev.color,
                        opacity: 0.7,
                      }}
                    />
                  </div>
                  <div className="text-xs font-mono w-12 text-right" style={{ color: sev.color }}>
                    {(alt.probability * 100).toFixed(0)}%
                  </div>
                  <span
                    className="text-[10px] px-1.5 py-0.5 rounded border font-medium"
                    style={{
                      color: sev.color,
                      borderColor: sev.color + '40',
                      backgroundColor: sev.color + '15',
                    }}
                  >
                    {sev.level}
                  </span>
                  <span className="text-[10px] text-text-secondary font-mono w-20">{alt.technique}</span>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Risk Assessment */}
      <div className="bg-bg-card border border-bg-card rounded-xl p-5">
        <h2 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <Shield className="w-4 h-4 text-red-400" />
          Risk Assessment &amp; Pre-emptive Actions
        </h2>
        <div className="grid md:grid-cols-2 gap-4">
          {/* Risk gauge */}
          <div>
            <div className="flex items-center gap-3 mb-3">
              <div className="text-3xl font-bold" style={{ color: riskAssessment.color }}>
                {riskAssessment.score}
              </div>
              <div>
                <div className="text-sm text-text-secondary">Overall Chain Risk</div>
                <span
                  className="text-xs px-2 py-0.5 rounded-full font-semibold uppercase"
                  style={{
                    color: riskAssessment.color,
                    backgroundColor: riskAssessment.color + '20',
                  }}
                >
                  {riskAssessment.level}
                </span>
              </div>
            </div>
            <div className="w-full h-3 bg-bg-surface rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-700"
                style={{
                  width: `${riskAssessment.score}%`,
                  background: `linear-gradient(90deg, #22C55E, #F59E0B, #EF4444)`,
                }}
              />
            </div>
            <div className="flex justify-between text-[10px] text-text-secondary mt-1">
              <span>Low</span>
              <span>Medium</span>
              <span>High</span>
              <span>Critical</span>
            </div>
          </div>

          {/* Pre-emptive actions */}
          <div>
            <div className="text-xs font-medium text-text-secondary mb-2 uppercase tracking-wider">
              Recommended Pre-emptive Actions
            </div>
            <ul className="space-y-1.5">
              {(PREEMPTIVE_ACTIONS[riskAssessment.level] ?? PREEMPTIVE_ACTIONS.medium).map((action, i) => (
                <li key={i} className="flex items-start gap-2 text-xs text-text-primary">
                  <ArrowRight className="w-3 h-3 mt-0.5 shrink-0" style={{ color: riskAssessment.color }} />
                  {action}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}

/* ── Chain node sub-component ────────────────────────────────────────── */

function ChainNode({
  label,
  subtitle,
  severity,
  probability,
  cumProb,
  technique,
  isStart,
}: {
  label: string
  subtitle: string
  severity: { level: string; color: string }
  probability: number | null
  cumProb: number | null
  technique: string | null
  isStart: boolean
}) {
  return (
    <div
      className="flex flex-col items-center justify-center min-w-[140px] max-w-[160px] rounded-xl border p-3 transition-all"
      style={{
        borderColor: isStart ? '#3B82F6' + '60' : severity.color + '40',
        backgroundColor: isStart ? '#3B82F6' + '08' : severity.color + '08',
      }}
    >
      <div className="text-[10px] text-text-secondary mb-1">{subtitle}</div>
      <div className="text-xs font-bold text-text-primary text-center leading-tight mb-1.5">{label}</div>
      <span
        className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold uppercase mb-1"
        style={{
          color: severity.color,
          backgroundColor: severity.color + '20',
        }}
      >
        {severity.level}
      </span>
      {technique && (
        <div className="text-[10px] font-mono text-text-secondary">{technique}</div>
      )}
      {probability !== null && (
        <div className="text-[10px] mt-1 text-text-secondary">
          P: {(probability * 100).toFixed(0)}%
          {cumProb !== null && (
            <span className="text-text-secondary/60"> | Cum: {(cumProb * 100).toFixed(1)}%</span>
          )}
        </div>
      )}
    </div>
  )
}

/* ── Chain arrow sub-component ───────────────────────────────────────── */

function ChainArrow({ probability }: { probability: number }) {
  const opacity = 0.4 + probability * 0.6
  return (
    <div className="flex items-center px-1" style={{ opacity }}>
      <div className="flex items-center">
        <div className="w-6 h-0.5 bg-accent-blue rounded" />
        <ChevronRight className="w-4 h-4 text-accent-blue -ml-1 animate-pulse" />
      </div>
    </div>
  )
}
