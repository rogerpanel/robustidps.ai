import { useState, useMemo } from 'react'
import {
  Shield, ExternalLink, Search, ChevronRight, Activity,
  Crosshair, Info, X,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'

/* ── MITRE ATT&CK mapping data ──────────────────────────────────────── */

interface AttackMapping {
  class: string
  technique: string
  tactic: string
  name: string
}

const ATTACK_CLASSES: AttackMapping[] = [
  { class: 'DDoS-TCP', technique: 'T1498.001', tactic: 'Impact', name: 'Network Denial of Service: Direct Network Flood' },
  { class: 'DDoS-UDP', technique: 'T1498.001', tactic: 'Impact', name: 'Network Denial of Service: Direct Network Flood' },
  { class: 'DDoS-ICMP', technique: 'T1498.001', tactic: 'Impact', name: 'Network Denial of Service: Direct Network Flood' },
  { class: 'DDoS-HTTP', technique: 'T1498.001', tactic: 'Impact', name: 'Network Denial of Service: Direct Network Flood' },
  { class: 'DDoS-SYN', technique: 'T1498.001', tactic: 'Impact', name: 'Network Denial of Service: Direct Network Flood' },
  { class: 'DDoS-SlowLoris', technique: 'T1499.002', tactic: 'Impact', name: 'Endpoint DoS: Service Exhaustion Flood' },
  { class: 'DDoS-RST-FIN', technique: 'T1498.001', tactic: 'Impact', name: 'Network Denial of Service: Direct Network Flood' },
  { class: 'DDoS-PSH-ACK', technique: 'T1498.001', tactic: 'Impact', name: 'Network Denial of Service: Direct Network Flood' },
  { class: 'Recon-PortScan', technique: 'T1046', tactic: 'Discovery', name: 'Network Service Discovery' },
  { class: 'Recon-OSScan', technique: 'T1082', tactic: 'Discovery', name: 'System Information Discovery' },
  { class: 'Recon-HostDiscovery', technique: 'T1018', tactic: 'Discovery', name: 'Remote System Discovery' },
  { class: 'Recon-PingSweep', technique: 'T1018', tactic: 'Discovery', name: 'Remote System Discovery' },
  { class: 'BruteForce-SSH', technique: 'T1110.001', tactic: 'Credential Access', name: 'Brute Force: Password Guessing' },
  { class: 'BruteForce-FTP', technique: 'T1110.001', tactic: 'Credential Access', name: 'Brute Force: Password Guessing' },
  { class: 'BruteForce-HTTP', technique: 'T1110.001', tactic: 'Credential Access', name: 'Brute Force: Password Guessing' },
  { class: 'BruteForce-Dictionary', technique: 'T1110.002', tactic: 'Credential Access', name: 'Brute Force: Password Cracking' },
  { class: 'Spoofing-ARP', technique: 'T1557.002', tactic: 'Credential Access', name: 'Adversary-in-the-Middle: ARP Cache Poisoning' },
  { class: 'Spoofing-DNS', technique: 'T1557.001', tactic: 'Credential Access', name: 'Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning' },
  { class: 'Spoofing-IP', technique: 'T1090', tactic: 'Command and Control', name: 'Proxy' },
  { class: 'WebAttack-SQLi', technique: 'T1190', tactic: 'Initial Access', name: 'Exploit Public-Facing Application' },
  { class: 'WebAttack-XSS', technique: 'T1189', tactic: 'Initial Access', name: 'Drive-by Compromise' },
  { class: 'WebAttack-CmdInjection', technique: 'T1059', tactic: 'Execution', name: 'Command and Scripting Interpreter' },
  { class: 'WebAttack-BrowserHijack', technique: 'T1185', tactic: 'Collection', name: 'Browser Session Hijacking' },
  { class: 'Malware-Backdoor', technique: 'T1059.001', tactic: 'Execution', name: 'Command and Scripting Interpreter: PowerShell' },
  { class: 'Malware-Ransomware', technique: 'T1486', tactic: 'Impact', name: 'Data Encrypted for Impact' },
  { class: 'Mirai-greeth', technique: 'T1583.005', tactic: 'Resource Development', name: 'Acquire Infrastructure: Botnet' },
  { class: 'Mirai-greip', technique: 'T1583.005', tactic: 'Resource Development', name: 'Acquire Infrastructure: Botnet' },
  { class: 'Mirai-udpplain', technique: 'T1583.005', tactic: 'Resource Development', name: 'Acquire Infrastructure: Botnet' },
  { class: 'DNS-Spoofing', technique: 'T1071.004', tactic: 'Command and Control', name: 'Application Layer Protocol: DNS' },
  { class: 'DDoS-Fragmentation', technique: 'T1498.001', tactic: 'Impact', name: 'Network Denial of Service: Direct Network Flood' },
  { class: 'Benign', technique: '-', tactic: '-', name: 'Normal Traffic' },
]

interface KillChainStage {
  id: string
  name: string
  tactic: string
  color: string
}

const KILL_CHAIN_STAGES: KillChainStage[] = [
  { id: 'recon', name: 'Reconnaissance', tactic: 'Reconnaissance', color: '#3B82F6' },
  { id: 'resource', name: 'Resource Dev', tactic: 'Resource Development', color: '#8B5CF6' },
  { id: 'initial', name: 'Initial Access', tactic: 'Initial Access', color: '#F59E0B' },
  { id: 'execution', name: 'Execution', tactic: 'Execution', color: '#EF4444' },
  { id: 'discovery', name: 'Discovery', tactic: 'Discovery', color: '#22C55E' },
  { id: 'credential', name: 'Credential Access', tactic: 'Credential Access', color: '#F97316' },
  { id: 'collection', name: 'Collection', tactic: 'Collection', color: '#EC4899' },
  { id: 'c2', name: 'Command & Control', tactic: 'Command and Control', color: '#A855F7' },
  { id: 'impact', name: 'Impact', tactic: 'Impact', color: '#EF4444' },
]

const TACTIC_COLORS: Record<string, string> = Object.fromEntries(
  KILL_CHAIN_STAGES.map(s => [s.tactic, s.color])
)

/* Cyber Kill Chain (Lockheed Martin) mapping for the visualization header */
const CYBER_KILL_CHAIN = [
  'Reconnaissance',
  'Weaponization',
  'Delivery',
  'Exploitation',
  'Installation',
  'C2',
  'Actions on Objectives',
]

/* ── Page guide steps ────────────────────────────────────────────────── */

const GUIDE_STEPS = [
  { title: 'Kill Chain Overview', desc: 'Review the ATT&CK tactic stages across the kill chain. Click any stage to filter the table below.' },
  { title: 'Explore Mappings', desc: 'Browse the full mapping table linking the platform\'s 34 attack classes to MITRE ATT&CK technique IDs.' },
  { title: 'Click a Technique', desc: 'Select any ATT&CK technique badge to see all attack classes that map to that technique.' },
  { title: 'Export Results', desc: 'Use the Export menu to download the mapping as a PNG, PDF, or slide deck for reporting.' },
]

/* ── Component ───────────────────────────────────────────────────────── */

export default function MitreAttackMapper() {
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null)
  const [selectedTechnique, setSelectedTechnique] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [detailTechnique, setDetailTechnique] = useState<string | null>(null)

  /* Derived data */
  const attackClasses = useMemo(() => ATTACK_CLASSES.filter(a => a.technique !== '-'), [])

  const uniqueTechniques = useMemo(() => {
    const seen = new Set<string>()
    return attackClasses.filter(a => {
      if (seen.has(a.technique)) return false
      seen.add(a.technique)
      return true
    })
  }, [attackClasses])

  const tacticCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const a of attackClasses) {
      counts[a.tactic] = (counts[a.tactic] || 0) + 1
    }
    return counts
  }, [attackClasses])

  const filteredClasses = useMemo(() => {
    let items = attackClasses
    if (selectedTactic) {
      items = items.filter(a => a.tactic === selectedTactic)
    }
    if (selectedTechnique) {
      items = items.filter(a => a.technique === selectedTechnique)
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      items = items.filter(a =>
        a.class.toLowerCase().includes(q) ||
        a.technique.toLowerCase().includes(q) ||
        a.name.toLowerCase().includes(q) ||
        a.tactic.toLowerCase().includes(q)
      )
    }
    return items
  }, [attackClasses, selectedTactic, selectedTechnique, searchQuery])

  const techniqueDetail = useMemo(() => {
    if (!detailTechnique) return null
    const matches = attackClasses.filter(a => a.technique === detailTechnique)
    if (!matches.length) return null
    return { technique: detailTechnique, name: matches[0].name, tactic: matches[0].tactic, classes: matches.map(m => m.class) }
  }, [detailTechnique, attackClasses])

  const handleTacticClick = (tactic: string) => {
    if (selectedTactic === tactic) {
      setSelectedTactic(null)
    } else {
      setSelectedTactic(tactic)
      setSelectedTechnique(null)
    }
  }

  const handleTechniqueClick = (technique: string) => {
    if (selectedTechnique === technique) {
      setSelectedTechnique(null)
    } else {
      setSelectedTechnique(technique)
      setSelectedTactic(null)
    }
  }

  const clearFilters = () => {
    setSelectedTactic(null)
    setSelectedTechnique(null)
    setSearchQuery('')
  }

  const hasFilters = selectedTactic || selectedTechnique || searchQuery.trim()

  return (
    <div className="space-y-6 mitre-mapper-root">
      {/* ── Header ──────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-accent-blue/10 flex items-center justify-center">
            <Shield className="w-5 h-5 text-accent-blue" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-text-primary">MITRE ATT&CK Mapper</h1>
            <p className="text-xs text-text-secondary mt-0.5">
              Mapping 34 detected attack classes to ATT&CK technique IDs with kill chain visualization
            </p>
          </div>
        </div>
        <ExportMenu targetSelector=".mitre-mapper-root" filename="mitre-attack-mapping" />
      </div>

      {/* ── Page Guide ──────────────────────────────────────────────── */}
      <PageGuide
        title="How to use the MITRE ATT&CK Mapper"
        steps={GUIDE_STEPS}
        tip="All 30 malicious attack classes (excluding Benign) are mapped to ATT&CK. Click any kill chain stage or technique badge to filter."
      />

      {/* ── Cyber Kill Chain Bar ────────────────────────────────────── */}
      <div className="bg-bg-secondary border border-bg-card rounded-xl p-5">
        <h2 className="text-sm font-semibold text-text-primary mb-1 flex items-center gap-2">
          <Activity className="w-4 h-4 text-accent-blue" />
          Cyber Kill Chain
        </h2>
        <p className="text-xs text-text-secondary mb-4">
          Lockheed Martin kill chain stages. Click to see how platform attacks map across stages.
        </p>
        <div className="flex items-center gap-0 overflow-x-auto pb-2">
          {CYBER_KILL_CHAIN.map((stage, i) => (
            <div key={stage} className="flex items-center shrink-0">
              <div className="px-3 py-2 rounded-lg text-xs font-medium bg-bg-card/60 border border-bg-card text-text-secondary">
                {stage}
              </div>
              {i < CYBER_KILL_CHAIN.length - 1 && (
                <ChevronRight className="w-4 h-4 text-text-secondary/40 mx-1 shrink-0" />
              )}
            </div>
          ))}
        </div>
      </div>

      {/* ── ATT&CK Tactic Stages (clickable) ────────────────────────── */}
      <div className="bg-bg-secondary border border-bg-card rounded-xl p-5">
        <h2 className="text-sm font-semibold text-text-primary mb-1 flex items-center gap-2">
          <Crosshair className="w-4 h-4 text-accent-purple" />
          ATT&CK Tactic Stages
        </h2>
        <p className="text-xs text-text-secondary mb-4">
          Click a tactic to filter the mapping table. Each badge shows the number of mapped attack classes.
        </p>
        <div className="grid grid-cols-3 sm:grid-cols-5 lg:grid-cols-9 gap-2">
          {KILL_CHAIN_STAGES.map(stage => {
            const count = tacticCounts[stage.tactic] || 0
            const isActive = selectedTactic === stage.tactic
            return (
              <button
                key={stage.id}
                onClick={() => handleTacticClick(stage.tactic)}
                className={`relative flex flex-col items-center gap-1.5 p-3 rounded-lg border transition-all text-center ${
                  isActive
                    ? 'border-opacity-60 bg-opacity-15 scale-[1.03] shadow-lg'
                    : 'border-bg-card bg-bg-card/30 hover:bg-bg-card/60'
                }`}
                style={{
                  borderColor: isActive ? stage.color : undefined,
                  backgroundColor: isActive ? `${stage.color}15` : undefined,
                }}
              >
                <div
                  className="w-3 h-3 rounded-full"
                  style={{ backgroundColor: stage.color }}
                />
                <span className="text-[10px] font-semibold text-text-primary leading-tight">
                  {stage.name}
                </span>
                <span
                  className="text-[10px] font-bold px-1.5 py-0.5 rounded-full"
                  style={{ backgroundColor: `${stage.color}20`, color: stage.color }}
                >
                  {count}
                </span>
              </button>
            )
          })}
        </div>
      </div>

      {/* ── Stats Row ───────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label="Attack Classes Mapped" value={attackClasses.length} color="#3B82F6" />
        <StatCard label="Unique Techniques" value={uniqueTechniques.length} color="#8B5CF6" />
        <StatCard label="Tactics Covered" value={Object.keys(tacticCounts).length} color="#22C55E" />
        <StatCard label="Kill Chain Coverage" value={`${Math.round((Object.keys(tacticCounts).length / KILL_CHAIN_STAGES.length) * 100)}%`} color="#F59E0B" />
      </div>

      {/* ── Technique Detail Modal ──────────────────────────────────── */}
      {techniqueDetail && (
        <div className="bg-bg-secondary border border-accent-blue/30 rounded-xl p-5 relative">
          <button
            onClick={() => setDetailTechnique(null)}
            className="absolute top-3 right-3 text-text-secondary hover:text-text-primary"
          >
            <X className="w-4 h-4" />
          </button>
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0" style={{ backgroundColor: `${TACTIC_COLORS[techniqueDetail.tactic] || '#3B82F6'}15` }}>
              <Info className="w-4 h-4" style={{ color: TACTIC_COLORS[techniqueDetail.tactic] || '#3B82F6' }} />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-bold text-text-primary">{techniqueDetail.technique}</span>
                <span className="text-xs text-text-secondary">{techniqueDetail.name}</span>
                <a
                  href={`https://attack.mitre.org/techniques/${techniqueDetail.technique.replace('.', '/')}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-accent-blue hover:underline flex items-center gap-1"
                >
                  View on MITRE <ExternalLink className="w-3 h-3" />
                </a>
              </div>
              <div className="flex items-center gap-1.5 mt-1.5">
                <TacticBadge tactic={techniqueDetail.tactic} />
              </div>
              <div className="mt-3">
                <p className="text-xs text-text-secondary mb-1.5">Mapped attack classes ({techniqueDetail.classes.length}):</p>
                <div className="flex flex-wrap gap-1.5">
                  {techniqueDetail.classes.map(cls => (
                    <span
                      key={cls}
                      className="px-2 py-0.5 bg-bg-card border border-bg-card rounded text-xs text-text-primary font-mono"
                    >
                      {cls}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Search & Filter Bar ─────────────────────────────────────── */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-secondary" />
          <input
            type="text"
            placeholder="Search attack class, technique ID, or name..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-2 bg-bg-secondary border border-bg-card rounded-lg text-xs text-text-primary placeholder-text-secondary/50 focus:outline-none focus:border-accent-blue/40"
          />
        </div>
        {hasFilters && (
          <button
            onClick={clearFilters}
            className="flex items-center gap-1.5 px-3 py-2 bg-bg-secondary border border-bg-card rounded-lg text-xs text-text-secondary hover:text-accent-red transition-colors"
          >
            <X className="w-3 h-3" />
            Clear filters
          </button>
        )}
        <span className="text-xs text-text-secondary">
          Showing {filteredClasses.length} of {attackClasses.length} mappings
        </span>
      </div>

      {/* ── Mapping Table ───────────────────────────────────────────── */}
      <div className="bg-bg-secondary border border-bg-card rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-bg-card">
                <th className="text-left px-4 py-3 text-text-secondary font-semibold">Attack Class</th>
                <th className="text-left px-4 py-3 text-text-secondary font-semibold">ATT&CK ID</th>
                <th className="text-left px-4 py-3 text-text-secondary font-semibold">Technique Name</th>
                <th className="text-left px-4 py-3 text-text-secondary font-semibold">Tactic</th>
                <th className="text-center px-4 py-3 text-text-secondary font-semibold">Link</th>
              </tr>
            </thead>
            <tbody>
              {filteredClasses.map((item, idx) => (
                <tr
                  key={`${item.class}-${idx}`}
                  className="border-b border-bg-card/50 hover:bg-bg-card/30 transition-colors"
                >
                  <td className="px-4 py-2.5">
                    <span className="font-mono font-medium text-text-primary">{item.class}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <button
                      onClick={() => {
                        handleTechniqueClick(item.technique)
                        setDetailTechnique(item.technique)
                      }}
                      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-bold transition-all hover:scale-105 cursor-pointer"
                      style={{
                        backgroundColor: `${TACTIC_COLORS[item.tactic] || '#3B82F6'}15`,
                        color: TACTIC_COLORS[item.tactic] || '#3B82F6',
                        border: `1px solid ${TACTIC_COLORS[item.tactic] || '#3B82F6'}30`,
                      }}
                    >
                      {item.technique}
                    </button>
                  </td>
                  <td className="px-4 py-2.5 text-text-secondary max-w-[280px] truncate">
                    {item.name}
                  </td>
                  <td className="px-4 py-2.5">
                    <TacticBadge tactic={item.tactic} />
                  </td>
                  <td className="px-4 py-2.5 text-center">
                    <a
                      href={`https://attack.mitre.org/techniques/${item.technique.replace('.', '/')}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-accent-blue hover:text-accent-blue/80 transition-colors"
                    >
                      <ExternalLink className="w-3.5 h-3.5 inline" />
                    </a>
                  </td>
                </tr>
              ))}
              {filteredClasses.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-text-secondary">
                    No mappings match your current filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Coverage Heatmap by Tactic ──────────────────────────────── */}
      <div className="bg-bg-secondary border border-bg-card rounded-xl p-5">
        <h2 className="text-sm font-semibold text-text-primary mb-3">Coverage by Tactic</h2>
        <div className="space-y-2">
          {KILL_CHAIN_STAGES.map(stage => {
            const count = tacticCounts[stage.tactic] || 0
            const maxCount = Math.max(...Object.values(tacticCounts), 1)
            const pct = Math.round((count / maxCount) * 100)
            return (
              <div key={stage.id} className="flex items-center gap-3">
                <span className="text-xs text-text-secondary w-32 shrink-0 truncate">{stage.name}</span>
                <div className="flex-1 h-5 bg-bg-card/50 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{ width: `${pct}%`, backgroundColor: stage.color }}
                  />
                </div>
                <span className="text-xs font-mono text-text-primary w-8 text-right">{count}</span>
              </div>
            )
          })}
        </div>
      </div>

      {/* ── Legend / Footer ──────────────────────────────────────────── */}
      <div className="flex items-center justify-between text-[10px] text-text-secondary/60 px-1">
        <span>Data based on MITRE ATT&CK Framework v14. Mappings are best-effort for IDS/network-level detection.</span>
        <a
          href="https://attack.mitre.org/"
          target="_blank"
          rel="noopener noreferrer"
          className="text-accent-blue/60 hover:text-accent-blue flex items-center gap-1"
        >
          attack.mitre.org <ExternalLink className="w-2.5 h-2.5" />
        </a>
      </div>
    </div>
  )
}

/* ── Sub-components ──────────────────────────────────────────────────── */

function TacticBadge({ tactic }: { tactic: string }) {
  const color = TACTIC_COLORS[tactic] || '#64748B'
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold"
      style={{ backgroundColor: `${color}15`, color }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: color }} />
      {tactic}
    </span>
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
