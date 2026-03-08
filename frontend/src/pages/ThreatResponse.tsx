import { useEffect } from 'react'
import {
  Zap, Shield, Loader2, AlertTriangle, CheckCircle, Play, Pause,
  ChevronDown, ChevronUp, Clock, Server, Target, Activity, Link,
  FileText, MessageSquare, Send,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid, Legend, RadarChart, Radar, PolarGrid,
  PolarAngleAxis, PolarRadiusAxis, Cell, PieChart, Pie,
} from 'recharts'
import PageGuide from '../components/PageGuide'
import {
  fetchPlaybooks, simulateThreatResponse, fetchIncidents,
  fetchSecurityIntegrations, fetchResponseMetrics, addIncidentNote,
} from '../utils/api'
import { usePageState } from '../hooks/usePageState'

const PAGE = 'threatresponse'
const TT = { background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }

const SEV_COLORS: Record<string, string> = {
  critical: '#EF4444', high: '#F97316', medium: '#F59E0B', low: '#3B82F6',
}

const ACTION_COLORS: Record<string, string> = {
  detect: '#3B82F6', verify: '#A855F7', alert: '#F59E0B', rate_limit: '#F97316',
  firewall: '#EF4444', upstream_notify: '#DC2626', log: '#22C55E',
  throttle: '#F97316', captcha: '#A855F7', block_temp: '#EF4444', block_perm: '#DC2626',
  credential_reset: '#F59E0B', fingerprint: '#3B82F6', honeypot: '#A855F7',
  tarpit: '#F97316', intel_collect: '#22C55E', isolate: '#EF4444',
  block_c2: '#DC2626', snapshot: '#F59E0B', ioc_extract: '#A855F7',
  threat_intel: '#3B82F6', edr_scan: '#22C55E', waf_rule: '#F97316',
  session_kill: '#EF4444', input_sanitise: '#F59E0B', geo_check: '#3B82F6',
  validate: '#A855F7', arp_guard: '#F97316', dns_sinkhole: '#F59E0B',
}

type Tab = 'playbooks' | 'simulate' | 'incidents' | 'integrations'

export default function ThreatResponse() {
  const [tab, setTab] = usePageState<Tab>(PAGE, 'tab', 'playbooks')
  const [playbooks, setPlaybooks] = usePageState<any>(PAGE, 'playbooks', null)
  const [incidents, setIncidents] = usePageState<any>(PAGE, 'incidents', null)
  const [integrations, setIntegrations] = usePageState<any>(PAGE, 'integrations', null)
  const [metrics, setMetrics] = usePageState<any>(PAGE, 'metrics', null)
  const [loading, setLoading] = usePageState(PAGE, 'loading', true)
  const [simulating, setSimulating] = usePageState(PAGE, 'simulating', false)
  const [simResult, setSimResult] = usePageState<any>(PAGE, 'simResult', null)
  const [selectedPlaybook, setSelectedPlaybook] = usePageState(PAGE, 'selectedPlaybook', '')
  const [sourceIp, setSourceIp] = usePageState(PAGE, 'sourceIp', '192.168.1.100')
  const [targetIp, setTargetIp] = usePageState(PAGE, 'targetIp', '10.0.0.1')
  const [confidence, setConfidence] = usePageState(PAGE, 'confidence', 0.95)
  const [error, setError] = usePageState(PAGE, 'error', '')
  const [expandedPb, setExpandedPb] = usePageState<string | null>(PAGE, 'expandedPb', null)
  const [expandedInc, setExpandedInc] = usePageState<string | null>(PAGE, 'expandedInc', null)
  const [noteText, setNoteText] = usePageState(PAGE, 'noteText', '')

  useEffect(() => {
    setLoading(true)
    Promise.all([
      fetchPlaybooks().catch(() => null),
      fetchIncidents().catch(() => null),
      fetchSecurityIntegrations().catch(() => null),
      fetchResponseMetrics().catch(() => null),
    ]).then(([pb, inc, integ, met]) => {
      setPlaybooks(pb)
      setIncidents(inc)
      setIntegrations(integ)
      setMetrics(met)
      if (pb?.playbooks) {
        setSelectedPlaybook(Object.keys(pb.playbooks)[0] || '')
      }
      setLoading(false)
    })
  }, [])

  const handleSimulate = async () => {
    if (!selectedPlaybook) return
    setSimulating(true)
    setError('')
    setSimResult(null)
    try {
      const data = await simulateThreatResponse(selectedPlaybook, sourceIp, targetIp, confidence)
      setSimResult(data)
      // Refresh incidents
      fetchIncidents().then(inc => setIncidents(inc)).catch(() => {})
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Simulation failed')
    } finally {
      setSimulating(false)
    }
  }

  const handleAddNote = async (incidentId: string) => {
    if (!noteText.trim()) return
    try {
      await addIncidentNote(incidentId, noteText)
      setNoteText('')
      fetchIncidents().then(inc => setIncidents(inc)).catch(() => {})
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to add note')
    }
  }

  const TABS: { id: Tab; label: string }[] = [
    { id: 'playbooks', label: 'Response Playbooks' },
    { id: 'simulate', label: 'Simulate & Test' },
    { id: 'incidents', label: 'Incident Timeline' },
    { id: 'integrations', label: 'Integrations' },
  ]

  // Metrics chart data
  const effectivenessData = metrics?.playbooks?.map((p: any) => ({
    name: p.name.split(' ').slice(0, 2).join(' '),
    effectiveness: Math.round(p.effectiveness_score * 100),
    fp_rate: Math.round(p.false_positive_rate * 100 * 10) / 10,
  })) || []

  const mttrData = metrics?.mttr_by_severity ? Object.entries(metrics.mttr_by_severity).map(([sev, ms]: [string, any]) => ({
    severity: sev.charAt(0).toUpperCase() + sev.slice(1),
    mttr_ms: ms,
    color: SEV_COLORS[sev],
  })) : []

  const coverageData = metrics?.summary?.coverage ? [
    { name: 'Covered', value: metrics.summary.coverage.covered_classes, fill: '#22C55E' },
    { name: 'Uncovered', value: metrics.summary.coverage.total_threat_classes - metrics.summary.coverage.covered_classes, fill: '#334155' },
  ] : []

  return (
    <div className="space-y-6">
      <PageGuide
        title="How to use Autonomous Threat Response"
        steps={[
          { title: 'Review playbooks', desc: 'Explore automated response chains for each threat category.' },
          { title: 'Simulate responses', desc: 'Run playbook simulations to validate response timing and steps.' },
          { title: 'Track incidents', desc: 'View incident timeline with step-by-step execution logs.' },
          { title: 'Configure integrations', desc: 'Connect to SIEM, SOAR, EDR, and threat intel platforms.' },
        ]}
        tip="Playbooks define automated response chains: detect → classify → verify → contain → remediate → log."
      />

      {/* Header */}
      <div className="flex items-center gap-3">
        <Zap className="w-7 h-7 text-accent-orange" />
        <div>
          <h1 className="text-xl md:text-2xl font-display font-bold">Autonomous Threat Response</h1>
          <p className="text-sm text-text-secondary mt-0.5">Automated playbooks, incident orchestration & SOAR integration</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-bg-secondary rounded-lg p-1 border border-bg-card">
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex-1 px-3 py-2 rounded-md text-xs font-medium transition-colors ${
              tab === t.id ? 'bg-accent-orange/15 text-accent-orange' : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {error && (
        <div className="px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">
          {error}
        </div>
      )}

      {loading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 animate-spin text-accent-orange" />
          <span className="ml-2 text-text-secondary text-sm">Loading threat response data...</span>
        </div>
      )}

      {/* ══ PLAYBOOKS TAB ══ */}
      {tab === 'playbooks' && !loading && playbooks && (
        <>
          {/* Summary cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <FileText className="w-3.5 h-3.5" /> Playbooks
              </div>
              <div className="text-xl font-mono font-bold text-text-primary">{playbooks.total}</div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Play className="w-3.5 h-3.5" /> Auto-Execute
              </div>
              <div className="text-xl font-mono font-bold text-accent-green">{playbooks.auto_execute_enabled}</div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Shield className="w-3.5 h-3.5" /> Requires Approval
              </div>
              <div className="text-xl font-mono font-bold text-accent-amber">{playbooks.requires_approval}</div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Target className="w-3.5 h-3.5" /> Coverage
              </div>
              <div className="text-xl font-mono font-bold text-accent-blue">
                {metrics?.summary?.coverage?.coverage_percentage || '—'}%
              </div>
            </div>
          </div>

          {/* Effectiveness chart */}
          {effectivenessData.length > 0 && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                <h3 className="text-sm font-semibold mb-3">Playbook Effectiveness</h3>
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={effectivenessData} barGap={4}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis dataKey="name" tick={{ fill: '#94A3B8', fontSize: 9 }} />
                    <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" />
                    <Tooltip contentStyle={TT} />
                    <Bar dataKey="effectiveness" fill="#22C55E" name="Effectiveness %" radius={[4, 4, 0, 0]} />
                    <Bar dataKey="fp_rate" fill="#EF4444" name="False Positive %" radius={[4, 4, 0, 0]} />
                    <Legend wrapperStyle={{ fontSize: 11, color: '#94A3B8' }} />
                  </BarChart>
                </ResponsiveContainer>
              </div>

              <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                <h3 className="text-sm font-semibold mb-3">Mean Time to Respond (ms)</h3>
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={mttrData} barGap={4}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis dataKey="severity" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                    <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} unit="ms" />
                    <Tooltip contentStyle={TT} />
                    <Bar dataKey="mttr_ms" name="MTTR" radius={[4, 4, 0, 0]}>
                      {mttrData.map((d, i) => (
                        <Cell key={i} fill={d.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* Playbook cards */}
          <div className="space-y-3">
            {Object.entries(playbooks.playbooks || {}).map(([pid, pb]: [string, any]) => (
              <div key={pid} className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
                <button
                  onClick={() => setExpandedPb(expandedPb === pid ? null : pid)}
                  className="w-full px-4 py-3 flex items-center gap-3 hover:bg-bg-card/30 transition-colors"
                >
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold" style={{
                    background: `${SEV_COLORS[pb.severity]}20`,
                    color: SEV_COLORS[pb.severity],
                  }}>
                    {pb.id}
                  </span>
                  <span className="text-sm font-medium flex-1 text-left">{pb.name}</span>
                  <span className="text-xs text-text-secondary">{pb.step_count} steps</span>
                  <span className="text-xs font-mono text-accent-green">{Math.round(pb.effectiveness_score * 100)}%</span>
                  <span className="text-xs text-text-secondary">{pb.estimated_response_ms}ms</span>
                  {pb.auto_execute ? (
                    <Play className="w-3.5 h-3.5 text-accent-green" />
                  ) : (
                    <Pause className="w-3.5 h-3.5 text-text-secondary" />
                  )}
                  {expandedPb === pid ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
                {expandedPb === pid && (
                  <div className="px-4 pb-4 border-t border-bg-card space-y-3">
                    <div className="text-xs text-text-secondary mt-3">{pb.description}</div>

                    {/* Response chain */}
                    <div className="space-y-1.5">
                      <h4 className="text-xs font-semibold text-text-secondary">Response Chain</h4>
                      {pb.response_chain?.map((step: any) => (
                        <div key={step.step} className="flex items-center gap-2 text-xs">
                          <div className="w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold shrink-0" style={{
                            background: `${ACTION_COLORS[step.action] || '#334155'}20`,
                            color: ACTION_COLORS[step.action] || '#94A3B8',
                          }}>
                            {step.step}
                          </div>
                          <span className="font-mono px-1.5 py-0.5 rounded text-[10px]" style={{
                            background: `${ACTION_COLORS[step.action] || '#334155'}15`,
                            color: ACTION_COLORS[step.action] || '#94A3B8',
                          }}>
                            {step.action}
                          </span>
                          <span className="text-text-secondary flex-1">{step.description}</span>
                          <span className="font-mono text-text-secondary">{step.delay_ms}ms</span>
                        </div>
                      ))}
                    </div>

                    {/* Trigger classes */}
                    <div>
                      <h4 className="text-xs font-semibold text-text-secondary mb-1">Trigger Classes</h4>
                      <div className="flex flex-wrap gap-1">
                        {pb.trigger_classes?.map((c: string) => (
                          <span key={c} className="px-1.5 py-0.5 bg-accent-red/10 text-accent-red text-[9px] rounded font-mono">
                            {c}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </>
      )}

      {/* ══ SIMULATE TAB ══ */}
      {tab === 'simulate' && !loading && (
        <>
          <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div>
                <label className="text-xs text-text-secondary block mb-1">Playbook</label>
                <select
                  value={selectedPlaybook}
                  onChange={e => setSelectedPlaybook(e.target.value)}
                  className="w-full px-3 py-2 bg-bg-primary border border-bg-card rounded-lg text-sm text-text-primary"
                >
                  {playbooks && Object.entries(playbooks.playbooks || {}).map(([pid, pb]: [string, any]) => (
                    <option key={pid} value={pid}>{pb.name}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-xs text-text-secondary block mb-1">Source IP</label>
                <input
                  type="text" value={sourceIp}
                  onChange={e => setSourceIp(e.target.value)}
                  className="w-full px-3 py-2 bg-bg-primary border border-bg-card rounded-lg text-sm text-text-primary font-mono"
                />
              </div>
              <div>
                <label className="text-xs text-text-secondary block mb-1">Target IP</label>
                <input
                  type="text" value={targetIp}
                  onChange={e => setTargetIp(e.target.value)}
                  className="w-full px-3 py-2 bg-bg-primary border border-bg-card rounded-lg text-sm text-text-primary font-mono"
                />
              </div>
              <div>
                <label className="text-xs text-text-secondary block mb-1">Confidence</label>
                <input
                  type="range" min={0.5} max={1.0} step={0.01}
                  value={confidence}
                  onChange={e => setConfidence(parseFloat(e.target.value))}
                  className="w-full accent-accent-orange"
                />
                <div className="text-xs text-center font-mono text-accent-orange">{confidence.toFixed(2)}</div>
              </div>
            </div>

            <button
              onClick={handleSimulate}
              disabled={simulating || !selectedPlaybook}
              className="px-5 py-2.5 bg-accent-orange text-white rounded-lg text-sm font-medium hover:bg-accent-orange/80 transition-colors disabled:opacity-40 flex items-center gap-2"
            >
              {simulating ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> Simulating...</>
              ) : (
                <><Zap className="w-4 h-4" /> Run Simulation</>
              )}
            </button>
          </div>

          {/* Simulation result */}
          {simResult && (
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs bg-accent-orange/15 text-accent-orange px-2 py-0.5 rounded">
                    {simResult.incident_id}
                  </span>
                  <span className="text-sm font-medium">{simResult.playbook_name}</span>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-medium" style={{
                  background: `${SEV_COLORS[simResult.severity]}20`,
                  color: SEV_COLORS[simResult.severity],
                }}>
                  {simResult.severity}
                </span>
              </div>

              {/* Summary */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                <div className="text-center bg-bg-primary rounded-lg p-2">
                  <div className="text-[10px] text-text-secondary">Mode</div>
                  <div className="text-xs font-mono text-accent-amber">{simResult.mode}</div>
                </div>
                <div className="text-center bg-bg-primary rounded-lg p-2">
                  <div className="text-[10px] text-text-secondary">Source</div>
                  <div className="text-xs font-mono">{simResult.source_ip}</div>
                </div>
                <div className="text-center bg-bg-primary rounded-lg p-2">
                  <div className="text-[10px] text-text-secondary">Target</div>
                  <div className="text-xs font-mono">{simResult.target_ip}</div>
                </div>
                <div className="text-center bg-bg-primary rounded-lg p-2">
                  <div className="text-[10px] text-text-secondary">Response Time</div>
                  <div className="text-xs font-mono text-accent-green">{simResult.total_simulated_ms}ms</div>
                </div>
                <div className="text-center bg-bg-primary rounded-lg p-2">
                  <div className="text-[10px] text-text-secondary">Effectiveness</div>
                  <div className="text-xs font-mono text-accent-green">{Math.round(simResult.effectiveness_score * 100)}%</div>
                </div>
              </div>

              {/* Step timeline */}
              <div className="space-y-1.5">
                <h4 className="text-xs font-semibold text-text-secondary">Execution Timeline</h4>
                {simResult.steps?.map((step: any) => (
                  <div key={step.step} className="flex items-center gap-2 text-xs bg-bg-primary rounded-lg px-3 py-2">
                    <div className="w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold shrink-0" style={{
                      background: `${ACTION_COLORS[step.action] || '#334155'}20`,
                      color: ACTION_COLORS[step.action] || '#94A3B8',
                    }}>
                      {step.step}
                    </div>
                    <span className="font-mono px-1.5 py-0.5 rounded text-[10px]" style={{
                      background: `${ACTION_COLORS[step.action] || '#334155'}15`,
                      color: ACTION_COLORS[step.action] || '#94A3B8',
                    }}>
                      {step.action}
                    </span>
                    <span className="text-text-secondary flex-1">{step.description}</span>
                    <span className="font-mono text-accent-green text-[10px]">+{step.simulated_ms}ms</span>
                    <span className="font-mono text-text-secondary text-[10px]">Σ{step.cumulative_ms}ms</span>
                    <CheckCircle className="w-3.5 h-3.5 text-accent-green" />
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {/* ══ INCIDENTS TAB ══ */}
      {tab === 'incidents' && !loading && (
        <>
          {/* Severity summary */}
          {incidents && (
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                <div className="text-text-secondary text-xs mb-1">Total</div>
                <div className="text-xl font-mono font-bold text-text-primary">{incidents.total}</div>
              </div>
              {Object.entries(incidents.by_severity || {}).map(([sev, count]: [string, any]) => (
                <div key={sev} className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                  <div className="text-text-secondary text-xs mb-1 capitalize">{sev}</div>
                  <div className="text-xl font-mono font-bold" style={{ color: SEV_COLORS[sev] }}>{count}</div>
                </div>
              ))}
            </div>
          )}

          {/* Incident list */}
          <div className="space-y-2">
            {incidents?.incidents?.length === 0 && (
              <div className="text-center text-text-secondary text-sm py-8">
                No incidents yet. Run a simulation to generate incident data.
              </div>
            )}
            {incidents?.incidents?.map((inc: any) => (
              <div key={inc.incident_id} className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
                <button
                  onClick={() => setExpandedInc(expandedInc === inc.incident_id ? null : inc.incident_id)}
                  className="w-full px-4 py-3 flex items-center gap-3 hover:bg-bg-card/30 transition-colors"
                >
                  <span className="font-mono text-xs px-2 py-0.5 rounded" style={{
                    background: `${SEV_COLORS[inc.severity]}20`,
                    color: SEV_COLORS[inc.severity],
                  }}>
                    {inc.incident_id}
                  </span>
                  <span className="text-sm font-medium flex-1 text-left">{inc.playbook_name}</span>
                  <span className="text-xs text-text-secondary">{inc.threat_label}</span>
                  <span className="text-xs font-mono text-accent-green">{inc.total_simulated_ms}ms</span>
                  <span className="text-xs text-text-secondary">{inc.mode}</span>
                  {expandedInc === inc.incident_id ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
                {expandedInc === inc.incident_id && (
                  <div className="px-4 pb-4 border-t border-bg-card space-y-3">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mt-3 text-xs">
                      <div className="bg-bg-primary rounded-lg p-2">
                        <span className="text-text-secondary">Source:</span>
                        <span className="font-mono ml-1">{inc.source_ip}</span>
                      </div>
                      <div className="bg-bg-primary rounded-lg p-2">
                        <span className="text-text-secondary">Target:</span>
                        <span className="font-mono ml-1">{inc.target_ip}</span>
                      </div>
                      <div className="bg-bg-primary rounded-lg p-2">
                        <span className="text-text-secondary">Confidence:</span>
                        <span className="font-mono ml-1">{(inc.confidence * 100).toFixed(0)}%</span>
                      </div>
                      <div className="bg-bg-primary rounded-lg p-2">
                        <span className="text-text-secondary">By:</span>
                        <span className="font-mono ml-1 text-[10px]">{inc.triggered_by}</span>
                      </div>
                    </div>

                    {/* Steps */}
                    <div className="space-y-1">
                      {inc.steps?.map((step: any) => (
                        <div key={step.step} className="flex items-center gap-2 text-[10px]">
                          <span className="w-4 text-center font-mono text-text-secondary">{step.step}</span>
                          <span className="font-mono px-1 rounded" style={{
                            background: `${ACTION_COLORS[step.action] || '#334155'}15`,
                            color: ACTION_COLORS[step.action] || '#94A3B8',
                          }}>
                            {step.action}
                          </span>
                          <span className="text-text-secondary flex-1 truncate">{step.description}</span>
                          <CheckCircle className="w-3 h-3 text-accent-green" />
                        </div>
                      ))}
                    </div>

                    {/* Notes */}
                    {inc.notes?.length > 0 && (
                      <div className="space-y-1">
                        <h5 className="text-xs font-semibold text-text-secondary">Analyst Notes</h5>
                        {inc.notes.map((n: any, i: number) => (
                          <div key={i} className="bg-bg-primary rounded p-2 text-xs">
                            <span className="text-accent-blue">{n.author}</span>
                            <span className="text-text-secondary ml-2">{n.note}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Add note */}
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={noteText}
                        onChange={e => setNoteText(e.target.value)}
                        placeholder="Add analyst note..."
                        className="flex-1 px-3 py-1.5 bg-bg-primary border border-bg-card rounded-lg text-xs text-text-primary"
                        onKeyDown={e => e.key === 'Enter' && handleAddNote(inc.incident_id)}
                      />
                      <button
                        onClick={() => handleAddNote(inc.incident_id)}
                        className="px-3 py-1.5 bg-accent-blue text-white rounded-lg text-xs flex items-center gap-1"
                      >
                        <Send className="w-3 h-3" /> Add
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </>
      )}

      {/* ══ INTEGRATIONS TAB ══ */}
      {tab === 'integrations' && !loading && integrations && (
        <>
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="text-text-secondary text-xs mb-1">Total Integrations</div>
              <div className="text-xl font-mono font-bold text-text-primary">{integrations.total}</div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="text-text-secondary text-xs mb-1">Native</div>
              <div className="text-xl font-mono font-bold text-accent-green">{integrations.native}</div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="text-text-secondary text-xs mb-1">Available</div>
              <div className="text-xl font-mono font-bold text-accent-blue">{integrations.available}</div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {Object.entries(integrations.integrations || {}).map(([iid, integ]: [string, any]) => (
              <div key={iid} className="bg-bg-secondary rounded-xl p-4 border border-bg-card space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Link className="w-4 h-4 text-accent-blue" />
                    <span className="text-sm font-medium">{integ.name}</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                    integ.status === 'native' ? 'bg-accent-green/15 text-accent-green' :
                    integ.status === 'configured' ? 'bg-accent-blue/15 text-accent-blue' :
                    'bg-bg-card text-text-secondary'
                  }`}>
                    {integ.status}
                  </span>
                </div>
                <div className="text-xs text-text-secondary">{integ.description}</div>
                <div>
                  <div className="text-[10px] text-text-secondary mb-1">Supported Platforms:</div>
                  <div className="flex flex-wrap gap-1">
                    {integ.supported?.map((s: string) => (
                      <span key={s} className="px-1.5 py-0.5 bg-bg-primary text-text-secondary text-[9px] rounded">
                        {s}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="text-[10px] text-text-secondary">
                  Protocol: <span className="font-mono text-text-primary">{integ.protocol}</span>
                </div>
              </div>
            ))}
          </div>

          {/* Uncovered classes */}
          {metrics?.summary?.coverage?.uncovered_classes?.length > 0 && (
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <h3 className="text-sm font-semibold mb-2 text-accent-amber">Uncovered Threat Classes</h3>
              <div className="flex flex-wrap gap-1">
                {metrics.summary.coverage.uncovered_classes.map((c: string) => (
                  <span key={c} className="px-2 py-0.5 bg-accent-amber/10 text-accent-amber text-[10px] rounded font-mono">
                    {c}
                  </span>
                ))}
              </div>
              <div className="text-xs text-text-secondary mt-2">
                Create playbooks for these threat classes to achieve full coverage.
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
