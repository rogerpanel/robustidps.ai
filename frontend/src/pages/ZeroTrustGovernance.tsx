import { useState, useEffect } from 'react'
import {
  ShieldCheck, ShieldAlert, Shield, Loader2, CheckCircle, XCircle,
  AlertTriangle, Eye, Lock, FileCheck, Users, BarChart3, Activity,
  ChevronDown, ChevronUp, Settings, Globe,
} from 'lucide-react'
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip,
  CartesianGrid, Legend, PieChart, Pie, Cell,
} from 'recharts'
import PageGuide from '../components/PageGuide'
import {
  fetchTrustScore, fetchGovernancePolicies, fetchComplianceDashboard,
  fetchModelProvenance, fetchVerificationStatus, fetchAccessAnalytics,
} from '../utils/api'

const TT = { background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }

const STATUS_COLORS: Record<string, string> = {
  pass: '#22C55E', warning: '#F59E0B', fail: '#EF4444',
  implemented: '#22C55E', partial: '#F59E0B', not_implemented: '#EF4444',
}

const TRUST_COLORS: Record<string, string> = {
  high: '#22C55E', medium: '#F59E0B', low: '#F97316', critical: '#EF4444',
}

const SEV_COLORS: Record<string, string> = {
  critical: '#EF4444', high: '#F97316', medium: '#F59E0B', low: '#3B82F6',
}

type Tab = 'trust' | 'policies' | 'compliance' | 'provenance'

export default function ZeroTrustGovernance() {
  const [tab, setTab] = useState<Tab>('trust')
  const [trustScore, setTrustScore] = useState<any>(null)
  const [policies, setPolicies] = useState<any>(null)
  const [compliance, setCompliance] = useState<any>(null)
  const [provenance, setProvenance] = useState<any>(null)
  const [verification, setVerification] = useState<any>(null)
  const [accessAnalytics, setAccessAnalytics] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [expandedFramework, setExpandedFramework] = useState<string | null>(null)

  useEffect(() => {
    setLoading(true)
    Promise.all([
      fetchTrustScore().catch(() => null),
      fetchGovernancePolicies().catch(() => null),
      fetchComplianceDashboard().catch(() => null),
      fetchModelProvenance().catch(() => null),
      fetchVerificationStatus().catch(() => null),
      fetchAccessAnalytics().catch(() => null),
    ]).then(([ts, pol, comp, prov, ver, aa]) => {
      setTrustScore(ts)
      setPolicies(pol)
      setCompliance(comp)
      setProvenance(prov)
      setVerification(ver)
      setAccessAnalytics(aa)
      setLoading(false)
    })
  }, [])

  const TABS: { id: Tab; label: string }[] = [
    { id: 'trust', label: 'Trust Score & Verification' },
    { id: 'policies', label: 'Governance Policies' },
    { id: 'compliance', label: 'Compliance Frameworks' },
    { id: 'provenance', label: 'Model Provenance' },
  ]

  // Trust radar data
  const trustRadarData = trustScore?.details?.map((d: any) => ({
    factor: d.factor.replace(' Strength', '').replace(' Security', ''),
    score: d.score,
    max: d.max,
    percentage: Math.round(d.score / d.max * 100),
  })) || []

  // Compliance pie data
  const compliancePieData = compliance ? Object.entries(compliance.frameworks || {}).map(([id, fw]: [string, any]) => ({
    name: fw.name.split(' ').slice(0, 2).join(' '),
    value: fw.compliance_percentage,
    fill: fw.compliance_percentage >= 80 ? '#22C55E' : fw.compliance_percentage >= 60 ? '#F59E0B' : '#EF4444',
  })) : []

  // Access analytics chart data
  const hourlyData = accessAnalytics?.hourly_activity?.map((h: any) => ({
    hour: h.hour,
    actions: h.count,
  })) || []

  return (
    <div className="space-y-6">
      <PageGuide
        title="How to use Zero-Trust AI Governance"
        steps={[
          { title: 'Check trust score', desc: 'View your current Zero-Trust posture across 5 security dimensions.' },
          { title: 'Review policies', desc: 'Manage governance policies for model drift, data handling, and access control.' },
          { title: 'Audit compliance', desc: 'Track compliance across NIST AI RMF, EU AI Act, ISO 27001, and ISO 42001.' },
          { title: 'Verify provenance', desc: 'Check model weight integrity and signing status.' },
        ]}
        tip="Zero-Trust means never trust, always verify — every access request is authenticated, authorized, and continuously validated."
      />

      {/* Header */}
      <div className="flex items-center gap-3">
        <ShieldCheck className="w-7 h-7 text-accent-green" />
        <div>
          <h1 className="text-xl md:text-2xl font-display font-bold">Zero-Trust AI Governance</h1>
          <p className="text-sm text-text-secondary mt-0.5">Continuous verification, policy enforcement & compliance monitoring</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-bg-secondary rounded-lg p-1 border border-bg-card">
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex-1 px-3 py-2 rounded-md text-xs font-medium transition-colors ${
              tab === t.id ? 'bg-accent-green/15 text-accent-green' : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {loading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 animate-spin text-accent-green" />
          <span className="ml-2 text-text-secondary text-sm">Loading governance data...</span>
        </div>
      )}

      {/* ══ TRUST SCORE TAB ══ */}
      {tab === 'trust' && !loading && (
        <>
          {trustScore && (
            <>
              {/* Trust score hero */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-bg-secondary rounded-xl p-6 border border-bg-card text-center">
                  <div className="text-text-secondary text-xs mb-2">Zero-Trust Score</div>
                  <div className="text-5xl font-mono font-bold" style={{ color: TRUST_COLORS[trustScore.trust_level] }}>
                    {trustScore.trust_score}
                  </div>
                  <div className="text-sm mt-1" style={{ color: TRUST_COLORS[trustScore.trust_level] }}>
                    / {trustScore.max_score}
                  </div>
                  <div className="mt-2 px-3 py-1 rounded-full text-xs font-medium inline-block" style={{
                    background: `${TRUST_COLORS[trustScore.trust_level]}20`,
                    color: TRUST_COLORS[trustScore.trust_level],
                  }}>
                    {trustScore.trust_label}
                  </div>
                </div>

                {/* Radar chart */}
                <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card col-span-2">
                  <h3 className="text-sm font-semibold mb-2">Trust Breakdown</h3>
                  <ResponsiveContainer width="100%" height={250}>
                    <RadarChart data={trustRadarData}>
                      <PolarGrid stroke="#334155" />
                      <PolarAngleAxis dataKey="factor" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                      <PolarRadiusAxis domain={[0, 100]} tick={{ fill: '#94A3B8', fontSize: 9 }} />
                      <Radar name="Score %" dataKey="percentage" stroke="#22C55E" fill="#22C55E" fillOpacity={0.2} />
                    </RadarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Trust factor details */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {trustScore.details?.map((d: any) => (
                  <div key={d.factor} className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">{d.factor}</span>
                      <span className="font-mono text-sm font-bold" style={{
                        color: d.score / d.max >= 0.8 ? '#22C55E' : d.score / d.max >= 0.6 ? '#F59E0B' : '#EF4444',
                      }}>
                        {d.score}/{d.max}
                      </span>
                    </div>
                    <div className="text-xs text-text-secondary">{d.reason}</div>
                    <div className="mt-2 h-1.5 bg-bg-primary rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all"
                        style={{
                          width: `${d.score / d.max * 100}%`,
                          background: d.score / d.max >= 0.8 ? '#22C55E' : d.score / d.max >= 0.6 ? '#F59E0B' : '#EF4444',
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}

          {/* Continuous verification checks */}
          {verification && (
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold">Continuous Verification Checks</h3>
                <span className="px-2 py-0.5 rounded text-xs font-medium" style={{
                  background: `${STATUS_COLORS[verification.overall_status]}20`,
                  color: STATUS_COLORS[verification.overall_status],
                }}>
                  {verification.summary.passed}/{verification.summary.total} passed
                </span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
                {verification.checks?.map((check: any) => (
                  <div key={check.check} className="bg-bg-primary rounded-lg p-3 flex items-start gap-2">
                    {check.status === 'pass' ? <CheckCircle className="w-4 h-4 text-accent-green shrink-0" /> :
                     check.status === 'warning' ? <AlertTriangle className="w-4 h-4 text-accent-amber shrink-0" /> :
                     <XCircle className="w-4 h-4 text-accent-red shrink-0" />}
                    <div>
                      <div className="text-xs font-medium">{check.check}</div>
                      <div className="text-[10px] text-text-secondary mt-0.5">{check.details}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Access analytics */}
          {accessAnalytics && hourlyData.length > 0 && (
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold">Access Activity (24h)</h3>
                <span className="text-xs text-text-secondary">{accessAnalytics.total_actions} total actions</span>
              </div>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={hourlyData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="hour" tick={{ fill: '#94A3B8', fontSize: 9 }} />
                  <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} />
                  <Tooltip contentStyle={TT} />
                  <Bar dataKey="actions" fill="#3B82F6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>

              {/* Anomalies */}
              {accessAnalytics.anomaly_count > 0 && (
                <div className="mt-3 space-y-2">
                  <h4 className="text-xs font-semibold text-accent-red">Anomalies Detected</h4>
                  {accessAnalytics.anomalies.map((a: any, i: number) => (
                    <div key={i} className="px-3 py-2 bg-accent-red/10 border border-accent-red/20 rounded-lg text-xs text-accent-red">
                      {a.message}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* ══ POLICIES TAB ══ */}
      {tab === 'policies' && !loading && policies && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Settings className="w-3.5 h-3.5" /> Total Policies
              </div>
              <div className="text-xl font-mono font-bold text-text-primary">
                {policies.total_policies}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Shield className="w-3.5 h-3.5" /> Categories
              </div>
              <div className="text-xl font-mono font-bold text-accent-blue">
                {policies.categories?.length || 0}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <AlertTriangle className="w-3.5 h-3.5" /> Critical
              </div>
              <div className="text-xl font-mono font-bold text-accent-red">
                {Object.values(policies.policies || {}).filter((p: any) => p.severity === 'critical').length}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Globe className="w-3.5 h-3.5" /> Frameworks
              </div>
              <div className="text-xl font-mono font-bold text-accent-green">
                {new Set(Object.values(policies.policies || {}).flatMap((p: any) => p.frameworks || [])).size}
              </div>
            </div>
          </div>

          {/* Policies by category */}
          {policies.by_category && Object.entries(policies.by_category).map(([cat, pols]: [string, any]) => (
            <div key={cat} className="space-y-2">
              <h3 className="text-sm font-semibold text-text-secondary">{cat}</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {pols.map((p: any) => (
                  <div key={p.id} className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-mono bg-bg-card px-1.5 py-0.5 rounded">{p.id}</span>
                        <span className="text-sm font-medium">{p.name}</span>
                      </div>
                      <span className="px-2 py-0.5 rounded text-[10px] font-medium" style={{
                        background: `${SEV_COLORS[p.severity]}20`,
                        color: SEV_COLORS[p.severity],
                      }}>
                        {p.severity}
                      </span>
                    </div>
                    <div className="text-xs text-text-secondary mb-2">{p.description}</div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-text-secondary">
                        Current: <span className="font-mono text-text-primary">
                          {typeof p.current_value === 'boolean' ? (p.current_value ? 'Enabled' : 'Disabled') : p.current_value} {p.unit !== 'boolean' ? p.unit : ''}
                        </span>
                      </span>
                      <span className="text-accent-blue text-[10px]">{p.enforcement}</span>
                    </div>
                    <div className="flex flex-wrap gap-1 mt-2">
                      {p.frameworks?.map((f: string) => (
                        <span key={f} className="px-1.5 py-0.5 bg-accent-blue/10 text-accent-blue text-[9px] rounded">
                          {f}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </>
      )}

      {/* ══ COMPLIANCE TAB ══ */}
      {tab === 'compliance' && !loading && compliance && (
        <>
          {/* Overall compliance */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-bg-secondary rounded-xl p-6 border border-bg-card text-center">
              <div className="text-text-secondary text-xs mb-2">Overall Compliance</div>
              <div className={`text-5xl font-mono font-bold ${
                compliance.overall_compliance >= 80 ? 'text-accent-green' :
                compliance.overall_compliance >= 60 ? 'text-accent-amber' : 'text-accent-red'
              }`}>
                {compliance.overall_compliance}%
              </div>
              <div className="text-xs text-text-secondary mt-1">
                across {compliance.total_frameworks} frameworks
              </div>
            </div>

            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card col-span-2">
              <h3 className="text-sm font-semibold mb-3">Framework Compliance</h3>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={Object.entries(compliance.frameworks || {}).map(([id, fw]: [string, any]) => ({
                  name: fw.name.split(' ').slice(0, 2).join(' '),
                  compliance: fw.compliance_percentage,
                  implemented: fw.controls_implemented,
                  partial: fw.controls_partial,
                }))} barGap={4}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="name" tick={{ fill: '#94A3B8', fontSize: 9 }} />
                  <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" domain={[0, 100]} />
                  <Tooltip contentStyle={TT} />
                  <Bar dataKey="compliance" radius={[4, 4, 0, 0]}>
                    {Object.entries(compliance.frameworks || {}).map(([id, fw]: [string, any], i: number) => (
                      <Cell key={i} fill={fw.compliance_percentage >= 80 ? '#22C55E' : fw.compliance_percentage >= 60 ? '#F59E0B' : '#EF4444'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Framework details */}
          <div className="space-y-3">
            {Object.entries(compliance.frameworks || {}).map(([fid, fw]: [string, any]) => (
              <div key={fid} className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
                <button
                  onClick={() => setExpandedFramework(expandedFramework === fid ? null : fid)}
                  className="w-full px-4 py-3 flex items-center gap-3 hover:bg-bg-card/30 transition-colors"
                >
                  <Shield className="w-4 h-4 text-accent-blue" />
                  <span className="text-sm font-medium flex-1 text-left">{fw.name}</span>
                  <span className="text-xs text-text-secondary">v{fw.version}</span>
                  <span className={`text-xs font-mono font-bold ${
                    fw.compliance_percentage >= 80 ? 'text-accent-green' :
                    fw.compliance_percentage >= 60 ? 'text-accent-amber' : 'text-accent-red'
                  }`}>
                    {fw.compliance_percentage}%
                  </span>
                  <span className="text-xs text-text-secondary">
                    {fw.controls_implemented}/{fw.controls_total}
                  </span>
                  {expandedFramework === fid ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
                {expandedFramework === fid && (
                  <div className="px-4 pb-4 border-t border-bg-card">
                    {fw.risk_classification && (
                      <div className="mt-2 px-3 py-1.5 bg-accent-amber/10 border border-accent-amber/20 rounded-lg text-xs text-accent-amber mb-3">
                        Classification: {fw.risk_classification}
                      </div>
                    )}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-3">
                      {fw.controls?.map((ctrl: any) => (
                        <div key={ctrl.id} className="bg-bg-primary rounded-lg p-3 flex items-start gap-2">
                          {ctrl.status === 'implemented' ? <CheckCircle className="w-4 h-4 text-accent-green shrink-0" /> :
                           ctrl.status === 'partial' ? <AlertTriangle className="w-4 h-4 text-accent-amber shrink-0" /> :
                           <XCircle className="w-4 h-4 text-accent-red shrink-0" />}
                          <div>
                            <div className="text-xs font-medium">
                              <span className="font-mono text-text-secondary mr-1">{ctrl.id}</span>
                              {ctrl.name}
                            </div>
                            <div className="text-[10px] text-text-secondary mt-0.5">{ctrl.evidence}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </>
      )}

      {/* ══ PROVENANCE TAB ══ */}
      {tab === 'provenance' && !loading && provenance && (
        <>
          {/* Summary */}
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <FileCheck className="w-3.5 h-3.5" /> Models
              </div>
              <div className="text-xl font-mono font-bold text-text-primary">
                {provenance.total_models}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <CheckCircle className="w-3.5 h-3.5" /> Verified
              </div>
              <div className="text-xl font-mono font-bold text-accent-green">
                {provenance.verified_count}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Lock className="w-3.5 h-3.5" /> Signed
              </div>
              <div className="text-xl font-mono font-bold text-accent-amber">
                {provenance.signed_count}
              </div>
            </div>
          </div>

          {/* Model provenance cards */}
          <div className="space-y-3">
            {provenance.models?.map((m: any) => (
              <div key={m.model_id} className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{m.name}</span>
                    <span className="px-1.5 py-0.5 bg-accent-blue/15 text-accent-blue text-[10px] rounded">
                      {m.category}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    {m.integrity_verified ? (
                      <span className="flex items-center gap-1 text-[10px] text-accent-green">
                        <CheckCircle className="w-3 h-3" /> Verified
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-[10px] text-accent-red">
                        <XCircle className="w-3 h-3" /> Unverified
                      </span>
                    )}
                    <span className="flex items-center gap-1 text-[10px] text-accent-amber">
                      <Lock className="w-3 h-3" /> {m.signing_status}
                    </span>
                  </div>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs text-text-secondary">
                  <div>
                    <span className="text-[10px]">Weight File:</span>
                    <div className="font-mono text-text-primary text-[10px]">{m.weight_file}</div>
                  </div>
                  <div>
                    <span className="text-[10px]">Size:</span>
                    <div className="font-mono text-text-primary text-[10px]">
                      {m.weight_size_bytes ? `${(m.weight_size_bytes / 1024).toFixed(1)} KB` : 'N/A'}
                    </div>
                  </div>
                  <div>
                    <span className="text-[10px]">Features/Classes:</span>
                    <div className="font-mono text-text-primary text-[10px]">{m.features_in} → {m.classes_out}</div>
                  </div>
                  <div>
                    <span className="text-[10px]">Recommendation:</span>
                    <div className="text-accent-blue text-[10px]">{m.signing_recommendation}</div>
                  </div>
                </div>
                {m.weight_sha256 && (
                  <div className="mt-2 text-[9px] font-mono text-text-secondary bg-bg-primary rounded p-1.5 break-all">
                    SHA-256: {m.weight_sha256}
                  </div>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
