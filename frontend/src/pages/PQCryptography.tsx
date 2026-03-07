import { useState, useEffect } from 'react'
import {
  Lock, Shield, Loader2, AlertTriangle, CheckCircle, XCircle,
  Zap, Key, ArrowRight, TrendingUp, BarChart3, ChevronDown, ChevronUp,
  Clock, Server,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid, Legend, RadarChart, Radar, PolarGrid,
  PolarAngleAxis, PolarRadiusAxis, Cell, ScatterChart, Scatter,
  ZAxis,
} from 'recharts'
import PageGuide from '../components/PageGuide'
import {
  fetchPqAlgorithms, benchmarkPqAlgorithm, fetchPqRiskAssessment,
  simulatePqHandshake, fetchPqComparisonMatrix, fetchPqMigrationAssessment,
} from '../utils/api'

const TT = { background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }

const NIST_COLORS: Record<number, string> = {
  1: '#3B82F6', 2: '#22C55E', 3: '#F59E0B', 4: '#F97316', 5: '#EF4444',
}

const RISK_COLORS: Record<string, string> = {
  low: '#22C55E', medium: '#F59E0B', high: '#EF4444', critical: '#DC2626',
}

type Tab = 'overview' | 'benchmark' | 'risk' | 'migration'

export default function PQCryptography() {
  const [tab, setTab] = useState<Tab>('overview')
  const [algorithms, setAlgorithms] = useState<any>(null)
  const [comparison, setComparison] = useState<any>(null)
  const [risk, setRisk] = useState<any>(null)
  const [migration, setMigration] = useState<any>(null)
  const [benchResult, setBenchResult] = useState<any>(null)
  const [handshakeResult, setHandshakeResult] = useState<any>(null)
  const [selectedAlgo, setSelectedAlgo] = useState('kyber768')
  const [benchIterations, setBenchIterations] = useState(100)
  const [loading, setLoading] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [expandedStep, setExpandedStep] = useState<number | null>(null)

  useEffect(() => {
    Promise.all([
      fetchPqAlgorithms().catch(() => null),
      fetchPqComparisonMatrix().catch(() => null),
      fetchPqRiskAssessment().catch(() => null),
      fetchPqMigrationAssessment().catch(() => null),
    ]).then(([algos, comp, rsk, mig]) => {
      setAlgorithms(algos)
      setComparison(comp)
      setRisk(rsk)
      setMigration(mig)
    })
  }, [])

  const runBenchmark = async () => {
    setLoading('benchmark')
    setError('')
    try {
      const data = await benchmarkPqAlgorithm(selectedAlgo, benchIterations)
      setBenchResult(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Benchmark failed')
    } finally {
      setLoading(null)
    }
  }

  const runHandshake = async () => {
    setLoading('handshake')
    setError('')
    try {
      const data = await simulatePqHandshake(selectedAlgo)
      setHandshakeResult(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Simulation failed')
    } finally {
      setLoading(null)
    }
  }

  const TABS: { id: Tab; label: string }[] = [
    { id: 'overview', label: 'Algorithm Catalogue' },
    { id: 'benchmark', label: 'Benchmark & Simulate' },
    { id: 'risk', label: 'Quantum Risk Assessment' },
    { id: 'migration', label: 'Migration Readiness' },
  ]

  // Chart data from comparison matrix
  const kemSizeData = comparison?.kem_comparison?.map((k: any) => ({
    name: k.name.split('-').pop() || k.name,
    'Public Key': k.pk_bytes,
    'Ciphertext': k.ct_bytes,
    level: k.nist_level,
  })) || []

  const kemSpeedData = comparison?.kem_comparison?.map((k: any) => ({
    name: k.name.split('-').pop() || k.name,
    'KeyGen': k.keygen_us,
    'Encaps': k.encaps_us,
    'Decaps': k.decaps_us,
    level: k.nist_level,
  })) || []

  const sigSizeData = comparison?.signature_comparison?.map((s: any) => ({
    name: s.name.replace('CRYSTALS-', '').replace('SPHINCS+-', 'SPHINCS+ '),
    'Signature': s.sig_bytes,
    'Public Key': s.pk_bytes,
    level: s.nist_level,
  })) || []

  return (
    <div className="space-y-6">
      <PageGuide
        title="How to use PQ Cryptography Dashboard"
        steps={[
          { title: 'Explore algorithms', desc: 'Browse NIST-standardised post-quantum KEMs and signature schemes.' },
          { title: 'Benchmark performance', desc: 'Run latency benchmarks for any PQ algorithm.' },
          { title: 'Assess risk', desc: 'Evaluate your system\'s quantum vulnerability.' },
          { title: 'Plan migration', desc: 'Get a phased PQ migration roadmap with recommended algorithms.' },
        ]}
        tip="Post-quantum cryptography protects IDS communications against future quantum computer attacks. Start with hybrid deployment."
      />

      {/* Header */}
      <div className="flex items-center gap-3">
        <Lock className="w-7 h-7 text-accent-purple" />
        <div>
          <h1 className="text-xl md:text-2xl font-display font-bold">Post-Quantum Cryptography</h1>
          <p className="text-sm text-text-secondary mt-0.5">NIST FIPS 203/204/205 algorithm dashboard & migration planner</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-bg-secondary rounded-lg p-1 border border-bg-card">
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex-1 px-3 py-2 rounded-md text-xs font-medium transition-colors ${
              tab === t.id ? 'bg-accent-purple/15 text-accent-purple' : 'text-text-secondary hover:text-text-primary'
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

      {/* ══ OVERVIEW TAB ══ */}
      {tab === 'overview' && (
        <>
          {/* Summary cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Key className="w-3.5 h-3.5" /> PQ Algorithms
              </div>
              <div className="text-xl font-mono font-bold text-accent-purple">
                {algorithms?.total_pq || '—'}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Shield className="w-3.5 h-3.5" /> KEMs
              </div>
              <div className="text-xl font-mono font-bold text-accent-blue">
                {algorithms ? Object.keys(algorithms.kem_algorithms || {}).length : '—'}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <Lock className="w-3.5 h-3.5" /> Signatures
              </div>
              <div className="text-xl font-mono font-bold text-accent-green">
                {algorithms ? Object.keys(algorithms.signature_algorithms || {}).length : '—'}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
                <AlertTriangle className="w-3.5 h-3.5" /> Classical (Vulnerable)
              </div>
              <div className="text-xl font-mono font-bold text-accent-red">
                {algorithms?.total_classical || '—'}
              </div>
            </div>
          </div>

          {/* Charts */}
          {comparison && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                <h3 className="text-sm font-semibold mb-3">KEM Key Sizes (bytes)</h3>
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart data={kemSizeData} barGap={4}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis dataKey="name" tick={{ fill: '#94A3B8', fontSize: 9 }} />
                    <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} />
                    <Tooltip contentStyle={TT} />
                    <Bar dataKey="Public Key" fill="#A855F7" radius={[4, 4, 0, 0]} />
                    <Bar dataKey="Ciphertext" fill="#3B82F6" radius={[4, 4, 0, 0]} />
                    <Legend wrapperStyle={{ fontSize: 11, color: '#94A3B8' }} />
                  </BarChart>
                </ResponsiveContainer>
              </div>

              <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
                <h3 className="text-sm font-semibold mb-3">Signature Sizes (bytes)</h3>
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart data={sigSizeData} barGap={4}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis dataKey="name" tick={{ fill: '#94A3B8', fontSize: 8 }} angle={-15} />
                    <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} />
                    <Tooltip contentStyle={TT} />
                    <Bar dataKey="Signature" fill="#F59E0B" radius={[4, 4, 0, 0]} />
                    <Bar dataKey="Public Key" fill="#22C55E" radius={[4, 4, 0, 0]} />
                    <Legend wrapperStyle={{ fontSize: 11, color: '#94A3B8' }} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* Algorithm cards */}
          {algorithms && (
            <div className="space-y-4">
              <h3 className="text-sm font-semibold text-text-secondary">Key Encapsulation Mechanisms (KEMs)</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {Object.entries(algorithms.kem_algorithms || {}).map(([id, algo]: [string, any]) => (
                  <div key={id} className="bg-bg-secondary rounded-xl p-4 border border-bg-card space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-sm">{algo.name}</span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold" style={{
                        background: `${NIST_COLORS[algo.nist_level]}20`,
                        color: NIST_COLORS[algo.nist_level],
                      }}>
                        NIST L{algo.nist_level}
                      </span>
                    </div>
                    <div className="text-[10px] text-accent-green">{algo.status}</div>
                    <div className="text-xs text-text-secondary">{algo.description}</div>
                    <div className="grid grid-cols-3 gap-1 text-[10px]">
                      <div className="bg-bg-primary rounded p-1.5 text-center">
                        <div className="text-text-secondary">PK</div>
                        <div className="font-mono">{algo.pk_bytes}B</div>
                      </div>
                      <div className="bg-bg-primary rounded p-1.5 text-center">
                        <div className="text-text-secondary">CT</div>
                        <div className="font-mono">{algo.ct_bytes}B</div>
                      </div>
                      <div className="bg-bg-primary rounded p-1.5 text-center">
                        <div className="text-text-secondary">Speed</div>
                        <div className="font-mono">{algo.encaps_us}μs</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              <h3 className="text-sm font-semibold text-text-secondary">Digital Signature Schemes</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {Object.entries(algorithms.signature_algorithms || {}).map(([id, algo]: [string, any]) => (
                  <div key={id} className="bg-bg-secondary rounded-xl p-4 border border-bg-card space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-sm">{algo.name}</span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold" style={{
                        background: `${NIST_COLORS[algo.nist_level]}20`,
                        color: NIST_COLORS[algo.nist_level],
                      }}>
                        NIST L{algo.nist_level}
                      </span>
                    </div>
                    <div className="text-[10px] text-accent-green">{algo.status}</div>
                    <div className="text-xs text-text-secondary">{algo.description}</div>
                    <div className="grid grid-cols-3 gap-1 text-[10px]">
                      <div className="bg-bg-primary rounded p-1.5 text-center">
                        <div className="text-text-secondary">PK</div>
                        <div className="font-mono">{algo.pk_bytes}B</div>
                      </div>
                      <div className="bg-bg-primary rounded p-1.5 text-center">
                        <div className="text-text-secondary">Sig</div>
                        <div className="font-mono">{algo.sig_bytes}B</div>
                      </div>
                      <div className="bg-bg-primary rounded p-1.5 text-center">
                        <div className="text-text-secondary">Verify</div>
                        <div className="font-mono">{algo.verify_us}μs</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {/* ══ BENCHMARK TAB ══ */}
      {tab === 'benchmark' && (
        <>
          <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="text-xs text-text-secondary block mb-1">Algorithm</label>
                <select
                  value={selectedAlgo}
                  onChange={e => setSelectedAlgo(e.target.value)}
                  className="w-full px-3 py-2 bg-bg-primary border border-bg-card rounded-lg text-sm text-text-primary"
                >
                  {algorithms && Object.entries({...algorithms.kem_algorithms, ...algorithms.signature_algorithms}).map(([id, algo]: [string, any]) => (
                    <option key={id} value={id}>{algo.name} ({algo.type})</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-xs text-text-secondary block mb-1">Iterations</label>
                <input
                  type="number" min={10} max={10000} value={benchIterations}
                  onChange={e => setBenchIterations(parseInt(e.target.value) || 100)}
                  className="w-full px-3 py-2 bg-bg-primary border border-bg-card rounded-lg text-sm text-text-primary"
                />
              </div>
              <div className="flex items-end gap-2">
                <button
                  onClick={runBenchmark}
                  disabled={loading === 'benchmark'}
                  className="px-4 py-2 bg-accent-purple text-white rounded-lg text-sm font-medium hover:bg-accent-purple/80 transition-colors disabled:opacity-40 flex items-center gap-2"
                >
                  {loading === 'benchmark' ? <Loader2 className="w-4 h-4 animate-spin" /> : <BarChart3 className="w-4 h-4" />}
                  Benchmark
                </button>
                <button
                  onClick={runHandshake}
                  disabled={loading === 'handshake'}
                  className="px-4 py-2 bg-accent-blue text-white rounded-lg text-sm font-medium hover:bg-accent-blue/80 transition-colors disabled:opacity-40 flex items-center gap-2"
                >
                  {loading === 'handshake' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                  Simulate Handshake
                </button>
              </div>
            </div>
          </div>

          {/* Benchmark results */}
          {benchResult && (
            <>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {Object.entries(benchResult.benchmark).filter(([k]) => k !== 'total_handshake_us').map(([key, val]: [string, any]) => (
                  <div key={key} className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                    <div className="text-text-secondary text-xs mb-1 capitalize">
                      {key.replace(/_us$/, '').replace(/_/g, ' ')}
                    </div>
                    <div className="text-lg font-mono font-bold text-accent-purple">
                      {val.mean}μs
                    </div>
                    <div className="text-[10px] text-text-secondary mt-1">
                      p50: {val.p50}μs · p99: {val.p99}μs
                    </div>
                  </div>
                ))}
                <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                  <div className="text-text-secondary text-xs mb-1">Total Handshake</div>
                  <div className="text-lg font-mono font-bold text-accent-green">
                    {benchResult.benchmark.total_handshake_us}μs
                  </div>
                </div>
              </div>

              {/* Key material info */}
              <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                <h3 className="text-sm font-semibold mb-2">Key Material</h3>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-text-secondary">Public Key Size:</span>
                    <span className="font-mono ml-2">{benchResult.key_material_sample.pk_size_bytes} bytes</span>
                  </div>
                  <div>
                    <span className="text-text-secondary">Secret Key Size:</span>
                    <span className="font-mono ml-2">{benchResult.key_material_sample.sk_size_bytes} bytes</span>
                  </div>
                  <div className="col-span-2">
                    <span className="text-text-secondary">PK Hex (prefix):</span>
                    <div className="font-mono text-[10px] text-accent-purple/80 break-all mt-1 bg-bg-primary rounded p-2">
                      {benchResult.key_material_sample.public_key_hex_prefix}
                    </div>
                  </div>
                </div>
              </div>
            </>
          )}

          {/* Handshake simulation */}
          {handshakeResult && (
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card space-y-4">
              <h3 className="text-sm font-semibold">Handshake Simulation — {handshakeResult.algorithm_info.name}</h3>

              {/* Steps timeline */}
              <div className="space-y-2">
                {handshakeResult.steps.map((step: any) => (
                  <div key={step.step} className="flex items-start gap-3">
                    <div className="w-6 h-6 rounded-full bg-accent-blue/15 text-accent-blue flex items-center justify-center text-xs font-bold shrink-0 mt-0.5">
                      {step.step}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium">{step.name}</span>
                        <span className="text-xs font-mono text-accent-purple">{step.simulated_time_us}μs</span>
                      </div>
                      <div className="text-xs text-text-secondary">{step.description}</div>
                      {step.wire_overhead_vs_x25519 && (
                        <div className="text-[10px] text-accent-amber mt-0.5">Wire overhead: {step.wire_overhead_vs_x25519}</div>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              {/* Comparison vs classical */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-3 border-t border-bg-card">
                <div className="text-center">
                  <div className="text-xs text-text-secondary">Compute Overhead</div>
                  <div className="text-sm font-mono font-bold text-accent-amber">
                    +{handshakeResult.comparison_vs_x25519.compute_overhead_percent}%
                  </div>
                </div>
                <div className="text-center">
                  <div className="text-xs text-text-secondary">Wire Overhead</div>
                  <div className="text-sm font-mono font-bold text-accent-amber">
                    +{handshakeResult.comparison_vs_x25519.wire_overhead_bytes}B
                  </div>
                </div>
                <div className="text-center">
                  <div className="text-xs text-text-secondary">Quantum Security</div>
                  <div className="text-sm font-mono font-bold text-accent-green">
                    {handshakeResult.security_gain.quantum_bits}-bit
                  </div>
                </div>
                <div className="text-center">
                  <div className="text-xs text-text-secondary">NIST Level</div>
                  <div className="text-sm font-mono font-bold text-accent-blue">
                    Level {handshakeResult.security_gain.nist_level}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* KEM speed comparison chart */}
          {comparison && kemSpeedData.length > 0 && (
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h3 className="text-sm font-semibold mb-3">KEM Operation Latency (μs)</h3>
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={kemSpeedData} barGap={4}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="name" tick={{ fill: '#94A3B8', fontSize: 9 }} />
                  <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} unit="μs" />
                  <Tooltip contentStyle={TT} />
                  <Bar dataKey="KeyGen" fill="#A855F7" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="Encaps" fill="#3B82F6" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="Decaps" fill="#22C55E" radius={[4, 4, 0, 0]} />
                  <Legend wrapperStyle={{ fontSize: 11, color: '#94A3B8' }} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </>
      )}

      {/* ══ RISK TAB ══ */}
      {tab === 'risk' && risk && (
        <>
          {/* Overall risk */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card col-span-1">
              <div className="text-center">
                <div className="text-text-secondary text-xs mb-2">Overall Quantum Risk</div>
                <div className="text-4xl font-mono font-bold" style={{ color: RISK_COLORS[risk.overall_risk_level] }}>
                  {risk.overall_risk_score}
                </div>
                <div className="text-sm font-medium mt-1 capitalize" style={{ color: RISK_COLORS[risk.overall_risk_level] }}>
                  {risk.overall_risk_level}
                </div>
                <div className="text-xs text-text-secondary mt-2">{risk.overall_message}</div>
              </div>
            </div>

            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card col-span-2">
              <h3 className="text-sm font-semibold mb-3">Quantum Timeline</h3>
              <div className="space-y-2">
                {Object.entries(risk.quantum_timeline).map(([key, val]: [string, any]) => (
                  <div key={key} className="flex items-start gap-2 text-xs">
                    <Clock className="w-3.5 h-3.5 text-accent-blue shrink-0 mt-0.5" />
                    <span className="text-text-secondary capitalize">{key.replace(/_/g, ' ')}:</span>
                    <span className="text-text-primary">{val}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Component risk breakdown */}
          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-text-secondary">Component Risk Assessment</h3>
            {risk.migration_priority?.map((comp: any) => (
              <div key={comp.component} className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    {comp.quantum_risk === 'high' ? <XCircle className="w-4 h-4 text-accent-red" /> :
                     comp.quantum_risk === 'medium' ? <AlertTriangle className="w-4 h-4 text-accent-amber" /> :
                     <CheckCircle className="w-4 h-4 text-accent-green" />}
                    <span className="text-sm font-medium capitalize">{comp.component.replace(/_/g, ' ')}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-medium capitalize" style={{
                      background: `${RISK_COLORS[comp.quantum_risk]}20`,
                      color: RISK_COLORS[comp.quantum_risk],
                    }}>
                      {comp.quantum_risk} risk
                    </span>
                    <span className="font-mono text-sm font-bold" style={{ color: RISK_COLORS[comp.quantum_risk] }}>
                      {comp.risk_score}/100
                    </span>
                  </div>
                </div>
                <div className="text-xs text-text-secondary mb-1">
                  <span className="font-medium">Current:</span> {comp.current}
                </div>
                <div className="text-xs text-text-secondary mb-1">{comp.explanation}</div>
                <div className="text-xs text-accent-blue mt-2">
                  <span className="font-medium">Recommendation:</span> {comp.recommendation}
                </div>
                {/* Risk bar */}
                <div className="mt-2 h-1.5 bg-bg-primary rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all"
                    style={{
                      width: `${comp.risk_score}%`,
                      background: RISK_COLORS[comp.quantum_risk],
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {/* ══ MIGRATION TAB ══ */}
      {tab === 'migration' && migration && (
        <>
          {/* Readiness score */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="text-text-secondary text-xs mb-1">Readiness Score</div>
              <div className={`text-2xl font-mono font-bold ${
                migration.readiness_score >= 70 ? 'text-accent-green' :
                migration.readiness_score >= 40 ? 'text-accent-amber' : 'text-accent-red'
              }`}>
                {migration.readiness_score}/100
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="text-text-secondary text-xs mb-1">Target NIST Level</div>
              <div className="text-2xl font-mono font-bold text-accent-purple">
                Level {migration.target_nist_level}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="text-text-secondary text-xs mb-1">Recommended KEM</div>
              <div className="text-sm font-mono font-bold text-accent-blue truncate">
                {migration.recommended_algorithms?.kem_info?.name || '—'}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="text-text-secondary text-xs mb-1">Recommended Sig</div>
              <div className="text-sm font-mono font-bold text-accent-green truncate">
                {migration.recommended_algorithms?.signature_info?.name || '—'}
              </div>
            </div>
          </div>

          {/* Migration phases */}
          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-text-secondary">Migration Phases</h3>
            {migration.migration_phases?.map((phase: any) => (
              <div key={phase.phase} className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
                <button
                  onClick={() => setExpandedStep(expandedStep === phase.phase ? null : phase.phase)}
                  className="w-full px-4 py-3 flex items-center gap-3 hover:bg-bg-card/30 transition-colors"
                >
                  <span className={`text-xs font-mono px-2 py-0.5 rounded font-bold ${
                    phase.status === 'actionable_now' ? 'bg-accent-green/15 text-accent-green' :
                    phase.status === 'recommended_next' ? 'bg-accent-blue/15 text-accent-blue' :
                    phase.status === 'planned' ? 'bg-accent-amber/15 text-accent-amber' :
                    'bg-bg-card text-text-secondary'
                  }`}>
                    Phase {phase.phase}
                  </span>
                  <span className="text-sm font-medium flex-1 text-left">{phase.name}</span>
                  <span className="text-xs text-text-secondary">{phase.duration}</span>
                  {expandedStep === phase.phase ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
                {expandedStep === phase.phase && (
                  <div className="px-4 pb-4 border-t border-bg-card">
                    <ul className="mt-3 space-y-2">
                      {phase.tasks.map((task: string, i: number) => (
                        <li key={i} className="flex items-start gap-2 text-xs text-text-secondary">
                          <ArrowRight className="w-3 h-3 text-accent-blue shrink-0 mt-0.5" />
                          {task}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Estimated timeline */}
          <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card text-center">
            <div className="text-text-secondary text-xs mb-1">Estimated Total Duration</div>
            <div className="text-xl font-mono font-bold text-accent-purple">
              {migration.estimated_total_duration}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
