import { useEffect } from 'react'
import {
  Lock, Shield, Loader2, AlertTriangle, CheckCircle, XCircle,
  Zap, Key, ArrowRight, TrendingUp, BarChart3, ChevronDown, ChevronUp,
  Clock, Server, Activity, Crosshair, GitCompare, Radio, ExternalLink,
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
  pqTrafficAnalysis, pqHandshakeIdsEval, pqAttackSimulation, pqModelComparison,
} from '../utils/api'
import { usePageState } from '../hooks/usePageState'

const PAGE = 'pqcrypto'
const TT = { background: '#1E293B', border: '1px solid #334155', borderRadius: '8px', color: '#F8FAFC', fontSize: 12 }

const NIST_COLORS: Record<number, string> = {
  1: '#3B82F6', 2: '#22C55E', 3: '#F59E0B', 4: '#F97316', 5: '#EF4444',
}

const RISK_COLORS: Record<string, string> = {
  low: '#22C55E', medium: '#F59E0B', high: '#EF4444', critical: '#DC2626',
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#DC2626', high: '#F97316', medium: '#F59E0B', low: '#22C55E',
}

type Tab = 'overview' | 'benchmark' | 'risk' | 'migration'
type SimMode = 'handshake' | 'traffic' | 'ids_eval' | 'attack' | 'model_compare'

export default function PQCryptography() {
  const [tab, setTab] = usePageState<Tab>(PAGE, 'tab', 'overview')
  const [algorithms, setAlgorithms] = usePageState<any>(PAGE, 'algorithms', null)
  const [comparison, setComparison] = usePageState<any>(PAGE, 'comparison', null)
  const [risk, setRisk] = usePageState<any>(PAGE, 'risk', null)
  const [migration, setMigration] = usePageState<any>(PAGE, 'migration', null)
  const [benchResult, setBenchResult] = usePageState<any>(PAGE, 'benchResult', null)
  const [handshakeResult, setHandshakeResult] = usePageState<any>(PAGE, 'handshakeResult', null)
  const [selectedAlgo, setSelectedAlgo] = usePageState(PAGE, 'selectedAlgo', 'kyber768')
  const [benchIterations, setBenchIterations] = usePageState(PAGE, 'benchIterations', 100)
  const [loading, setLoading] = usePageState<string | null>(PAGE, 'loading', null)
  const [error, setError] = usePageState(PAGE, 'error', '')
  const [expandedStep, setExpandedStep] = usePageState<number | null>(PAGE, 'expandedStep', null)
  const [simMode, setSimMode] = usePageState<SimMode>(PAGE, 'simMode', 'handshake')
  const [trafficResult, setTrafficResult] = usePageState<any>(PAGE, 'trafficResult', null)
  const [idsEvalResult, setIdsEvalResult] = usePageState<any>(PAGE, 'idsEvalResult', null)
  const [attackResult, setAttackResult] = usePageState<any>(PAGE, 'attackResult', null)
  const [modelCompResult, setModelCompResult] = usePageState<any>(PAGE, 'modelCompResult', null)
  const [trafficScenario, setTrafficScenario] = usePageState(PAGE, 'trafficScenario', 'normal')
  const [attackType, setAttackType] = usePageState(PAGE, 'attackType', 'downgrade_attack')

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

  const runTrafficAnalysis = async () => {
    setLoading('traffic')
    setError('')
    try {
      const data = await pqTrafficAnalysis(selectedAlgo, trafficScenario)
      setTrafficResult(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Traffic analysis failed')
    } finally {
      setLoading(null)
    }
  }

  const runIdsEval = async () => {
    setLoading('ids_eval')
    setError('')
    try {
      const data = await pqHandshakeIdsEval(selectedAlgo)
      setIdsEvalResult(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'IDS evaluation failed')
    } finally {
      setLoading(null)
    }
  }

  const runAttackSim = async () => {
    setLoading('attack')
    setError('')
    try {
      const data = await pqAttackSimulation(selectedAlgo, attackType)
      setAttackResult(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Attack simulation failed')
    } finally {
      setLoading(null)
    }
  }

  const runModelComparison = async () => {
    setLoading('model_compare')
    setError('')
    try {
      const data = await pqModelComparison(selectedAlgo)
      setModelCompResult(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Model comparison failed')
    } finally {
      setLoading(null)
    }
  }

  const SIM_MODES: { id: SimMode; label: string; icon: any; desc: string }[] = [
    { id: 'handshake', label: 'Handshake', icon: Zap, desc: 'Protocol step simulation' },
    { id: 'traffic', label: 'Traffic Analysis', icon: Activity, desc: 'PQ traffic through IDS' },
    { id: 'ids_eval', label: 'IDS Evaluation', icon: Shield, desc: 'Detection impact analysis' },
    { id: 'attack', label: 'Attack Sim', icon: Crosshair, desc: 'PQ attack scenarios' },
    { id: 'model_compare', label: 'Model Compare', icon: GitCompare, desc: 'PQ-IDPS vs others' },
  ]

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
          {/* Algorithm + Iterations controls */}
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
              <div className="flex items-end">
                <button
                  onClick={runBenchmark}
                  disabled={loading === 'benchmark'}
                  className="px-4 py-2 bg-accent-purple text-white rounded-lg text-sm font-medium hover:bg-accent-purple/80 transition-colors disabled:opacity-40 flex items-center gap-2"
                >
                  {loading === 'benchmark' ? <Loader2 className="w-4 h-4 animate-spin" /> : <BarChart3 className="w-4 h-4" />}
                  Benchmark
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

          {/* ── Simulation Mode Tabs ── */}
          <div className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
            <div className="flex border-b border-bg-card overflow-x-auto">
              {SIM_MODES.map(m => (
                <button
                  key={m.id}
                  onClick={() => setSimMode(m.id)}
                  className={`flex items-center gap-1.5 px-4 py-3 text-xs font-medium whitespace-nowrap transition-colors border-b-2 ${
                    simMode === m.id
                      ? 'border-accent-blue text-accent-blue bg-accent-blue/5'
                      : 'border-transparent text-text-secondary hover:text-text-primary'
                  }`}
                >
                  <m.icon className="w-3.5 h-3.5" />
                  {m.label}
                </button>
              ))}
            </div>

            <div className="p-5">
              {/* ── Handshake Mode ── */}
              {simMode === 'handshake' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-semibold">PQ Key Exchange Handshake Simulation</h3>
                      <p className="text-xs text-text-secondary mt-0.5">5-step TLS 1.3 handshake with PQ KEM key exchange vs classical X25519</p>
                    </div>
                    <button
                      onClick={runHandshake}
                      disabled={loading === 'handshake' || !algorithms?.kem_algorithms?.[selectedAlgo]}
                      className="px-4 py-2 bg-accent-blue text-white rounded-lg text-sm font-medium hover:bg-accent-blue/80 transition-colors disabled:opacity-40 flex items-center gap-2"
                    >
                      {loading === 'handshake' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                      Simulate Handshake
                    </button>
                  </div>
                  {!algorithms?.kem_algorithms?.[selectedAlgo] && (
                    <div className="text-xs text-accent-amber bg-accent-amber/10 rounded-lg px-3 py-2">
                      Select a KEM algorithm (Kyber variants, NTRU, McEliece) to simulate a handshake.
                    </div>
                  )}
                  {handshakeResult && (
                    <>
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
                    </>
                  )}
                </div>
              )}

              {/* ── Traffic Analysis Mode ── */}
              {simMode === 'traffic' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between flex-wrap gap-3">
                    <div>
                      <h3 className="text-sm font-semibold">PQ Traffic Analysis Mode</h3>
                      <p className="text-xs text-text-secondary mt-0.5">Generate synthetic PQ flows and evaluate PQ-IDPS detection performance</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <select
                        value={trafficScenario}
                        onChange={e => setTrafficScenario(e.target.value)}
                        className="px-3 py-2 bg-bg-primary border border-bg-card rounded-lg text-xs text-text-primary"
                      >
                        <option value="normal">Normal (5% attacks)</option>
                        <option value="mixed">Mixed (25% attacks)</option>
                        <option value="high_volume">High Volume (15% attacks)</option>
                      </select>
                      <button
                        onClick={runTrafficAnalysis}
                        disabled={loading === 'traffic' || !algorithms?.kem_algorithms?.[selectedAlgo]}
                        className="px-4 py-2 bg-accent-green text-white rounded-lg text-sm font-medium hover:bg-accent-green/80 transition-colors disabled:opacity-40 flex items-center gap-2"
                      >
                        {loading === 'traffic' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Activity className="w-4 h-4" />}
                        Analyse Traffic
                      </button>
                    </div>
                  </div>
                  {!algorithms?.kem_algorithms?.[selectedAlgo] && (
                    <div className="text-xs text-accent-amber bg-accent-amber/10 rounded-lg px-3 py-2">
                      Select a KEM algorithm to analyse PQ traffic patterns.
                    </div>
                  )}
                  {trafficResult && (
                    <>
                      {/* Key finding */}
                      <div className="bg-accent-blue/10 border border-accent-blue/20 rounded-lg px-4 py-3">
                        <div className="text-xs font-medium text-accent-blue mb-1">Key Finding</div>
                        <div className="text-xs text-text-primary">{trafficResult.pq_traffic_insights.key_finding}</div>
                      </div>

                      {/* Detection metrics */}
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <div className="bg-bg-primary rounded-lg p-3 text-center">
                          <div className="text-[10px] text-text-secondary">Accuracy</div>
                          <div className="text-lg font-mono font-bold text-accent-green">
                            {(trafficResult.detection_results.accuracy * 100).toFixed(1)}%
                          </div>
                        </div>
                        <div className="bg-bg-primary rounded-lg p-3 text-center">
                          <div className="text-[10px] text-text-secondary">F1-Score</div>
                          <div className="text-lg font-mono font-bold text-accent-blue">
                            {(trafficResult.detection_results.f1_score * 100).toFixed(1)}%
                          </div>
                        </div>
                        <div className="bg-bg-primary rounded-lg p-3 text-center">
                          <div className="text-[10px] text-text-secondary">Precision</div>
                          <div className="text-lg font-mono font-bold text-accent-purple">
                            {(trafficResult.detection_results.precision * 100).toFixed(1)}%
                          </div>
                        </div>
                        <div className="bg-bg-primary rounded-lg p-3 text-center">
                          <div className="text-[10px] text-text-secondary">Recall</div>
                          <div className="text-lg font-mono font-bold text-accent-amber">
                            {(trafficResult.detection_results.recall * 100).toFixed(1)}%
                          </div>
                        </div>
                      </div>

                      {/* Fingerprint comparison */}
                      <div>
                        <h4 className="text-xs font-semibold text-text-secondary mb-2">Traffic Fingerprint: PQ vs Classical</h4>
                        <div className="grid grid-cols-3 gap-2 text-xs">
                          {[
                            { label: 'Avg Packet Size', pq: `${trafficResult.fingerprint_comparison.pq_avg_packet_bytes}B`, cl: `${trafficResult.fingerprint_comparison.classical_avg_packet_bytes}B`, ratio: `${trafficResult.fingerprint_comparison.size_ratio}x` },
                            { label: 'ClientHello', pq: `${trafficResult.fingerprint_comparison.pq_client_hello_bytes}B`, cl: `${trafficResult.fingerprint_comparison.classical_client_hello_bytes}B`, ratio: `${trafficResult.fingerprint_comparison.client_hello_ratio}x` },
                            { label: 'Handshake Pkts', pq: trafficResult.fingerprint_comparison.pq_handshake_packets, cl: trafficResult.fingerprint_comparison.classical_handshake_packets, ratio: '' },
                          ].map(r => (
                            <div key={r.label} className="bg-bg-primary rounded-lg p-2">
                              <div className="text-[10px] text-text-secondary mb-1">{r.label}</div>
                              <div className="flex justify-between">
                                <span className="text-accent-blue font-mono">PQ: {r.pq}</span>
                                <span className="text-text-secondary font-mono">CL: {r.cl}</span>
                              </div>
                              {r.ratio && <div className="text-[10px] text-accent-amber mt-0.5">{r.ratio} larger</div>}
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* T/D/L fingerprint */}
                      <div>
                        <h4 className="text-xs font-semibold text-text-secondary mb-2">PQClass T/D/L Packet Fingerprint</h4>
                        <div className="text-[10px] text-text-secondary mb-1">{trafficResult.traffic_profile.tdl_fingerprint.description}</div>
                        <div className="bg-bg-primary rounded-lg p-2 overflow-x-auto">
                          <table className="text-[10px] font-mono w-full">
                            <thead><tr className="text-text-secondary"><th className="text-left px-2">Pkt#</th><th className="text-right px-2">T (ms)</th><th className="text-center px-2">Dir</th><th className="text-right px-2">L (bytes)</th></tr></thead>
                            <tbody>
                              {trafficResult.traffic_profile.tdl_fingerprint.first_5_packets.map((p: any, i: number) => (
                                <tr key={i} className={p.direction === 0 ? 'text-accent-blue' : 'text-accent-green'}>
                                  <td className="px-2">{i + 1}</td>
                                  <td className="text-right px-2">{p.t_ms}</td>
                                  <td className="text-center px-2">{p.direction === 0 ? 'C→S' : 'S→C'}</td>
                                  <td className="text-right px-2">{p.length}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>

                      {/* Confusion matrix summary */}
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                        {[
                          { label: 'True Positives', val: trafficResult.detection_results.true_positives, color: 'text-accent-green' },
                          { label: 'False Positives', val: trafficResult.detection_results.false_positives, color: 'text-accent-amber' },
                          { label: 'True Negatives', val: trafficResult.detection_results.true_negatives, color: 'text-accent-blue' },
                          { label: 'False Negatives', val: trafficResult.detection_results.false_negatives, color: 'text-accent-red' },
                        ].map(c => (
                          <div key={c.label} className="bg-bg-primary rounded-lg p-2 text-center">
                            <div className="text-[10px] text-text-secondary">{c.label}</div>
                            <div className={`text-sm font-mono font-bold ${c.color}`}>{c.val}</div>
                          </div>
                        ))}
                      </div>

                      {/* Dataset references */}
                      {trafficResult.dataset_references && (
                        <div className="border-t border-bg-card pt-3">
                          <div className="text-[10px] text-text-secondary font-medium mb-1">Dataset Sources</div>
                          <div className="flex flex-wrap gap-2">
                            {trafficResult.dataset_references.map((d: any) => (
                              <a key={d.id} href={d.url} target="_blank" rel="noopener noreferrer"
                                className="inline-flex items-center gap-1 text-[10px] text-accent-blue hover:text-accent-blue/80 bg-accent-blue/5 rounded px-2 py-0.5">
                                <ExternalLink className="w-2.5 h-2.5" />{d.name}
                              </a>
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}

              {/* ── IDS Evaluation Mode ── */}
              {simMode === 'ids_eval' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-semibold">Handshake-Aware IDS Evaluation</h3>
                      <p className="text-xs text-text-secondary mt-0.5">How PQ handshake characteristics affect intrusion detection accuracy</p>
                    </div>
                    <button
                      onClick={runIdsEval}
                      disabled={loading === 'ids_eval' || !algorithms?.kem_algorithms?.[selectedAlgo]}
                      className="px-4 py-2 bg-accent-purple text-white rounded-lg text-sm font-medium hover:bg-accent-purple/80 transition-colors disabled:opacity-40 flex items-center gap-2"
                    >
                      {loading === 'ids_eval' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
                      Evaluate IDS
                    </button>
                  </div>
                  {!algorithms?.kem_algorithms?.[selectedAlgo] && (
                    <div className="text-xs text-accent-amber bg-accent-amber/10 rounded-lg px-3 py-2">
                      Select a KEM algorithm to evaluate IDS impact.
                    </div>
                  )}
                  {idsEvalResult && (
                    <>
                      {/* FPR comparison */}
                      <div className="bg-accent-green/10 border border-accent-green/20 rounded-lg px-4 py-3">
                        <div className="text-xs font-medium text-accent-green mb-1">False Positive Reduction</div>
                        <div className="text-xs text-text-primary">{idsEvalResult.false_positive_analysis.explanation}</div>
                      </div>

                      {/* Impact analysis table */}
                      <div className="space-y-2">
                        {idsEvalResult.ids_impact_analysis.map((impact: any) => (
                          <div key={impact.category} className="bg-bg-primary rounded-lg p-3">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-xs font-medium">{impact.category}</span>
                              <span className={`text-[10px] font-medium px-2 py-0.5 rounded ${
                                impact.impact === 'high' ? 'bg-accent-red/15 text-accent-red' :
                                impact.impact === 'medium' ? 'bg-accent-amber/15 text-accent-amber' :
                                'bg-accent-green/15 text-accent-green'
                              }`}>{impact.impact} impact</span>
                            </div>
                            <div className="flex items-center gap-4 text-[10px] mb-1">
                              <span className="text-text-secondary">Classical: <span className="font-mono text-text-primary">{impact.classical_value}</span></span>
                              <ArrowRight className="w-3 h-3 text-text-secondary" />
                              <span className="text-text-secondary">PQ: <span className="font-mono text-accent-blue">{impact.pq_value}</span></span>
                              <span className="text-accent-amber font-mono">+{impact.change_percent}%</span>
                            </div>
                            <div className="text-[10px] text-text-secondary">{impact.ids_effect}</div>
                          </div>
                        ))}
                      </div>

                      {/* PQClass detection rates */}
                      <div>
                        <h4 className="text-xs font-semibold text-text-secondary mb-2">PQClass Traffic Classification Accuracy</h4>
                        <div className="grid grid-cols-3 gap-2">
                          {[
                            { label: 'PQ Presence', val: idsEvalResult.pqclass_detection.pq_presence_accuracy },
                            { label: 'Algorithm ID', val: idsEvalResult.pqclass_detection.algorithm_identification_accuracy },
                            { label: 'Application ID', val: idsEvalResult.pqclass_detection.application_identification_accuracy },
                          ].map(d => (
                            <div key={d.label} className="bg-bg-primary rounded-lg p-2 text-center">
                              <div className="text-[10px] text-text-secondary">{d.label}</div>
                              <div className="text-sm font-mono font-bold text-accent-blue">{(d.val * 100).toFixed(0)}%</div>
                            </div>
                          ))}
                        </div>
                        <div className="text-[10px] text-text-secondary mt-1">{idsEvalResult.pqclass_detection.source}</div>
                      </div>

                      {/* Recommendations */}
                      <div className="border-t border-bg-card pt-3">
                        <h4 className="text-xs font-semibold text-text-secondary mb-2">Recommendations</h4>
                        <ul className="space-y-1">
                          {idsEvalResult.recommendations.map((rec: string, i: number) => (
                            <li key={i} className="flex items-start gap-2 text-[11px] text-text-secondary">
                              <CheckCircle className="w-3 h-3 text-accent-green shrink-0 mt-0.5" />
                              {rec}
                            </li>
                          ))}
                        </ul>
                      </div>

                      {/* Dataset references */}
                      {idsEvalResult.dataset_references && (
                        <div className="border-t border-bg-card pt-3">
                          <div className="text-[10px] text-text-secondary font-medium mb-1">Dataset Sources</div>
                          <div className="flex flex-wrap gap-2">
                            {idsEvalResult.dataset_references.map((d: any) => (
                              <a key={d.id} href={d.url} target="_blank" rel="noopener noreferrer"
                                className="inline-flex items-center gap-1 text-[10px] text-accent-blue hover:text-accent-blue/80 bg-accent-blue/5 rounded px-2 py-0.5">
                                <ExternalLink className="w-2.5 h-2.5" />{d.name}
                              </a>
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}

              {/* ── Attack Simulation Mode ── */}
              {simMode === 'attack' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between flex-wrap gap-3">
                    <div>
                      <h3 className="text-sm font-semibold">PQ Attack Simulation</h3>
                      <p className="text-xs text-text-secondary mt-0.5">Simulate quantum-context attacks and PQ-IDPS detection response</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <select
                        value={attackType}
                        onChange={e => setAttackType(e.target.value)}
                        className="px-3 py-2 bg-bg-primary border border-bg-card rounded-lg text-xs text-text-primary"
                      >
                        <option value="downgrade_attack">Downgrade Attack</option>
                        <option value="harvest_now_decrypt_later">Harvest-Now-Decrypt-Later</option>
                        <option value="side_channel_timing">Timing Side-Channel</option>
                        <option value="pq_replay_attack">Session Replay</option>
                      </select>
                      <button
                        onClick={runAttackSim}
                        disabled={loading === 'attack'}
                        className="px-4 py-2 bg-accent-red text-white rounded-lg text-sm font-medium hover:bg-accent-red/80 transition-colors disabled:opacity-40 flex items-center gap-2"
                      >
                        {loading === 'attack' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Crosshair className="w-4 h-4" />}
                        Simulate Attack
                      </button>
                    </div>
                  </div>
                  {attackResult && (
                    <>
                      {/* Attack header */}
                      <div className="flex items-center gap-3 bg-bg-primary rounded-lg p-3">
                        <div className="px-2 py-0.5 rounded text-[10px] font-bold uppercase" style={{
                          background: `${SEVERITY_COLORS[attackResult.attack.severity]}20`,
                          color: SEVERITY_COLORS[attackResult.attack.severity],
                        }}>
                          {attackResult.attack.severity}
                        </div>
                        <div>
                          <div className="text-sm font-medium">{attackResult.attack.name}</div>
                          <div className="text-[10px] text-text-secondary">MITRE ATT&CK: {attackResult.attack.mitre_id}</div>
                        </div>
                      </div>

                      <div className="text-xs text-text-secondary">{attackResult.attack.description}</div>

                      {/* Attack steps timeline */}
                      <div>
                        <h4 className="text-xs font-semibold text-text-secondary mb-2">Attack Timeline</h4>
                        <div className="space-y-2">
                          {attackResult.attack_steps.map((step: any, i: number) => (
                            <div key={i} className="flex items-start gap-3">
                              <div className="w-5 h-5 rounded-full bg-accent-red/15 text-accent-red flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5">
                                {i + 1}
                              </div>
                              <div className="flex-1">
                                <div className="flex items-center gap-2">
                                  <span className="text-xs font-medium">{step.phase}</span>
                                  {step.time_ms > 0 && <span className="text-[10px] font-mono text-text-secondary">+{step.time_ms}ms</span>}
                                </div>
                                <div className="text-[10px] text-text-secondary">{step.action}</div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Detection signals */}
                      <div>
                        <h4 className="text-xs font-semibold text-text-secondary mb-2">PQ-IDPS Detection Signals</h4>
                        <div className="space-y-1.5">
                          {attackResult.ids_detection.signals.map((sig: any, i: number) => (
                            <div key={i} className="flex items-center gap-2 bg-bg-primary rounded-lg px-3 py-2">
                              {sig.detected
                                ? <CheckCircle className="w-3.5 h-3.5 text-accent-green shrink-0" />
                                : <XCircle className="w-3.5 h-3.5 text-accent-red shrink-0" />}
                              <div className="flex-1 text-[11px]">{sig.signal}</div>
                              <div className="text-[10px] font-mono text-text-secondary">{sig.method}</div>
                              <div className={`text-[10px] font-mono font-bold ${sig.confidence >= 0.9 ? 'text-accent-green' : sig.confidence >= 0.8 ? 'text-accent-amber' : 'text-accent-red'}`}>
                                {(sig.confidence * 100).toFixed(1)}%
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Overall detection */}
                      <div className="grid grid-cols-3 gap-3">
                        <div className="bg-bg-primary rounded-lg p-3 text-center">
                          <div className="text-[10px] text-text-secondary">Overall Detection</div>
                          <div className={`text-lg font-mono font-bold ${attackResult.ids_detection.detected ? 'text-accent-green' : 'text-accent-red'}`}>
                            {(attackResult.ids_detection.overall_confidence * 100).toFixed(1)}%
                          </div>
                        </div>
                        <div className="bg-bg-primary rounded-lg p-3 text-center">
                          <div className="text-[10px] text-text-secondary">Detection Time</div>
                          <div className="text-lg font-mono font-bold text-accent-blue">
                            {attackResult.ids_detection.detection_time_ms}ms
                          </div>
                        </div>
                        <div className="bg-bg-primary rounded-lg p-3 text-center">
                          <div className="text-[10px] text-text-secondary">Status</div>
                          <div className={`text-sm font-bold ${attackResult.ids_detection.detected ? 'text-accent-green' : 'text-accent-red'}`}>
                            {attackResult.ids_detection.detected ? 'DETECTED' : 'MISSED'}
                          </div>
                        </div>
                      </div>

                      {/* Algorithm-specific notes */}
                      <div className="bg-accent-blue/10 border border-accent-blue/20 rounded-lg px-4 py-3">
                        <div className="text-xs font-medium text-accent-blue mb-1">Algorithm-Specific Note</div>
                        <div className="text-[11px] text-text-primary">{attackResult.algorithm_specific_notes}</div>
                      </div>

                      {/* Mitigation */}
                      <div className="bg-accent-green/10 border border-accent-green/20 rounded-lg px-4 py-3">
                        <div className="text-xs font-medium text-accent-green mb-1">Recommended Mitigation</div>
                        <div className="text-[11px] text-text-primary">{attackResult.mitigation}</div>
                      </div>
                    </>
                  )}
                </div>
              )}

              {/* ── Model Comparison Mode ── */}
              {simMode === 'model_compare' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-semibold">Model Comparison on PQ Traffic</h3>
                      <p className="text-xs text-text-secondary mt-0.5">Compare PQ-IDPS (Branch 3) against all 7 surrogate models on PQ-encrypted traffic</p>
                    </div>
                    <button
                      onClick={runModelComparison}
                      disabled={loading === 'model_compare' || !algorithms?.kem_algorithms?.[selectedAlgo]}
                      className="px-4 py-2 bg-accent-amber text-white rounded-lg text-sm font-medium hover:bg-accent-amber/80 transition-colors disabled:opacity-40 flex items-center gap-2"
                    >
                      {loading === 'model_compare' ? <Loader2 className="w-4 h-4 animate-spin" /> : <GitCompare className="w-4 h-4" />}
                      Compare Models
                    </button>
                  </div>
                  {!algorithms?.kem_algorithms?.[selectedAlgo] && (
                    <div className="text-xs text-accent-amber bg-accent-amber/10 rounded-lg px-3 py-2">
                      Select a KEM algorithm to compare model performance on PQ traffic.
                    </div>
                  )}
                  {modelCompResult && (
                    <>
                      {/* PQ-IDPS advantage summary */}
                      <div className="bg-accent-purple/10 border border-accent-purple/20 rounded-lg px-4 py-3">
                        <div className="text-xs font-medium text-accent-purple mb-1">PQ-IDPS Advantage</div>
                        <div className="text-xs text-text-primary">{modelCompResult.pq_idps_advantage.explanation}</div>
                      </div>

                      {/* Model comparison table */}
                      <div className="overflow-x-auto">
                        <table className="w-full text-xs">
                          <thead>
                            <tr className="border-b border-bg-card">
                              <th className="text-left py-2 px-2 text-text-secondary font-medium">Model</th>
                              <th className="text-right py-2 px-2 text-text-secondary font-medium">F1</th>
                              <th className="text-right py-2 px-2 text-text-secondary font-medium">Accuracy</th>
                              <th className="text-right py-2 px-2 text-text-secondary font-medium">Precision</th>
                              <th className="text-right py-2 px-2 text-text-secondary font-medium">Recall</th>
                              <th className="text-right py-2 px-2 text-text-secondary font-medium">FPR</th>
                              <th className="text-right py-2 px-2 text-text-secondary font-medium">Latency</th>
                            </tr>
                          </thead>
                          <tbody>
                            {modelCompResult.model_results.map((m: any) => (
                              <tr key={m.model_id} className={`border-b border-bg-card/50 ${m.is_pq_optimised ? 'bg-accent-purple/5' : ''}`}>
                                <td className="py-2 px-2">
                                  <div className="flex items-center gap-1.5">
                                    {m.is_pq_optimised && <Radio className="w-3 h-3 text-accent-purple" />}
                                    <span className={m.is_pq_optimised ? 'font-medium text-accent-purple' : ''}>{m.name}</span>
                                  </div>
                                </td>
                                <td className="text-right py-2 px-2 font-mono font-bold text-accent-green">{(m.f1_score * 100).toFixed(1)}%</td>
                                <td className="text-right py-2 px-2 font-mono">{(m.accuracy * 100).toFixed(1)}%</td>
                                <td className="text-right py-2 px-2 font-mono">{(m.precision * 100).toFixed(1)}%</td>
                                <td className="text-right py-2 px-2 font-mono">{(m.recall * 100).toFixed(1)}%</td>
                                <td className="text-right py-2 px-2 font-mono text-accent-amber">{(m.false_positive_rate * 100).toFixed(2)}%</td>
                                <td className="text-right py-2 px-2 font-mono text-text-secondary">{m.latency_ms}ms</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>

                      {/* F1 Score bar chart */}
                      <div>
                        <h4 className="text-xs font-semibold text-text-secondary mb-2">F1-Score on PQ Traffic</h4>
                        <ResponsiveContainer width="100%" height={200}>
                          <BarChart data={modelCompResult.model_results.map((m: any) => ({
                            name: m.name.split(' ')[0],
                            F1: +(m.f1_score * 100).toFixed(1),
                            fill: m.is_pq_optimised ? '#A855F7' : '#3B82F6',
                          }))} barGap={4}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                            <XAxis dataKey="name" tick={{ fill: '#94A3B8', fontSize: 8 }} angle={-20} />
                            <YAxis domain={[80, 100]} tick={{ fill: '#94A3B8', fontSize: 10 }} unit="%" />
                            <Tooltip contentStyle={TT} />
                            <Bar dataKey="F1" radius={[4, 4, 0, 0]}>
                              {modelCompResult.model_results.map((m: any, i: number) => (
                                <Cell key={i} fill={m.is_pq_optimised ? '#A855F7' : '#3B82F6'} />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      </div>

                      {/* Why PQ-IDPS matters */}
                      <div className="border-t border-bg-card pt-3">
                        <h4 className="text-xs font-semibold text-text-secondary mb-2">Why PQ-IDPS Outperforms</h4>
                        <ul className="space-y-1">
                          {modelCompResult.why_pq_idps_matters.map((reason: string, i: number) => (
                            <li key={i} className="flex items-start gap-2 text-[11px] text-text-secondary">
                              <TrendingUp className="w-3 h-3 text-accent-purple shrink-0 mt-0.5" />
                              {reason}
                            </li>
                          ))}
                        </ul>
                      </div>

                      {/* Dataset references */}
                      {modelCompResult.dataset_references && (
                        <div className="border-t border-bg-card pt-3">
                          <div className="text-[10px] text-text-secondary font-medium mb-1">Training Data Sources</div>
                          <div className="flex flex-wrap gap-2">
                            {modelCompResult.dataset_references.map((d: any) => (
                              <a key={d.id} href={d.url} target="_blank" rel="noopener noreferrer"
                                className="inline-flex items-center gap-1 text-[10px] text-accent-blue hover:text-accent-blue/80 bg-accent-blue/5 rounded px-2 py-0.5">
                                <ExternalLink className="w-2.5 h-2.5" />{d.name}
                              </a>
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}
            </div>
          </div>

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
