import { useEffect, useState, useRef } from 'react'
import {
  Shield, Loader2, AlertTriangle, Activity,
  Zap, Target, BarChart3, ChevronDown, ChevronUp,
  CheckCircle2, XCircle, Eye, Ban, Lock,
  FlaskConical, Save, Wifi, TrendingUp,
  Upload, FileText, X, GitCompare,
} from 'lucide-react'
import { runRLSimulation, fetchRLMetrics, fetchCLRLStatus, createExperiment } from '../utils/api'
import AutoTuneButton from '../components/AutoTuneButton'
import ExportMenu from '../components/ExportMenu'
import PageGuide from '../components/PageGuide'
import { registerSessionReset } from '../utils/sessionReset'
import { useNoticeBoard } from '../hooks/useNoticeBoard'

const ACTION_ICONS = [Eye, Activity, Zap, Ban, Lock]
const ACTION_COLORS = ['#22C55E', '#3B82F6', '#F59E0B', '#EF4444', '#A855F7']
const ACTION_NAMES = ['Monitor', 'RateLimit', 'Reset', 'Block', 'Quarantine']

const _store: {
  file: File | null
  numEpisodes: number
  result: any
  rlMetrics: any
  clrlStatus: any
  savedExperiment: boolean
  multiResults: any[]
} = {
  file: null,
  numEpisodes: 50,
  result: null,
  rlMetrics: null,
  clrlStatus: null,
  savedExperiment: false,
  multiResults: [] as any[],
}

registerSessionReset(() => {
  _store.file = null
  _store.numEpisodes = 50
  _store.result = null
  _store.rlMetrics = null
  _store.clrlStatus = null
  _store.savedExperiment = false
  _store.multiResults = []
})

export default function RLResponseAgent() {
  const [file, _setFile] = useState<File | null>(_store.file)
  const [numEpisodes, _setNumEpisodes] = useState(_store.numEpisodes)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')
  const [result, _setResult] = useState<any>(_store.result)
  const [rlMetrics, _setRlMetrics] = useState<any>(_store.rlMetrics)
  const [clrlStatus, _setClrlStatus] = useState<any>(_store.clrlStatus)
  const [showEpisodes, setShowEpisodes] = useState(false)
  const [showClrlStatus, setShowClrlStatus] = useState(false)
  const [savedExperiment, _setSavedExperiment] = useState(_store.savedExperiment)
  const [saving, setSaving] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)
  const [mode, setMode] = useState<'single' | 'multi'>('single')
  const [multiSlots, setMultiSlots] = useState<{ file: File | null; fileName: string | null }[]>([
    { file: null, fileName: null },
    { file: null, fileName: null },
    { file: null, fileName: null },
  ])
  const [multiResults, setMultiResults] = useState<any[]>(_store.multiResults)
  const [multiRunning, setMultiRunning] = useState(false)
  const { addNotice, updateNotice } = useNoticeBoard()

  const setFile = (f: File | null) => { _store.file = f; _setFile(f) }
  const setNumEpisodes = (v: number) => { _store.numEpisodes = v; _setNumEpisodes(v) }
  const setResult = (v: any) => { _store.result = v; _store.savedExperiment = false; _setResult(v); _setSavedExperiment(false) }
  const setRlMetrics = (v: any) => { _store.rlMetrics = v; _setRlMetrics(v) }
  const setClrlStatus = (v: any) => { _store.clrlStatus = v; _setClrlStatus(v) }
  const setSavedExperiment = (v: boolean) => { _store.savedExperiment = v; _setSavedExperiment(v) }

  useEffect(() => {
    fetchRLMetrics().then(setRlMetrics).catch(() => {})
    fetchCLRLStatus().then(setClrlStatus).catch(() => {})
  }, [])

  const handleRun = async () => {
    if (!file) return
    setRunning(true)
    setError('')
    const nid = addNotice({ title: 'RL Response Simulation', description: `${numEpisodes} episodes`, status: 'running', page: '/rl-agent' })
    try {
      const data = await runRLSimulation(file, numEpisodes)
      setResult(data)
      fetchRLMetrics().then(setRlMetrics).catch(() => {})
      updateNotice(nid, { status: 'completed', description: `${numEpisodes} episodes completed` })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Simulation failed')
      updateNotice(nid, { status: 'error', description: `Failed: ${err instanceof Error ? err.message : err}` })
    }
    setRunning(false)
  }

  const handleMultiRun = async () => {
    const activeSlots = multiSlots.filter(s => s.file)
    if (activeSlots.length === 0) return
    setMultiRunning(true)
    setError('')
    setMultiResults([])
    const nid = addNotice({ title: 'RL Multi-Dataset Comparison', description: `${activeSlots.length} datasets × ${numEpisodes} episodes`, status: 'running', page: '/rl-agent' })
    try {
      const results = await Promise.all(
        activeSlots.map(async (slot) => {
          const data = await runRLSimulation(slot.file!, numEpisodes)
          return { fileName: slot.fileName, ...data }
        })
      )
      setMultiResults(results)
      _store.multiResults = results
      updateNotice(nid, { status: 'completed', description: `${results.length} datasets compared` })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Multi-dataset simulation failed')
      updateNotice(nid, { status: 'error', description: `Failed: ${err instanceof Error ? err.message : err}` })
    }
    setMultiRunning(false)
  }

  const handleSaveExperiment = async () => {
    if (!result || saving) return
    setSaving(true)
    try {
      await createExperiment({
        name: `RL Response — ${numEpisodes} episodes`,
        task_type: 'rl_response',
        tags: ['rl', 'cpo', 'response-agent'],
        params: { num_episodes: numEpisodes, dataset_format: result.dataset_format },
        results: result,
        metrics: {
          threat_mitigation_rate: result.threat_mitigation_rate,
          fp_blocking_rate: result.fp_blocking_rate,
          mean_episode_reward: result.mean_episode_reward,
          constraint_violations: result.constraint_violations,
          total_steps: result.total_steps,
          total_attacks: result.total_attacks,
          total_threats_mitigated: result.total_threats_mitigated,
        },
      })
      setSavedExperiment(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save experiment')
    }
    setSaving(false)
  }

  const pct = (v: number) => `${(v * 100).toFixed(2)}%`

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex items-center gap-3">
        <Shield className="w-6 h-6 text-accent-red" />
        <div className="flex-1">
          <h1 className="text-2xl font-display font-bold">RL Response Agent</h1>
          <p className="text-sm text-text-secondary mt-1">
            Constrained Policy Optimisation (CPO) agent with 5 graduated response actions.
            Simulates autonomous threat response on uploaded traffic data.
          </p>
        </div>
        <ExportMenu filename="rl-response-agent" />
      </div>

      <PageGuide
        title="How to use the RL Response Agent"
        steps={[
          { title: 'Upload traffic data', desc: 'Provide a CSV/PCAP file with network flows. The agent uses detection outputs as its state observations.' },
          { title: 'Set simulation parameters', desc: 'Configure the number of episodes for the CPO agent to run. More episodes yield more stable policy estimates.' },
          { title: 'Run the simulation', desc: 'The agent processes each flow and selects from 5 actions: Monitor, RateLimit, Reset, Block, or Quarantine — subject to safety constraints.' },
          { title: 'Review action distribution', desc: 'Analyse which actions the policy selected and at what frequency. Check the false-positive rate stays below the 0.1% safety threshold.' },
          { title: 'Inspect per-episode metrics', desc: 'Expand the episode details to see reward curves, cost violations, action severity breakdown, and convergence trends.' },
          { title: 'Compare across datasets', desc: 'Switch to Multi-Dataset Comparison mode to run the RL agent on up to 3 different traffic files and compare mitigation rates, FP rates, and action distributions side-by-side.' },
        ]}
        tip="Tip: The agent uses Constrained Policy Optimisation (CPO) — it maximises threat mitigation while respecting the false-positive blocking constraint."
      />

      {error && (
        <div className="px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {error}
          <button onClick={() => setError('')} className="ml-auto text-xs hover:underline">dismiss</button>
        </div>
      )}

      {/* Mode Toggle */}
      <div className="flex gap-2">
        <button
          onClick={() => setMode('single')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
            mode === 'single'
              ? 'bg-accent-red text-white'
              : 'bg-bg-secondary border border-bg-card text-text-secondary hover:text-text-primary'
          }`}
        >
          <Target className="w-4 h-4" /> Single Dataset
        </button>
        <button
          onClick={() => setMode('multi')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
            mode === 'multi'
              ? 'bg-accent-purple text-white'
              : 'bg-bg-secondary border border-bg-card text-text-secondary hover:text-text-primary'
          }`}
        >
          <GitCompare className="w-4 h-4" /> Multi-Dataset Comparison
        </button>
      </div>

      {mode === 'single' && (
      <>
      {/* Action Space Overview */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold mb-3">CMDP Action Space</h2>
        <div className="grid grid-cols-5 gap-2">
          {ACTION_NAMES.map((name, i) => {
            const Icon = ACTION_ICONS[i]
            const count = result?.action_distribution?.[name] ?? 0
            const total = result?.total_steps ?? 1
            return (
              <div key={name} className="bg-bg-primary rounded-lg p-3 border border-bg-card text-center">
                <Icon className="w-5 h-5 mx-auto mb-1" style={{ color: ACTION_COLORS[i] }} />
                <div className="text-xs font-medium">{name}</div>
                <div className="text-[10px] text-text-secondary">Severity: {[0, 0.5, 1, 2, 5][i]}</div>
                {result && (
                  <div className="mt-1 text-sm font-mono font-semibold" style={{ color: ACTION_COLORS[i] }}>
                    {count} <span className="text-[10px] text-text-secondary">({((count / total) * 100).toFixed(1)}%)</span>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* Simulation Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">
            <Target className="w-5 h-5 text-accent-blue" />
            Run Simulation
          </h2>
          <div className="space-y-3">
            <div>
              <label className="text-xs text-text-secondary block mb-1">Traffic Data (.csv)</label>
              {file ? (
                <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-accent-green/30 bg-accent-green/5">
                  <FileText className="w-4 h-4 text-accent-green shrink-0" />
                  <span className="text-xs font-mono truncate flex-1">{file.name}</span>
                  <button onClick={() => setFile(null)} className="text-text-secondary hover:text-text-primary">
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              ) : (
                <label
                  onDragOver={(e) => { e.preventDefault(); e.currentTarget.classList.add('border-accent-blue', 'bg-accent-blue/10'); e.currentTarget.classList.remove('border-bg-card') }}
                  onDragLeave={(e) => { e.currentTarget.classList.remove('border-accent-blue', 'bg-accent-blue/10'); e.currentTarget.classList.add('border-bg-card') }}
                  onDrop={(e) => {
                    e.preventDefault()
                    e.currentTarget.classList.remove('border-accent-blue', 'bg-accent-blue/10')
                    e.currentTarget.classList.add('border-bg-card')
                    const f = e.dataTransfer.files[0]
                    if (f) setFile(f)
                  }}
                  className="flex flex-col items-center justify-center gap-1 px-3 py-3 rounded-lg border-2 border-dashed border-bg-card hover:border-text-secondary cursor-pointer transition-colors"
                >
                  <Upload className="w-5 h-5 text-text-secondary" />
                  <span className="text-[10px] text-text-secondary">Drop or click to upload</span>
                  <span className="text-[9px] text-text-secondary/60">.csv .pcap .pcapng</span>
                  <input ref={fileRef} type="file" accept=".csv,.pcap,.pcapng" onChange={(e) => setFile(e.target.files?.[0] || null)} className="hidden" />
                </label>
              )}
            </div>
            <div>
              <label className="text-[10px] text-text-secondary block mb-1">Episodes</label>
              <input
                type="number"
                value={numEpisodes}
                onChange={(e) => setNumEpisodes(Number(e.target.value))}
                min={10} max={500}
                className="w-full px-2 py-1.5 bg-bg-primary border border-bg-card rounded text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent-blue/50"
              />
            </div>
            <AutoTuneButton file={file} context="general" compact />
            <button
              onClick={handleRun}
              disabled={!file || running}
              className="w-full px-4 py-2.5 bg-accent-orange text-white rounded-lg text-xs font-medium hover:bg-accent-orange/80 disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {running ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> Simulating...</>
              ) : (
                <><Shield className="w-4 h-4" /> Run RL Agent</>
              )}
            </button>
          </div>
        </div>

        {/* Key Metrics */}
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">
            <BarChart3 className="w-5 h-5 text-accent-green" />
            Performance Metrics
          </h2>
          {result ? (
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-bg-primary rounded-lg p-3 border border-bg-card">
                <div className="text-[10px] text-text-secondary">Threat Mitigation</div>
                <div className="text-xl font-display font-bold text-accent-green">
                  {pct(result.threat_mitigation_rate)}
                </div>
              </div>
              <div className="bg-bg-primary rounded-lg p-3 border border-bg-card">
                <div className="text-[10px] text-text-secondary">FP Blocking Rate</div>
                <div className="text-xl font-display font-bold text-accent-red">
                  {pct(result.fp_blocking_rate)}
                </div>
              </div>
              <div className="bg-bg-primary rounded-lg p-3 border border-bg-card">
                <div className="text-[10px] text-text-secondary">Mean Reward</div>
                <div className="text-xl font-display font-bold text-accent-blue">
                  {result.mean_episode_reward}
                </div>
              </div>
              <div className="bg-bg-primary rounded-lg p-3 border border-bg-card">
                <div className="text-[10px] text-text-secondary">Constraint Violations</div>
                <div className="text-xl font-display font-bold">
                  {result.constraint_violations === 0 ? (
                    <span className="text-accent-green flex items-center gap-1">
                      <CheckCircle2 className="w-4 h-4" /> 0
                    </span>
                  ) : (
                    <span className="text-accent-red flex items-center gap-1">
                      <XCircle className="w-4 h-4" /> {result.constraint_violations}
                    </span>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="text-center py-8 text-text-secondary">
              <Shield className="w-8 h-8 mx-auto mb-2 opacity-20" />
              <p className="text-xs">Run a simulation to see response metrics</p>
            </div>
          )}
        </div>
      </div>

      {/* Summary Stats + Save Experiment */}
      {result && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card text-center">
              <div className="text-[10px] text-text-secondary">Total Steps</div>
              <div className="text-lg font-display font-bold text-accent-blue">
                {result.total_steps?.toLocaleString()}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card text-center">
              <div className="text-[10px] text-text-secondary">Attacks Seen</div>
              <div className="text-lg font-display font-bold text-accent-red">
                {result.total_attacks?.toLocaleString()}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card text-center">
              <div className="text-[10px] text-text-secondary">Threats Mitigated</div>
              <div className="text-lg font-display font-bold text-accent-green">
                {result.total_threats_mitigated?.toLocaleString()}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card text-center">
              <div className="text-[10px] text-text-secondary">FP Blocked</div>
              <div className="text-lg font-display font-bold text-accent-amber">
                {result.total_benign_blocked?.toLocaleString()}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card text-center">
              <div className="text-[10px] text-text-secondary">Episodes</div>
              <div className="text-lg font-display font-bold text-accent-purple">
                {result.num_episodes}
              </div>
            </div>
          </div>

          {/* Save as Experiment */}
          <div className="flex gap-2">
            <button
              onClick={handleSaveExperiment}
              disabled={saving || savedExperiment}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-colors ${
                savedExperiment
                  ? 'bg-accent-green/15 text-accent-green'
                  : 'bg-accent-blue/15 text-accent-blue hover:bg-accent-blue/25'
              } disabled:opacity-60`}
            >
              {saving ? (
                <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Saving...</>
              ) : savedExperiment ? (
                <><CheckCircle2 className="w-3.5 h-3.5" /> Saved to Research Hub</>
              ) : (
                <><FlaskConical className="w-3.5 h-3.5" /> Save as Experiment</>
              )}
            </button>
          </div>
        </>
      )}
      </>
      )}

      {mode === 'multi' && (
        <div className="space-y-4">
          {/* Multi-dataset file slots */}
          <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
            <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">
              <GitCompare className="w-5 h-5 text-accent-purple" />
              Multi-Dataset RL Comparison
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
              {multiSlots.map((slot, i) => (
                <div key={i}>
                  <div className="text-[10px] text-text-secondary mb-1 flex items-center gap-1">
                    <div className="w-2 h-2 rounded-full" style={{ background: ['#3B82F6', '#A855F7', '#22C55E'][i] }} />
                    Dataset {String.fromCharCode(65 + i)}
                  </div>
                  {slot.file ? (
                    <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-accent-green/30 bg-accent-green/5">
                      <FileText className="w-4 h-4 text-accent-green shrink-0" />
                      <span className="text-xs font-mono truncate flex-1">{slot.fileName}</span>
                      <button onClick={() => {
                        const next = [...multiSlots]
                        next[i] = { file: null, fileName: null }
                        setMultiSlots(next)
                      }} className="text-text-secondary hover:text-text-primary">
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ) : (
                    <label
                      onDragOver={(e) => { e.preventDefault(); e.currentTarget.classList.add('border-accent-blue', 'bg-accent-blue/10') }}
                      onDragLeave={(e) => { e.currentTarget.classList.remove('border-accent-blue', 'bg-accent-blue/10') }}
                      onDrop={(e) => {
                        e.preventDefault()
                        e.currentTarget.classList.remove('border-accent-blue', 'bg-accent-blue/10')
                        const f = e.dataTransfer.files[0]
                        if (f) {
                          const next = [...multiSlots]
                          next[i] = { file: f, fileName: f.name }
                          setMultiSlots(next)
                        }
                      }}
                      className="flex flex-col items-center justify-center gap-1 px-3 py-4 rounded-lg border-2 border-dashed border-bg-card hover:border-text-secondary cursor-pointer transition-colors"
                    >
                      <Upload className="w-5 h-5 text-text-secondary" />
                      <span className="text-[10px] text-text-secondary">Drop or click</span>
                      <span className="text-[9px] text-text-secondary/60">.csv .pcap .pcapng</span>
                      <input type="file" accept=".csv,.pcap,.pcapng" className="hidden" onChange={(e) => {
                        const f = e.target.files?.[0]
                        if (f) {
                          const next = [...multiSlots]
                          next[i] = { file: f, fileName: f.name }
                          setMultiSlots(next)
                        }
                      }} />
                    </label>
                  )}
                </div>
              ))}
            </div>

            <div className="flex items-center gap-3">
              <div>
                <label className="text-[10px] text-text-secondary block mb-1">Episodes per dataset</label>
                <input type="number" value={numEpisodes} onChange={(e) => setNumEpisodes(Number(e.target.value))} min={10} max={500}
                  className="w-24 px-2 py-1.5 bg-bg-primary border border-bg-card rounded text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent-blue/50" />
              </div>
              <button
                onClick={handleMultiRun}
                disabled={multiSlots.every(s => !s.file) || multiRunning}
                className="flex-1 px-4 py-2.5 bg-accent-purple text-white rounded-lg text-xs font-medium hover:bg-accent-purple/80 disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {multiRunning ? <><Loader2 className="w-4 h-4 animate-spin" /> Running RL Agent on {multiSlots.filter(s => s.file).length} datasets...</> : <><GitCompare className="w-4 h-4" /> Run RL Agent &amp; Compare</>}
              </button>
            </div>
          </div>

          {/* Multi-dataset comparison results */}
          {multiResults.length > 0 && (
            <>
            {/* CMDP Action Space — Multi-Dataset */}
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h2 className="text-lg font-display font-semibold mb-3">CMDP Action Space — Multi-Dataset</h2>
              <div className="grid grid-cols-5 gap-2">
                {ACTION_NAMES.map((name, i) => {
                  const Icon = ACTION_ICONS[i]
                  return (
                    <div key={name} className="bg-bg-primary rounded-lg p-3 border border-bg-card text-center">
                      <Icon className="w-5 h-5 mx-auto mb-1" style={{ color: ACTION_COLORS[i] }} />
                      <div className="text-xs font-medium">{name}</div>
                      <div className="text-[10px] text-text-secondary">Severity: {[0, 0.5, 1, 2, 5][i]}</div>
                      <div className="mt-1.5 space-y-0.5">
                        {multiResults.map((r, ri) => {
                          const count = r.action_distribution?.[name] ?? 0
                          const total = r.total_steps ?? 1
                          return (
                            <div key={ri} className="flex items-center gap-1 justify-center text-[10px]">
                              <div className="w-1.5 h-1.5 rounded-full" style={{ background: ['#3B82F6', '#A855F7', '#22C55E'][ri] }} />
                              <span className="font-mono" style={{ color: ACTION_COLORS[i] }}>{count}</span>
                              <span className="text-text-secondary">({((count / total) * 100).toFixed(0)}%)</span>
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>

            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">
                <BarChart3 className="w-5 h-5 text-accent-green" />
                Comparison Results
              </h2>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-text-secondary border-b border-bg-card">
                      <th className="px-3 py-2 text-left">Dataset</th>
                      <th className="px-3 py-2 text-right">Mitigation Rate</th>
                      <th className="px-3 py-2 text-right">FP Rate</th>
                      <th className="px-3 py-2 text-right">Mean Reward</th>
                      <th className="px-3 py-2 text-right">Violations</th>
                      <th className="px-3 py-2 text-right">Total Steps</th>
                      <th className="px-3 py-2 text-right">Threats</th>
                    </tr>
                  </thead>
                  <tbody>
                    {multiResults.map((r, i) => (
                      <tr key={i} className="border-b border-bg-card/50">
                        <td className="px-3 py-2 font-medium flex items-center gap-2">
                          <div className="w-2 h-2 rounded-full" style={{ background: ['#3B82F6', '#A855F7', '#22C55E'][i] }} />
                          <span className="truncate max-w-[150px]">{r.fileName || `Dataset ${String.fromCharCode(65 + i)}`}</span>
                        </td>
                        <td className="px-3 py-2 text-right font-mono text-accent-green">{(r.threat_mitigation_rate * 100).toFixed(1)}%</td>
                        <td className="px-3 py-2 text-right font-mono text-accent-red">{(r.fp_blocking_rate * 100).toFixed(3)}%</td>
                        <td className="px-3 py-2 text-right font-mono">{r.mean_episode_reward?.toFixed(1)}</td>
                        <td className="px-3 py-2 text-right">{r.constraint_violations === 0 ? <CheckCircle2 className="w-3 h-3 text-accent-green inline" /> : <span className="text-accent-red">{r.constraint_violations}</span>}</td>
                        <td className="px-3 py-2 text-right font-mono">{r.total_steps?.toLocaleString()}</td>
                        <td className="px-3 py-2 text-right font-mono">{r.total_attacks?.toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Action distribution comparison */}
              <div className="mt-4">
                <h3 className="text-xs font-semibold text-text-primary mb-2">Action Distribution Comparison</h3>
                <div className="grid grid-cols-5 gap-2 text-center text-[10px]">
                  {ACTION_NAMES.map((name, ai) => (
                    <div key={name} className="bg-bg-primary rounded-lg p-2 border border-bg-card">
                      <div className="font-medium mb-1" style={{ color: ACTION_COLORS[ai] }}>{name}</div>
                      {multiResults.map((r, ri) => {
                        const count = r.action_distribution?.[name] ?? 0
                        const total = r.total_steps ?? 1
                        return (
                          <div key={ri} className="flex items-center gap-1 justify-center">
                            <div className="w-1.5 h-1.5 rounded-full" style={{ background: ['#3B82F6', '#A855F7', '#22C55E'][ri] }} />
                            <span className="font-mono">{((count / total) * 100).toFixed(0)}%</span>
                          </div>
                        )
                      })}
                    </div>
                  ))}
                </div>
              </div>
            </div>
            </>
          )}
        </div>
      )}

      {/* CL-RL Framework Status */}
      {clrlStatus && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <button
            onClick={() => setShowClrlStatus(!showClrlStatus)}
            className="w-full flex items-center justify-between"
          >
            <h2 className="text-lg font-display font-semibold flex items-center gap-2">
              <Wifi className="w-5 h-5 text-accent-blue" />
              CL-RL Framework Status
            </h2>
            {showClrlStatus ? <ChevronUp className="w-5 h-5 text-text-secondary" /> : <ChevronDown className="w-5 h-5 text-text-secondary" />}
          </button>
          {showClrlStatus && (
            <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
              {clrlStatus.rl_metrics && (
                <div className="bg-bg-primary rounded-lg p-3 border border-bg-card space-y-1">
                  <div className="text-xs font-medium text-accent-blue flex items-center gap-1">
                    <TrendingUp className="w-3.5 h-3.5" /> RL Metrics Summary
                  </div>
                  <div className="text-[10px] text-text-secondary space-y-0.5">
                    {clrlStatus.rl_metrics.total_episodes != null && (
                      <div>Total Episodes: <span className="text-text-primary font-mono">{clrlStatus.rl_metrics.total_episodes}</span></div>
                    )}
                    {clrlStatus.rl_metrics.avg_mitigation_rate != null && (
                      <div>Avg Mitigation: <span className="text-accent-green font-mono">{(clrlStatus.rl_metrics.avg_mitigation_rate * 100).toFixed(1)}%</span></div>
                    )}
                    {clrlStatus.rl_metrics.avg_fp_rate != null && (
                      <div>Avg FP Rate: <span className="text-accent-red font-mono">{(clrlStatus.rl_metrics.avg_fp_rate * 100).toFixed(3)}%</span></div>
                    )}
                  </div>
                </div>
              )}
              {clrlStatus.drift && (
                <div className="bg-bg-primary rounded-lg p-3 border border-bg-card space-y-1">
                  <div className="text-xs font-medium text-accent-amber flex items-center gap-1">
                    <Activity className="w-3.5 h-3.5" /> Drift Detection
                  </div>
                  <div className="text-[10px] text-text-secondary space-y-0.5">
                    {clrlStatus.drift.drift_detected != null && (
                      <div>Drift Detected: <span className={clrlStatus.drift.drift_detected ? 'text-accent-red' : 'text-accent-green'}>{clrlStatus.drift.drift_detected ? 'Yes' : 'No'}</span></div>
                    )}
                    {clrlStatus.drift.p_value != null && (
                      <div>P-Value: <span className="text-text-primary font-mono">{clrlStatus.drift.p_value.toFixed(4)}</span></div>
                    )}
                  </div>
                </div>
              )}
              {clrlStatus.unified_fim && (
                <div className="bg-bg-primary rounded-lg p-3 border border-bg-card space-y-1">
                  <div className="text-xs font-medium text-accent-purple flex items-center gap-1">
                    <Save className="w-3.5 h-3.5" /> Fisher Information
                  </div>
                  <div className="text-[10px] text-text-secondary space-y-0.5">
                    {clrlStatus.unified_fim.status && (
                      <div>Status: <span className="text-text-primary">{clrlStatus.unified_fim.status}</span></div>
                    )}
                    {clrlStatus.unified_fim.n_params != null && (
                      <div>Parameters: <span className="text-text-primary font-mono">{clrlStatus.unified_fim.n_params?.toLocaleString()}</span></div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* RL Metrics History */}
      {rlMetrics && rlMetrics.total_episodes > 0 && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">
            <TrendingUp className="w-5 h-5 text-accent-green" />
            Cumulative RL Training Metrics
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-bg-primary rounded-lg p-3 border border-bg-card">
              <div className="text-[10px] text-text-secondary">Total Episodes</div>
              <div className="text-lg font-display font-bold text-accent-blue">{rlMetrics.total_episodes}</div>
            </div>
            {rlMetrics.avg_mitigation_rate != null && (
              <div className="bg-bg-primary rounded-lg p-3 border border-bg-card">
                <div className="text-[10px] text-text-secondary">Avg Mitigation Rate</div>
                <div className="text-lg font-display font-bold text-accent-green">{(rlMetrics.avg_mitigation_rate * 100).toFixed(1)}%</div>
              </div>
            )}
            {rlMetrics.avg_fp_rate != null && (
              <div className="bg-bg-primary rounded-lg p-3 border border-bg-card">
                <div className="text-[10px] text-text-secondary">Avg FP Rate</div>
                <div className="text-lg font-display font-bold text-accent-red">{(rlMetrics.avg_fp_rate * 100).toFixed(3)}%</div>
              </div>
            )}
            {rlMetrics.constraint_violation_rate != null && (
              <div className="bg-bg-primary rounded-lg p-3 border border-bg-card">
                <div className="text-[10px] text-text-secondary">Constraint Violation %</div>
                <div className="text-lg font-display font-bold text-accent-amber">{(rlMetrics.constraint_violation_rate * 100).toFixed(1)}%</div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Episode Details */}
      {mode === 'single' && result?.episodes && result.episodes.length > 0 && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <button
            onClick={() => setShowEpisodes(!showEpisodes)}
            className="w-full flex items-center justify-between"
          >
            <h2 className="text-lg font-display font-semibold flex items-center gap-2">
              <Activity className="w-5 h-5 text-text-secondary" />
              Episode Details ({result.episodes.length})
            </h2>
            {showEpisodes ? <ChevronUp className="w-5 h-5 text-text-secondary" /> : <ChevronDown className="w-5 h-5 text-text-secondary" />}
          </button>
          {showEpisodes && (
            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-text-secondary border-b border-bg-card">
                    <th className="px-2 py-2 text-left">Episode</th>
                    <th className="px-2 py-2 text-right">Reward</th>
                    <th className="px-2 py-2 text-right">Cost</th>
                    <th className="px-2 py-2 text-right">FP Rate</th>
                    <th className="px-2 py-2 text-right">Steps</th>
                    <th className="px-2 py-2 text-center">Constraint</th>
                  </tr>
                </thead>
                <tbody>
                  {result.episodes.map((ep: any) => (
                    <tr key={ep.episode} className="border-b border-bg-card/50">
                      <td className="px-2 py-2 font-mono text-accent-blue">#{ep.episode}</td>
                      <td className="px-2 py-2 text-right font-mono">{ep.total_reward?.toFixed(1)}</td>
                      <td className="px-2 py-2 text-right font-mono">{ep.total_cost?.toFixed(1)}</td>
                      <td className="px-2 py-2 text-right font-mono">{((ep.fp_blocking_rate ?? 0) * 100).toFixed(2)}%</td>
                      <td className="px-2 py-2 text-right">{ep.num_steps}</td>
                      <td className="px-2 py-2 text-center">
                        {ep.constraint_violated ? (
                          <span className="text-accent-red"><XCircle className="w-3 h-3 inline" /></span>
                        ) : (
                          <span className="text-accent-green"><CheckCircle2 className="w-3 h-3 inline" /></span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* How CPO Works */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold mb-3">How CPO Response Works</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs text-text-secondary">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-accent-blue font-medium text-sm">
              <div className="w-6 h-6 rounded-full bg-accent-blue/15 flex items-center justify-center text-accent-blue font-bold text-xs">1</div>
              State Construction
            </div>
            <p>
              The 55-dim state vector combines detection probabilities, epistemic/aleatoric uncertainty from MC Dropout,
              flow metadata, and contextual features (connection rate, CPU, memory).
            </p>
          </div>
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-accent-red font-medium text-sm">
              <div className="w-6 h-6 rounded-full bg-accent-red/15 flex items-center justify-center text-accent-red font-bold text-xs">2</div>
              Constrained Optimisation
            </div>
            <p>
              CPO maximises threat mitigation reward subject to: D_KL(pi || pi_old) &le; delta (trust region)
              and J_C(pi) &le; epsilon_fp (false-positive constraint &lt; 0.1%).
            </p>
          </div>
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-accent-green font-medium text-sm">
              <div className="w-6 h-6 rounded-full bg-accent-green/15 flex items-center justify-center text-accent-green font-bold text-xs">3</div>
              Graduated Response
            </div>
            <p>
              5 actions from Monitor (severity 0) to Quarantine (severity 5). Block/Quarantine require
              &gt;95% detection confidence. Actions auto-downgrade if confidence is insufficient.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
