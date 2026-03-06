import { useEffect, useState, useRef } from 'react'
import {
  RefreshCw, Upload, TrendingUp, TrendingDown, AlertTriangle,
  CheckCircle2, Loader2, RotateCcw, Activity, Database,
  Zap, Shield, Clock, BarChart3, ChevronDown, ChevronUp,
} from 'lucide-react'
import {
  fetchContinualStatus, triggerContinualUpdate,
  measureDrift, rollbackModel,
} from '../utils/api'

interface UpdateRecord {
  update_id: string
  timestamp: number
  n_samples: number
  epochs: number
  ewc_lambda: number
  loss_before: number
  loss_after: number
  acc_before: number
  acc_after: number
  dataset_format: string
  replay_size: number
}

interface CLStatus {
  version: number
  total_samples_seen: number
  replay_buffer_size: number
  max_replay: number
  has_fisher: boolean
  can_rollback: boolean
  n_updates: number
  history: UpdateRecord[]
}

export default function ContinualLearning() {
  const [status, setStatus] = useState<CLStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  // Update form
  const [file, setFile] = useState<File | null>(null)
  const [epochs, setEpochs] = useState(5)
  const [lr, setLr] = useState(0.0001)
  const [ewcLambda, setEwcLambda] = useState(5000)
  const [updating, setUpdating] = useState(false)
  const [updateResult, setUpdateResult] = useState<string>('')
  const fileRef = useRef<HTMLInputElement>(null)

  // Drift measurement
  const [driftFile, setDriftFile] = useState<File | null>(null)
  const [measuring, setMeasuring] = useState(false)
  const [driftResult, setDriftResult] = useState<{accuracy: number; loss: number; recommendation: string} | null>(null)
  const driftFileRef = useRef<HTMLInputElement>(null)

  // Rollback
  const [rollingBack, setRollingBack] = useState(false)

  // Expanded history
  const [historyExpanded, setHistoryExpanded] = useState(false)

  const loadStatus = async () => {
    try {
      const data = await fetchContinualStatus()
      if (data.error) {
        setError(data.error)
      } else {
        setStatus(data)
        setError('')
      }
    } catch {
      setError('Failed to load continual learning status')
    }
    setLoading(false)
  }

  useEffect(() => { loadStatus() }, [])

  const handleUpdate = async () => {
    if (!file) return
    setUpdating(true)
    setUpdateResult('')
    setError('')
    try {
      const data = await triggerContinualUpdate(file, epochs, lr, ewcLambda)
      if (data.error || data.detail) {
        setError(data.error || data.detail)
      } else {
        setUpdateResult(data.message || `Model updated to v${data.version}`)
        setFile(null)
        if (fileRef.current) fileRef.current.value = ''
        await loadStatus()
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Update failed')
    }
    setUpdating(false)
  }

  const handleDrift = async () => {
    if (!driftFile) return
    setMeasuring(true)
    setDriftResult(null)
    try {
      const data = await measureDrift(driftFile)
      if (data.error || data.detail) {
        setError(data.error || data.detail)
      } else {
        setDriftResult(data)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Drift measurement failed')
    }
    setMeasuring(false)
  }

  const handleRollback = async () => {
    setRollingBack(true)
    try {
      const data = await rollbackModel()
      if (data.error) {
        setError(data.error)
      } else {
        setUpdateResult(data.message || 'Model rolled back')
        await loadStatus()
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Rollback failed')
    }
    setRollingBack(false)
  }

  const formatTime = (ts: number) => {
    const d = new Date(ts * 1000)
    return d.toLocaleString()
  }

  const pct = (v: number) => `${(v * 100).toFixed(1)}%`

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-2xl font-display font-bold flex items-center gap-2">
          <RefreshCw className="w-6 h-6 text-accent-purple" />
          Continual Learning
        </h1>
        <p className="text-sm text-text-secondary mt-1">
          Incrementally update the IDS model on new traffic data using Elastic Weight Consolidation (EWC) to prevent catastrophic forgetting.
        </p>
      </div>

      {error && (
        <div className="px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {error}
          <button onClick={() => setError('')} className="ml-auto text-xs hover:underline">dismiss</button>
        </div>
      )}

      {updateResult && (
        <div className="px-4 py-2 bg-accent-green/10 border border-accent-green/30 rounded-lg text-accent-green text-sm flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          {updateResult}
          <button onClick={() => setUpdateResult('')} className="ml-auto text-xs hover:underline">dismiss</button>
        </div>
      )}

      {loading ? (
        <div className="text-center py-12 text-text-secondary">
          <Loader2 className="w-8 h-8 mx-auto mb-3 animate-spin" />
          <p className="text-sm">Loading continual learning status...</p>
        </div>
      ) : (
        <>
          {/* Status cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="text-xs text-text-secondary mb-1 flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5" /> Model Version
              </div>
              <div className="text-2xl font-display font-bold text-accent-blue">
                v{status?.version ?? 0}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="text-xs text-text-secondary mb-1 flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5" /> Total Samples
              </div>
              <div className="text-2xl font-display font-bold text-accent-green">
                {(status?.total_samples_seen ?? 0).toLocaleString()}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="text-xs text-text-secondary mb-1 flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5" /> Replay Buffer
              </div>
              <div className="text-2xl font-display font-bold text-accent-amber">
                {(status?.replay_buffer_size ?? 0).toLocaleString()}
              </div>
              <div className="text-[10px] text-text-secondary">
                / {(status?.max_replay ?? 5000).toLocaleString()} max
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card">
              <div className="text-xs text-text-secondary mb-1 flex items-center gap-1.5">
                <Zap className="w-3.5 h-3.5" /> EWC Active
              </div>
              <div className="text-2xl font-display font-bold">
                {status?.has_fisher ? (
                  <span className="text-accent-green">Yes</span>
                ) : (
                  <span className="text-text-secondary">No</span>
                )}
              </div>
            </div>
          </div>

          {/* Main actions: Update + Drift side by side */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Incremental Update */}
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">
                <TrendingUp className="w-5 h-5 text-accent-blue" />
                Incremental Update
              </h2>
              <p className="text-xs text-text-secondary mb-4">
                Upload new labelled traffic data to fine-tune the model. EWC regularisation preserves knowledge from previous updates.
              </p>

              <div className="space-y-3">
                <div>
                  <label className="text-xs text-text-secondary block mb-1">Training Data (.csv)</label>
                  <input
                    ref={fileRef}
                    type="file"
                    accept=".csv,.pcap,.pcapng"
                    onChange={(e) => setFile(e.target.files?.[0] || null)}
                    className="w-full text-sm text-text-secondary file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-medium file:bg-accent-blue/15 file:text-accent-blue hover:file:bg-accent-blue/25 cursor-pointer"
                  />
                </div>

                <div className="grid grid-cols-3 gap-2">
                  <div>
                    <label className="text-[10px] text-text-secondary block mb-1">Epochs</label>
                    <input
                      type="number"
                      value={epochs}
                      onChange={(e) => setEpochs(Number(e.target.value))}
                      min={1}
                      max={50}
                      className="w-full px-2 py-1.5 bg-bg-primary border border-bg-card rounded text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent-blue/50"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] text-text-secondary block mb-1">Learning Rate</label>
                    <input
                      type="number"
                      value={lr}
                      onChange={(e) => setLr(Number(e.target.value))}
                      step={0.00001}
                      min={0.000001}
                      max={0.01}
                      className="w-full px-2 py-1.5 bg-bg-primary border border-bg-card rounded text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent-blue/50"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] text-text-secondary block mb-1">EWC Lambda</label>
                    <input
                      type="number"
                      value={ewcLambda}
                      onChange={(e) => setEwcLambda(Number(e.target.value))}
                      min={0}
                      max={100000}
                      step={500}
                      className="w-full px-2 py-1.5 bg-bg-primary border border-bg-card rounded text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent-blue/50"
                    />
                  </div>
                </div>

                <div className="flex items-start gap-2 text-[10px] text-text-secondary bg-bg-card/50 px-2 py-1.5 rounded">
                  <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5 text-accent-amber" />
                  Higher EWC lambda = more weight preservation (less forgetting, slower adaptation). Lower = faster adaptation but risk of forgetting.
                </div>

                <button
                  onClick={handleUpdate}
                  disabled={!file || updating}
                  className="w-full px-4 py-2.5 bg-accent-blue text-white rounded-lg text-xs font-medium hover:bg-accent-blue/80 disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  {updating ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" /> Updating model...
                    </>
                  ) : (
                    <>
                      <Upload className="w-4 h-4" /> Update Model
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Drift Measurement */}
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">
                <BarChart3 className="w-5 h-5 text-accent-amber" />
                Drift Detection
              </h2>
              <p className="text-xs text-text-secondary mb-4">
                Test the current model on new data to detect distribution shift before committing to an update.
              </p>

              <div className="space-y-3">
                <div>
                  <label className="text-xs text-text-secondary block mb-1">Test Data (.csv)</label>
                  <input
                    ref={driftFileRef}
                    type="file"
                    accept=".csv,.pcap,.pcapng"
                    onChange={(e) => setDriftFile(e.target.files?.[0] || null)}
                    className="w-full text-sm text-text-secondary file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-medium file:bg-accent-amber/15 file:text-accent-amber hover:file:bg-accent-amber/25 cursor-pointer"
                  />
                </div>

                <button
                  onClick={handleDrift}
                  disabled={!driftFile || measuring}
                  className="w-full px-4 py-2.5 bg-accent-amber text-white rounded-lg text-xs font-medium hover:bg-accent-amber/80 disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  {measuring ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" /> Measuring drift...
                    </>
                  ) : (
                    <>
                      <Activity className="w-4 h-4" /> Measure Drift
                    </>
                  )}
                </button>

                {driftResult && (
                  <div className={`p-4 rounded-lg border ${
                    driftResult.recommendation === 'stable'
                      ? 'bg-accent-green/5 border-accent-green/30'
                      : driftResult.recommendation === 'monitor'
                      ? 'bg-accent-amber/5 border-accent-amber/30'
                      : 'bg-accent-red/5 border-accent-red/30'
                  }`}>
                    <div className="grid grid-cols-2 gap-3 mb-3">
                      <div>
                        <div className="text-[10px] text-text-secondary">Accuracy</div>
                        <div className="text-lg font-bold font-display">
                          {pct(driftResult.accuracy)}
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] text-text-secondary">Loss</div>
                        <div className="text-lg font-bold font-display">
                          {driftResult.loss.toFixed(4)}
                        </div>
                      </div>
                    </div>
                    <div className={`text-xs font-medium px-2 py-1 rounded inline-flex items-center gap-1 ${
                      driftResult.recommendation === 'stable'
                        ? 'bg-accent-green/15 text-accent-green'
                        : driftResult.recommendation === 'monitor'
                        ? 'bg-accent-amber/15 text-accent-amber'
                        : 'bg-accent-red/15 text-accent-red'
                    }`}>
                      {driftResult.recommendation === 'stable' ? (
                        <><CheckCircle2 className="w-3 h-3" /> Stable — no update needed</>
                      ) : driftResult.recommendation === 'monitor' ? (
                        <><Activity className="w-3 h-3" /> Monitor — consider updating soon</>
                      ) : (
                        <><AlertTriangle className="w-3 h-3" /> Update recommended — significant drift detected</>
                      )}
                    </div>
                  </div>
                )}

                {/* Rollback button */}
                {status?.can_rollback && (
                  <div className="pt-3 border-t border-bg-card">
                    <button
                      onClick={handleRollback}
                      disabled={rollingBack}
                      className="w-full px-4 py-2 border border-accent-red/30 text-accent-red rounded-lg text-xs font-medium hover:bg-accent-red/10 disabled:opacity-50 flex items-center justify-center gap-2"
                    >
                      {rollingBack ? (
                        <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Rolling back...</>
                      ) : (
                        <><RotateCcw className="w-3.5 h-3.5" /> Rollback to Previous Version</>
                      )}
                    </button>
                    <p className="text-[10px] text-text-secondary mt-1 text-center">
                      Reverts the model to the state before the last update
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* How it works */}
          <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
            <h2 className="text-lg font-display font-semibold mb-3">How EWC Continual Learning Works</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs text-text-secondary">
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-accent-blue font-medium text-sm">
                  <div className="w-6 h-6 rounded-full bg-accent-blue/15 flex items-center justify-center text-accent-blue font-bold text-xs">1</div>
                  Fisher Information
                </div>
                <p>
                  After each update, the system computes the diagonal Fisher Information Matrix (FIM) for each model parameter.
                  This measures how important each weight is for classifying the current data.
                </p>
              </div>
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-accent-purple font-medium text-sm">
                  <div className="w-6 h-6 rounded-full bg-accent-purple/15 flex items-center justify-center text-accent-purple font-bold text-xs">2</div>
                  EWC Penalty
                </div>
                <p>
                  During fine-tuning on new data, a quadratic penalty prevents important weights from
                  changing too much: L = L_new + (lambda/2) * sum(F_i * (theta_i - theta*_i)^2).
                </p>
              </div>
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-accent-green font-medium text-sm">
                  <div className="w-6 h-6 rounded-full bg-accent-green/15 flex items-center justify-center text-accent-green font-bold text-xs">3</div>
                  Experience Replay
                </div>
                <p>
                  A bounded buffer retains representative samples from past tasks. These are mixed into new
                  training batches to further reinforce previously learned patterns.
                </p>
              </div>
            </div>
          </div>

          {/* Update History */}
          {status && status.history.length > 0 && (
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <button
                onClick={() => setHistoryExpanded(!historyExpanded)}
                className="w-full flex items-center justify-between"
              >
                <h2 className="text-lg font-display font-semibold flex items-center gap-2">
                  <Clock className="w-5 h-5 text-text-secondary" />
                  Update History ({status.history.length})
                </h2>
                {historyExpanded ? (
                  <ChevronUp className="w-5 h-5 text-text-secondary" />
                ) : (
                  <ChevronDown className="w-5 h-5 text-text-secondary" />
                )}
              </button>

              {historyExpanded && (
                <div className="mt-4 overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="text-text-secondary border-b border-bg-card">
                        <th className="px-2 py-2 text-left">Version</th>
                        <th className="px-2 py-2 text-left">Time</th>
                        <th className="px-2 py-2 text-right">Samples</th>
                        <th className="px-2 py-2 text-right">Epochs</th>
                        <th className="px-2 py-2 text-right">Lambda</th>
                        <th className="px-2 py-2 text-right">Acc Before</th>
                        <th className="px-2 py-2 text-right">Acc After</th>
                        <th className="px-2 py-2 text-center">Change</th>
                        <th className="px-2 py-2 text-left">Format</th>
                      </tr>
                    </thead>
                    <tbody>
                      {[...status.history].reverse().map((r, idx) => {
                        const accChange = r.acc_after - r.acc_before
                        const improved = accChange >= 0
                        return (
                          <tr key={r.update_id} className="border-b border-bg-card/50">
                            <td className="px-2 py-2 font-mono text-accent-blue">
                              v{status.history.length - idx}
                            </td>
                            <td className="px-2 py-2 text-text-secondary">
                              {formatTime(r.timestamp)}
                            </td>
                            <td className="px-2 py-2 text-right">{r.n_samples.toLocaleString()}</td>
                            <td className="px-2 py-2 text-right">{r.epochs}</td>
                            <td className="px-2 py-2 text-right font-mono">{r.ewc_lambda}</td>
                            <td className="px-2 py-2 text-right font-mono">{pct(r.acc_before)}</td>
                            <td className="px-2 py-2 text-right font-mono">{pct(r.acc_after)}</td>
                            <td className="px-2 py-2 text-center">
                              <span className={`inline-flex items-center gap-0.5 ${
                                improved ? 'text-accent-green' : 'text-accent-red'
                              }`}>
                                {improved ? (
                                  <TrendingUp className="w-3 h-3" />
                                ) : (
                                  <TrendingDown className="w-3 h-3" />
                                )}
                                {improved ? '+' : ''}{(accChange * 100).toFixed(1)}%
                              </span>
                            </td>
                            <td className="px-2 py-2 text-text-secondary">{r.dataset_format}</td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* Accuracy trend chart (simple bar visualization) */}
          {status && status.history.length > 1 && (
            <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
              <h2 className="text-lg font-display font-semibold mb-4">Accuracy Trend</h2>
              <div className="flex items-end gap-1 h-32">
                {status.history.map((r, idx) => {
                  const barH = Math.max(r.acc_after * 100, 5)
                  const improved = r.acc_after >= r.acc_before
                  return (
                    <div key={r.update_id} className="flex-1 flex flex-col items-center gap-1" title={`v${idx + 1}: ${pct(r.acc_after)}`}>
                      <span className="text-[9px] text-text-secondary font-mono">{pct(r.acc_after)}</span>
                      <div
                        className={`w-full rounded-t transition-all ${
                          improved ? 'bg-accent-green/60' : 'bg-accent-red/60'
                        }`}
                        style={{ height: `${barH}%` }}
                      />
                      <span className="text-[9px] text-text-secondary">v{idx + 1}</span>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
