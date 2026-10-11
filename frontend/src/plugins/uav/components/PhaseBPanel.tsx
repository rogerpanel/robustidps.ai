import { useEffect, useState } from 'react'
import { Layers, Cpu, Sparkles, AlertCircle, Play, Loader2 } from 'lucide-react'

const API = import.meta.env.VITE_API_URL || ''

interface PhaseBStatus {
  phase: string
  stages: {
    automl: {
      status: 'ready' | 'not_run'
      models_searched: string[]
      best_per_model: Record<string, { value: number; params: Record<string, unknown> }>
    }
    onnx_export: {
      status: 'ready' | 'not_run'
      models_exported: string[]
      edge_target_ms_per_frame: number
      results: Record<string, {
        median_latency_ms: number
        p95_latency_ms: number
        meets_edge_target: boolean
        round_trip_ok: boolean
      }>
    }
    progressive_distillation: {
      status: string
      target_cw_kappa5_robust_acc: number
      phase_a_baseline: number
      curriculum_eps_255: number[]
      module: string
      runner_hint: string
    }
  }
}

export default function PhaseBPanel() {
  const [status, setStatus] = useState<PhaseBStatus | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [running, setRunning] = useState<string | null>(null)

  const reload = () => fetch(`${API}/api/uav/phase-b/status`)
    .then((r) => { if (!r.ok) throw new Error(`status ${r.status}`); return r.json() })
    .then(setStatus)
    .catch((e) => setErr(String(e)))

  useEffect(() => { reload() }, [])

  const runAction = async (label: string, url: string) => {
    setRunning(label); setErr(null)
    try {
      const r = await fetch(`${API}${url}`, { method: 'POST' })
      if (!r.ok) throw new Error(`${url} → ${r.status}`)
      await r.json()
      await reload()
    } catch (e) {
      setErr(String(e))
    } finally {
      setRunning(null)
    }
  }

  if (err) return (
    <div className="bg-bg-card rounded-xl p-4">
      <div className="text-xs text-accent-red flex items-center gap-1.5">
        <AlertCircle className="w-3.5 h-3.5" /> Phase B endpoint error: {err}
      </div>
    </div>
  )
  if (!status) return null

  const automl = status.stages.automl
  const onnx = status.stages.onnx_export
  const distill = status.stages.progressive_distillation

  return (
    <div className="bg-bg-card rounded-xl p-4">
      <h2 className="text-sm font-semibold mb-2 flex items-center gap-1.5">
        <Layers className="w-3.5 h-3.5 text-accent-orange" /> Phase B status (chapter 6 §6.4 roadmap)
      </h2>
      <p className="text-[10px] text-text-secondary mb-3">
        AutoML (Optuna) + ONNX export with edge-latency benchmark + progressive adversarial distillation —
        the chapter-6 trio that turns Phase A into a deployable airframe-edge artefact.
      </p>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <StageCard
          icon={<Sparkles className="w-3.5 h-3.5 text-accent-blue" />}
          title="AutoML (Optuna)"
          status={automl.status}
          action={
            <RunButton label="automl" running={running}
                       onRun={() => runAction('automl', '/api/uav/phase-b/automl/run?model_kind=ct_tgnn&n_trials=8')} />
          }
          body={
            automl.status === 'ready' ? (
              <div className="space-y-1 text-[11px] font-mono">
                {Object.entries(automl.best_per_model).map(([m, v]) => (
                  <div key={m}>
                    <div className="text-text-primary">{m}</div>
                    <div className="text-text-secondary pl-2">
                      best robust acc: <span className="text-accent-green">{v.value.toFixed(3)}</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-[11px] text-text-secondary">
                No trials run yet — click <em>Run</em> to launch 8 Optuna trials live (~5 min CPU).
              </div>
            )
          }
        />

        <StageCard
          icon={<Cpu className="w-3.5 h-3.5 text-accent-blue" />}
          title={`ONNX (target ≤${onnx.edge_target_ms_per_frame} ms)`}
          status={onnx.status}
          action={
            <RunButton label="onnx" running={running}
                       onRun={() => runAction('onnx', '/api/uav/phase-b/onnx/export?model_kind=ct_tgnn')} />
          }
          body={
            onnx.status === 'ready' ? (
              <div className="space-y-1 text-[11px] font-mono">
                {Object.entries(onnx.results).map(([m, v]) => (
                  <div key={m}>
                    <div className="text-text-primary">{m}</div>
                    <div className="pl-2">
                      <span className="text-text-secondary">median: </span>
                      <span className={v.meets_edge_target ? 'text-accent-green' : 'text-accent-red'}>
                        {v.median_latency_ms.toFixed(2)} ms
                      </span>
                      <span className="text-text-secondary"> · p95: {v.p95_latency_ms.toFixed(2)} ms</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-[11px] text-text-secondary">
                Not exported yet — click <em>Run</em> to export the current checkpoint + benchmark (~30 s).
              </div>
            )
          }
        />

        <StageCard
          icon={<Sparkles className="w-3.5 h-3.5 text-accent-orange" />}
          title="Progressive distillation"
          status={distill.status}
          body={
            <div className="text-[11px] font-mono space-y-1">
              <div>
                target CW κ=5: <span className="text-accent-green">{distill.target_cw_kappa5_robust_acc}</span>
              </div>
              <div className="text-text-secondary">
                Phase A baseline: {distill.phase_a_baseline.toFixed(2)}
              </div>
              <div className="text-text-secondary">
                curriculum ε (×255): {distill.curriculum_eps_255.join(' → ')}
              </div>
              <div className="text-[10px] text-text-secondary italic mt-1">
                {distill.runner_hint}
              </div>
            </div>
          }
        />
      </div>
    </div>
  )
}

function StageCard({ icon, title, status, body, action }: {
  icon: React.ReactNode; title: string; status: string; body: React.ReactNode; action?: React.ReactNode
}) {
  const statusTone =
    status === 'ready' ? 'bg-accent-green/10 text-accent-green border-accent-green/30'
    : status === 'framework_ready' ? 'bg-accent-amber/10 text-accent-amber border-accent-amber/30'
    : 'bg-bg-secondary text-text-secondary border-bg-card/40'

  return (
    <div className="border border-bg-card/40 rounded-md p-3">
      <div className="flex items-center justify-between mb-2 gap-1">
        <div className="flex items-center gap-1.5">
          {icon}
          <span className="text-xs font-semibold">{title}</span>
        </div>
        <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono border uppercase ${statusTone}`}>
          {status.replace('_', ' ')}
        </span>
      </div>
      {body}
      {action && <div className="mt-2 pt-2 border-t border-bg-card/40">{action}</div>}
    </div>
  )
}

function RunButton({ label, running, onRun }: { label: string; running: string | null; onRun: () => void }) {
  const isRunning = running === label
  const anyRunning = running !== null
  return (
    <button onClick={onRun} disabled={anyRunning}
            className={`w-full flex items-center justify-center gap-1 px-2 py-1 rounded text-[10px] font-medium ${
              isRunning ? 'bg-accent-amber text-white' :
              anyRunning ? 'bg-bg-secondary text-text-secondary' :
              'bg-accent-blue text-white hover:bg-accent-blue/90'
            }`}>
      {isRunning
        ? <><Loader2 className="w-3 h-3 animate-spin" /> running…</>
        : <><Play className="w-3 h-3" /> Run now</>}
    </button>
  )
}
