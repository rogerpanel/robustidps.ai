import { useEffect, useState } from 'react'
import { Eye, Play, Loader2 } from 'lucide-react'
import PageGuide from '../../../components/PageGuide'
import ExportMenu from '../../../components/ExportMenu'
import DatasetSelector from '../components/DatasetSelector'
import { runPerceptionAttack, fetchAttackCatalog } from '../api'
import type { AttackResult, AttackCatalogEntry } from '../api'

interface HyperParams {
  epsilon: number
  pgd_steps: number
  sample_index: number
  cw_kappa: number
  cw_c: number
  cw_steps: number
  deepfool_max_iter: number
  hsj_queries: number
  boundary_steps: number
  gaussian_sigma: number
  mask_fraction: number
  label_flip_fraction: number
}

const DEFAULTS: HyperParams = {
  epsilon: 4 / 255,
  pgd_steps: 20,
  sample_index: 0,
  cw_kappa: 5.0,
  cw_c: 1.0,
  cw_steps: 100,
  deepfool_max_iter: 50,
  hsj_queries: 200,
  boundary_steps: 100,
  gaussian_sigma: 0.05,
  mask_fraction: 0.2,
  label_flip_fraction: 0.1,
}

const KIND_COLOR: Record<string, string> = {
  white_box: 'bg-accent-red/10 text-accent-red border-accent-red/30',
  black_box: 'bg-accent-purple/10 text-accent-purple border-accent-purple/30',
  baseline:  'bg-accent-blue/10 text-accent-blue border-accent-blue/30',
  training:  'bg-accent-amber/10 text-accent-amber border-accent-amber/30',
}

export default function PerceptionTester() {
  const [catalog, setCatalog] = useState<AttackCatalogEntry[]>([])
  const [attack, setAttack] = useState<string>('pgd')
  const [hp, setHp] = useState<HyperParams>(DEFAULTS)
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<AttackResult | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    fetchAttackCatalog().then((d) => setCatalog(d.attacks)).catch(() => {})
  }, [])

  const run = async () => {
    setRunning(true); setErr(null)
    try {
      const body: Record<string, unknown> = { attack, sample_index: hp.sample_index }
      // Send only the hyperparams the chosen attack uses (keeps the
      // request payload focused; backend ignores unknown keys safely)
      if (attack === 'fgsm' || attack === 'pgd' || attack === 'deepfool')
        body.epsilon = hp.epsilon
      if (attack === 'pgd') body.pgd_steps = hp.pgd_steps
      if (attack === 'cw') {
        body.cw_kappa = hp.cw_kappa; body.cw_c = hp.cw_c; body.cw_steps = hp.cw_steps
      }
      if (attack === 'deepfool') body.deepfool_max_iter = hp.deepfool_max_iter
      if (attack === 'hop_skip_jump') body.hsj_queries = hp.hsj_queries
      if (attack === 'boundary') body.boundary_steps = hp.boundary_steps
      if (attack === 'gaussian') body.gaussian_sigma = hp.gaussian_sigma
      if (attack === 'feature_mask') body.mask_fraction = hp.mask_fraction
      if (attack === 'label_flip') body.label_flip_fraction = hp.label_flip_fraction
      setResult(await runPerceptionAttack(body))
    } catch (e) {
      setErr(String(e))
    } finally {
      setRunning(false)
    }
  }

  const current = catalog.find((a) => a.id === attack)

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-display font-bold flex items-center gap-2">
            <Eye className="w-5 h-5 text-accent-blue" /> Perception Tester
          </h1>
          <p className="text-xs text-text-secondary mt-1">
            Nine attack families across white-box / black-box / baseline / training-time categories.
            M1 CT-TGNN on the SyntheticTEXBAT 8-satellite CAF graph.
            Phase-A surrogate of the YOLOv8/v10/DETR vision-perception page chapter 6 §6.5.1 binds to.
          </p>
        </div>
        <ExportMenu filename="uav-perception-tester" />
      </div>

      <PageGuide
        title="How to use Perception Tester"
        steps={[
          { title: 'Pick a dataset', desc: 'Default is the SyntheticTEXBAT CAF batch. Switch to AU-AIR or other datasets (badge shows tier).' },
          { title: 'Pick an attack family', desc: 'Tabs are grouped by kind: white-box (gradient access) / black-box (decision queries) / baseline / training-time.' },
          { title: 'Tune hyperparameters', desc: 'The form changes per-attack — only the params that matter for the chosen attack appear.' },
          { title: 'Run', desc: 'Result panel shows clean vs adversarial prediction + confidence; L2 / L∞ distortion; "fooled: YES" means label flipped.' },
          { title: 'Compare attacks', desc: 'Stronger attacks (PGD > FGSM, CW > DeepFool) achieve lower distortion for the same fool rate. Baselines should rarely fool the model.' },
        ]}
        tip="C&W κ=5 is the chapter-6 stress test that exposes the Phase-A distillation gap — it flips the prediction with the smallest perturbation budget of all attacks."
      />

      <DatasetSelector page="/uav/perception" />

      {/* Attack catalog — tabbed by kind */}
      <div className="bg-bg-card rounded-xl p-4">
        <h2 className="text-sm font-semibold mb-2">Attack family</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
          {catalog.map((a) => (
            <button
              key={a.id}
              onClick={() => setAttack(a.id)}
              className={`text-left p-2 rounded-md border transition-colors ${
                attack === a.id
                  ? 'bg-accent-blue text-white border-accent-blue'
                  : 'bg-bg-secondary border-bg-card/40 hover:border-accent-blue/40'
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold">{a.label}</span>
                <span className={`text-[9px] font-mono uppercase px-1.5 py-0.5 rounded border ${
                  attack === a.id ? 'bg-white/20 text-white border-white/30' : KIND_COLOR[a.kind]
                }`}>{a.kind}</span>
              </div>
              <div className={`text-[10px] mt-0.5 ${attack === a.id ? 'text-white/80' : 'text-text-secondary'}`}>
                {a.desc}
              </div>
            </button>
          ))}
        </div>
        {current && (
          <p className="text-[10px] text-text-secondary mt-3 italic">
            Active: <span className="font-mono">{current.id}</span> · {current.desc}
          </p>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-bg-card rounded-xl p-4 space-y-3">
          <h2 className="text-sm font-semibold">Hyperparameters</h2>

          {/* Common: sample index */}
          <NumberField label="Sample index (0-63)" value={hp.sample_index} min={0} max={63}
                       onChange={(v) => setHp({ ...hp, sample_index: v })} />

          {(attack === 'fgsm' || attack === 'pgd' || attack === 'deepfool') && (
            <RangeField label="ε perturbation budget" value={hp.epsilon} min={1 / 255} max={16 / 255} step={1 / 255}
                        suffix={`(${(hp.epsilon * 255).toFixed(2)}/255)`}
                        onChange={(v) => setHp({ ...hp, epsilon: v })} />
          )}
          {attack === 'pgd' && (
            <RangeField label="PGD steps" value={hp.pgd_steps} min={1} max={50} step={1}
                        onChange={(v) => setHp({ ...hp, pgd_steps: Math.round(v) })} />
          )}
          {attack === 'cw' && (
            <>
              <RangeField label="C&W κ (confidence)" value={hp.cw_kappa} min={0} max={20} step={1}
                          onChange={(v) => setHp({ ...hp, cw_kappa: Math.round(v) })} />
              <RangeField label="C&W c (trade-off)" value={hp.cw_c} min={0.01} max={10} step={0.01}
                          onChange={(v) => setHp({ ...hp, cw_c: v })} />
              <RangeField label="C&W optimisation steps" value={hp.cw_steps} min={10} max={500} step={10}
                          onChange={(v) => setHp({ ...hp, cw_steps: Math.round(v) })} />
            </>
          )}
          {attack === 'deepfool' && (
            <RangeField label="DeepFool max iters" value={hp.deepfool_max_iter} min={5} max={200} step={5}
                        onChange={(v) => setHp({ ...hp, deepfool_max_iter: Math.round(v) })} />
          )}
          {attack === 'hop_skip_jump' && (
            <RangeField label="Query budget" value={hp.hsj_queries} min={50} max={2000} step={50}
                        onChange={(v) => setHp({ ...hp, hsj_queries: Math.round(v) })} />
          )}
          {attack === 'boundary' && (
            <RangeField label="BoundaryAttack steps" value={hp.boundary_steps} min={10} max={500} step={10}
                        onChange={(v) => setHp({ ...hp, boundary_steps: Math.round(v) })} />
          )}
          {attack === 'gaussian' && (
            <RangeField label="σ (noise std)" value={hp.gaussian_sigma} min={0.01} max={1.0} step={0.01}
                        onChange={(v) => setHp({ ...hp, gaussian_sigma: v })} />
          )}
          {attack === 'feature_mask' && (
            <RangeField label="Mask fraction" value={hp.mask_fraction} min={0.05} max={0.95} step={0.05}
                        onChange={(v) => setHp({ ...hp, mask_fraction: v })} />
          )}
          {attack === 'label_flip' && (
            <RangeField label="Flip fraction" value={hp.label_flip_fraction} min={0.05} max={1.0} step={0.05}
                        onChange={(v) => setHp({ ...hp, label_flip_fraction: v })} />
          )}

          <button onClick={run} disabled={running}
                  className="w-full bg-accent-blue hover:bg-accent-blue/90 text-white px-3 py-2 rounded-md text-xs font-medium flex items-center justify-center gap-2 disabled:opacity-50">
            {running ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
            Run {current?.label ?? attack}
          </button>
        </div>

        <div className="bg-bg-card rounded-xl p-4">
          <h2 className="text-sm font-semibold mb-2">Result</h2>
          {err && <div className="text-xs text-accent-red font-mono">{err}</div>}
          {result ? (
            result.is_training_time ? (
              <div className="space-y-1.5 text-xs font-mono">
                <ResultRow label="attack" value={result.attack.toUpperCase()} />
                <ResultRow label="flip fraction" value={String(result.label_flip_fraction)} />
                <ResultRow label="true label" value={String(result.true_label)} />
                <ResultRow label="flipped label" value={String(result.flipped_label)}
                           emphasis={result.label_changed ? 'red' : 'green'} />
                <ResultRow label="label changed" value={result.label_changed ? 'YES' : 'no'}
                           emphasis={result.label_changed ? 'red' : 'green'} />
                <hr className="border-bg-card/40 my-1" />
                <ResultRow label="clean prediction" value={String(result.clean_prediction ?? '')} />
                <ResultRow label="clean confidence" value={(result.clean_confidence ?? 0).toFixed(3)} />
                {result.hint && <p className="text-[10px] text-text-secondary italic mt-2">{result.hint}</p>}
              </div>
            ) : (
              <div className="space-y-1.5 text-xs font-mono">
                <ResultRow label="attack" value={result.attack.toUpperCase()} />
                <ResultRow label="true label" value={String(result.true_label)} />
                <ResultRow label="clean prediction" value={String(result.clean_prediction ?? '')} />
                <ResultRow label="clean confidence" value={(result.clean_confidence ?? 0).toFixed(3)} />
                <hr className="border-bg-card/40 my-1" />
                <ResultRow label="adv prediction" value={String(result.adversarial_prediction ?? '')}
                           emphasis={result.fooled ? 'red' : 'green'} />
                <ResultRow label="adv confidence" value={(result.adversarial_confidence ?? 0).toFixed(3)} />
                <ResultRow label="fooled" value={result.fooled ? 'YES' : 'no'}
                           emphasis={result.fooled ? 'red' : 'green'} />
                <hr className="border-bg-card/40 my-1" />
                <ResultRow label="L₂ distortion"  value={(result.l2_distortion  ?? 0).toFixed(4)} />
                <ResultRow label="L∞ distortion" value={(result.linf_distortion ?? 0).toFixed(4)} />
                <ResultRow label="confidence drop" value={(result.confidence_drop ?? 0).toFixed(3)} />
              </div>
            )
          ) : (
            !err && <div className="text-xs text-text-secondary">Configure an attack and press Run.</div>
          )}
        </div>
      </div>
    </div>
  )
}

function NumberField({ label, value, min, max, onChange }: {
  label: string; value: number; min: number; max: number; onChange: (v: number) => void
}) {
  return (
    <div>
      <label className="text-xs text-text-secondary block mb-1">{label}</label>
      <input type="number" min={min} max={max} value={value}
             onChange={(e) => onChange(parseInt(e.target.value || '0', 10))}
             className="w-full bg-bg-secondary border border-bg-card/60 rounded-md px-2 py-1 text-xs font-mono" />
    </div>
  )
}

function RangeField({ label, value, min, max, step, suffix, onChange }: {
  label: string; value: number; min: number; max: number; step: number; suffix?: string; onChange: (v: number) => void
}) {
  return (
    <div>
      <label className="text-xs text-text-secondary block mb-1">
        {label}: <span className="font-mono text-text-primary">{typeof value === 'number' ? value.toFixed(value < 1 ? 4 : 0) : value}</span>
        {suffix && <span className="ml-1 text-[10px]">{suffix}</span>}
      </label>
      <input type="range" min={min} max={max} step={step} value={value}
             onChange={(e) => onChange(parseFloat(e.target.value))}
             className="w-full accent-accent-blue" />
    </div>
  )
}

function ResultRow({ label, value, emphasis }: { label: string; value: string; emphasis?: 'red' | 'green' }) {
  const tone = emphasis === 'red' ? 'text-accent-red' : emphasis === 'green' ? 'text-accent-green' : 'text-text-primary'
  return (
    <div className="flex items-center justify-between">
      <span className="text-text-secondary">{label}</span>
      <span className={`font-semibold ${tone}`}>{value}</span>
    </div>
  )
}
