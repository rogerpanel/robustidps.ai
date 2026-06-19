import { useState } from 'react'
import { Eye, Play, Loader2 } from 'lucide-react'
import PageGuide from '../../../components/PageGuide'
import DatasetSelector from '../components/DatasetSelector'
import { runPerceptionAttack } from '../api'
import type { AttackResult } from '../api'

export default function PerceptionTester() {
  const [attack, setAttack] = useState<'fgsm' | 'pgd'>('pgd')
  const [epsilon, setEpsilon] = useState(4 / 255)
  const [pgdSteps, setPgdSteps] = useState(20)
  const [sampleIdx, setSampleIdx] = useState(0)
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<AttackResult | null>(null)
  const [err, setErr] = useState<string | null>(null)

  const run = async () => {
    setRunning(true); setErr(null)
    try {
      const r = await runPerceptionAttack({ attack, epsilon, pgd_steps: pgdSteps, sample_index: sampleIdx })
      setResult(r)
    } catch (e) {
      setErr(String(e))
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-display font-bold flex items-center gap-2">
          <Eye className="w-5 h-5 text-accent-blue" /> Perception Tester
        </h1>
        <p className="text-xs text-text-secondary mt-1">
          White-box adversarial attacks (FGSM / PGD) on the M1 CT-TGNN run over the SyntheticTEXBAT
          8-satellite CAF graph. Phase-A surrogate of the YOLOv8/v10/DETR vision-perception page that
          chapter 6 §6.5.1 binds to the same kernel.
        </p>
      </div>

      <PageGuide
        title="How to use Perception Tester"
        steps={[
          { title: 'Pick a dataset', desc: 'Default is the SyntheticTEXBAT CAF batch. Switch to AU-AIR or VisDrone (badge shows what\'s loaded vs reference-only).' },
          { title: 'Choose attack family', desc: 'FGSM is single-step (fast, weak); PGD is iterative (stronger). Both are white-box.' },
          { title: 'Set ε and sample index', desc: 'ε is the L∞ perturbation budget (typical range 2/255–8/255); sample 0–63 selects which CAF graph to attack.' },
          { title: 'Run', desc: 'Result panel shows clean prediction → adversarial prediction; "fooled: YES" means the attack flipped the label.' },
          { title: 'Interpret L₂ / L∞', desc: 'Smaller perturbation that still flips the prediction = stronger attack. Compare FGSM vs PGD at the same ε.' },
        ]}
        tip="If 'fooled: NO' at ε=4/255 with PGD-20, the M1 CT-TGNN's Lipschitz bound is holding around that sample — see Certification Dashboard for the radius."
      />

      <DatasetSelector page="/uav/perception" />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-bg-card rounded-xl p-4 space-y-3">
          <h2 className="text-sm font-semibold">Attack configuration</h2>

          <div>
            <label className="text-xs text-text-secondary block mb-1">Attack family</label>
            <div className="flex gap-1">
              {(['fgsm', 'pgd'] as const).map((a) => (
                <button
                  key={a} onClick={() => setAttack(a)}
                  className={`px-3 py-1 rounded-md text-xs font-mono ${attack === a
                    ? 'bg-accent-blue text-white'
                    : 'bg-bg-secondary text-text-secondary hover:text-text-primary'}`}
                >
                  {a.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="text-xs text-text-secondary block mb-1">
              ε perturbation budget: <span className="font-mono text-text-primary">{epsilon.toFixed(4)}</span>
              <span className="ml-1 text-[10px]">({(epsilon * 255).toFixed(2)}/255)</span>
            </label>
            <input
              type="range" min={1 / 255} max={16 / 255} step={1 / 255}
              value={epsilon} onChange={(e) => setEpsilon(parseFloat(e.target.value))}
              className="w-full accent-accent-blue"
            />
          </div>

          {attack === 'pgd' && (
            <div>
              <label className="text-xs text-text-secondary block mb-1">
                PGD steps: <span className="font-mono text-text-primary">{pgdSteps}</span>
              </label>
              <input
                type="range" min={1} max={50} step={1}
                value={pgdSteps} onChange={(e) => setPgdSteps(parseInt(e.target.value, 10))}
                className="w-full accent-accent-blue"
              />
            </div>
          )}

          <div>
            <label className="text-xs text-text-secondary block mb-1">
              Sample index (0-63)
            </label>
            <input
              type="number" min={0} max={63} value={sampleIdx}
              onChange={(e) => setSampleIdx(parseInt(e.target.value || '0', 10))}
              className="w-full bg-bg-secondary border border-bg-card/60 rounded-md px-2 py-1 text-xs font-mono"
            />
          </div>

          <button
            onClick={run} disabled={running}
            className="w-full bg-accent-blue hover:bg-accent-blue/90 text-white px-3 py-2 rounded-md text-xs font-medium flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {running ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
            Run attack
          </button>
        </div>

        <div className="bg-bg-card rounded-xl p-4">
          <h2 className="text-sm font-semibold mb-2">Result</h2>
          {err && <div className="text-xs text-accent-red font-mono">{err}</div>}
          {result ? (
            <div className="space-y-2 text-xs font-mono">
              <ResultRow label="attack" value={result.attack.toUpperCase()} />
              <ResultRow label="ε" value={result.epsilon.toFixed(4)} />
              {result.attack === 'pgd' && <ResultRow label="PGD steps" value={String(result.pgd_steps)} />}
              <hr className="border-bg-card/40 my-1" />
              <ResultRow label="true label" value={String(result.true_label)} />
              <ResultRow label="clean prediction" value={String(result.clean_prediction)} />
              <ResultRow label="adv prediction" value={String(result.adversarial_prediction)}
                         emphasis={result.fooled ? 'red' : 'green'} />
              <ResultRow label="model fooled" value={result.fooled ? 'YES' : 'no'}
                         emphasis={result.fooled ? 'red' : 'green'} />
              <hr className="border-bg-card/40 my-1" />
              <ResultRow label="l2 distortion" value={result.l2_distortion.toFixed(4)} />
              <ResultRow label="l∞ distortion" value={result.linf_distortion.toFixed(4)} />
            </div>
          ) : (
            !err && <div className="text-xs text-text-secondary">Configure an attack and press Run.</div>
          )}
        </div>
      </div>
    </div>
  )
}

function ResultRow({ label, value, emphasis }: { label: string; value: string; emphasis?: 'red' | 'green' }) {
  const tone = emphasis === 'red' ? 'text-accent-red'
             : emphasis === 'green' ? 'text-accent-green'
             : 'text-text-primary'
  return (
    <div className="flex items-center justify-between">
      <span className="text-text-secondary">{label}</span>
      <span className={`font-semibold ${tone}`}>{value}</span>
    </div>
  )
}
