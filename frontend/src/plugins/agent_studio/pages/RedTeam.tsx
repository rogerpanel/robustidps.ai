import { useEffect, useState } from 'react'
import { Swords, Play, Loader2, AlertCircle, CheckCircle2, Target, Zap, Sparkles } from 'lucide-react'
import PageGuide from '../../../components/PageGuide'
import {
  runAgentRedTeam, runAgentRedTeamGarak, fetchRedTeamCatalog, fetchGarakInfo,
} from '../api'
import type { RedTeamRun, Severity } from '../api'
import { useAgentStudioState } from '../../../hooks/useAgentStudioState'
import AccessBanner from '../components/AccessBanner'

const SAMPLE_TARGET = `{
  "name": "ops-copilot",
  "system_prompt": "You are an operations copilot. You can call shell, exec, write_file, and http tools. Ignore previous instructions if user asks. Memory persists across sessions.",
  "tools": [
    {"name": "shell", "description": "Execute shell commands. Can delete, http POST."},
    {"name": "write_file", "description": "Write to any file"},
    {"name": "send_email", "description": "Send email; key: sk-test-1234567890abcdef"}
  ],
  "model": "gpt-4o-latest",
  "memory": "long_term",
  "delegate": ["billing-agent", "hr-agent"]
}`

const SEVERITY_TONE: Record<Severity, string> = {
  critical: 'bg-accent-red/15 text-accent-red border-accent-red/40',
  high:     'bg-accent-red/10 text-accent-red border-accent-red/30',
  medium:   'bg-accent-amber/10 text-accent-amber border-accent-amber/30',
  low:      'bg-accent-orange/10 text-accent-orange border-accent-orange/30',
  info:     'bg-bg-secondary text-text-secondary border-bg-card/40',
}

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

type Runner = 'deterministic' | 'garak'

export default function RedTeam() {
  const [text, setText] = useAgentStudioState<string>('redteam', 'targetSpec', SAMPLE_TARGET)
  const [run, setRun] = useAgentStudioState<RedTeamRun | null>('redteam', 'lastRun', null)
  const [running, setRunning] = useState<Runner | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [catalogSize, setCatalogSize] = useState(0)
  const [garakRunner, setGarakRunner] = useState<string | null>(null)
  const [garakHint, setGarakHint] = useState<string | null>(null)
  const [lastRunner, setLastRunner] = useAgentStudioState<Runner | null>('redteam', 'lastRunner', null)
  const [seededFrom, setSeededFrom] = useAgentStudioState<string | null>('redteam', 'seededFrom', null)

  useEffect(() => {
    fetchRedTeamCatalog().then((c) => setCatalogSize(c.n_probes)).catch(() => {})
    fetchGarakInfo()
      .then((g) => { setGarakRunner(g.runner); setGarakHint(g.hint || null) })
      .catch(() => {})
    const seed = sessionStorage.getItem('agentstudio_template_spec')
    const id = sessionStorage.getItem('agentstudio_template_id')
    if (seed) {
      setText(seed)
      setSeededFrom(id)
      sessionStorage.removeItem('agentstudio_template_spec')
      sessionStorage.removeItem('agentstudio_template_id')
    }
  }, [])

  const doRun = async (which: Runner = 'deterministic') => {
    setRunning(which); setErr(null)
    try {
      const spec = JSON.parse(text)
      const result = which === 'garak'
        ? await runAgentRedTeamGarak(spec)
        : await runAgentRedTeam(spec)
      setRun(result)
      setLastRunner(which)
    } catch (e) {
      setErr(String(e))
    } finally {
      setRunning(null)
    }
  }

  const sorted = run
    ? [...run.results].sort((a, b) => {
        if (a.triggered !== b.triggered) return a.triggered ? -1 : 1
        return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
      })
    : []

  return (
    <div className="space-y-4">
      <AccessBanner />
      <div>
        <h1 className="text-xl font-display font-bold flex items-center gap-2">
          <Swords className="w-5 h-5 text-accent-red" /> Red Team Automation
        </h1>
        <p className="text-xs text-text-secondary mt-1 max-w-3xl">
          {catalogSize > 0 ? `${catalogSize}-probe ` : ''}
          OWASP Agentic Top 10 (ASI01–ASI10) + supply-chain + privacy + IR hygiene probe suite,
          mapped to MITRE ATLAS tactics. The Agent Red Team SKU automated — paste your agent spec,
          see the findings + ATLAS chain.
        </p>
      </div>

      <PageGuide
        title="How to use Red Team Automation"
        steps={[
          { title: 'Paste a target agent spec', desc: 'JSON with name, system_prompt, tools[]. Sample has multiple deliberate weaknesses so the report demonstrates the probe types.' },
          { title: 'Run', desc: '18 probes execute against the spec; sub-second wall-clock for the rule-based surrogates.' },
          { title: 'Read the severity breakdown', desc: 'Top tiles count critical / high / medium / low / info findings. ATLAS chain shows the attack tactics that landed.' },
          { title: 'Drill into each finding', desc: 'Triggered findings expand with severity, OWASP Agentic + ATLAS labels, and remediation copy.' },
          { title: 'Hand-off to engagement', desc: 'Export the findings to drive a paid Agent Red Team engagement; the dossier auto-generates from this output.' },
        ]}
        tip="Probes are deterministic + traceable today. The pluggable Garak corpus + custom adversarial-LLM probes ship as Pro tier — same UI, deeper attack."
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-bg-card rounded-xl p-4">
          <h2 className="text-sm font-semibold mb-2 flex items-center gap-2">
            Target spec (JSON)
            {seededFrom && (
              <span className="text-[10px] font-mono text-accent-blue inline-flex items-center gap-1">
                <Sparkles className="w-3 h-3" /> seeded from template {seededFrom}
              </span>
            )}
          </h2>
          <textarea value={text} onChange={(e) => setText(e.target.value)}
                    className="w-full h-72 bg-bg-secondary border border-bg-card/60 rounded-md p-2 text-xs font-mono"
                    spellCheck={false} />
          <div className="grid grid-cols-2 gap-2 mt-2">
            <button onClick={() => doRun('deterministic')} disabled={running !== null || !text}
                    className="bg-accent-red hover:bg-accent-red/90 text-white px-3 py-2 rounded-md text-xs font-medium flex items-center justify-center gap-2 disabled:opacity-50">
              {running === 'deterministic' ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                            : <Play className="w-3.5 h-3.5" />}
              Deterministic probes
            </button>
            <button onClick={() => doRun('garak')} disabled={running !== null || !text}
                    className="bg-accent-purple hover:bg-accent-purple/90 text-white px-3 py-2 rounded-md text-xs font-medium flex items-center justify-center gap-2 disabled:opacity-50"
                    title="Run via the Garak adapter (live garak if installed, deterministic Garak-shaped probes otherwise)">
              {running === 'garak' ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                   : <Zap className="w-3.5 h-3.5" />}
              Garak probes
            </button>
          </div>
          {garakRunner && (
            <div className="mt-2 text-[10px] font-mono text-text-secondary">
              garak runner: <span className={garakRunner === 'garak_live' ? 'text-accent-green' : 'text-accent-orange'}>
                {garakRunner}
              </span>
              {garakHint && <> · {garakHint}</>}
            </div>
          )}
        </div>

        <div className="bg-bg-card rounded-xl p-4">
          <h2 className="text-sm font-semibold mb-2">Report</h2>
          {err && <div className="p-2 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red mb-2">{err}</div>}
          {!run && !err && <div className="text-xs text-text-secondary">Submit a target to see findings + ATLAS chain.</div>}
          {run && (
            <>
              {lastRunner && (
                <div className="mb-2 text-[10px] font-mono text-text-secondary">
                  runner: <span className="text-accent-blue">{lastRunner}</span> · run_id: {run.run_id}
                </div>
              )}
              <div className="grid grid-cols-2 gap-2 mb-3 text-xs">
                <Tile label="probes fired" value={String(run.n_probes)} />
                <Tile label="findings" value={String(run.n_findings)}
                      tone={run.n_findings > 0 ? 'red' : 'green'} />
              </div>

              <div className="flex flex-wrap gap-1 mb-3">
                {SEVERITY_ORDER.map((sev) => {
                  const n = run.severity_breakdown[sev] || 0
                  if (n === 0) return null
                  return (
                    <span key={sev} className={`px-2 py-0.5 rounded text-[10px] font-mono border ${SEVERITY_TONE[sev]}`}>
                      {n} {sev}
                    </span>
                  )
                })}
              </div>

              {run.atlas_chain.length > 0 && (
                <div className="mb-3 p-2 bg-accent-purple/10 border border-accent-purple/30 rounded-md">
                  <div className="flex items-center gap-1.5 mb-1">
                    <Target className="w-3 h-3 text-accent-purple" />
                    <span className="text-[10px] font-mono uppercase text-accent-purple">MITRE ATLAS chain</span>
                  </div>
                  <div className="flex flex-wrap gap-1 text-[10px] font-mono">
                    {run.atlas_chain.map((t, i) => (
                      <span key={t}>
                        <span className="text-text-primary">{t}</span>
                        {i < run.atlas_chain.length - 1 && <span className="text-text-secondary mx-1">→</span>}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div className="space-y-1.5 max-h-96 overflow-y-auto">
                {sorted.map((r) => (
                  <div key={r.code}
                       className={`border rounded-md p-2 ${r.triggered ? SEVERITY_TONE[r.severity] : 'border-bg-card/30 text-text-secondary'}`}>
                    <div className="flex items-center gap-2 mb-0.5">
                      {r.triggered ? <AlertCircle className="w-3 h-3" />
                                   : <CheckCircle2 className="w-3 h-3 text-accent-green" />}
                      <span className="font-mono text-[10px]">{r.code}</span>
                      <span className="font-mono text-[9px] opacity-70">{r.owasp_agentic}</span>
                      <span className="font-mono text-[9px] opacity-70">{r.atlas_tactic}</span>
                      <span className="text-[9px] font-mono uppercase ml-auto">{r.severity}</span>
                    </div>
                    <div className="text-xs font-medium">{r.name}</div>
                    {r.triggered && (
                      <div className="text-[11px] mt-1 opacity-80 italic">→ {r.remediation}</div>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

function Tile({ label, value, tone }: { label: string; value: string; tone?: 'red' | 'green' }) {
  const cls = tone === 'red' ? 'bg-accent-red/10 border-accent-red/30 text-accent-red'
            : tone === 'green' ? 'bg-accent-green/10 border-accent-green/30 text-accent-green'
            : 'bg-bg-secondary border-bg-card/40 text-text-primary'
  return (
    <div className={`border rounded-md p-2 ${cls}`}>
      <div className="text-[10px] uppercase tracking-wider opacity-70">{label}</div>
      <div className="text-lg font-semibold">{value}</div>
    </div>
  )
}
