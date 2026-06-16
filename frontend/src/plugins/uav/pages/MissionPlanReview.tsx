import { useState } from 'react'
import { ClipboardCheck, Play, Loader2, AlertCircle, CheckCircle2, AlertTriangle } from 'lucide-react'
import { reviewMissionPlan } from '../api'
import type { MissionReview } from '../api'

const SAMPLE_PLAN = `# Mission plan (.plan)
geofence: -12.0 to +12.0 km (lat/lon)
altitude: 50 - 120 m AGL
waypoints:
  - {lat: 55.6500, lon: 37.4500, alt: 80, action: hover_2s}
  - {lat: 55.6520, lon: 37.4550, alt: 100, action: photo_burst}
fallback: RTL on link loss > 4s or M6 epistemic uncertainty > 0.45
decree_1701_ack: yes
`

export default function MissionPlanReview() {
  const [text, setText] = useState(SAMPLE_PLAN)
  const [fmt, setFmt] = useState<'plan' | 'json-ld' | 'owl'>('plan')
  const [result, setResult] = useState<MissionReview | null>(null)
  const [running, setRunning] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const run = async () => {
    setRunning(true); setErr(null)
    try {
      setResult(await reviewMissionPlan({ plan_text: text, plan_format: fmt }))
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
          <ClipboardCheck className="w-5 h-5 text-accent-blue" /> Mission Plan Review
        </h1>
        <p className="text-xs text-text-secondary mt-1">
          Chapter 6 §6.5 cloud-tier surface — CyberSecLLM zero-shot audit of <span className="font-mono">.plan</span> /
          JSON-LD / OWL mission documents. Phase-A surrogate flags missing geofence, RTL fallback, altitude band,
          and RF Decree №1701 acknowledgment. Production swap-in: existing LLM router (<span className="font-mono">copilot.py</span>).
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-bg-card rounded-xl p-4">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-sm font-semibold">Plan document</h2>
            <div className="flex gap-1">
              {(['plan', 'json-ld', 'owl'] as const).map((f) => (
                <button
                  key={f} onClick={() => setFmt(f)}
                  className={`px-2 py-0.5 rounded text-[10px] font-mono ${fmt === f
                    ? 'bg-accent-blue text-white'
                    : 'bg-bg-secondary text-text-secondary hover:text-text-primary'}`}
                >.{f}</button>
              ))}
            </div>
          </div>
          <textarea
            value={text} onChange={(e) => setText(e.target.value)}
            className="w-full h-64 bg-bg-secondary border border-bg-card/60 rounded-md p-2 text-xs font-mono"
            spellCheck={false}
          />
          <button
            onClick={run} disabled={running || !text}
            className="mt-2 w-full bg-accent-blue hover:bg-accent-blue/90 text-white px-3 py-2 rounded-md text-xs font-medium flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {running ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
            Audit
          </button>
        </div>

        <div className="bg-bg-card rounded-xl p-4">
          <h2 className="text-sm font-semibold mb-2">Verdict</h2>
          {err && <div className="text-xs text-accent-red">{err}</div>}
          {!result && !err && <div className="text-xs text-text-secondary">Submit a plan to see the audit verdict and findings.</div>}
          {result && (
            <>
              <div className={`mb-3 p-2 rounded-md flex items-center gap-2 ${
                result.verdict === 'approve' ? 'bg-accent-green/10 text-accent-green' : 'bg-accent-red/10 text-accent-red'
              }`}>
                {result.verdict === 'approve'
                  ? <CheckCircle2 className="w-4 h-4" />
                  : <AlertCircle className="w-4 h-4" />}
                <span className="text-xs font-semibold uppercase tracking-wider">{result.verdict}</span>
                <span className="text-[10px] font-mono ml-auto">{result.n_findings} findings · {result.model}</span>
              </div>
              <div className="space-y-1.5">
                {result.findings.length === 0 && <div className="text-xs text-text-secondary">No issues found.</div>}
                {result.findings.map((f) => (
                  <div key={f.code} className="border border-bg-card/50 rounded-md p-2">
                    <div className="flex items-center gap-2 mb-0.5">
                      <SeverityIcon severity={f.severity} />
                      <span className="font-mono text-[10px] text-text-secondary">{f.code}</span>
                      <span className={`text-[9px] font-mono uppercase ${severityColor(f.severity)}`}>{f.severity}</span>
                    </div>
                    <div className="text-xs">{f.message}</div>
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

function severityColor(s: string): string {
  if (s === 'high' || s === 'critical') return 'text-accent-red'
  if (s === 'medium') return 'text-accent-amber'
  if (s === 'low') return 'text-accent-orange'
  return 'text-text-secondary'
}

function SeverityIcon({ severity }: { severity: string }) {
  if (severity === 'high' || severity === 'critical')
    return <AlertCircle className="w-3 h-3 text-accent-red" />
  if (severity === 'medium')
    return <AlertTriangle className="w-3 h-3 text-accent-amber" />
  return <AlertTriangle className="w-3 h-3 text-text-secondary" />
}
