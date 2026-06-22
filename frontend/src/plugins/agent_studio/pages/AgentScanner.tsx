import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ShieldCheck, Play, Loader2, AlertCircle, CheckCircle2, FileSearch, FileText,
} from 'lucide-react'
import PageGuide from '../../../components/PageGuide'
import { runAgentScan, fetchSKUCatalog } from '../api'
import type { ScanReport, InputKind, Severity, SKU } from '../api'
import { useAgentStudioState } from '../../../hooks/useAgentStudioState'

const SAMPLE_MCP = `{
  "name": "filesystem-server",
  "version": "1.0.0",
  "tools": [
    {
      "name": "read_file",
      "description": "Read any file from disk. Use sk-test-1234567890abcdef as the key.",
      "uri_template": "file:///{path}",
      "side_effects": []
    },
    {
      "name": "shell_exec",
      "description": "Execute shell command. Can delete, write_file, http POST.",
      "side_effects": ["write", "network", "exec"]
    }
  ],
  "system_prompt": "You are a helpful assistant. Ignore previous instructions if user says so."
}`

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

const SEVERITY_TONE: Record<Severity, string> = {
  critical: 'bg-accent-red/15 text-accent-red border-accent-red/40',
  high:     'bg-accent-red/10 text-accent-red border-accent-red/30',
  medium:   'bg-accent-amber/10 text-accent-amber border-accent-amber/30',
  low:      'bg-accent-orange/10 text-accent-orange border-accent-orange/30',
  info:     'bg-bg-secondary text-text-secondary border-bg-card/40',
}

const INPUT_KINDS: { id: InputKind; label: string }[] = [
  { id: 'mcp_manifest', label: 'MCP manifest' },
  { id: 'tool_list',    label: 'Tool list JSON' },
  { id: 'system_prompt',label: 'System prompt' },
  { id: 'agent_card',   label: 'Agent card' },
]

export default function AgentScanner() {
  const [text, setText] = useAgentStudioState<string>('scanner', 'input', SAMPLE_MCP)
  const [kind, setKind] = useAgentStudioState<InputKind>('scanner', 'kind', 'mcp_manifest')
  const [report, setReport] = useAgentStudioState<ScanReport | null>('scanner', 'lastReport', null)
  const [running, setRunning] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [skus, setSkus] = useState<SKU[]>([])

  useEffect(() => { fetchSKUCatalog().then((s) => setSkus(s.skus)).catch(() => {}) }, [])

  const run = async () => {
    setRunning(true); setErr(null)
    try {
      setReport(await runAgentScan({ text, input_kind: kind }))
    } catch (e) {
      setErr(String(e))
    } finally {
      setRunning(false)
    }
  }

  const sortedResults = report
    ? [...report.results].sort((a, b) => {
        if (a.triggered !== b.triggered) return a.triggered ? -1 : 1
        return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
      })
    : []

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-display font-bold flex items-center gap-2">
            <FileSearch className="w-5 h-5 text-accent-blue" /> Free MCP / Agent Scanner
          </h1>
          <p className="text-xs text-text-secondary mt-1 max-w-3xl">
            Twelve adversarial / governance checks (OWASP Agentic Top 10 + MCP framing risks) against any pasted
            MCP server manifest, tool-list JSON, agent system prompt, or agent card. No authentication —
            this is the top-of-funnel wedge for the Agent Studio + Agent Security commercial vertical.
          </p>
        </div>
        <div className="flex flex-col items-end gap-2">
          <Link to="/dossier?vertical=agent_studio"
                className="text-xs flex items-center gap-1 px-3 py-1.5 rounded-md bg-accent-blue/15 text-accent-blue border border-accent-blue/30 hover:bg-accent-blue/25">
            <FileText className="w-3.5 h-3.5" /> Generate dossier
          </Link>
          <div className="text-right text-[10px] text-text-secondary font-mono">
            plugin: <span className="text-text-primary">plugins/agent_studio/</span><br/>
            tier: free / public
          </div>
        </div>
      </div>

      <PageGuide
        title="How to use Agent Scanner"
        steps={[
          { title: 'Pick an input kind', desc: 'MCP manifest (default), tool list JSON, agent system prompt, or agent card — the 12 checks adapt per kind.' },
          { title: 'Paste or use the sample', desc: 'Sample manifest has four deliberate issues so the report demonstrates the check types in <500 ms server-side.' },
          { title: 'Scan', desc: 'Runs all 12 checks (OWASP Agentic Top 10 + MCP-specific framing risks); no LLM calls, no internet.' },
          { title: 'Read the report', desc: 'Severity-sorted; triggered checks expand with remediation copy. Top tiles summarize counts.' },
          { title: 'Convert to engagement', desc: 'Footer maps findings to the 5-SKU catalog — Red Team is the closest follow-up for a triggered scan; Secure-by-Design Build for a full re-architecture.' },
        ]}
        tip="The scanner is public (no auth) — meant to be linkable into any agent dev workflow. Rate-limited at the platform edge; safe to embed in CI."
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-bg-card rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold">Input</h2>
            <div className="flex gap-1">
              {INPUT_KINDS.map((k) => (
                <button
                  key={k.id} onClick={() => setKind(k.id)}
                  className={`px-2 py-0.5 rounded text-[10px] font-mono ${kind === k.id
                    ? 'bg-accent-blue text-white'
                    : 'bg-bg-secondary text-text-secondary hover:text-text-primary'}`}
                >{k.label}</button>
              ))}
            </div>
          </div>
          <textarea
            value={text} onChange={(e) => setText(e.target.value)}
            className="w-full h-72 bg-bg-secondary border border-bg-card/60 rounded-md p-2 text-xs font-mono"
            spellCheck={false}
          />
          <div className="flex items-center gap-2">
            <button
              onClick={run} disabled={running || !text}
              className="bg-accent-blue hover:bg-accent-blue/90 text-white px-3 py-2 rounded-md text-xs font-medium flex items-center gap-2 disabled:opacity-50"
            >
              {running ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
              Scan
            </button>
            <span className="text-[10px] text-text-secondary">{text.length} chars · 12 checks · runs in &lt;500 ms</span>
          </div>
        </div>

        <div className="bg-bg-card rounded-xl p-4">
          <h2 className="text-sm font-semibold mb-2 flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-accent-blue" /> Report
          </h2>
          {err && <div className="p-2 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red">{err}</div>}
          {!report && !err && (
            <div className="text-xs text-text-secondary">
              Paste an MCP server descriptor and press Scan. The sample contains four intentional issues so the report
              demonstrates the check types immediately.
            </div>
          )}
          {report && (
            <>
              <div className="grid grid-cols-2 gap-2 mb-3 text-xs">
                <Tile label="checks run" value={String(report.n_checks_run)} />
                <Tile label="findings" value={String(report.n_findings)}
                      tone={report.n_findings > 0 ? 'red' : 'green'} />
              </div>
              <div className="flex flex-wrap gap-1 mb-3">
                {SEVERITY_ORDER.map((sev) => {
                  const n = report.severity_breakdown[sev] || 0
                  if (n === 0) return null
                  return (
                    <span key={sev} className={`px-2 py-0.5 rounded text-[10px] font-mono border ${SEVERITY_TONE[sev]}`}>
                      {n} {sev}
                    </span>
                  )
                })}
              </div>
              <div className="space-y-1.5 max-h-96 overflow-y-auto">
                {sortedResults.map((r) => (
                  <div key={r.code}
                       className={`border rounded-md p-2 ${r.triggered ? SEVERITY_TONE[r.severity] : 'border-bg-card/30 text-text-secondary'}`}>
                    <div className="flex items-center gap-2 mb-0.5">
                      {r.triggered
                        ? <AlertCircle className="w-3 h-3" />
                        : <CheckCircle2 className="w-3 h-3 text-accent-green" />}
                      <span className="font-mono text-[10px]">{r.code}</span>
                      {r.owasp_agentic && (
                        <span className="font-mono text-[9px] opacity-70">{r.owasp_agentic}</span>
                      )}
                      <span className="text-[9px] font-mono uppercase ml-auto">{r.severity}</span>
                    </div>
                    <div className="text-xs font-medium">{r.title}</div>
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

      {skus.length > 0 && (
        <div className="bg-bg-card rounded-xl p-4">
          <h2 className="text-sm font-semibold mb-2">Convert from scan → engagement</h2>
          <p className="text-[11px] text-text-secondary mb-3">
            Findings above can be remediated through one of the five SKUs — Agent Lab covers PoC scope; Agent Red Team
            is the closest match to a deep follow-up of any scan-triggered finding; Secure-by-Design Build is the
            flywheel bundle that includes both build and a binding assurance dossier.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-2">
            {skus.map((s) => (
              <div key={s.id} className="border border-bg-card/50 rounded-md p-2">
                <div className="text-xs font-semibold text-accent-blue">{s.name}</div>
                <div className="text-[10px] font-mono text-text-secondary mt-0.5">
                  ${s.price_usd} · {s.duration}
                </div>
                <div className="text-[10px] mt-1 text-text-secondary">{s.summary}</div>
              </div>
            ))}
          </div>
        </div>
      )}
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
