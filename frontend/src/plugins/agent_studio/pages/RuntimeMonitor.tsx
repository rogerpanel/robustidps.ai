import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Activity, Play, Pause, RotateCcw, Sparkles, AlertCircle, Loader2,
  Send, ChevronDown, ChevronUp,
} from 'lucide-react'
import PageGuide from '../../../components/PageGuide'
import {
  fetchRuntimeSnapshot, seedRuntimeDemo, resetRuntime,
  fetchOTelInfo, ingestOTelSpan,
} from '../api'
import type { RuntimeSnapshot, RuntimeAgentSummary, RuntimeAlert } from '../api'

const FRAMEWORK_COLOR: Record<string, string> = {
  langgraph:     '#1D4ED8',
  crewai:        '#F59E0B',
  mcp:           '#0F8B8D',
  a2a:           '#7C3AED',
  anp:           '#DC2626',
  openai_agents: '#22C55E',
  autogen:       '#EC4899',
  pydantic_ai:   '#8B5CF6',
}

const SAMPLE_OTEL_SPAN = JSON.stringify({
  trace_id: '0af7651916cd43dd8448eb211c80319c',
  span_id: 'b7ad6b7169203331',
  name: 'agent.run',
  start_time_unix_nano: 1717000000000000000,
  end_time_unix_nano: 1717000000345000000,
  attributes: {
    'gen_ai.operation.name': 'chat',
    'gen_ai.system': 'openai',
    'gen_ai.request.model': 'gpt-4o',
    'gen_ai.agent.name': 'ops-copilot-demo',
    'gen_ai.framework': 'langgraph',
    'gen_ai.tool.name': 'shell_exec',
    'aegis.decision': 'block',
    'aegis.finding_codes': ['ASI01', 'ASI03'],
  },
}, null, 2)

export default function RuntimeMonitor() {
  const [snap, setSnap] = useState<RuntimeSnapshot | null>(null)
  const [running, setRunning] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [seeding, setSeeding] = useState(false)
  const [otelOpen, setOtelOpen] = useState(false)
  const [otelInfo, setOtelInfo] = useState<{ receiver: string; semconv_version: string } | null>(null)
  const [otelPayload, setOtelPayload] = useState(SAMPLE_OTEL_SPAN)
  const [otelBusy, setOtelBusy] = useState(false)
  const [otelLastResp, setOtelLastResp] = useState<string | null>(null)
  const tickRef = useRef<number | null>(null)

  const refresh = useCallback(async () => {
    try {
      setSnap(await fetchRuntimeSnapshot())
    } catch (e) {
      setErr(String(e))
    }
  }, [])

  useEffect(() => { refresh() }, [refresh])

  useEffect(() => {
    fetchOTelInfo().then((i) => setOtelInfo({
      receiver: i.receiver, semconv_version: i.semconv_version,
    })).catch(() => {})
  }, [])

  const ingestOTel = async () => {
    setOtelBusy(true); setOtelLastResp(null); setErr(null)
    try {
      const parsed = JSON.parse(otelPayload)
      const resp = await ingestOTelSpan(parsed)
      setOtelLastResp(JSON.stringify(resp, null, 2))
      await refresh()
    } catch (e) {
      setErr(String(e))
    } finally {
      setOtelBusy(false)
    }
  }

  useEffect(() => {
    if (!running) return
    tickRef.current = window.setInterval(refresh, 2000)
    return () => { if (tickRef.current) window.clearInterval(tickRef.current) }
  }, [running, refresh])

  const doSeed = async () => {
    setSeeding(true); setErr(null)
    try {
      setSnap(await seedRuntimeDemo())
    } catch (e) {
      setErr(String(e))
    } finally {
      setSeeding(false)
    }
  }

  const doReset = async () => {
    setRunning(false); setErr(null)
    try {
      await resetRuntime()
      await refresh()
    } catch (e) {
      setErr(String(e))
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-display font-bold flex items-center gap-2">
            <Activity className="w-5 h-5 text-accent-green" /> Runtime Monitor
          </h1>
          <p className="text-xs text-text-secondary mt-1 max-w-3xl">
            Live agent-traffic dashboard. Customer agents instrumented with the AegisAgents Kit ship
            verdict envelopes here; per-agent windowed metrics (block rate, warn rate, p50/p95 latency,
            top finding codes) drive alerts when thresholds cross.
          </p>
        </div>
        <div className="text-right text-[10px] text-text-secondary font-mono">
          ingest: <span className="text-text-primary">POST /api/agent-studio/runtime/ingest</span><br />
          OTel: <span className="text-text-primary">POST /api/agent-studio/runtime/otel/{`{spans,traces}`}</span>
          {otelInfo && (
            <span className="text-accent-green"> · semconv {otelInfo.semconv_version}</span>
          )}
        </div>
      </div>

      <PageGuide
        title="How to use Runtime Monitor"
        steps={[
          { title: 'Seed a demo fleet', desc: 'Click "Seed demo" — three synthetic agents (langgraph / openai_agents / crewai) populate with 60-event windows.' },
          { title: 'Play (2 Hz polling)', desc: 'Dashboard polls /runtime/snapshot every 2 s; per-agent meters update in place.' },
          { title: 'Watch alerts', desc: 'When block_rate exceeds 20 % in the rolling window, an alert fires (throttled to one per agent per minute) and surfaces in the bottom panel.' },
          { title: 'Wire customer agents', desc: 'In production, the AegisAgents Kit\'s MambaGuardClient POSTs each verdict to /runtime/ingest with the agent_id + framework.' },
          { title: 'Reset', desc: 'Clear the in-memory store to start fresh; seed again or wait for real customer traffic.' },
        ]}
        tip="The in-memory store caps at 100 events per agent; production swap-in is per-tenant ClickHouse or Postgres. The dashboard contract is the same."
      />

      <div className="bg-bg-card rounded-xl p-4 flex flex-wrap items-center gap-3">
        <button onClick={() => setRunning(!running)} disabled={!snap}
                className={`flex items-center gap-1.5 px-3 py-2 rounded-md text-xs font-medium ${
                  running ? 'bg-accent-amber text-white' : 'bg-accent-blue text-white hover:bg-accent-blue/90'
                } disabled:opacity-50`}>
          {running ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
          {running ? 'Pause (2 Hz polling)' : 'Play (2 Hz polling)'}
        </button>
        <button onClick={doSeed} disabled={seeding}
                className="flex items-center gap-1.5 px-3 py-2 rounded-md text-xs font-medium bg-accent-orange/15 text-accent-orange border border-accent-orange/30 hover:bg-accent-orange/25 disabled:opacity-50">
          {seeding ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
          Seed demo
        </button>
        <button onClick={doReset}
                className="flex items-center gap-1.5 px-3 py-2 rounded-md text-xs font-medium bg-bg-secondary border border-bg-card/40 hover:border-accent-blue/40">
          <RotateCcw className="w-3.5 h-3.5" /> Reset
        </button>
        <div className="ml-auto text-[10px] font-mono text-text-secondary">
          {snap ? `${snap.n_agents} agent${snap.n_agents === 1 ? '' : 's'} tracked` : 'loading…'}
        </div>
      </div>

      {err && (
        <div className="px-3 py-2 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red flex items-center gap-2">
          <AlertCircle className="w-3.5 h-3.5" />{err}
        </div>
      )}

      {snap && snap.agents.length === 0 && (
        <div className="bg-bg-card rounded-xl p-4 text-center text-xs text-text-secondary">
          No agents tracked yet. Click <strong>Seed demo</strong> to populate three synthetic agents,
          or POST verdicts to <code className="text-text-primary">/api/agent-studio/runtime/ingest</code>.
        </div>
      )}

      {snap && snap.agents.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {snap.agents.map((a) => <AgentCard key={a.agent_id} agent={a} />)}
        </div>
      )}

      <div className="bg-bg-card rounded-xl p-4">
        <button onClick={() => setOtelOpen(!otelOpen)}
                className="w-full flex items-center justify-between text-sm font-semibold">
          <span className="inline-flex items-center gap-2">
            <Send className="w-4 h-4 text-accent-purple" /> OTel-GenAI trace inspector
          </span>
          {otelOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>
        {otelOpen && (
          <div className="mt-3 space-y-2">
            <div className="text-[10px] font-mono text-text-secondary">
              Paste a single OTel GenAI span (trimmed JSON shape — `attributes` uses bare Python values).
              The receiver also accepts full OTLP/JSON envelopes at <code>/runtime/otel/traces</code>.
            </div>
            <textarea value={otelPayload} onChange={(e) => setOtelPayload(e.target.value)}
                      className="w-full h-44 bg-bg-secondary border border-bg-card/60 rounded-md p-2 text-[11px] font-mono"
                      spellCheck={false} />
            <button onClick={ingestOTel} disabled={otelBusy}
                    className="px-3 py-1.5 rounded-md bg-accent-purple text-white text-xs font-medium hover:bg-accent-purple/90 disabled:opacity-50 inline-flex items-center gap-1.5">
              {otelBusy ? <Loader2 className="w-3 h-3 animate-spin" /> : <Send className="w-3 h-3" />}
              Ingest span
            </button>
            {otelLastResp && (
              <pre className="text-[10px] font-mono bg-bg-secondary p-2 rounded border border-bg-card/40 overflow-x-auto max-h-40">{otelLastResp}</pre>
            )}
          </div>
        )}
      </div>

      {snap && snap.recent_alerts.length > 0 && (
        <div className="bg-bg-card rounded-xl p-4">
          <h2 className="text-sm font-semibold mb-2">Recent alerts</h2>
          <div className="space-y-1.5 max-h-64 overflow-y-auto">
            {[...snap.recent_alerts].reverse().map((a) => <AlertRow key={a.alert_id} alert={a} />)}
          </div>
        </div>
      )}
    </div>
  )
}

function AgentCard({ agent }: { agent: RuntimeAgentSummary }) {
  const blockTone = agent.block_rate >= 0.20 ? 'text-accent-red'
                  : agent.block_rate >= 0.05 ? 'text-accent-amber'
                  : 'text-accent-green'
  return (
    <div className="bg-bg-card rounded-xl p-3 border-t-2"
         style={{ borderTopColor: FRAMEWORK_COLOR[agent.framework] || '#94A3B8' }}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-semibold">{agent.agent_id}</span>
        <span className="text-[9px] font-mono text-text-secondary uppercase">{agent.framework}</span>
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs mb-2">
        <div>
          <div className="text-[9px] font-mono text-text-secondary uppercase">block rate</div>
          <div className={`text-lg font-mono font-semibold ${blockTone}`}>{(agent.block_rate * 100).toFixed(1)}%</div>
        </div>
        <div>
          <div className="text-[9px] font-mono text-text-secondary uppercase">warn rate</div>
          <div className="text-lg font-mono font-semibold text-accent-amber">{(agent.warn_rate * 100).toFixed(1)}%</div>
        </div>
        <div>
          <div className="text-[9px] font-mono text-text-secondary uppercase">p50 latency</div>
          <div className="text-sm font-mono">{agent.p50_latency_ms.toFixed(0)} ms</div>
        </div>
        <div>
          <div className="text-[9px] font-mono text-text-secondary uppercase">p95 latency</div>
          <div className="text-sm font-mono">{agent.p95_latency_ms.toFixed(0)} ms</div>
        </div>
      </div>
      <div className="text-[9px] font-mono text-text-secondary uppercase mb-1">top findings</div>
      <div className="flex flex-wrap gap-1">
        {agent.top_findings.length === 0
          ? <span className="text-[10px] text-text-secondary italic">none</span>
          : agent.top_findings.map((f) => (
              <span key={f.code} className="text-[10px] font-mono bg-bg-secondary px-1.5 py-0.5 rounded">
                {f.code} <span className="opacity-60">×{f.count}</span>
              </span>
            ))}
      </div>
      <div className="text-[9px] font-mono text-text-secondary mt-2">
        window: {agent.window_size}/{100} events
      </div>
    </div>
  )
}

function AlertRow({ alert }: { alert: RuntimeAlert }) {
  return (
    <div className="border border-accent-red/30 bg-accent-red/5 rounded-md p-2 text-xs">
      <div className="flex items-center gap-2 mb-0.5">
        <AlertCircle className="w-3 h-3 text-accent-red" />
        <span className="font-mono text-[10px]">{alert.alert_id}</span>
        <span className="font-mono text-[10px] text-text-secondary">{alert.agent_id}</span>
        <span className="font-mono text-[10px] text-text-secondary ml-auto">
          {new Date(alert.ts_ms).toLocaleTimeString()}
        </span>
      </div>
      <div className="text-text-primary">{alert.message}</div>
      {alert.trigger.length > 0 && (
        <div className="text-[10px] font-mono text-text-secondary mt-0.5">
          trigger: {alert.trigger.join(', ')}
        </div>
      )}
    </div>
  )
}
