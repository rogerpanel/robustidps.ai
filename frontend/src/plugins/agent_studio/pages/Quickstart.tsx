import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Sparkles, Search, Shield, Swords, MessageSquare, FileCode, Copy,
  Play, FlaskConical, FileText, Rocket,
} from 'lucide-react'
import PageGuide from '../../../components/PageGuide'
import { listTemplates } from '../api'
import type { AgentTemplate, TemplateStats } from '../api'
import { useAgentStudioState } from '../../../hooks/useAgentStudioState'
import AccessBanner from '../components/AccessBanner'

const TIER_META: Record<string, { label: string; tone: string; icon: typeof Shield }> = {
  A:     { label: 'Security defenders',    tone: 'bg-accent-green/10 text-accent-green border-accent-green/30',   icon: Shield },
  B:     { label: 'Security attackers',    tone: 'bg-accent-red/10 text-accent-red border-accent-red/30',         icon: Swords },
  C:     { label: 'Productivity (secure)', tone: 'bg-accent-blue/10 text-accent-blue border-accent-blue/30',      icon: MessageSquare },
  blank: { label: 'Blank',                 tone: 'bg-bg-secondary text-text-secondary border-bg-card/40',         icon: FileCode },
}

export default function Quickstart() {
  const [templates, setTemplates] = useState<AgentTemplate[]>([])
  const [stats, setStats] = useState<TemplateStats | null>(null)
  const [tierFilter, setTierFilter] = useAgentStudioState<'all' | 'A' | 'B' | 'C' | 'blank'>(
    'quickstart', 'tier', 'all')
  const [search, setSearch] = useAgentStudioState<string>('quickstart', 'search', '')
  const [err, setErr] = useState<string | null>(null)
  const [openId, setOpenId] = useState<string | null>(null)
  const navigate = useNavigate()

  useEffect(() => {
    listTemplates()
      .then((r) => { setTemplates(r.templates); setStats(r.stats) })
      .catch((e) => setErr(String(e)))
  }, [])

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim()
    return templates.filter((t) => {
      if (tierFilter !== 'all' && t.tier !== tierFilter) return false
      if (!q) return true
      const hay = `${t.name} ${t.summary} ${t.use_case} ${t.category}`.toLowerCase()
      return hay.includes(q)
    })
  }, [templates, tierFilter, search])

  const opened = openId ? templates.find((t) => t.id === openId) : null

  const useInEval = (t: AgentTemplate) => {
    sessionStorage.setItem('agentstudio_template_spec', JSON.stringify(t.spec, null, 2))
    sessionStorage.setItem('agentstudio_template_id', t.id)
    navigate('/agent-studio/eval')
  }
  const useInRedTeam = (t: AgentTemplate) => {
    sessionStorage.setItem('agentstudio_template_spec', JSON.stringify(t.spec, null, 2))
    sessionStorage.setItem('agentstudio_template_id', t.id)
    navigate('/agent-studio/red-team')
  }
  const copySpec = (t: AgentTemplate) =>
    navigator.clipboard?.writeText(JSON.stringify(t.spec, null, 2))

  return (
    <div className="space-y-6">
      <AccessBanner />
      <section className="flex items-end justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-2xl font-display font-bold flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-accent-blue" /> Quickstart — agent templates
          </h1>
          <p className="text-sm text-text-secondary mt-1 max-w-3xl">
            Pick an archetype, fork the spec, push it through the eval harness +
            red-team in one click. Each template is a complete agent spec — the same
            JSON the SDK and the assurance dossier consume.
          </p>
        </div>
        {stats && (
          <div className="text-[10px] font-mono text-text-secondary text-right">
            <div>{stats.n_templates} templates</div>
            <div>{Object.entries(stats.by_tier).map(([k, v]) => `${k}:${v}`).join('  ·  ')}</div>
          </div>
        )}
      </section>

      <PageGuide
        title="How to use the Quickstart"
        steps={[
          { title: 'Filter by tier', desc: 'A = defenders (SOC/IR/compliance/vuln/MCP/hunt). B = attackers (red-team/recon/awareness). C = general productivity, shipped secure. Or "blank" to start from scratch.' },
          { title: 'Skim the card', desc: 'Each card shows summary, use-case, and recommended Aegis wrappers. Click "Inspect" to see the full agent spec.' },
          { title: 'Use the spec', desc: 'Send it straight to /agent-studio/eval, /agent-studio/red-team, or copy the JSON to integrate locally.' },
          { title: 'Wrap it', desc: 'Once you fork, install the SDK and wrap your real agent with aegis.guard() from the recommended framework wrapper.' },
        ]}
        tip="Templates are JSON files — adding your own is one PR away. See backend/plugins/agent_studio/templates.py."
      />

      <section className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1 bg-bg-card rounded-md p-1">
          {(['all', 'A', 'B', 'C', 'blank'] as const).map((k) => (
            <button key={k}
                    onClick={() => setTierFilter(k)}
                    className={`px-2.5 py-1 rounded text-[11px] font-mono ${
                      tierFilter === k ? 'bg-accent-blue text-white' : 'text-text-secondary hover:text-text-primary'
                    }`}>
              {k === 'all' ? 'All' : TIER_META[k]?.label || k}
            </button>
          ))}
        </div>
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search className="w-3.5 h-3.5 absolute top-2 left-2 text-text-secondary" />
          <input value={search} onChange={(e) => setSearch(e.target.value)}
                 placeholder="Search name, category, use-case…"
                 className="w-full pl-7 pr-2 py-1.5 rounded-md bg-bg-card border border-bg-card/40 text-xs" />
        </div>
      </section>

      {err && (
        <div className="p-3 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red">
          {err}
        </div>
      )}

      <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {filtered.map((t) => {
          const meta = TIER_META[t.tier] || TIER_META.blank
          const Icon = meta.icon
          return (
            <div key={t.id} className="bg-bg-card rounded-xl p-4 flex flex-col gap-2">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className={`inline-flex items-center justify-center w-7 h-7 rounded ${meta.tone} border`}>
                    <Icon className="w-3.5 h-3.5" />
                  </span>
                  <div>
                    <div className="text-sm font-semibold">{t.name}</div>
                    <div className="text-[10px] font-mono text-text-secondary">{t.id} · {t.category}</div>
                  </div>
                </div>
                <span className={`text-[9px] font-mono uppercase px-1.5 py-0.5 rounded border ${meta.tone}`}>
                  tier {t.tier}
                </span>
              </div>

              <p className="text-xs text-text-secondary">{t.summary}</p>
              <p className="text-[11px] text-text-secondary italic">→ {t.use_case}</p>

              <div className="flex flex-wrap gap-1">
                {t.frameworks.map((f) => (
                  <span key={f} className="text-[9px] font-mono bg-bg-secondary px-1.5 py-0.5 rounded">
                    {f}
                  </span>
                ))}
              </div>

              <Link to={`/agent-studio/build/${t.id}`}
                    className="mt-1 px-2 py-2 rounded bg-accent-blue text-white text-xs font-medium inline-flex items-center justify-center gap-1.5 hover:bg-accent-blue/90">
                <Rocket className="w-3.5 h-3.5" /> Build → Configure → Test → Ship
              </Link>
              <div className="grid grid-cols-4 gap-1">
                <button onClick={() => useInEval(t)}
                        className="px-1 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-[10px] inline-flex items-center justify-center gap-1 hover:border-accent-blue/40">
                  <FlaskConical className="w-3 h-3" /> Eval
                </button>
                <button onClick={() => useInRedTeam(t)}
                        className="px-1 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-[10px] inline-flex items-center justify-center gap-1 hover:border-accent-red/40">
                  <Play className="w-3 h-3" /> Red
                </button>
                <button onClick={() => copySpec(t)}
                        className="px-1 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-[10px] inline-flex items-center justify-center gap-1 hover:border-accent-blue/40">
                  <Copy className="w-3 h-3" /> Copy
                </button>
                <button onClick={() => setOpenId(t.id)}
                        className="px-1 py-1.5 rounded bg-bg-secondary border border-bg-card/40 text-[10px] inline-flex items-center justify-center gap-1 hover:border-accent-blue/40">
                  <FileText className="w-3 h-3" /> View
                </button>
              </div>
            </div>
          )
        })}
      </section>

      {opened && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4"
             onClick={() => setOpenId(null)}>
          <div className="bg-bg-secondary border border-bg-card rounded-xl max-w-2xl w-full max-h-[80vh] overflow-auto p-5 space-y-3"
               onClick={(e) => e.stopPropagation()}>
            <div className="flex items-start justify-between gap-2">
              <div>
                <div className="text-lg font-semibold">{opened.name}</div>
                <div className="text-[10px] font-mono text-text-secondary">
                  {opened.id} · tier {opened.tier} · {opened.category}
                </div>
              </div>
              <button onClick={() => setOpenId(null)}
                      className="text-text-secondary hover:text-text-primary">✕</button>
            </div>
            <p className="text-sm">{opened.summary}</p>
            <p className="text-xs text-text-secondary italic">→ {opened.use_case}</p>
            <div className="text-[10px] font-mono text-text-secondary">
              Recommended SKUs: {opened.recommended_skus.join(', ') || '—'}
            </div>
            <div>
              <div className="text-[10px] font-mono text-text-secondary uppercase mb-1">Agent spec (JSON)</div>
              <pre className="text-[11px] font-mono bg-bg-card border border-bg-card/40 rounded p-3 overflow-x-auto max-h-80">{JSON.stringify(opened.spec, null, 2)}</pre>
            </div>
            <div className="flex gap-2">
              <button onClick={() => { copySpec(opened); }}
                      className="px-3 py-1.5 rounded bg-bg-card border border-bg-card/40 text-xs inline-flex items-center gap-1">
                <Copy className="w-3 h-3" /> Copy spec
              </button>
              <button onClick={() => useInEval(opened)}
                      className="px-3 py-1.5 rounded bg-accent-blue text-white text-xs inline-flex items-center gap-1">
                <FlaskConical className="w-3 h-3" /> Send to Eval
              </button>
              <button onClick={() => useInRedTeam(opened)}
                      className="px-3 py-1.5 rounded bg-accent-red text-white text-xs inline-flex items-center gap-1">
                <Play className="w-3 h-3" /> Send to Red-team
              </button>
            </div>
            <Link to="/agent-studio/account"
                  className="block text-[11px] text-accent-blue underline text-center">
              Need an API key? Open the account console →
            </Link>
          </div>
        </div>
      )}
    </div>
  )
}
