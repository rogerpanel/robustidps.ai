import { useMemo } from 'react'
import {
  ShieldCheck, CheckCircle, AlertTriangle, XCircle, MinusCircle,
  BarChart3, BookOpen, Layers,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import { usePageState } from '../hooks/usePageState'

const PAGE = 'compliancehub'

type Tab = 'owasp' | 'nist'
type Status = 'covered' | 'partial' | 'na'

/* ── OWASP LLM Top 10 ── */
const OWASP_LLM_TOP_10 = [
  { id: 'LLM01', name: 'Prompt Injection', status: 'covered' as Status, coverage: 95, feature: 'Prompt Injection Playground + Defense Pipeline' },
  { id: 'LLM02', name: 'Insecure Output Handling', status: 'covered' as Status, coverage: 85, feature: 'DOMPurify sanitization + output filtering' },
  { id: 'LLM03', name: 'Training Data Poisoning', status: 'partial' as Status, coverage: 60, feature: 'RAG Poisoning Simulator (educational)' },
  { id: 'LLM04', name: 'Model Denial of Service', status: 'covered' as Status, coverage: 80, feature: 'Rate limiting + input size validation' },
  { id: 'LLM05', name: 'Supply Chain Vulnerabilities', status: 'covered' as Status, coverage: 90, feature: 'Model Supply Chain page + integrity checks' },
  { id: 'LLM06', name: 'Sensitive Information Disclosure', status: 'covered' as Status, coverage: 85, feature: 'Output filtering + PII detection in Defense Pipeline' },
  { id: 'LLM07', name: 'Insecure Plugin Design', status: 'covered' as Status, coverage: 75, feature: 'Tool-use sandboxing in SOC Copilot' },
  { id: 'LLM08', name: 'Excessive Agency', status: 'covered' as Status, coverage: 90, feature: 'Bounded autonomy + CPO safety constraints' },
  { id: 'LLM09', name: 'Overreliance', status: 'partial' as Status, coverage: 50, feature: 'MC Dropout uncertainty + confidence thresholds' },
  { id: 'LLM10', name: 'Model Theft', status: 'partial' as Status, coverage: 55, feature: 'Auth-gated API + rate limiting (no extraction defense)' },
]

/* ── NIST AI RMF ── */
interface NistItem { id: string; name: string; status: Status; feature: string }
interface NistCategory { category: string; items: NistItem[] }

const NIST_AI_RMF: NistCategory[] = [
  { category: 'GOVERN', items: [
    { id: 'GV-1', name: 'Policies & Procedures', status: 'covered', feature: 'Zero-Trust Governance page' },
    { id: 'GV-2', name: 'Accountability', status: 'covered', feature: 'Audit logging + admin dashboard' },
    { id: 'GV-3', name: 'Workforce Diversity', status: 'na', feature: 'N/A — organizational policy' },
  ]},
  { category: 'MAP', items: [
    { id: 'MP-1', name: 'Intended Purpose', status: 'covered', feature: 'Architecture page + About page' },
    { id: 'MP-2', name: 'Context of Use', status: 'covered', feature: 'Datasets page + benchmark documentation' },
    { id: 'MP-3', name: 'Stakeholder Analysis', status: 'partial', feature: 'Lab Partnerships page' },
  ]},
  { category: 'MEASURE', items: [
    { id: 'MS-1', name: 'Performance Metrics', status: 'covered', feature: 'Analytics (10 tabs) + Benchmarks page' },
    { id: 'MS-2', name: 'Bias & Fairness', status: 'partial', feature: 'Dataset distribution analysis' },
    { id: 'MS-3', name: 'Robustness Testing', status: 'covered', feature: 'Adversarial Eval (6 attacks) + Red Team Arena' },
    { id: 'MS-4', name: 'Uncertainty Quantification', status: 'covered', feature: 'MC Dropout (T=20) + calibration metrics' },
  ]},
  { category: 'MANAGE', items: [
    { id: 'MG-1', name: 'Risk Response', status: 'covered', feature: 'Threat Response + RL Response Agent' },
    { id: 'MG-2', name: 'Monitoring', status: 'covered', feature: 'Live Monitor + drift detection + admin health' },
    { id: 'MG-3', name: 'Incident Management', status: 'covered', feature: 'SOC Copilot + playbook engine' },
    { id: 'MG-4', name: 'Model Updates', status: 'covered', feature: 'Continual Learning (EWC) + model registry' },
  ]},
]

const CATEGORY_COLORS: Record<string, string> = {
  GOVERN: 'accent-blue',
  MAP: 'accent-purple',
  MEASURE: 'accent-amber',
  MANAGE: 'accent-green',
}

const STATUS_CONFIG: Record<Status, { label: string; icon: typeof CheckCircle; color: string; bg: string }> = {
  covered: { label: 'Covered', icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-500/15 text-green-400 border-green-500/30' },
  partial: { label: 'Partial', icon: AlertTriangle, color: 'text-amber-400', bg: 'bg-amber-500/15 text-amber-400 border-amber-500/30' },
  na: { label: 'N/A', icon: MinusCircle, color: 'text-text-secondary', bg: 'bg-bg-secondary text-text-secondary border-bg-card' },
}

const BAR_COLORS: Record<Status, string> = {
  covered: 'bg-green-500',
  partial: 'bg-amber-500',
  na: 'bg-gray-600',
}

const GUIDE_STEPS = [
  { title: 'Choose a Framework', desc: 'Switch between OWASP LLM Top 10 and NIST AI RMF tabs.' },
  { title: 'Review Coverage', desc: 'Each item shows its coverage percentage and the platform feature that addresses it.' },
  { title: 'Export for Auditors', desc: 'Use the Export button to generate compliance reports for external audits.' },
]

export default function ComplianceHub() {
  const [tab, setTab] = usePageState<Tab>(PAGE, 'tab', 'owasp')

  /* ── OWASP aggregate metrics ── */
  const owaspMetrics = useMemo(() => {
    const total = OWASP_LLM_TOP_10.length
    const covered = OWASP_LLM_TOP_10.filter(i => i.status === 'covered').length
    const partial = OWASP_LLM_TOP_10.filter(i => i.status === 'partial').length
    const avgCoverage = Math.round(OWASP_LLM_TOP_10.reduce((s, i) => s + i.coverage, 0) / total)
    return { total, covered, partial, avgCoverage }
  }, [])

  /* ── NIST category percentages ── */
  const nistCategoryPct = useMemo(() => {
    const result: Record<string, number> = {}
    for (const cat of NIST_AI_RMF) {
      const applicable = cat.items.filter(i => i.status !== 'na')
      if (applicable.length === 0) { result[cat.category] = 100; continue }
      const covered = applicable.filter(i => i.status === 'covered').length
      const partial = applicable.filter(i => i.status === 'partial').length
      result[cat.category] = Math.round(((covered + partial * 0.5) / applicable.length) * 100)
    }
    return result
  }, [])

  const nistOverall = useMemo(() => {
    const vals = Object.values(nistCategoryPct)
    return Math.round(vals.reduce((s, v) => s + v, 0) / vals.length)
  }, [nistCategoryPct])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-accent-blue" />
            Compliance Hub
          </h1>
          <p className="text-sm text-text-secondary mt-1">
            Framework compliance scorecards for OWASP LLM Top 10 and NIST AI RMF
          </p>
        </div>
        <ExportMenu filename="compliance-report" />
      </div>

      <PageGuide
        title="How to use the Compliance Hub"
        steps={GUIDE_STEPS}
        tip="Coverage percentages reflect platform features already implemented. Partial items may need organizational policies."
      />

      {/* Tab bar */}
      <div className="flex gap-1 bg-bg-secondary rounded-lg p-1 w-fit">
        {([
          { key: 'owasp' as Tab, label: 'OWASP LLM Top 10', icon: BookOpen },
          { key: 'nist' as Tab, label: 'NIST AI RMF', icon: Layers },
        ]).map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-md text-xs font-medium transition-colors ${
              tab === t.key
                ? 'bg-accent-blue/20 text-accent-blue'
                : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            <t.icon className="w-3.5 h-3.5" />
            {t.label}
          </button>
        ))}
      </div>

      {/* ════════════════════════ OWASP TAB ════════════════════════ */}
      {tab === 'owasp' && (
        <>
          {/* Summary stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Average Coverage', value: `${owaspMetrics.avgCoverage}%`, icon: BarChart3, color: 'text-accent-blue' },
              { label: 'Fully Covered', value: `${owaspMetrics.covered}/10`, icon: CheckCircle, color: 'text-green-400' },
              { label: 'Partial Coverage', value: `${owaspMetrics.partial}/10`, icon: AlertTriangle, color: 'text-amber-400' },
              { label: 'Not Covered', value: `${owaspMetrics.total - owaspMetrics.covered - owaspMetrics.partial}/10`, icon: XCircle, color: 'text-red-400' },
            ].map(m => (
              <div key={m.label} className="bg-bg-card border border-bg-card rounded-xl p-4">
                <div className="flex items-center gap-2 text-xs text-text-secondary mb-1">
                  <m.icon className={`w-3.5 h-3.5 ${m.color}`} />
                  {m.label}
                </div>
                <div className="text-2xl font-bold">{m.value}</div>
              </div>
            ))}
          </div>

          {/* OWASP cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {OWASP_LLM_TOP_10.map(item => {
              const sc = STATUS_CONFIG[item.status]
              return (
                <div key={item.id} className="bg-bg-card border border-bg-card rounded-xl p-4">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-accent-blue bg-accent-blue/10 px-2 py-0.5 rounded">
                        {item.id}
                      </span>
                      <h4 className="text-sm font-semibold">{item.name}</h4>
                    </div>
                    <span className={`flex items-center gap-1 text-[10px] font-semibold border px-2 py-0.5 rounded-full ${sc.bg}`}>
                      <sc.icon className="w-3 h-3" />
                      {sc.label}
                    </span>
                  </div>
                  {/* Progress bar */}
                  <div className="mb-2">
                    <div className="flex justify-between text-[10px] text-text-secondary mb-1">
                      <span>Coverage</span>
                      <span className="font-semibold text-text-primary">{item.coverage}%</span>
                    </div>
                    <div className="w-full h-2 bg-bg-secondary rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all ${BAR_COLORS[item.status]}`}
                        style={{ width: `${item.coverage}%` }}
                      />
                    </div>
                  </div>
                  <p className="text-[11px] text-text-secondary leading-relaxed">
                    {item.feature}
                  </p>
                </div>
              )
            })}
          </div>
        </>
      )}

      {/* ════════════════════════ NIST TAB ════════════════════════ */}
      {tab === 'nist' && (
        <>
          {/* Overall score */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="bg-bg-card border border-bg-card rounded-xl p-4">
              <div className="text-xs text-text-secondary mb-1">Overall Compliance</div>
              <div className="text-2xl font-bold text-accent-blue">{nistOverall}%</div>
            </div>
            {NIST_AI_RMF.map(cat => {
              const pct = nistCategoryPct[cat.category]
              const clr = CATEGORY_COLORS[cat.category] || 'accent-blue'
              return (
                <div key={cat.category} className="bg-bg-card border border-bg-card rounded-xl p-4">
                  <div className="text-xs text-text-secondary mb-1">{cat.category}</div>
                  <div className={`text-2xl font-bold text-${clr}`}>{pct}%</div>
                </div>
              )
            })}
          </div>

          {/* NIST categories */}
          <div className="space-y-6">
            {NIST_AI_RMF.map(cat => {
              const clr = CATEGORY_COLORS[cat.category] || 'accent-blue'
              const pct = nistCategoryPct[cat.category]
              return (
                <div key={cat.category}>
                  {/* Category header */}
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <span className={`text-xs font-bold px-2.5 py-1 rounded-lg bg-${clr}/15 text-${clr}`}>
                        {cat.category}
                      </span>
                      <span className="text-sm font-semibold">
                        {cat.category === 'GOVERN' && 'Governance'}
                        {cat.category === 'MAP' && 'Mapping'}
                        {cat.category === 'MEASURE' && 'Measurement'}
                        {cat.category === 'MANAGE' && 'Management'}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-24 h-2 bg-bg-secondary rounded-full overflow-hidden">
                        <div className={`h-full rounded-full bg-${clr}`} style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-xs font-semibold">{pct}%</span>
                    </div>
                  </div>

                  {/* Item cards */}
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                    {cat.items.map(item => {
                      const sc = STATUS_CONFIG[item.status]
                      return (
                        <div key={item.id} className="bg-bg-card border border-bg-card rounded-xl p-4">
                          <div className="flex items-center justify-between mb-2">
                            <span className={`text-xs font-mono px-2 py-0.5 rounded bg-${clr}/10 text-${clr}`}>
                              {item.id}
                            </span>
                            <span className={`flex items-center gap-1 text-[10px] font-semibold border px-2 py-0.5 rounded-full ${sc.bg}`}>
                              <sc.icon className="w-3 h-3" />
                              {sc.label}
                            </span>
                          </div>
                          <h4 className="text-sm font-semibold mb-1">{item.name}</h4>
                          <p className="text-[11px] text-text-secondary leading-relaxed">
                            {item.feature}
                          </p>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}
