import { useEffect, useMemo, useState } from 'react'
import { Play, Loader2, Download, CheckCircle2, AlertTriangle } from 'lucide-react'
import {
  guardCompare, guardEvaluate, guardSuites,
  type CompareResult, type EvalResult, type GuardPolicy, type GuardSuite,
} from '../../guardApi'

interface Props {
  policies: GuardPolicy[]
  policyId: string
  inlinePolicy?: unknown   // the policy edited in the Test tab, if any
}

function pct(x: number | null) {
  return x == null ? 'n/a' : `${Math.round(x * 1000) / 10}%`
}

function download(name: string, data: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }))
  const a = document.createElement('a')
  a.href = url; a.download = name; a.click()
  URL.revokeObjectURL(url)
}

/** Run a labelled suite against a policy. Deterministic: the result digest identifies suite, policy and verdicts. */
export default function EvaluateTab({ policies, policyId, inlinePolicy }: Props) {
  const [suites, setSuites] = useState<GuardSuite[]>([])
  const [suiteId, setSuiteId] = useState('')
  const [useEdited, setUseEdited] = useState(false)
  const [customSuite, setCustomSuite] = useState('')
  const [res, setRes] = useState<EvalResult | null>(null)
  const [cmp, setCmp] = useState<CompareResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  useEffect(() => {
    guardSuites().then((s) => {
      setSuites(s)
      setSuiteId((cur) => cur || s.find((x) => x.policy_id === policyId)?.id || s[0]?.id || '')
    }).catch((e) => setErr(String(e.message || e)))
  }, [policyId])

  const suite = useMemo(() => suites.find((s) => s.id === suiteId), [suites, suiteId])

  const request = () => {
    let custom: unknown
    if (suiteId === '__custom') {
      try { custom = JSON.parse(customSuite) } catch { throw new Error('Custom suite is not valid JSON') }
    }
    const pid = suiteId === '__custom' ? policyId : (suite?.policy_id || policyId)
    return {
      suite_id: suiteId === '__custom' ? undefined : suiteId, suite: custom,
      policy_id: pid, policy: useEdited && inlinePolicy ? inlinePolicy : undefined,
    }
  }

  const run = async () => {
    setBusy(true); setErr(''); setRes(null); setCmp(null)
    try { setRes(await guardEvaluate(request())) }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)) } finally { setBusy(false) }
  }

  const runCompare = async () => {
    setBusy(true); setErr(''); setCmp(null)
    try { setCmp(await guardCompare(request())) }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)) } finally { setBusy(false) }
  }

  return (
    <div className="space-y-4">
      <div className="bg-bg-card rounded-xl p-5 space-y-3">
        <p className="text-sm text-text-secondary">
          Each case is a proposed call with the verdict it should get. Cases in a group differ only in names an attacker
          controls (files, processes, accounts, hosts) or in the agent's stated reason, so they must get the same verdict.
          The built-in suites are regression tests for the built-in packs, not an independent benchmark; bring your own
          labelled cases for that.
        </p>
        <div className="flex flex-wrap items-center gap-3">
          <select value={suiteId} onChange={(e) => setSuiteId(e.target.value)}
                  className="px-3 py-1.5 bg-bg-primary border border-bg-card rounded-lg text-sm">
            {suites.map((s) => <option key={s.id} value={s.id}>{s.id} ({s.cases.length} cases, {s.policy_id})</option>)}
            <option value="__custom">Custom suite (JSON)</option>
          </select>
          <label className={`text-xs flex items-center gap-1.5 ${inlinePolicy ? '' : 'opacity-40'}`}>
            <input type="checkbox" disabled={!inlinePolicy} checked={useEdited && !!inlinePolicy}
                   onChange={(e) => setUseEdited(e.target.checked)} />
            use the policy edited in the Test tab
          </label>
          <button onClick={run} disabled={busy || !suiteId}
                  className="ml-auto px-4 py-2 bg-accent-blue text-white rounded-lg text-sm font-medium inline-flex items-center gap-2 disabled:opacity-50">
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Run evaluation
          </button>
          <button onClick={runCompare} disabled={busy || !suiteId}
                  className="px-4 py-2 bg-accent-blue/15 text-accent-blue rounded-lg text-sm font-medium disabled:opacity-50">
            Compare with baselines and layers
          </button>
        </div>
        {suite && suiteId !== '__custom' && <p className="text-xs text-text-secondary">{suite.description}</p>}
        {suiteId === '__custom' && (
          <textarea value={customSuite} onChange={(e) => setCustomSuite(e.target.value)} spellCheck={false}
                    placeholder={'{"id": "my-suite", "cases": [{"id": "c1", "tool": "isolate_host", "args": {"host": "10.0.0.5"}, "expect": "ask", "group": "g1"}]}'}
                    className="w-full h-40 px-3 py-2 bg-bg-primary border border-bg-card rounded-lg font-mono text-xs" />
        )}
        {err && <p className="text-sm text-accent-red">{err}</p>}
      </div>

      {cmp && (
        <div className="bg-bg-card rounded-xl p-4 space-y-3 overflow-x-auto">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="font-semibold mr-auto">{cmp.policy} on {cmp.suite} ({cmp.cases} cases)</h3>
            <button onClick={() => download(`guard-compare-${cmp.comparison_digest.slice(0, 12)}.json`, cmp)}
                    className="text-accent-blue inline-flex items-center gap-1 text-xs"><Download className="w-3.5 h-3.5" /> Export JSON</button>
          </div>
          <table className="w-full text-xs">
            <thead className="text-text-secondary text-left">
              <tr><th className="py-1">Configuration</th><th>Exact verdicts (95% CI)</th><th>Stop recall (95% CI)</th><th>False stops (95% CI)</th><th>Interventions</th><th>of which repairs</th></tr>
            </thead>
            <tbody>
              {cmp.table.map((r) => (
                <tr key={r.name} className={`border-t border-bg-primary ${r.kind === 'policy' ? 'font-semibold' : ''}`}>
                  <td className="py-1.5">{r.name}<span className="ml-1.5 text-text-secondary font-normal">{r.kind !== 'policy' ? r.kind : ''}</span></td>
                  {(['exact_accuracy', 'stop_recall', 'false_stop_rate'] as const).map((k) => (
                    <td key={k}>{pct(r[k])}{r.ci95[k] && <span className="text-text-secondary font-normal"> [{pct(r.ci95[k]![0])}, {pct(r.ci95[k]![1])}]</span>}</td>
                  ))}
                  <td>{pct(r.intervention_rate)}</td>
                  <td>{pct(r.repair_rate)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="text-[11px] text-text-secondary">
            Ablations remove one layer of the policy at a time; baselines need no filter at all. Intervals come from
            {' '}{cmp.bootstrap.resamples} resamples of the cases with a fixed seed, so the whole table is reproducible
            (comparison digest <span className="font-mono">{cmp.comparison_digest.slice(0, 16)}</span>, ledger record #{cmp.evidence.seq}). {cmp.note}
          </p>
        </div>
      )}

      {res && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
            {[
              ['Exact verdicts', pct(res.summary.exact_accuracy)],
              ['Stop recall', pct(res.summary.stop_recall)],
              ['False stops', pct(res.summary.false_stop_rate)],
              ['Name-invariance', res.summary.invariance_violations.length ? `${res.summary.invariance_violations.length} broken` : `${res.summary.groups}/${res.summary.groups} groups`],
              ['Repaired, not stopped', `${pct(res.summary.repair_rate)} of ${pct(res.summary.intervention_rate)} interventions`],
              ['Mean latency', `${res.summary.mean_latency_ms} ms`],
            ].map(([k, v]) => (
              <div key={k} className="bg-bg-card rounded-xl p-3">
                <div className="text-[11px] text-text-secondary">{k}</div>
                <div className="text-lg font-semibold">{v}</div>
              </div>
            ))}
          </div>
          <div className="bg-bg-card rounded-xl p-4 text-xs space-y-1 font-mono break-all">
            <div className="flex items-center gap-2 font-sans text-sm">
              {res.reproduction.all_match === false ? (
                <span className="text-accent-red inline-flex items-center gap-1"><AlertTriangle className="w-4 h-4" /> Differs from an earlier run with the same suite, policy and filter version</span>
              ) : res.reproduction.all_match ? (
                <span className="text-accent-green inline-flex items-center gap-1"><CheckCircle2 className="w-4 h-4" /> Reproduces {res.reproduction.earlier_runs_same_inputs} earlier run(s) exactly</span>
              ) : <span className="text-text-secondary">First run with these inputs</span>}
              <button onClick={() => download(`guard-eval-${res.result_digest.slice(0, 12)}.json`, res)}
                      className="ml-auto text-accent-blue inline-flex items-center gap-1 text-xs"><Download className="w-3.5 h-3.5" /> Export JSON</button>
            </div>
            <div>result {res.result_digest}</div>
            <div className="text-text-secondary">suite {res.suite_digest} · policy {res.policy_digest} · filter {res.filter_version}</div>
            <div className="text-text-secondary">evidence ledger record #{res.evidence.seq} · {res.evidence.hash}</div>
          </div>
          <div className="bg-bg-card rounded-xl p-4 overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="text-text-secondary text-left">
                <tr><th className="py-1">Case</th><th>Tool</th><th>Group</th><th>Expected</th><th>Got</th><th>Rules</th></tr>
              </thead>
              <tbody>
                {res.rows.map((r) => (
                  <tr key={r.id} className={`border-t border-bg-primary ${r.correct ? '' : 'bg-accent-red/10'}`}>
                    <td className="py-1 font-mono">{r.id}</td>
                    <td className="font-mono">{r.tool}</td>
                    <td className={res.summary.invariance_violations.includes(r.group || '') ? 'text-accent-red' : 'text-text-secondary'}>{r.group || ''}</td>
                    <td>{r.expect}</td>
                    <td className={r.correct ? '' : 'text-accent-red font-semibold'}>{r.got}</td>
                    <td className="font-mono text-text-secondary">{r.rules.join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
      {!res && policies.length === 0 && <p className="text-sm text-text-secondary">Loading…</p>}
    </div>
  )
}
