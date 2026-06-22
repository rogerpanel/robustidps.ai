import { useEffect, useState } from 'react'
import {
  Package, Play, Loader2, ShieldCheck, ExternalLink, Copy, Globe,
} from 'lucide-react'
import PageGuide from '../../../components/PageGuide'
import { scanModel, scanModelLive, fetchHfInfo } from '../api'
import type { ModelScan } from '../api'
import { useAgentStudioState } from '../../../hooks/useAgentStudioState'

const SAMPLE_MODEL = 'meta-llama/Llama-3.1-8B-Instruct'
const SAMPLE_SPEC = `{
  "licence": "llama-3",
  "files": ["model.safetensors", "config.json", "tokenizer.json"],
  "dependencies": ["transformers==4.45.0", "huggingface_hub==0.26.0"],
  "framework": "pytorch",
  "size_gb": 16.0,
  "downloads": 1820000,
  "likes": 3400,
  "parent_models": []
}`

const RISK_TONE: Record<string, string> = {
  safe:     'bg-accent-green/10 text-accent-green border-accent-green/30',
  low:      'bg-accent-green/10 text-accent-green border-accent-green/30',
  medium:   'bg-accent-amber/10 text-accent-amber border-accent-amber/30',
  high:     'bg-accent-red/10 text-accent-red border-accent-red/30',
  critical: 'bg-accent-red/15 text-accent-red border-accent-red/40',
}

type Mode = 'static' | 'live'

export default function SupplyChainScanner() {
  const [modelId, setModelId] = useAgentStudioState<string>('supply', 'modelId', SAMPLE_MODEL)
  const [specText, setSpecText] = useAgentStudioState<string>('supply', 'spec', SAMPLE_SPEC)
  const [result, setResult] = useAgentStudioState<ModelScan | null>('supply', 'lastResult', null)
  const [hfUsed, setHfUsed] = useAgentStudioState<boolean | null>('supply', 'hfUsed', null)
  const [running, setRunning] = useState<Mode | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [hfInfo, setHfInfo] = useState<{ has_token: boolean; base_url: string } | null>(null)

  useEffect(() => {
    fetchHfInfo()
      .then((i) => setHfInfo({ has_token: i.has_token, base_url: i.base_url }))
      .catch(() => {})
  }, [])

  const doScan = async (mode: Mode = 'static') => {
    setRunning(mode); setErr(null); setHfUsed(null)
    try {
      const spec = specText.trim() ? JSON.parse(specText) : {}
      if (mode === 'live') {
        const res = await scanModelLive(modelId, spec)
        setHfUsed(res.hf_enrichment_used)
        setResult(res)
      } else {
        setResult(await scanModel(modelId, spec))
      }
    } catch (e) {
      setErr(String(e))
    } finally {
      setRunning(null)
    }
  }

  const copySbom = () => {
    if (!result) return
    navigator.clipboard.writeText(JSON.stringify(result.sbom_fragment, null, 2))
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-display font-bold flex items-center gap-2">
          <Package className="w-5 h-5 text-accent-blue" /> Model Supply-Chain Scanner
        </h1>
        <p className="text-xs text-text-secondary mt-1 max-w-3xl">
          HuggingFace risk scoring + CycloneDX-AI SBOM fragment + pickle/safetensors format risk +
          CVE matching against the transformers / huggingface_hub / llama.cpp corpus. Fills the
          gap left by Protect AI's acquisition into Palo Alto.
        </p>
      </div>

      <PageGuide
        title="How to use the Supply Chain Scanner"
        steps={[
          { title: 'Enter a model ID', desc: 'HuggingFace repo (e.g. meta-llama/Llama-3.1-8B-Instruct), local path, or URL.' },
          { title: 'Optional: paste a spec', desc: 'JSON with licence, files[], dependencies[]. Fills in fields the HF API would auto-fetch in production.' },
          { title: 'Scan', desc: 'File-format risk + CVE match + licence risk → aggregate 0–1 risk score with risk_level (safe / low / medium / high / critical).' },
          { title: 'Read the rationale', desc: 'Each risk-score contributor explained in plain text — auditable, not a black box.' },
          { title: 'Export SBOM', desc: 'CycloneDX-AI fragment ready to copy into a downstream SBOM aggregator (Anchore, Snyk, FOSSA).' },
        ]}
        tip="The CVE corpus is curated for the agentic-AI dependency tree. Production swap-in: live OSV.dev + NIST NVD API lookup keeping the same JSON contract."
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-bg-card rounded-xl p-4 space-y-3">
          <div>
            <label className="text-xs text-text-secondary block mb-1">Model identifier</label>
            <input value={modelId} onChange={(e) => setModelId(e.target.value)}
                   className="w-full bg-bg-secondary border border-bg-card/60 rounded-md px-2 py-1 text-xs font-mono" />
          </div>
          <div>
            <label className="text-xs text-text-secondary block mb-1">Spec (JSON, optional)</label>
            <textarea value={specText} onChange={(e) => setSpecText(e.target.value)}
                      className="w-full h-56 bg-bg-secondary border border-bg-card/60 rounded-md p-2 text-xs font-mono"
                      spellCheck={false} />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <button onClick={() => doScan('static')} disabled={running !== null || !modelId}
                    className="bg-accent-blue hover:bg-accent-blue/90 text-white px-3 py-2 rounded-md text-xs font-medium flex items-center justify-center gap-2 disabled:opacity-50">
              {running === 'static' ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                    : <Play className="w-3.5 h-3.5" />}
              Static scan
            </button>
            <button onClick={() => doScan('live')} disabled={running !== null || !modelId}
                    className="bg-accent-purple hover:bg-accent-purple/90 text-white px-3 py-2 rounded-md text-xs font-medium flex items-center justify-center gap-2 disabled:opacity-50"
                    title="Enriches the spec with live HuggingFace Hub metadata before scoring.">
              {running === 'live' ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                  : <Globe className="w-3.5 h-3.5" />}
              Live HF scan
            </button>
          </div>
          {hfInfo && (
            <div className="text-[10px] font-mono text-text-secondary">
              HF API: <span className="text-text-primary">{hfInfo.base_url}</span>
              {hfInfo.has_token ? (
                <span className="ml-2 text-accent-green">· token set</span>
              ) : (
                <span className="ml-2 text-accent-orange">· anonymous (rate-limited)</span>
              )}
            </div>
          )}
          {hfUsed !== null && (
            <div className={`text-[10px] font-mono ${hfUsed ? 'text-accent-green' : 'text-accent-amber'}`}>
              {hfUsed ? '✓ HF metadata merged into spec.' : '⚠ HF unreachable — used only the spec you provided.'}
            </div>
          )}
        </div>

        <div className="bg-bg-card rounded-xl p-4">
          <h2 className="text-sm font-semibold mb-2 flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-accent-blue" /> Risk report
          </h2>
          {err && <div className="p-2 bg-accent-red/10 border border-accent-red/30 rounded-md text-xs text-accent-red mb-2">{err}</div>}
          {!result && !err && <div className="text-xs text-text-secondary">Enter a model identifier and press Scan.</div>}
          {result && (
            <>
              <div className={`p-3 rounded-md border mb-3 ${RISK_TONE[result.risk_level]}`}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] font-mono uppercase opacity-70">risk level</span>
                  <span className="text-2xl font-display font-bold uppercase">{result.risk_level}</span>
                </div>
                <div className="text-[10px] font-mono opacity-70">score {(result.risk_score * 100).toFixed(0)}% · {result.architecture}</div>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs mb-3">
                <Field label="origin" value={result.origin} />
                <Field label="licence" value={result.licence} />
                {result.size_gb !== null && <Field label="size" value={`${result.size_gb} GB`} />}
                {result.downloads !== null && <Field label="downloads" value={(result.downloads || 0).toLocaleString()} />}
              </div>

              <div className="mb-2">
                <div className="text-[10px] font-mono uppercase text-text-secondary mb-1">file-format risks</div>
                <div className="space-y-1">
                  {result.format_risks.map((f, i) => (
                    <div key={i} className={`border rounded p-1.5 text-[11px] ${RISK_TONE[f.risk_level]}`}>
                      <span className="font-mono">{f.file_format}</span>
                      <span className="text-[10px] uppercase ml-2 opacity-70">{f.risk_level}</span>
                      <div className="text-[10px] opacity-80 mt-0.5">{f.rationale}</div>
                    </div>
                  ))}
                </div>
              </div>

              {result.cve_matches.length > 0 && (
                <div className="mb-2">
                  <div className="text-[10px] font-mono uppercase text-text-secondary mb-1">CVE matches</div>
                  <div className="space-y-1">
                    {result.cve_matches.map((c) => (
                      <div key={c.cve} className="border border-accent-red/30 bg-accent-red/5 rounded p-1.5 text-[11px]">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-accent-red">{c.cve}</span>
                          <span className="text-[9px] font-mono uppercase text-text-secondary">{c.severity}</span>
                          <a href={`https://nvd.nist.gov/vuln/detail/${c.cve}`} target="_blank" rel="noreferrer"
                             className="ml-auto text-accent-blue hover:text-accent-orange">
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        </div>
                        <div className="text-[10px] opacity-80 mt-0.5">{c.summary}</div>
                        <div className="text-[9px] font-mono opacity-60 mt-0.5">affects: {c.affects}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="mb-3">
                <div className="text-[10px] font-mono uppercase text-text-secondary mb-1">rationale</div>
                <ul className="text-[10px] space-y-0.5 list-disc list-inside text-text-secondary">
                  {result.rationale.map((r, i) => <li key={i}>{r}</li>)}
                </ul>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] font-mono uppercase text-text-secondary">CycloneDX-AI SBOM</span>
                  <button onClick={copySbom}
                          className="text-[10px] flex items-center gap-1 text-accent-blue hover:text-accent-orange">
                    <Copy className="w-3 h-3" /> Copy
                  </button>
                </div>
                <pre className="text-[9px] font-mono bg-bg-secondary border border-bg-card/40 rounded p-2 overflow-x-auto max-h-32">
{JSON.stringify(result.sbom_fragment, null, 2)}
                </pre>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-bg-secondary border border-bg-card/40 rounded p-2">
      <div className="text-[9px] font-mono uppercase text-text-secondary">{label}</div>
      <div className="text-xs font-mono text-text-primary">{value}</div>
    </div>
  )
}
