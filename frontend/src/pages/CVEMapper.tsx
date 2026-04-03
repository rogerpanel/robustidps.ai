import { useState, useMemo } from 'react'
import {
  AlertTriangle, Upload, FileText, X, Loader2, Radio,
  ExternalLink, Shield, Activity,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import ModelSelector from '../components/ModelSelector'
import { analyseFile, cachePageResult } from '../utils/api'
import { useNoticeBoard } from '../hooks/useNoticeBoard'
import { getLiveData, hasLiveData } from '../utils/liveDataStore'

/* ── CVE mapping data ────────────────────────────────────────────────── */

interface CVEEntry { id: string; description: string; cvss: number; year: number }
interface CVEMapping { cves: CVEEntry[]; remediation: string }

const CVE_MAPPINGS: Record<string, CVEMapping> = {
  'WebAttack-SQLi': {
    cves: [
      { id: 'CVE-2024-32651', description: 'SQL injection in web application framework', cvss: 9.8, year: 2024 },
      { id: 'CVE-2023-34362', description: 'MOVEit Transfer SQL injection (Cl0p ransomware)', cvss: 9.8, year: 2023 },
      { id: 'CVE-2021-44228', description: 'Log4Shell — remote code execution via JNDI injection', cvss: 10.0, year: 2021 },
    ],
    remediation: 'Use parameterized queries. Deploy WAF. Input validation on all user inputs.',
  },
  'WebAttack-XSS': {
    cves: [
      { id: 'CVE-2024-21388', description: 'Microsoft Edge XSS via extension installation', cvss: 6.5, year: 2024 },
      { id: 'CVE-2023-29489', description: 'cPanel XSS vulnerability', cvss: 6.1, year: 2023 },
    ],
    remediation: 'Encode output. Use Content-Security-Policy headers. Sanitize HTML with DOMPurify.',
  },
  'WebAttack-CommandInjection': {
    cves: [
      { id: 'CVE-2024-3400', description: 'Palo Alto PAN-OS command injection (zero-day)', cvss: 10.0, year: 2024 },
      { id: 'CVE-2023-46805', description: 'Ivanti Connect Secure command injection', cvss: 8.2, year: 2023 },
    ],
    remediation: 'Never pass user input to system commands. Use allowlists. Sandbox execution.',
  },
  'BruteForce-SSH': {
    cves: [
      { id: 'CVE-2024-6387', description: 'regreSSHion — OpenSSH remote code execution', cvss: 8.1, year: 2024 },
      { id: 'CVE-2023-48795', description: 'Terrapin SSH prefix truncation attack', cvss: 5.9, year: 2023 },
    ],
    remediation: 'Update OpenSSH. Enforce key-based auth. Implement fail2ban. Use MFA.',
  },
  'Malware-Ransomware': {
    cves: [
      { id: 'CVE-2024-1709', description: 'ConnectWise ScreenConnect auth bypass (ransomware vector)', cvss: 10.0, year: 2024 },
      { id: 'CVE-2023-27997', description: 'FortiGate SSL VPN RCE (ransomware entry point)', cvss: 9.8, year: 2023 },
    ],
    remediation: 'Patch all edge devices. Maintain offline backups. Network segmentation.',
  },
  'Spoofing-DNS': {
    cves: [
      { id: 'CVE-2024-33655', description: 'DNS KeyTrap denial-of-service via DNSSEC', cvss: 7.5, year: 2024 },
      { id: 'CVE-2008-1447', description: 'Kaminsky DNS cache poisoning (foundational)', cvss: 6.8, year: 2008 },
    ],
    remediation: 'Enable DNSSEC. Use DNS-over-HTTPS. Monitor for unusual DNS responses.',
  },
}

/* ── CVSS color helpers ──────────────────────────────────────────────── */

function cvssColor(score: number): string {
  if (score >= 9) return 'text-red-400 bg-red-500/15 border-red-500/30'
  if (score >= 7) return 'text-orange-400 bg-orange-500/15 border-orange-500/30'
  if (score >= 4) return 'text-amber-400 bg-amber-500/15 border-amber-500/30'
  return 'text-green-400 bg-green-500/15 border-green-500/30'
}

function cvssLabel(score: number): string {
  if (score >= 9) return 'Critical'
  if (score >= 7) return 'High'
  if (score >= 4) return 'Medium'
  return 'Low'
}

const GUIDE_STEPS = [
  { title: 'Upload traffic data', desc: 'Upload a CSV/PCAP or use Live Monitor data to identify attack types in your traffic.' },
  { title: 'Review CVE mappings', desc: 'Each detected web attack is mapped to real-world CVEs with CVSS scores and remediation guidance.' },
  { title: 'Export findings', desc: 'Download the vulnerability report as PNG, PDF or slides for your security team.' },
]

/* ── Component ───────────────────────────────────────────────────────── */

export default function CVEMapper() {
  const [file, setFile] = useState<File | null>(null)
  const [modelId, setModelId] = useState('surrogate')
  const [analysisResult, setAnalysisResult] = useState<any>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [liveDataLoaded, setLiveDataLoaded] = useState(false)
  const { addNotice, updateNotice } = useNoticeBoard()

  /* Derive detected attack types */
  const detectedAttacks = useMemo(() => {
    if (!analysisResult?.predictions) return {}
    const counts: Record<string, number> = {}
    analysisResult.predictions.forEach((p: any) => {
      const label = p.label_predicted || ''
      if (label && label !== 'Benign') counts[label] = (counts[label] || 0) + 1
    })
    return counts
  }, [analysisResult])

  /* Map detected attacks to CVEs */
  const mappedCVEs = useMemo(() => {
    const results: { attackType: string; count: number; mapping: CVEMapping }[] = []
    for (const [attackType, count] of Object.entries(detectedAttacks)) {
      const key = Object.keys(CVE_MAPPINGS).find(k =>
        attackType.toLowerCase().replace(/[_-]/g, '').includes(k.toLowerCase().replace(/[_-]/g, '')) ||
        k.toLowerCase().replace(/[_-]/g, '').includes(attackType.toLowerCase().replace(/[_-]/g, ''))
      )
      if (key) results.push({ attackType, count, mapping: CVE_MAPPINGS[key] })
    }
    return results
  }, [detectedAttacks])

  /* Summary stats */
  const totalCVEs = mappedCVEs.reduce((s, m) => s + m.mapping.cves.length, 0)
  const highestCVSS = mappedCVEs.length > 0
    ? Math.max(...mappedCVEs.flatMap(m => m.mapping.cves.map(c => c.cvss)))
    : 0

  const runAnalysis = async () => {
    if (!file) return
    setAnalyzing(true)
    const nid = addNotice({ title: 'CVE Mapper', description: `Analyzing ${file.name}...`, status: 'running', page: '/cve-mapper' })
    try {
      const data = await analyseFile(file, modelId, 'cve_mapper')
      setAnalysisResult(data)
      const nThreats = data.predictions?.filter((p: any) => p.label_predicted !== 'Benign').length || 0
      updateNotice(nid, { status: 'completed', description: `${nThreats} threats analyzed for CVE mapping` })
      cachePageResult('cve_mapper', {
        n_flows: data.predictions?.length || 0,
        n_threats: nThreats,
        model_used: modelId,
      }).catch(() => {})
    } catch (err) {
      updateNotice(nid, { status: 'error', description: err instanceof Error ? err.message : 'Analysis failed' })
    }
    setAnalyzing(false)
  }

  const loadLiveData = () => {
    const live = getLiveData()
    if (!live) return
    setAnalysisResult({ predictions: live.predictions, n_flows: live.totalFlows, n_threats: live.threatCount })
    setLiveDataLoaded(true)
  }

  return (
    <div className="space-y-6 cve-mapper-root">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-accent-red/10 flex items-center justify-center">
            <AlertTriangle className="w-5 h-5 text-accent-red" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-text-primary">CVE Mapper</h1>
            <p className="text-xs text-text-secondary mt-0.5">
              Map detected attacks to real-world CVE vulnerabilities with CVSS scoring
            </p>
          </div>
        </div>
        <ExportMenu targetSelector=".cve-mapper-root" filename="cve-mapping-report" />
      </div>

      <PageGuide title="How to use the CVE Mapper" steps={GUIDE_STEPS} tip="CVE mappings cover the most common web attacks, brute force, ransomware, and DNS spoofing with remediation guidance." />

      {/* Upload + Model */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold mb-3">Analyze Traffic for CVE Mapping</h2>
        <p className="text-xs text-text-secondary mb-3">Upload a dataset or use Live Monitor data. Detected attacks are mapped to known CVEs.</p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end">
          <div>
            {file ? (
              <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-accent-green/30 bg-accent-green/5">
                <FileText className="w-4 h-4 text-accent-green shrink-0" />
                <span className="text-xs font-mono truncate flex-1">{file.name}</span>
                <button onClick={() => { setFile(null); setAnalysisResult(null) }} className="text-text-secondary hover:text-text-primary"><X className="w-3.5 h-3.5" /></button>
              </div>
            ) : (
              <label onDragOver={e => { e.preventDefault(); e.currentTarget.classList.add('border-accent-blue', 'bg-accent-blue/10') }} onDragLeave={e => { e.currentTarget.classList.remove('border-accent-blue', 'bg-accent-blue/10') }} onDrop={e => { e.preventDefault(); e.currentTarget.classList.remove('border-accent-blue', 'bg-accent-blue/10'); const f = e.dataTransfer.files[0]; if (f) setFile(f) }} className="flex flex-col items-center gap-1 px-3 py-3 rounded-lg border-2 border-dashed border-bg-card hover:border-text-secondary cursor-pointer transition-colors">
                <Upload className="w-5 h-5 text-text-secondary" />
                <span className="text-[10px] text-text-secondary">Drop or click</span>
                <span className="text-[9px] text-text-secondary/60">.csv .pcap .pcapng</span>
                <input type="file" accept=".csv,.pcap,.pcapng" className="hidden" onChange={e => setFile(e.target.files?.[0] || null)} />
              </label>
            )}
          </div>
          <div>
            <label className="text-xs text-text-secondary block mb-1">Detection Model</label>
            <ModelSelector value={modelId} onChange={setModelId} compact />
          </div>
          <button onClick={runAnalysis} disabled={!file || analyzing} className="px-4 py-2.5 bg-accent-red hover:bg-accent-red/80 text-white rounded-lg text-xs font-medium disabled:opacity-50 flex items-center justify-center gap-2">
            {analyzing ? <><Loader2 className="w-4 h-4 animate-spin" /> Analyzing...</> : 'Analyze & Map CVEs'}
          </button>
        </div>
      </div>

      {/* Live Monitor banner */}
      {hasLiveData() && !liveDataLoaded && !analysisResult && (
        <div className="flex items-center gap-3 px-4 py-3 bg-accent-orange/10 border border-accent-orange/20 rounded-xl">
          <Radio className="w-4 h-4 text-accent-orange" />
          <div className="flex-1">
            <span className="text-xs font-medium text-accent-orange">Live Monitor data available</span>
            <span className="text-[10px] text-text-secondary ml-2">{getLiveData()?.totalFlows} flows from {getLiveData()?.source}</span>
          </div>
          <button onClick={loadLiveData} className="px-3 py-1 bg-accent-orange hover:bg-accent-orange/80 text-white text-[10px] font-medium rounded-lg transition-colors">
            Use Live Data
          </button>
        </div>
      )}

      {/* Summary stats */}
      {mappedCVEs.length > 0 && (
        <div className="grid grid-cols-3 gap-3">
          <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card text-center">
            <p className="text-2xl font-bold text-accent-blue">{totalCVEs}</p>
            <p className="text-[10px] text-text-secondary mt-1">CVEs Mapped</p>
          </div>
          <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card text-center">
            <p className={`text-2xl font-bold ${highestCVSS >= 9 ? 'text-red-400' : highestCVSS >= 7 ? 'text-orange-400' : 'text-amber-400'}`}>{highestCVSS.toFixed(1)}</p>
            <p className="text-[10px] text-text-secondary mt-1">Highest CVSS</p>
          </div>
          <div className="bg-bg-secondary rounded-xl p-4 border border-bg-card text-center">
            <p className="text-2xl font-bold text-accent-purple">{mappedCVEs.length}</p>
            <p className="text-[10px] text-text-secondary mt-1">Attack Types with CVEs</p>
          </div>
        </div>
      )}

      {/* CVE results */}
      {mappedCVEs.length > 0 && (
        <div className="space-y-4">
          {mappedCVEs.map(({ attackType, count, mapping }) => (
            <div key={attackType} className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
              <div className="px-5 py-3 border-b border-bg-card/50 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Activity className="w-4 h-4 text-accent-red" />
                  <span className="text-sm font-semibold text-text-primary">{attackType}</span>
                  <span className="text-[10px] text-text-secondary bg-bg-card px-2 py-0.5 rounded">{count} flows</span>
                </div>
                <span className="text-[10px] text-text-secondary">{mapping.cves.length} CVE{mapping.cves.length !== 1 ? 's' : ''}</span>
              </div>
              <div className="p-4 space-y-2">
                {mapping.cves.map(cve => (
                  <div key={cve.id} className="flex items-start gap-3 p-3 rounded-lg bg-bg-card/30">
                    <div className={`shrink-0 px-2 py-1 rounded border text-[10px] font-bold ${cvssColor(cve.cvss)}`}>
                      {cve.cvss.toFixed(1)} {cvssLabel(cve.cvss)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <a href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noopener noreferrer" className="text-xs font-mono font-semibold text-accent-blue hover:underline inline-flex items-center gap-1">
                        {cve.id} <ExternalLink className="w-3 h-3" />
                      </a>
                      <p className="text-[11px] text-text-secondary mt-0.5">{cve.description}</p>
                    </div>
                    <span className="text-[10px] text-text-secondary/60 shrink-0">{cve.year}</span>
                  </div>
                ))}
                <div className="mt-2 px-3 py-2 bg-accent-green/5 border border-accent-green/20 rounded-lg">
                  <div className="flex items-start gap-2">
                    <Shield className="w-3.5 h-3.5 text-accent-green shrink-0 mt-0.5" />
                    <p className="text-[11px] text-accent-green">{mapping.remediation}</p>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Related */}
      {mappedCVEs.length > 0 && (
        <div className="flex flex-wrap gap-2 pt-3 border-t border-bg-card">
          <span className="text-[10px] text-text-secondary mr-2">Related:</span>
          <a href="/mitre-attack" className="text-[10px] px-2 py-1 rounded bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20 transition-colors">MITRE ATT&CK</a>
          <a href="/rule-generator" className="text-[10px] px-2 py-1 rounded bg-accent-orange/10 text-accent-orange hover:bg-accent-orange/20 transition-colors">Rule Generator</a>
          <a href="/threat-response" className="text-[10px] px-2 py-1 rounded bg-accent-green/10 text-accent-green hover:bg-accent-green/20 transition-colors">Threat Response</a>
        </div>
      )}

      {/* Empty state */}
      {analysisResult && mappedCVEs.length === 0 && (
        <div className="bg-bg-secondary rounded-xl p-8 border border-bg-card text-center">
          <Shield className="w-8 h-8 text-accent-green mx-auto mb-3" />
          <p className="text-sm text-text-primary font-medium">No CVE-mapped attacks detected</p>
          <p className="text-xs text-text-secondary mt-1">Detected traffic did not match any attack types with known CVE mappings.</p>
        </div>
      )}

      {/* Reference: supported attack types */}
      {!analysisResult && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-semibold text-text-primary mb-3">CVE Coverage ({Object.keys(CVE_MAPPINGS).length} attack types)</h3>
          <div className="flex flex-wrap gap-2">
            {Object.entries(CVE_MAPPINGS).map(([k, v]) => (
              <span key={k} className="px-2.5 py-1 bg-bg-card rounded-lg text-[10px] font-mono text-text-secondary">
                {k} <span className="text-text-secondary/50">({v.cves.length} CVEs)</span>
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
