import { useState, useMemo, useCallback } from 'react'
import {
  Shield, Upload, FileText, X, Loader2, Radio, Copy, Download,
  Check, ChevronDown, Activity,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import ModelSelector from '../components/ModelSelector'
import { analyseFile, cachePageResult } from '../utils/api'
import { useNoticeBoard } from '../hooks/useNoticeBoard'
import { getLiveData, hasLiveData } from '../utils/liveDataStore'

/* ── Suricata / Snort rule templates ─────────────────────────────────── */

const RULE_TEMPLATES: Record<string, (src: string, dst: string) => string> = {
  'DDoS-TCP_Flood': (s, d) => `alert tcp ${s} any -> ${d} any (msg:"RobustIDPS: DDoS TCP Flood detected"; flow:stateless; threshold:type both,track by_src,count 100,seconds 10; classtype:denial-of-service; sid:3000001; rev:1;)`,
  'DDoS-UDP_Flood': (s, d) => `alert udp ${s} any -> ${d} any (msg:"RobustIDPS: DDoS UDP Flood detected"; threshold:type both,track by_src,count 100,seconds 10; classtype:denial-of-service; sid:3000002; rev:1;)`,
  'DDoS-SYN_Flood': (s, d) => `alert tcp ${s} any -> ${d} any (msg:"RobustIDPS: SYN Flood detected"; flags:S; threshold:type both,track by_src,count 50,seconds 5; classtype:denial-of-service; sid:3000003; rev:1;)`,
  'DDoS-HTTP_Flood': (s, d) => `alert tcp ${s} any -> ${d} 80 (msg:"RobustIDPS: HTTP Flood detected"; content:"GET"; http_method; threshold:type both,track by_src,count 50,seconds 10; classtype:denial-of-service; sid:3000004; rev:1;)`,
  'BruteForce-SSH': (s, d) => `alert tcp ${s} any -> ${d} 22 (msg:"RobustIDPS: SSH Brute Force detected"; flow:to_server,established; threshold:type both,track by_src,count 5,seconds 60; classtype:attempted-admin; sid:3000010; rev:1;)`,
  'BruteForce-FTP': (s, d) => `alert tcp ${s} any -> ${d} 21 (msg:"RobustIDPS: FTP Brute Force detected"; flow:to_server,established; threshold:type both,track by_src,count 5,seconds 60; classtype:attempted-admin; sid:3000011; rev:1;)`,
  'WebAttack-SQLi': (s, d) => `alert tcp ${s} any -> ${d} 80 (msg:"RobustIDPS: SQL Injection detected"; content:"SELECT"; nocase; content:"FROM"; nocase; classtype:web-application-attack; sid:3000020; rev:1;)`,
  'WebAttack-XSS': (s, d) => `alert tcp ${s} any -> ${d} 80 (msg:"RobustIDPS: XSS Attack detected"; content:"<script"; nocase; classtype:web-application-attack; sid:3000021; rev:1;)`,
  'WebAttack-CommandInjection': (s, d) => `alert tcp ${s} any -> ${d} 80 (msg:"RobustIDPS: Command Injection detected"; content:"|3b|"; content:"cat"; nocase; classtype:web-application-attack; sid:3000022; rev:1;)`,
  'Recon-PortScan': (s, d) => `alert tcp ${s} any -> ${d} any (msg:"RobustIDPS: Port Scan detected"; flags:S; threshold:type both,track by_src,count 20,seconds 5; classtype:attempted-recon; sid:3000030; rev:1;)`,
  'Spoofing-DNS': (s, d) => `alert udp ${s} 53 -> ${d} any (msg:"RobustIDPS: DNS Spoofing detected"; content:"|81 80|"; offset:2; depth:2; classtype:bad-unknown; sid:3000040; rev:1;)`,
  'Malware-Backdoor': (s, d) => `alert tcp ${d} any -> ${s} [4444,5555,8888,1337] (msg:"RobustIDPS: Backdoor C2 Communication"; flow:to_server,established; classtype:trojan-activity; sid:3000050; rev:1;)`,
  'Malware-Ransomware': (s, d) => `alert tcp ${s} any -> ${d} 445 (msg:"RobustIDPS: Ransomware SMB Activity"; flow:to_server,established; content:"|ff|SMB"; classtype:trojan-activity; sid:3000051; rev:1;)`,
}

const GUIDE_STEPS = [
  { title: 'Upload traffic data', desc: 'Upload a CSV/PCAP file or use Live Monitor data to detect attacks in your network traffic.' },
  { title: 'Select detection model', desc: 'Choose the ML model to classify traffic flows. The surrogate model works well for most scenarios.' },
  { title: 'Generate rules', desc: 'After analysis, Suricata/Snort rules are auto-generated for every detected attack type.' },
  { title: 'Export rules', desc: 'Copy all rules to clipboard or download a .rules file ready to deploy in your IDS.' },
]

type RuleFormat = 'Suricata' | 'Snort'

/* ── Component ───────────────────────────────────────────────────────── */

export default function RuleGenerator() {
  const [file, setFile] = useState<File | null>(null)
  const [modelId, setModelId] = useState('surrogate')
  const [analysisResult, setAnalysisResult] = useState<any>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [liveDataLoaded, setLiveDataLoaded] = useState(false)
  const [format, setFormat] = useState<RuleFormat>('Suricata')
  const [excluded, setExcluded] = useState<Set<string>>(new Set())
  const [copied, setCopied] = useState(false)
  const { addNotice, updateNotice } = useNoticeBoard()

  /* Derive detected attack types from analysis */
  const detectedAttacks = useMemo(() => {
    if (!analysisResult?.predictions) return {}
    const counts: Record<string, { count: number; srcIps: Set<string>; dstIps: Set<string> }> = {}
    analysisResult.predictions.forEach((p: any) => {
      const label = p.label_predicted || ''
      if (label && label !== 'Benign') {
        if (!counts[label]) counts[label] = { count: 0, srcIps: new Set(), dstIps: new Set() }
        counts[label].count += 1
        if (p.src_ip) counts[label].srcIps.add(p.src_ip)
        if (p.dst_ip) counts[label].dstIps.add(p.dst_ip)
      }
    })
    return counts
  }, [analysisResult])

  /* Generate rules from detected attacks */
  const generatedRules = useMemo(() => {
    const rules: { attackType: string; rule: string; count: number }[] = []
    for (const [attackType, info] of Object.entries(detectedAttacks)) {
      const templateKey = Object.keys(RULE_TEMPLATES).find(k =>
        attackType.toLowerCase().includes(k.toLowerCase().replace(/[_-]/g, '')) ||
        k.toLowerCase().replace(/[_-]/g, '').includes(attackType.toLowerCase().replace(/[_-]/g, ''))
      )
      if (templateKey) {
        const src = info.srcIps.size === 1 ? [...info.srcIps][0] : '$EXTERNAL_NET'
        const dst = info.dstIps.size === 1 ? [...info.dstIps][0] : '$HOME_NET'
        rules.push({ attackType, rule: RULE_TEMPLATES[templateKey](src, dst), count: info.count })
      }
    }
    return rules
  }, [detectedAttacks])

  const activeRules = useMemo(() => generatedRules.filter(r => !excluded.has(r.attackType)), [generatedRules, excluded])

  const toggleRule = useCallback((attackType: string) => {
    setExcluded(prev => {
      const next = new Set(prev)
      if (next.has(attackType)) next.delete(attackType)
      else next.add(attackType)
      return next
    })
  }, [])

  const rulesText = useMemo(() => {
    const header = `# RobustIDPS.AI — Auto-generated ${format} rules\n# Generated: ${new Date().toISOString()}\n# Attack types covered: ${activeRules.length}\n\n`
    return header + activeRules.map(r => r.rule).join('\n\n')
  }, [activeRules, format])

  const runAnalysis = async () => {
    if (!file) return
    setAnalyzing(true)
    const nid = addNotice({ title: 'Rule Generator', description: `Analyzing ${file.name}...`, status: 'running', page: '/rule-generator' })
    try {
      const data = await analyseFile(file, modelId, 'rule_generator')
      setAnalysisResult(data)
      const nThreats = data.predictions?.filter((p: any) => p.label_predicted !== 'Benign').length || 0
      updateNotice(nid, { status: 'completed', description: `${nThreats} threats detected — rules generated` })
      cachePageResult('rule_generator', {
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

  const copyRules = async () => {
    await navigator.clipboard.writeText(rulesText)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const downloadRules = () => {
    const blob = new Blob([rulesText], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `robustidps_${format.toLowerCase()}.rules`
    a.click()
    URL.revokeObjectURL(url)
  }

  /* Syntax highlight keywords in a rule string */
  const highlightRule = (rule: string) => {
    return rule
      .replace(/^(alert)\b/g, '<span class="text-accent-red font-bold">$1</span>')
      .replace(/\b(tcp|udp|icmp)\b/g, '<span class="text-accent-blue">$1</span>')
      .replace(/\b(msg|content|flow|flags|threshold|classtype|sid|rev|nocase|offset|depth|http_method)\b/g, '<span class="text-accent-amber">$1</span>')
      .replace(/"([^"]+)"/g, '<span class="text-accent-green">"$1"</span>')
      .replace(/(\$[A-Z_]+)/g, '<span class="text-accent-purple">$1</span>')
  }

  return (
    <div className="space-y-6 rule-generator-root">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-accent-blue/10 flex items-center justify-center">
            <Shield className="w-5 h-5 text-accent-blue" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-text-primary">IDS Rule Generator</h1>
            <p className="text-xs text-text-secondary mt-0.5">
              Auto-generate Suricata/Snort detection rules from detected attacks
            </p>
          </div>
        </div>
        <ExportMenu targetSelector=".rule-generator-root" filename="ids-rules" />
      </div>

      <PageGuide title="How to use the Rule Generator" steps={GUIDE_STEPS} tip="Rules use standard Suricata/Snort syntax and can be deployed directly into your IDS configuration." />

      {/* Upload + Model */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold mb-3">Analyze Traffic & Generate Rules</h2>
        <p className="text-xs text-text-secondary mb-3">Upload a dataset or use Live Monitor data. Rules are generated for each detected attack type.</p>
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
          <button onClick={runAnalysis} disabled={!file || analyzing} className="px-4 py-2.5 bg-accent-blue hover:bg-accent-blue/80 text-white rounded-lg text-xs font-medium disabled:opacity-50 flex items-center justify-center gap-2">
            {analyzing ? <><Loader2 className="w-4 h-4 animate-spin" /> Analyzing...</> : 'Analyze & Generate Rules'}
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

      {/* Results */}
      {generatedRules.length > 0 && (
        <>
          {/* Stats + controls */}
          <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
            <div className="flex items-center justify-between flex-wrap gap-3 mb-4">
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-accent-blue" />
                  <span className="text-sm font-semibold text-text-primary">{activeRules.length} rules generated</span>
                  <span className="text-xs text-text-secondary">({generatedRules.length} attack types covered)</span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {/* Format selector */}
                <div className="relative">
                  <select value={format} onChange={e => setFormat(e.target.value as RuleFormat)} className="appearance-none bg-bg-card border border-bg-card text-text-primary text-xs rounded-lg px-3 py-1.5 pr-7 focus:outline-none focus:border-accent-blue">
                    <option value="Suricata">Suricata</option>
                    <option value="Snort">Snort</option>
                  </select>
                  <ChevronDown className="w-3 h-3 text-text-secondary absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none" />
                </div>
                <button onClick={copyRules} className="flex items-center gap-1.5 px-3 py-1.5 bg-accent-blue/15 text-accent-blue hover:bg-accent-blue/25 rounded-lg text-xs font-medium transition-colors">
                  {copied ? <><Check className="w-3.5 h-3.5" /> Copied</> : <><Copy className="w-3.5 h-3.5" /> Copy All</>}
                </button>
                <button onClick={downloadRules} className="flex items-center gap-1.5 px-3 py-1.5 bg-accent-green/15 text-accent-green hover:bg-accent-green/25 rounded-lg text-xs font-medium transition-colors">
                  <Download className="w-3.5 h-3.5" /> Download .rules
                </button>
              </div>
            </div>

            {/* Rule list with checkboxes */}
            <div className="space-y-3">
              {generatedRules.map(({ attackType, rule, count }) => {
                const isIncluded = !excluded.has(attackType)
                return (
                  <div key={attackType} className={`rounded-lg border p-3 transition-colors ${isIncluded ? 'border-accent-blue/20 bg-bg-card/50' : 'border-bg-card/30 bg-bg-card/20 opacity-50'}`}>
                    <div className="flex items-center gap-3 mb-2">
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input type="checkbox" checked={isIncluded} onChange={() => toggleRule(attackType)} className="rounded border-bg-card text-accent-blue focus:ring-accent-blue/30 w-3.5 h-3.5" />
                        <span className="text-xs font-semibold text-text-primary">{attackType}</span>
                      </label>
                      <span className="text-[10px] text-text-secondary bg-bg-card px-2 py-0.5 rounded">{count} flows detected</span>
                    </div>
                    <pre className="text-[11px] font-mono leading-relaxed overflow-x-auto whitespace-pre-wrap break-all bg-[#0d1117] rounded-lg p-3 border border-bg-card/50" dangerouslySetInnerHTML={{ __html: highlightRule(rule) }} />
                  </div>
                )
              })}
            </div>
          </div>
        </>
      )}

      {/* Empty state */}
      {analysisResult && generatedRules.length === 0 && (
        <div className="bg-bg-secondary rounded-xl p-8 border border-bg-card text-center">
          <Shield className="w-8 h-8 text-accent-green mx-auto mb-3" />
          <p className="text-sm text-text-primary font-medium">No attack types detected</p>
          <p className="text-xs text-text-secondary mt-1">All traffic appears benign. No IDS rules needed.</p>
        </div>
      )}

      {/* Template reference */}
      {!analysisResult && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-semibold text-text-primary mb-3">Supported Attack Types ({Object.keys(RULE_TEMPLATES).length} rule templates)</h3>
          <div className="flex flex-wrap gap-2">
            {Object.keys(RULE_TEMPLATES).map(k => (
              <span key={k} className="px-2.5 py-1 bg-bg-card rounded-lg text-[10px] font-mono text-text-secondary">{k}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
