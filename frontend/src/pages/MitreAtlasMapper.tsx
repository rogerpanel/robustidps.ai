import { useState, useMemo } from 'react'
import {
  Brain, ExternalLink, Search, Activity,
  Crosshair, Info, X, Upload, FileText, Loader2, Radio, Shield,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'
import ExportMenu from '../components/ExportMenu'
import ModelSelector from '../components/ModelSelector'
import { analyseFile, cachePageResult } from '../utils/api'
import { useNoticeBoard } from '../hooks/useNoticeBoard'
import { getLiveData, hasLiveData } from '../utils/liveDataStore'
import { registerSessionReset } from '../utils/sessionReset'

/* ── MITRE ATLAS — Adversarial Threat Landscape for AI Systems ─────────
 * https://atlas.mitre.org/
 * Tactics & techniques here track ATLAS v4.7.x (14 tactics, 80+ techniques).
 */

interface AtlasTechnique {
  id: string             // AML.T0xxx
  name: string
  tactic: string         // tactic name
  description: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  matched_classes?: string[]   // platform attack classes that imply this technique
}

interface AtlasTactic {
  id: string             // AML.TAxxxx
  name: string
  color: string
  short: string
}

const ATLAS_TACTICS: AtlasTactic[] = [
  { id: 'AML.TA0002', name: 'Reconnaissance',         color: '#3B82F6', short: 'Recon' },
  { id: 'AML.TA0003', name: 'Resource Development',   color: '#8B5CF6', short: 'Resource Dev' },
  { id: 'AML.TA0004', name: 'Initial Access',         color: '#F59E0B', short: 'Initial Access' },
  { id: 'AML.TA0000', name: 'ML Model Access',        color: '#06B6D4', short: 'Model Access' },
  { id: 'AML.TA0005', name: 'Execution',              color: '#EF4444', short: 'Execution' },
  { id: 'AML.TA0006', name: 'Persistence',            color: '#84CC16', short: 'Persistence' },
  { id: 'AML.TA0012', name: 'Privilege Escalation',   color: '#A855F7', short: 'Priv Esc' },
  { id: 'AML.TA0007', name: 'Defense Evasion',        color: '#F97316', short: 'Def Evasion' },
  { id: 'AML.TA0013', name: 'Credential Access',      color: '#EC4899', short: 'Cred Access' },
  { id: 'AML.TA0008', name: 'Discovery',              color: '#22C55E', short: 'Discovery' },
  { id: 'AML.TA0009', name: 'Collection',             color: '#14B8A6', short: 'Collection' },
  { id: 'AML.TA0001', name: 'ML Attack Staging',      color: '#FB923C', short: 'Attack Staging' },
  { id: 'AML.TA0010', name: 'Exfiltration',           color: '#DC2626', short: 'Exfiltration' },
  { id: 'AML.TA0011', name: 'Impact',                 color: '#B91C1C', short: 'Impact' },
]

const TACTIC_COLORS: Record<string, string> = Object.fromEntries(
  ATLAS_TACTICS.map(t => [t.name, t.color])
)

const ATLAS_TECHNIQUES: AtlasTechnique[] = [
  // Reconnaissance
  { id: 'AML.T0000',   name: 'Search for Victim\'s Publicly Available Research Materials', tactic: 'Reconnaissance', description: 'Adversaries search public papers, docs, blog posts to learn about a target ML system.', severity: 'low' },
  { id: 'AML.T0001',   name: 'Search for Publicly Available Adversarial Vulnerability Analysis', tactic: 'Reconnaissance', description: 'Public attack write-ups (Adv-ML, Robust-ML benchmarks) reveal system weaknesses.', severity: 'low' },
  { id: 'AML.T0003',   name: 'Search Victim-Owned Websites', tactic: 'Reconnaissance', description: 'Probe API docs / model cards / public dashboards.', severity: 'low' },
  { id: 'AML.T0004',   name: 'Search Application Repositories', tactic: 'Reconnaissance', description: 'Find leaked weights / configs in public GitHub / HuggingFace repos.', severity: 'medium', matched_classes: ['Recon-PortScan', 'Recon-OSScan'] },
  { id: 'AML.T0006',   name: 'Active Scanning', tactic: 'Reconnaissance', description: 'Probe inference endpoints to map model behaviour.', severity: 'medium', matched_classes: ['Recon-PortScan', 'Recon-HostDiscovery', 'Recon-PingSweep'] },

  // Resource Development
  { id: 'AML.T0002',   name: 'Acquire Public ML Artifacts', tactic: 'Resource Development', description: 'Download public datasets / pretrained weights for offline attack crafting.', severity: 'medium' },
  { id: 'AML.T0008',   name: 'Acquire Infrastructure', tactic: 'Resource Development', description: 'Adversary stands up GPU compute and proxies for crafting + delivering attacks.', severity: 'medium', matched_classes: ['Mirai-greeth', 'Mirai-greip'] },
  { id: 'AML.T0016',   name: 'Obtain Capabilities', tactic: 'Resource Development', description: 'Download adversarial-ML toolkits (CleverHans, ART, foolbox).', severity: 'medium' },
  { id: 'AML.T0017',   name: 'Develop Capabilities', tactic: 'Resource Development', description: 'Build custom poisoning / evasion code targeted at the victim\'s feature space.', severity: 'high' },

  // Initial Access
  { id: 'AML.T0010.001', name: 'ML Supply Chain Compromise: GPU Hardware', tactic: 'Initial Access', description: 'Implants in firmware of inference accelerators.', severity: 'critical' },
  { id: 'AML.T0010.002', name: 'ML Supply Chain Compromise: ML Software', tactic: 'Initial Access', description: 'Compromised PyPI / conda / HuggingFace package.', severity: 'critical' },
  { id: 'AML.T0010.003', name: 'ML Supply Chain Compromise: Data', tactic: 'Initial Access', description: 'Poisoned public datasets ingested into training.', severity: 'critical' },
  { id: 'AML.T0010.004', name: 'ML Supply Chain Compromise: Model', tactic: 'Initial Access', description: 'Maliciously fine-tuned weights distributed via model hubs.', severity: 'critical' },
  { id: 'AML.T0012',     name: 'Valid Accounts', tactic: 'Initial Access', description: 'Stolen API keys / IAM creds for inference services.', severity: 'high', matched_classes: ['BruteForce-SSH','BruteForce-FTP','BruteForce-HTTP','BruteForce-Dictionary'] },
  { id: 'AML.T0049',     name: 'Exploit Public-Facing Application', tactic: 'Initial Access', description: 'Web/SQL/RCE on inference gateway.', severity: 'high', matched_classes: ['WebAttack-SQLi','WebAttack-XSS','WebAttack-CmdInjection'] },

  // ML Model Access
  { id: 'AML.T0040',   name: 'ML Model Inference API Access', tactic: 'ML Model Access', description: 'Black-box queries to a hosted model endpoint.', severity: 'medium' },
  { id: 'AML.T0044',   name: 'Full ML Model Access', tactic: 'ML Model Access', description: 'White-box access (weights downloadable).', severity: 'high' },
  { id: 'AML.T0047',   name: 'ML-Enabled Product or Service', tactic: 'ML Model Access', description: 'Indirect access via a downstream LLM-powered product.', severity: 'medium' },
  { id: 'AML.T0050',   name: 'Physical Environment Access', tactic: 'ML Model Access', description: 'Adversarial patches in cameras / sensors.', severity: 'medium' },

  // Execution
  { id: 'AML.T0011.000', name: 'User Execution: Unsafe ML Artifacts', tactic: 'Execution', description: 'pickle/.pt with malicious __reduce__.', severity: 'critical' },
  { id: 'AML.T0050.000', name: 'Command and Scripting Interpreter', tactic: 'Execution', description: 'Code-execution via prompt-engineered tool calls.', severity: 'high', matched_classes: ['WebAttack-CmdInjection','Malware-Backdoor'] },
  { id: 'AML.T0053',     name: 'LLM Plugin Compromise', tactic: 'Execution', description: 'Plugin / tool-use exec primitive abused.', severity: 'high' },

  // Persistence
  { id: 'AML.T0018.000', name: 'Manipulate ML Model: Poison Training Data', tactic: 'Persistence', description: 'Backdoor remains across retraining.', severity: 'critical' },
  { id: 'AML.T0018.001', name: 'Manipulate ML Model: Modify ML Model', tactic: 'Persistence', description: 'Patch weights post-training.', severity: 'critical' },
  { id: 'AML.T0020',     name: 'Poison Training Data', tactic: 'Persistence', description: 'Crafted inputs added to retrain pool.', severity: 'high' },

  // Privilege Escalation
  { id: 'AML.T0054',   name: 'LLM Jailbreak', tactic: 'Privilege Escalation', description: 'Bypass safety alignment to access elevated tool surface.', severity: 'high' },
  { id: 'AML.T0055',   name: 'Unsecured Credentials in ML Artifacts', tactic: 'Privilege Escalation', description: 'API tokens leaked via model card / config.', severity: 'high' },

  // Defense Evasion
  { id: 'AML.T0015',   name: 'Evade ML Model', tactic: 'Defense Evasion', description: 'Adversarial perturbations evade detector at inference.', severity: 'critical', matched_classes: ['Spoofing-IP','Spoofing-DNS','Spoofing-ARP'] },
  { id: 'AML.T0043',   name: 'Craft Adversarial Data', tactic: 'Defense Evasion', description: 'FGSM / PGD / C&W / DeepFool style perturbations.', severity: 'high' },
  { id: 'AML.T0051',   name: 'LLM Prompt Injection', tactic: 'Defense Evasion', description: 'Direct or indirect injection that overrides system instructions.', severity: 'high' },
  { id: 'AML.T0052',   name: 'Phishing for ML Model Inputs', tactic: 'Defense Evasion', description: 'Trick humans to feed the model crafted samples.', severity: 'medium' },

  // Credential Access
  { id: 'AML.T0055.000', name: 'Cloud API Token Theft', tactic: 'Credential Access', description: 'Steal Anthropic/OpenAI/HF API tokens from compromised CI.', severity: 'high' },
  { id: 'AML.T0056',     name: 'Extract ML Training Data', tactic: 'Credential Access', description: 'Membership-inference / extraction attacks reveal PII in training set.', severity: 'high' },

  // Discovery
  { id: 'AML.T0013',   name: 'Discover ML Model Ontology', tactic: 'Discovery', description: 'Probe label space, output classes.', severity: 'low' },
  { id: 'AML.T0014',   name: 'Discover ML Model Family', tactic: 'Discovery', description: 'Identify architecture (CNN, GNN, Transformer, Mamba).', severity: 'medium' },
  { id: 'AML.T0035',   name: 'ML Artifact Collection', tactic: 'Discovery', description: 'Enumerate config files, datasets, model registry.', severity: 'medium' },

  // Collection
  { id: 'AML.T0036',   name: 'Data from Information Repositories', tactic: 'Collection', description: 'Scrape model registry / dataset pool / experiment store.', severity: 'medium' },
  { id: 'AML.T0037',   name: 'Data from Local System', tactic: 'Collection', description: 'Read on-host datasets and weights.', severity: 'medium' },

  // ML Attack Staging
  { id: 'AML.T0005.000', name: 'Create Proxy ML Model: Train Proxy via Distillation', tactic: 'ML Attack Staging', description: 'Distil black-box behaviour into a local proxy.', severity: 'high' },
  { id: 'AML.T0005.001', name: 'Create Proxy ML Model: Train via Replicated Architecture', tactic: 'ML Attack Staging', description: 'Recreate suspected target architecture for white-box attacks.', severity: 'high' },
  { id: 'AML.T0019',     name: 'Publish Poisoned Datasets', tactic: 'ML Attack Staging', description: 'Upload tainted dataset to a public hub.', severity: 'critical' },
  { id: 'AML.T0042',     name: 'Verify Attack', tactic: 'ML Attack Staging', description: 'Validate adversarial effectiveness pre-deployment.', severity: 'medium' },

  // Exfiltration
  { id: 'AML.T0024.000', name: 'Exfiltration via ML Inference API: Infer Training Data Membership', tactic: 'Exfiltration', description: 'Membership inference attack.', severity: 'high' },
  { id: 'AML.T0024.001', name: 'Exfiltration via ML Inference API: Invert ML Model', tactic: 'Exfiltration', description: 'Reconstruct training samples from logits.', severity: 'critical' },
  { id: 'AML.T0024.002', name: 'Exfiltration via ML Inference API: Extract ML Model', tactic: 'Exfiltration', description: 'Steal model functionality through systematic queries.', severity: 'critical' },
  { id: 'AML.T0025',     name: 'Exfiltration via Cyber Means', tactic: 'Exfiltration', description: 'Standard data-egress channels — DNS / HTTPS.', severity: 'high', matched_classes: ['DNS-Spoofing'] },

  // Impact
  { id: 'AML.T0029',   name: 'Denial of ML Service', tactic: 'Impact', description: 'Resource exhaustion via crafted inputs.', severity: 'high', matched_classes: ['DDoS-TCP','DDoS-UDP','DDoS-ICMP','DDoS-HTTP','DDoS-SYN','DDoS-SlowLoris','DDoS-RST-FIN','DDoS-PSH-ACK','DDoS-Fragmentation'] },
  { id: 'AML.T0031',   name: 'Erode ML Model Integrity', tactic: 'Impact', description: 'Model accuracy degrades over time via repeated nudging.', severity: 'high' },
  { id: 'AML.T0034',   name: 'Cost Harvesting', tactic: 'Impact', description: 'Drive cost via amplification of expensive inference calls.', severity: 'medium' },
  { id: 'AML.T0048',   name: 'External Harms', tactic: 'Impact', description: 'Reputational, financial, regulatory, safety damage downstream.', severity: 'high', matched_classes: ['Malware-Ransomware','Malware-Backdoor'] },
]

const SEV_STYLE: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium:   'bg-amber-500/15 text-amber-400 border-amber-500/30',
  low:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
}

const GUIDE_STEPS = [
  { title: 'Browse the kill chain', desc: 'The horizontal stage bar shows ATLAS\'s 14 adversarial-ML tactics. Click any tactic to filter the technique table.' },
  { title: 'Map your traffic', desc: 'Upload a CSV/PCAP or use Live Monitor data — detected attack classes are auto-mapped to ATLAS techniques in the orange "Detected" banner.' },
  { title: 'Inspect a technique', desc: 'Click any AML.T0xxx badge to see its description, tactic, severity, and which platform attack classes it covers.' },
  { title: 'Cross-reference', desc: 'Each row links to the official ATLAS page on atlas.mitre.org. Use the Compliance Hub for OWASP LLM Top 10 + NIST AI RMF mapping.' },
  { title: 'Export', desc: 'Use the Export menu to download a snapshot for reporting / red-team briefings.' },
]

const _store: {
  selectedTactic: string | null
  selectedTechnique: string | null
  searchQuery: string
  detailTechnique: string | null
  file: File | null
  modelId: string
  analysisResult: any
} = {
  selectedTactic: null, selectedTechnique: null, searchQuery: '',
  detailTechnique: null, file: null, modelId: 'surrogate', analysisResult: null,
}
registerSessionReset(() => {
  _store.selectedTactic = null; _store.selectedTechnique = null; _store.searchQuery = ''
  _store.detailTechnique = null; _store.file = null; _store.modelId = 'surrogate'
  _store.analysisResult = null
})

export default function MitreAtlasMapper() {
  const [selectedTactic, _setSelectedTactic] = useState<string | null>(_store.selectedTactic)
  const [selectedTechnique, _setSelectedTechnique] = useState<string | null>(_store.selectedTechnique)
  const [searchQuery, _setSearchQuery] = useState(_store.searchQuery)
  const [detailTechnique, _setDetailTechnique] = useState<string | null>(_store.detailTechnique)
  const [file, _setFile] = useState<File | null>(_store.file)
  const [modelId, _setModelId] = useState(_store.modelId)
  const [analysisResult, _setAnalysisResult] = useState<any>(_store.analysisResult)
  const [analyzing, setAnalyzing] = useState(false)
  const [liveDataLoaded, setLiveDataLoaded] = useState(false)
  const { addNotice, updateNotice } = useNoticeBoard()

  const setSelectedTactic = (v: string | null) => { _store.selectedTactic = v; _setSelectedTactic(v) }
  const setSelectedTechnique = (v: string | null) => { _store.selectedTechnique = v; _setSelectedTechnique(v) }
  const setSearchQuery = (v: string) => { _store.searchQuery = v; _setSearchQuery(v) }
  const setDetailTechnique = (v: string | null) => { _store.detailTechnique = v; _setDetailTechnique(v) }
  const setFile = (v: File | null) => { _store.file = v; _setFile(v) }
  const setModelId = (v: string) => { _store.modelId = v; _setModelId(v) }
  const setAnalysisResult = (v: any) => { _store.analysisResult = v; _setAnalysisResult(v) }

  const tacticCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const t of ATLAS_TECHNIQUES) counts[t.tactic] = (counts[t.tactic] || 0) + 1
    return counts
  }, [])

  const filtered = useMemo(() => {
    let items = ATLAS_TECHNIQUES
    if (selectedTactic) items = items.filter(t => t.tactic === selectedTactic)
    if (selectedTechnique) items = items.filter(t => t.id === selectedTechnique)
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      items = items.filter(t =>
        t.id.toLowerCase().includes(q) ||
        t.name.toLowerCase().includes(q) ||
        t.tactic.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q)
      )
    }
    return items
  }, [selectedTactic, selectedTechnique, searchQuery])

  const techniqueDetail = useMemo(() => {
    if (!detailTechnique) return null
    return ATLAS_TECHNIQUES.find(t => t.id === detailTechnique) || null
  }, [detailTechnique])

  const detectedTechniques = useMemo(() => {
    if (!analysisResult?.predictions) return new Map<string, number>()
    const m = new Map<string, number>()
    const classCounts: Record<string, number> = {}
    analysisResult.predictions.forEach((p: any) => {
      const lbl = p.label_predicted || ''
      if (lbl && lbl !== 'Benign') classCounts[lbl] = (classCounts[lbl] || 0) + 1
    })
    for (const t of ATLAS_TECHNIQUES) {
      if (!t.matched_classes) continue
      let total = 0
      for (const cls of t.matched_classes) total += classCounts[cls] || 0
      if (total > 0) m.set(t.id, total)
    }
    return m
  }, [analysisResult])

  const totalDetected = useMemo(() => {
    let s = 0
    detectedTechniques.forEach(v => s += v)
    return s
  }, [detectedTechniques])

  const runAnalysis = async () => {
    if (!file) return
    setAnalyzing(true)
    const nid = addNotice({ title: 'MITRE ATLAS Mapping', description: `Mapping ${file.name}...`, status: 'running', page: '/atlas' })
    try {
      const data = await analyseFile(file, modelId, 'mitre_atlas')
      setAnalysisResult(data)
      updateNotice(nid, { status: 'completed', description: `${data.predictions?.length || 0} flows mapped to ATLAS` })
    } catch (err) {
      updateNotice(nid, { status: 'error', description: err instanceof Error ? err.message : 'Analysis failed' })
    }
    setAnalyzing(false)
  }

  const loadLiveData = () => {
    const live = getLiveData()
    if (!live) return
    setAnalysisResult({ predictions: live.predictions, n_flows: live.totalFlows, n_threats: live.threatCount })
    cachePageResult('mitre_atlas', { n_flows: live.totalFlows, n_threats: live.threatCount }).catch(() => {})
    setLiveDataLoaded(true)
  }

  const hasFilters = selectedTactic || selectedTechnique || searchQuery.trim()
  const clearFilters = () => { setSelectedTactic(null); setSelectedTechnique(null); setSearchQuery('') }

  return (
    <div className="space-y-6 atlas-mapper-root">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-accent-purple/10 flex items-center justify-center">
            <Brain className="w-5 h-5 text-accent-purple" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-text-primary">MITRE ATLAS Mapper</h1>
            <p className="text-xs text-text-secondary mt-0.5">
              Adversarial Threat Landscape for AI Systems — 14 tactics · {ATLAS_TECHNIQUES.length} techniques
            </p>
          </div>
        </div>
        <ExportMenu targetSelector=".atlas-mapper-root" filename="mitre-atlas-mapping" />
      </div>

      <PageGuide title="How to use the MITRE ATLAS Mapper" steps={GUIDE_STEPS}
        tip="Tip: ATLAS extends ATT&CK with adversarial-ML-specific tactics like ML Model Access and ML Attack Staging. Use both mappers together to get full coverage." />

      {/* Data integration */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold flex items-center gap-2 mb-3">
          <Activity className="w-5 h-5 text-accent-purple" /> Map Your Traffic to ATLAS
        </h2>
        <p className="text-xs text-text-secondary mb-3">Upload a dataset or use Live Monitor data — flows tagged as adversarial-ML behaviours will be mapped to ATLAS techniques.</p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end">
          <div>
            {file ? (
              <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-accent-green/30 bg-accent-green/5">
                <FileText className="w-4 h-4 text-accent-green shrink-0" />
                <span className="text-xs font-mono truncate flex-1">{file.name}</span>
                <button onClick={() => { setFile(null); setAnalysisResult(null) }} className="text-text-secondary hover:text-text-primary"><X className="w-3.5 h-3.5" /></button>
              </div>
            ) : (
              <label
                onDragOver={e => { e.preventDefault(); e.currentTarget.classList.add('border-accent-purple','bg-accent-purple/10') }}
                onDragLeave={e => { e.currentTarget.classList.remove('border-accent-purple','bg-accent-purple/10') }}
                onDrop={e => { e.preventDefault(); e.currentTarget.classList.remove('border-accent-purple','bg-accent-purple/10'); const f = e.dataTransfer.files[0]; if(f) setFile(f) }}
                className="flex flex-col items-center gap-1 px-3 py-3 rounded-lg border-2 border-dashed border-bg-card hover:border-text-secondary cursor-pointer transition-colors">
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
          <button onClick={runAnalysis} disabled={!file || analyzing}
            className="px-4 py-2.5 bg-accent-purple hover:bg-accent-purple/80 text-white rounded-lg text-xs font-medium disabled:opacity-50 flex items-center justify-center gap-2">
            {analyzing ? <><Loader2 className="w-4 h-4 animate-spin" /> Mapping...</> : 'Analyze & Map to ATLAS'}
          </button>
        </div>
      </div>

      {hasLiveData() && !liveDataLoaded && !analysisResult && (
        <div className="flex items-center gap-3 px-4 py-3 bg-accent-purple/10 border border-accent-purple/20 rounded-xl">
          <Radio className="w-4 h-4 text-accent-purple" />
          <div className="flex-1">
            <span className="text-xs font-medium text-accent-purple">Live Monitor data available</span>
            <span className="text-[10px] text-text-secondary ml-2">{getLiveData()?.totalFlows} flows from {getLiveData()?.source}</span>
          </div>
          <button onClick={loadLiveData} className="px-3 py-1 bg-accent-purple hover:bg-accent-purple/80 text-white text-[10px] font-medium rounded-lg">
            Use Live Data
          </button>
        </div>
      )}

      {analysisResult && totalDetected > 0 && (
        <div className="bg-accent-orange/5 border border-accent-orange/20 rounded-xl p-4">
          <h3 className="text-sm font-semibold text-accent-orange mb-2 flex items-center gap-2">
            <Shield className="w-4 h-4" />
            Detected in Your Traffic — {totalDetected} flows mapped to {detectedTechniques.size} ATLAS techniques
          </h3>
          <div className="flex flex-wrap gap-2">
            {Array.from(detectedTechniques.entries()).sort((a,b)=>b[1]-a[1]).slice(0,12).map(([tid, count]) => {
              const t = ATLAS_TECHNIQUES.find(x => x.id === tid)
              if (!t) return null
              return (
                <button key={tid} onClick={() => setDetailTechnique(tid)}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[10px] font-medium bg-accent-orange/15 text-accent-orange hover:bg-accent-orange/25 transition-colors">
                  <span className="font-mono">{tid}</span>
                  <span className="truncate max-w-[180px]">{t.name}</span>
                  <span className="bg-accent-orange/30 px-1 rounded">{count}</span>
                </button>
              )
            })}
          </div>
        </div>
      )}

      {/* Tactic stage bar */}
      <div className="bg-bg-secondary border border-bg-card rounded-xl p-5">
        <h2 className="text-sm font-semibold text-text-primary mb-1 flex items-center gap-2">
          <Crosshair className="w-4 h-4 text-accent-purple" /> ATLAS Tactic Stages
        </h2>
        <p className="text-xs text-text-secondary mb-4">14 tactics organised across the adversarial-ML kill chain. Click to filter.</p>
        <div className="grid grid-cols-3 sm:grid-cols-5 lg:grid-cols-7 gap-2">
          {ATLAS_TACTICS.map(tactic => {
            const count = tacticCounts[tactic.name] || 0
            const isActive = selectedTactic === tactic.name
            return (
              <button key={tactic.id}
                onClick={() => setSelectedTactic(isActive ? null : tactic.name)}
                className={`flex flex-col items-center gap-1.5 p-3 rounded-lg border transition-all text-center ${
                  isActive ? 'scale-[1.03] shadow-lg' : 'border-bg-card bg-bg-card/30 hover:bg-bg-card/60'
                }`}
                style={{
                  borderColor: isActive ? tactic.color : undefined,
                  backgroundColor: isActive ? `${tactic.color}15` : undefined,
                }}>
                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: tactic.color }} />
                <span className="text-[10px] font-semibold text-text-primary leading-tight">{tactic.short}</span>
                <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full"
                  style={{ backgroundColor: `${tactic.color}20`, color: tactic.color }}>{count}</span>
              </button>
            )
          })}
        </div>
      </div>

      {/* Stats */}
      <div className={`grid grid-cols-2 ${analysisResult ? 'sm:grid-cols-5' : 'sm:grid-cols-4'} gap-3`}>
        <StatCard label="Tactics" value={ATLAS_TACTICS.length} color="#8B5CF6" />
        <StatCard label="Techniques" value={ATLAS_TECHNIQUES.length} color="#3B82F6" />
        <StatCard label="Critical Severity" value={ATLAS_TECHNIQUES.filter(t=>t.severity==='critical').length} color="#EF4444" />
        <StatCard label="With ATT&CK Overlap" value={ATLAS_TECHNIQUES.filter(t=>t.matched_classes?.length).length} color="#22C55E" />
        {analysisResult && <StatCard label="Mapped Flows" value={totalDetected} color="#F97316" />}
      </div>

      {/* Detail card */}
      {techniqueDetail && (
        <div className="bg-bg-secondary border border-accent-purple/30 rounded-xl p-5 relative">
          <button onClick={() => setDetailTechnique(null)} className="absolute top-3 right-3 text-text-secondary hover:text-text-primary"><X className="w-4 h-4" /></button>
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
              style={{ backgroundColor: `${TACTIC_COLORS[techniqueDetail.tactic] || '#8B5CF6'}15` }}>
              <Info className="w-4 h-4" style={{ color: TACTIC_COLORS[techniqueDetail.tactic] || '#8B5CF6' }} />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-bold text-text-primary font-mono">{techniqueDetail.id}</span>
                <span className="text-xs text-text-secondary">{techniqueDetail.name}</span>
                <a href={`https://atlas.mitre.org/techniques/${techniqueDetail.id}`}
                  target="_blank" rel="noopener noreferrer"
                  className="text-xs text-accent-purple hover:underline flex items-center gap-1">
                  View on ATLAS <ExternalLink className="w-3 h-3" />
                </a>
              </div>
              <div className="flex items-center gap-1.5 mt-1.5 flex-wrap">
                <TacticBadge tactic={techniqueDetail.tactic} />
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${SEV_STYLE[techniqueDetail.severity]}`}>
                  {techniqueDetail.severity}
                </span>
              </div>
              <p className="text-xs text-text-secondary mt-2.5">{techniqueDetail.description}</p>
              {techniqueDetail.matched_classes && techniqueDetail.matched_classes.length > 0 && (
                <div className="mt-3">
                  <p className="text-xs text-text-secondary mb-1.5">Platform attack classes mapped to this technique:</p>
                  <div className="flex flex-wrap gap-1.5">
                    {techniqueDetail.matched_classes.map(c => (
                      <span key={c} className="px-2 py-0.5 bg-bg-card border border-bg-card rounded text-xs text-text-primary font-mono">{c}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Search & filter */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-secondary" />
          <input type="text" placeholder="Search by ATLAS ID, technique name, tactic, or description..."
            value={searchQuery} onChange={e => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-2 bg-bg-secondary border border-bg-card rounded-lg text-xs text-text-primary placeholder-text-secondary/50 focus:outline-none focus:border-accent-purple/40" />
        </div>
        {hasFilters && (
          <button onClick={clearFilters} className="flex items-center gap-1.5 px-3 py-2 bg-bg-secondary border border-bg-card rounded-lg text-xs text-text-secondary hover:text-accent-red transition-colors">
            <X className="w-3 h-3" /> Clear filters
          </button>
        )}
        <span className="text-xs text-text-secondary">Showing {filtered.length} of {ATLAS_TECHNIQUES.length} techniques</span>
      </div>

      {/* Techniques table */}
      <div className="bg-bg-secondary border border-bg-card rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-bg-card">
                <th className="text-left px-4 py-3 text-text-secondary font-semibold">ATLAS ID</th>
                <th className="text-left px-4 py-3 text-text-secondary font-semibold">Technique</th>
                <th className="text-left px-4 py-3 text-text-secondary font-semibold">Tactic</th>
                <th className="text-left px-4 py-3 text-text-secondary font-semibold">Severity</th>
                <th className="text-center px-4 py-3 text-text-secondary font-semibold">Detected</th>
                <th className="text-center px-4 py-3 text-text-secondary font-semibold">Link</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(t => {
                const detected = detectedTechniques.get(t.id) || 0
                return (
                  <tr key={t.id}
                    className={`border-b border-bg-card/50 hover:bg-bg-card/30 transition-colors cursor-pointer ${detected ? 'border-l-2 border-l-accent-orange bg-accent-orange/5' : ''}`}
                    onClick={() => setDetailTechnique(t.id)}>
                    <td className="px-4 py-2.5">
                      <span className="inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-bold font-mono"
                        style={{
                          backgroundColor: `${TACTIC_COLORS[t.tactic] || '#8B5CF6'}15`,
                          color: TACTIC_COLORS[t.tactic] || '#8B5CF6',
                          border: `1px solid ${TACTIC_COLORS[t.tactic] || '#8B5CF6'}30`,
                        }}>{t.id}</span>
                    </td>
                    <td className="px-4 py-2.5 max-w-[420px]">
                      <div className="font-medium text-text-primary truncate">{t.name}</div>
                      <div className="text-[10px] text-text-secondary truncate">{t.description}</div>
                    </td>
                    <td className="px-4 py-2.5"><TacticBadge tactic={t.tactic} /></td>
                    <td className="px-4 py-2.5">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${SEV_STYLE[t.severity]}`}>
                        {t.severity}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-center">
                      {detected > 0 ? (
                        <span className="px-1.5 py-0.5 rounded bg-accent-orange/20 text-accent-orange text-[10px] font-bold">{detected}</span>
                      ) : (
                        <span className="text-text-secondary/40 text-[10px]">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-center">
                      <a href={`https://atlas.mitre.org/techniques/${t.id}`}
                        target="_blank" rel="noopener noreferrer"
                        onClick={e => e.stopPropagation()}
                        className="text-accent-purple hover:text-accent-purple/80">
                        <ExternalLink className="w-3.5 h-3.5 inline" />
                      </a>
                    </td>
                  </tr>
                )
              })}
              {filtered.length === 0 && (
                <tr><td colSpan={6} className="px-4 py-8 text-center text-text-secondary">No techniques match your current filters.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Coverage by tactic */}
      <div className="bg-bg-secondary border border-bg-card rounded-xl p-5">
        <h2 className="text-sm font-semibold text-text-primary mb-3">Coverage by Tactic</h2>
        <div className="space-y-2">
          {ATLAS_TACTICS.map(stage => {
            const count = tacticCounts[stage.name] || 0
            const maxCount = Math.max(...Object.values(tacticCounts), 1)
            const pct = Math.round((count / maxCount) * 100)
            return (
              <div key={stage.id} className="flex items-center gap-3">
                <span className="text-xs text-text-secondary w-36 shrink-0 truncate">{stage.name}</span>
                <div className="flex-1 h-5 bg-bg-card/50 rounded-full overflow-hidden">
                  <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, backgroundColor: stage.color }} />
                </div>
                <span className="text-xs font-mono text-text-primary w-8 text-right">{count}</span>
              </div>
            )
          })}
        </div>
      </div>

      {/* Related */}
      <div className="flex flex-wrap gap-2 pt-3 border-t border-bg-card">
        <span className="text-[10px] text-text-secondary mr-2">Related:</span>
        <a href="/mitre-attack" className="text-[10px] px-2 py-1 rounded bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20 transition-colors">MITRE ATT&CK</a>
        <a href="/compliance" className="text-[10px] px-2 py-1 rounded bg-accent-green/10 text-accent-green hover:bg-accent-green/20 transition-colors">Compliance Hub</a>
        <a href="/prompt-injection" className="text-[10px] px-2 py-1 rounded bg-accent-orange/10 text-accent-orange hover:bg-accent-orange/20 transition-colors">Prompt Injection</a>
        <a href="/jailbreak-taxonomy" className="text-[10px] px-2 py-1 rounded bg-accent-orange/10 text-accent-orange hover:bg-accent-orange/20 transition-colors">Jailbreak Taxonomy</a>
        <a href="/data-poisoning" className="text-[10px] px-2 py-1 rounded bg-accent-orange/10 text-accent-orange hover:bg-accent-orange/20 transition-colors">Data Poisoning</a>
        <a href="/mcp-security" className="text-[10px] px-2 py-1 rounded bg-accent-orange/10 text-accent-orange hover:bg-accent-orange/20 transition-colors">MCP Security</a>
      </div>

      <div className="flex items-center justify-between text-[10px] text-text-secondary/60 px-1">
        <span>Data based on MITRE ATLAS v4.7+. Mappings are best-effort for AI/ML system threat modelling.</span>
        <a href="https://atlas.mitre.org/" target="_blank" rel="noopener noreferrer" className="text-accent-purple/60 hover:text-accent-purple flex items-center gap-1">
          atlas.mitre.org <ExternalLink className="w-2.5 h-2.5" />
        </a>
      </div>
    </div>
  )
}

function TacticBadge({ tactic }: { tactic: string }) {
  const color = TACTIC_COLORS[tactic] || '#64748B'
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold"
      style={{ backgroundColor: `${color}15`, color }}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: color }} />
      {tactic}
    </span>
  )
}

function StatCard({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div className="bg-bg-secondary border border-bg-card rounded-xl p-4">
      <p className="text-[10px] text-text-secondary uppercase tracking-wider mb-1">{label}</p>
      <p className="text-2xl font-bold" style={{ color }}>{value}</p>
    </div>
  )
}

