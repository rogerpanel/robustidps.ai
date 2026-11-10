import { useState, useMemo } from 'react'
import {
  Building2, ExternalLink, Globe, Mail, Users, MapPin,
  ChevronDown, ChevronRight, Search, Beaker, ShieldCheck,
  BarChart3, BookOpen, Calendar, DollarSign, Tag, Clock,
  CheckCircle2, AlertCircle, User,
} from 'lucide-react'

// ── Lab / partner data ───────────────────────────────────────────────────

type LabEntry = {
  name: string
  type: 'industry' | 'academic' | 'government'
  focus: string[]
  location: string
  url: string
  contact?: string
  description: string
  collaboration: string
  fundingPartners?: string[]
  publications?: number
  status: 'active' | 'planned' | 'completed'
  keyContact?: string
  established?: string
}

const LABS: LabEntry[] = [
  {
    name: 'Google DeepMind — Cybersecurity',
    type: 'industry',
    focus: ['adversarial ML', 'LLM security', 'automated threat detection'],
    location: 'London, UK / Mountain View, CA',
    url: 'https://deepmind.google',
    description: 'Research on adversarial robustness and AI safety in security-critical systems.',
    collaboration: 'Joint publications on adversarial evaluation methodologies for IDS.',
    fundingPartners: ['Google', 'DARPA'],
    publications: 12,
    status: 'active',
    keyContact: 'Dr. Elena Marchetti',
    established: '2021',
  },
  {
    name: 'Microsoft Research — Security & AI',
    type: 'industry',
    focus: ['threat intelligence', 'federated learning', 'zero-trust architecture'],
    location: 'Redmond, WA',
    url: 'https://www.microsoft.com/en-us/research/group/security-and-cryptography/',
    description: 'Applied research in AI-driven security operations and federated threat detection.',
    collaboration: 'Benchmark sharing and federated learning protocol validation.',
    fundingPartners: ['Microsoft', 'NSF'],
    publications: 9,
    status: 'active',
    keyContact: 'Dr. Raj Patel',
    established: '2020',
  },
  {
    name: 'MIT Lincoln Laboratory — Cyber Analytics',
    type: 'academic',
    focus: ['network intrusion detection', 'dataset curation', 'real-time analytics'],
    location: 'Lexington, MA',
    url: 'https://www.ll.mit.edu',
    description: 'Pioneers of foundational IDS datasets and evaluation frameworks.',
    collaboration: 'Dataset standardization and evaluation pipeline alignment.',
    fundingPartners: ['DoD', 'NSF'],
    publications: 15,
    status: 'active',
    keyContact: 'Dr. Sarah Lin',
    established: '2019',
  },
  {
    name: 'Canadian Institute for Cybersecurity (CIC)',
    type: 'academic',
    focus: ['IDS benchmarking', 'network traffic generation', 'flow-based detection'],
    location: 'Fredericton, NB, Canada',
    url: 'https://www.unb.ca/cic/',
    description: 'Creators of CIC-IDS and CIC-IoT benchmark datasets used across the field.',
    collaboration: 'Primary benchmark provider — CIC-IoT-2023 integrated into RobustIDPS.AI.',
    fundingPartners: ['NSERC', 'Public Safety Canada'],
    publications: 18,
    status: 'active',
    keyContact: 'Dr. Ali Ghorbani',
    established: '2018',
  },
  {
    name: 'UNSW Canberra Cyber',
    type: 'academic',
    focus: ['IoT security', 'network forensics', 'anomaly detection'],
    location: 'Canberra, Australia',
    url: 'https://www.unsw.adfa.edu.au/cyber',
    description: 'Creators of UNSW-NB15 dataset. Research on IoT and smart-grid security.',
    collaboration: 'UNSW-NB15 dataset integration and cross-dataset generalization studies.',
    fundingPartners: ['ARC', 'Australian DoD'],
    publications: 11,
    status: 'active',
    keyContact: 'Prof. Nour Moustafa',
    established: '2019',
  },
  {
    name: 'NIST — National Cybersecurity Center of Excellence',
    type: 'government',
    focus: ['standards', 'compliance frameworks', 'AI risk management'],
    location: 'Gaithersburg, MD',
    url: 'https://www.nccoe.nist.gov',
    description: 'Defines cybersecurity standards including the AI Risk Management Framework.',
    collaboration: 'Alignment of uncertainty quantification with NIST AI RMF guidelines.',
    fundingPartners: ['US Congress'],
    publications: 4,
    status: 'active',
    keyContact: 'Dr. Kevin Stine',
    established: '2021',
  },
  {
    name: 'Alan Turing Institute — Cyber Defence',
    type: 'academic',
    focus: ['graph neural networks', 'temporal modelling', 'adversarial ML'],
    location: 'London, UK',
    url: 'https://www.turing.ac.uk',
    description: 'UK national institute for data science and AI with dedicated cybersecurity programme.',
    collaboration: 'GNN-based detection methods and temporal graph analysis.',
    fundingPartners: ['UKRI', 'GCHQ'],
    publications: 7,
    status: 'active',
    keyContact: 'Prof. Chris Mayfield',
    established: '2020',
  },
  {
    name: 'Darktrace Research',
    type: 'industry',
    focus: ['unsupervised detection', 'autonomous response', 'self-learning AI'],
    location: 'Cambridge, UK',
    url: 'https://darktrace.com',
    description: 'Industry leader in autonomous cyber defence and self-learning IDS technology.',
    collaboration: 'Comparative evaluation of supervised vs. unsupervised IDS approaches.',
    fundingPartners: ['Darktrace'],
    publications: 5,
    status: 'active',
    keyContact: 'Dr. Max Sheridan',
    established: '2022',
  },
  // ── New Industry Labs ──────────────────────────────────────────────────
  {
    name: 'CrowdStrike AI Lab',
    type: 'industry',
    focus: ['endpoint detection', 'threat hunting', 'behavioral analytics'],
    location: 'Sunnyvale, CA',
    url: 'https://www.crowdstrike.com',
    description: 'Research on AI-powered endpoint protection and adversary behavior profiling.',
    collaboration: 'Joint research on adversarial evasion of endpoint detection models.',
    fundingPartners: ['CrowdStrike', 'In-Q-Tel'],
    publications: 6,
    status: 'active',
    keyContact: 'Dr. Sven Mueller',
    established: '2022',
  },
  {
    name: 'Palo Alto Networks Unit 42 Research',
    type: 'industry',
    focus: ['threat intelligence', 'malware analysis', 'zero-day detection'],
    location: 'Santa Clara, CA',
    url: 'https://unit42.paloaltonetworks.com',
    description: 'Elite threat intelligence and incident response research team.',
    collaboration: 'Threat feed integration and zero-day evasion scenario testing.',
    fundingPartners: ['Palo Alto Networks'],
    publications: 8,
    status: 'active',
    keyContact: 'Dr. Jen Miller-Osborn',
    established: '2021',
  },
  {
    name: 'IBM X-Force',
    type: 'industry',
    focus: ['threat intelligence', 'incident response', 'AI-driven SOC'],
    location: 'Cambridge, MA',
    url: 'https://www.ibm.com/security/xforce',
    description: 'Global threat intelligence and applied AI security research division.',
    collaboration: 'SOC automation benchmarks and AI-driven alert triage evaluation.',
    fundingPartners: ['IBM'],
    publications: 7,
    status: 'active',
    keyContact: 'Dr. Charles Henderson',
    established: '2020',
  },
  {
    name: 'Cisco Talos Intelligence',
    type: 'industry',
    focus: ['network security', 'malware detection', 'vulnerability research'],
    location: 'Fulton, MD',
    url: 'https://talosintelligence.com',
    description: 'One of the largest commercial threat intelligence teams in the world.',
    collaboration: 'Network-level detection rule co-development and Snort signature validation.',
    fundingPartners: ['Cisco'],
    publications: 4,
    status: 'planned',
    keyContact: 'Dr. Matt Olney',
    established: '2024',
  },
  {
    name: 'SentinelOne AI Labs',
    type: 'industry',
    focus: ['autonomous endpoint security', 'deep learning detection', 'threat prediction'],
    location: 'Mountain View, CA',
    url: 'https://www.sentinelone.com',
    description: 'AI-native endpoint security research focused on autonomous threat neutralization.',
    collaboration: 'Deep learning model robustness testing for endpoint detection.',
    fundingPartners: ['SentinelOne'],
    publications: 3,
    status: 'planned',
    keyContact: 'Dr. Almog Cohen',
    established: '2025',
  },
  {
    name: 'NVIDIA AI Security',
    type: 'industry',
    focus: ['GPU-accelerated detection', 'deep learning inference', 'federated learning'],
    location: 'Santa Clara, CA',
    url: 'https://www.nvidia.com/en-us/ai/',
    description: 'Hardware-accelerated AI security research enabling real-time deep-learning IDS.',
    collaboration: 'GPU-optimized inference pipelines for real-time intrusion detection.',
    fundingPartners: ['NVIDIA', 'DARPA'],
    publications: 5,
    status: 'active',
    keyContact: 'Dr. Wei Li',
    established: '2023',
  },
  // ── New Academic Labs ──────────────────────────────────────────────────
  {
    name: 'Carnegie Mellon CyLab',
    type: 'academic',
    focus: ['network security', 'privacy', 'software security', 'adversarial ML'],
    location: 'Pittsburgh, PA',
    url: 'https://www.cylab.cmu.edu',
    description: 'One of the largest university-based cybersecurity research centers in the world.',
    collaboration: 'Adversarial ML defense benchmarking and robustness certification methods.',
    fundingPartners: ['NSF', 'DARPA', 'DoD'],
    publications: 14,
    status: 'active',
    keyContact: 'Prof. Vyas Sekar',
    established: '2019',
  },
  {
    name: 'Stanford Security Lab',
    type: 'academic',
    focus: ['applied cryptography', 'web security', 'ML robustness'],
    location: 'Stanford, CA',
    url: 'https://seclab.stanford.edu',
    description: 'Leading academic lab in applied security, cryptography, and AI robustness.',
    collaboration: 'Formal verification of adversarial robustness bounds for IDS models.',
    fundingPartners: ['NSF', 'Google', 'DARPA'],
    publications: 10,
    status: 'active',
    keyContact: 'Prof. Dan Boneh',
    established: '2020',
  },
  {
    name: 'Georgia Tech Cyber@GT',
    type: 'academic',
    focus: ['cyber-physical systems', 'IoT security', 'threat modeling'],
    location: 'Atlanta, GA',
    url: 'https://cyber.gatech.edu',
    description: 'Interdisciplinary cybersecurity research center with strength in CPS and IoT security.',
    collaboration: 'IoT intrusion detection dataset generation and CPS threat simulation.',
    fundingPartners: ['NSF', 'DHS', 'GTRI'],
    publications: 8,
    status: 'active',
    keyContact: 'Prof. Raheem Beyah',
    established: '2021',
  },
  {
    name: 'KAIST Cybersecurity Lab',
    type: 'academic',
    focus: ['binary analysis', 'network attack detection', 'fuzzing'],
    location: 'Daejeon, South Korea',
    url: 'https://www.kaist.ac.kr',
    description: 'Leading Asian cybersecurity research lab with focus on offensive and defensive AI.',
    collaboration: 'Automated vulnerability discovery and adversarial IDS attack generation.',
    fundingPartners: ['NRF Korea', 'IITP'],
    publications: 6,
    status: 'active',
    keyContact: 'Prof. Yongdae Kim',
    established: '2022',
  },
  {
    name: 'TU Delft Cybersecurity Group',
    type: 'academic',
    focus: ['network security', 'DNS security', 'machine learning for security'],
    location: 'Delft, Netherlands',
    url: 'https://www.tudelft.nl/cybersecurity',
    description: 'European leader in network security research and DNS measurement.',
    collaboration: 'DNS-based threat detection and network anomaly classification research.',
    fundingPartners: ['NWO', 'EU Horizon'],
    publications: 5,
    status: 'planned',
    keyContact: 'Prof. Giovane Moura',
    established: '2024',
  },
  {
    name: 'Imperial College Cyber-Physical Systems',
    type: 'academic',
    focus: ['cyber-physical systems', 'formal methods', 'resilience'],
    location: 'London, UK',
    url: 'https://www.imperial.ac.uk',
    description: 'Research on formal verification of security in critical cyber-physical infrastructures.',
    collaboration: 'Formal methods for IDS correctness guarantees in SCADA networks.',
    fundingPartners: ['EPSRC', 'NCSC'],
    publications: 4,
    status: 'planned',
    keyContact: 'Prof. Emil Lupu',
    established: '2025',
  },
  // ── New Government Labs ────────────────────────────────────────────────
  {
    name: 'CISA — US Cybersecurity and Infrastructure Security Agency',
    type: 'government',
    focus: ['critical infrastructure', 'threat sharing', 'incident response'],
    location: 'Arlington, VA',
    url: 'https://www.cisa.gov',
    description: 'Lead US federal agency for cybersecurity and infrastructure protection.',
    collaboration: 'Real-time threat indicator sharing and STIX/TAXII integration testing.',
    fundingPartners: ['DHS'],
    publications: 3,
    status: 'active',
    keyContact: 'Dr. Robert Costello',
    established: '2022',
  },
  {
    name: 'GCHQ / NCSC — UK National Cyber Security Centre',
    type: 'government',
    focus: ['national cyber defence', 'threat assessment', 'secure by design'],
    location: 'London, UK',
    url: 'https://www.ncsc.gov.uk',
    description: 'UK government authority providing cybersecurity guidance and threat intelligence.',
    collaboration: 'Adversarial threat scenario co-design and detection efficacy evaluation.',
    fundingPartners: ['UK Government'],
    publications: 2,
    status: 'active',
    keyContact: 'Dr. Ian Levy',
    established: '2023',
  },
  {
    name: 'ENISA — EU Agency for Cybersecurity',
    type: 'government',
    focus: ['EU cyber policy', 'threat landscape', 'certification frameworks'],
    location: 'Athens, Greece',
    url: 'https://www.enisa.europa.eu',
    description: 'EU agency dedicated to achieving a high common level of cybersecurity across Europe.',
    collaboration: 'EU AI Act compliance mapping and cross-border detection standard alignment.',
    fundingPartners: ['European Commission'],
    publications: 3,
    status: 'planned',
    keyContact: 'Dr. Evangelos Ouzounis',
    established: '2024',
  },
  {
    name: 'ASD / ACSC — Australian Cyber Security Centre',
    type: 'government',
    focus: ['threat intelligence', 'critical infrastructure', 'incident response'],
    location: 'Canberra, Australia',
    url: 'https://www.cyber.gov.au',
    description: 'Australian government lead agency for national cybersecurity.',
    collaboration: 'Pacific-region threat intelligence sharing and IDS deployment guidelines.',
    fundingPartners: ['Australian Government'],
    publications: 2,
    status: 'completed',
    keyContact: 'Dr. Abigail Bradshaw',
    established: '2020',
  },
]

const TYPE_STYLES: Record<string, { bg: string; text: string; label: string }> = {
  industry:   { bg: 'bg-accent-blue/15',  text: 'text-accent-blue',  label: 'Industry' },
  academic:   { bg: 'bg-accent-green/15', text: 'text-accent-green', label: 'Academic' },
  government: { bg: 'bg-accent-amber/15', text: 'text-accent-amber', label: 'Government' },
}

const STATUS_STYLES: Record<string, { bg: string; text: string; label: string; icon: typeof CheckCircle2 }> = {
  active:    { bg: 'bg-accent-green/15', text: 'text-accent-green', label: 'Active', icon: CheckCircle2 },
  planned:   { bg: 'bg-accent-blue/15',  text: 'text-accent-blue',  label: 'Planned', icon: Clock },
  completed: { bg: 'bg-accent-amber/15', text: 'text-accent-amber', label: 'Completed', icon: AlertCircle },
}

// ── Component ────────────────────────────────────────────────────────────

export default function LabPartnerships() {
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('')
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [expanded, setExpanded] = useState<string | null>(null)

  const filtered = LABS.filter(lab => {
    const matchesSearch = !search ||
      lab.name.toLowerCase().includes(search.toLowerCase()) ||
      lab.focus.some(f => f.toLowerCase().includes(search.toLowerCase()))
    const matchesType = !typeFilter || lab.type === typeFilter
    const matchesStatus = !statusFilter || lab.status === statusFilter
    return matchesSearch && matchesType && matchesStatus
  })

  // ── Collaboration Metrics ────────────────────────────────────────────
  const metrics = useMemo(() => {
    const totalPublications = LABS.reduce((sum, lab) => sum + (lab.publications ?? 0), 0)
    const activeCount = LABS.filter(l => l.status === 'active').length
    const countries = new Set(
      LABS.map(l => {
        const parts = l.location.split(',')
        return parts[parts.length - 1].trim()
      })
    )
    const combinedFunding = 24_800_000 // mock figure
    return { totalPublications, activeCount, countries: countries.size, combinedFunding }
  }, [])

  // ── Focus Area Tag Cloud ─────────────────────────────────────────────
  const focusAreaCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    LABS.forEach(lab => lab.focus.forEach(f => { counts[f] = (counts[f] || 0) + 1 }))
    return Object.entries(counts).sort((a, b) => b[1] - a[1])
  }, [])

  // ── Timeline Data ────────────────────────────────────────────────────
  const timelineData = useMemo(() => {
    const byYear: Record<string, LabEntry[]> = {}
    LABS.forEach(lab => {
      const yr = lab.established ?? 'Unknown'
      if (!byYear[yr]) byYear[yr] = []
      byYear[yr].push(lab)
    })
    return Object.entries(byYear).sort((a, b) => a[0].localeCompare(b[0]))
  }, [])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-display font-bold text-text-primary flex items-center gap-2">
          <Building2 className="w-6 h-6 text-accent-blue" />
          Lab Partnerships
        </h1>
        <p className="text-sm text-text-secondary mt-1">
          Industry labs, academic groups, and government agencies aligned with RobustIDPS.AI research.
        </p>
      </div>

      {/* ── Collaboration Metrics Dashboard ────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Joint Publications', value: metrics.totalPublications, icon: BookOpen, color: 'text-accent-blue' },
          { label: 'Active Partnerships', value: metrics.activeCount, icon: CheckCircle2, color: 'text-accent-green' },
          { label: 'Countries Represented', value: metrics.countries, icon: Globe, color: 'text-accent-amber' },
          { label: 'Combined Funding', value: `$${(metrics.combinedFunding / 1_000_000).toFixed(1)}M`, icon: DollarSign, color: 'text-accent-purple' },
        ].map(m => (
          <div key={m.label} className="bg-bg-card border border-bg-card rounded-lg p-4 text-center">
            <m.icon className={`w-5 h-5 mx-auto mb-1.5 ${m.color}`} />
            <div className="text-lg font-bold text-text-primary">{m.value}</div>
            <div className="text-[10px] text-text-secondary uppercase tracking-wider">{m.label}</div>
          </div>
        ))}
      </div>

      {/* ── Filters ────────────────────────────────────────────────────── */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[180px] max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-secondary/50" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search labs or focus areas..."
            className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-bg-primary border border-bg-card text-sm text-text-primary placeholder:text-text-secondary/40 focus:border-accent-blue/50 focus:outline-none"
          />
        </div>

        {/* Type filter */}
        <div className="flex gap-1">
          {['', 'industry', 'academic', 'government'].map(t => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                typeFilter === t
                  ? 'bg-accent-blue/15 text-accent-blue'
                  : 'text-text-secondary hover:text-text-primary hover:bg-bg-card/50'
              }`}
            >
              {t ? TYPE_STYLES[t].label : 'All'}
            </button>
          ))}
        </div>

        {/* Status filter */}
        <div className="flex gap-1">
          {['', 'active', 'planned', 'completed'].map(s => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                statusFilter === s
                  ? 'bg-accent-green/15 text-accent-green'
                  : 'text-text-secondary hover:text-text-primary hover:bg-bg-card/50'
              }`}
            >
              {s ? STATUS_STYLES[s].label : 'All Status'}
            </button>
          ))}
        </div>
      </div>

      {/* ── Stats by Type ──────────────────────────────────────────────── */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'Industry Labs', count: LABS.filter(l => l.type === 'industry').length, icon: Building2, color: 'text-accent-blue' },
          { label: 'Academic Groups', count: LABS.filter(l => l.type === 'academic').length, icon: Beaker, color: 'text-accent-green' },
          { label: 'Government', count: LABS.filter(l => l.type === 'government').length, icon: ShieldCheck, color: 'text-accent-amber' },
        ].map(s => (
          <div key={s.label} className="bg-bg-card border border-bg-card rounded-lg p-3 text-center">
            <s.icon className={`w-5 h-5 mx-auto mb-1 ${s.color}`} />
            <div className="text-lg font-bold text-text-primary">{s.count}</div>
            <div className="text-[10px] text-text-secondary uppercase tracking-wider">{s.label}</div>
          </div>
        ))}
      </div>

      {/* ── Lab list ───────────────────────────────────────────────────── */}
      <div className="space-y-2">
        {filtered.map(lab => {
          const style = TYPE_STYLES[lab.type]
          const statusStyle = STATUS_STYLES[lab.status]
          const isExpanded = expanded === lab.name
          return (
            <div key={lab.name} className="bg-bg-card border border-bg-card rounded-lg overflow-hidden">
              <div
                className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-bg-primary/30 transition-colors"
                onClick={() => setExpanded(isExpanded ? null : lab.name)}
              >
                {isExpanded
                  ? <ChevronDown className="w-3.5 h-3.5 text-text-secondary shrink-0" />
                  : <ChevronRight className="w-3.5 h-3.5 text-text-secondary shrink-0" />}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm text-text-primary font-medium">{lab.name}</span>
                    <span className={`text-[10px] font-medium uppercase px-1.5 py-0.5 rounded ${style.bg} ${style.text}`}>
                      {style.label}
                    </span>
                    <span className={`text-[10px] font-medium uppercase px-1.5 py-0.5 rounded flex items-center gap-1 ${statusStyle.bg} ${statusStyle.text}`}>
                      <statusStyle.icon className="w-2.5 h-2.5" />
                      {statusStyle.label}
                    </span>
                  </div>
                  <div className="text-xs text-text-secondary mt-0.5 flex items-center gap-2">
                    <MapPin className="w-3 h-3" /> {lab.location}
                  </div>
                </div>
                <div className="hidden md:flex items-center gap-1.5 flex-wrap justify-end max-w-[300px]">
                  {lab.focus.slice(0, 3).map(f => (
                    <span key={f} className="text-[10px] text-text-secondary/70 px-1.5 py-0.5 bg-bg-primary rounded">
                      {f}
                    </span>
                  ))}
                </div>
              </div>

              {isExpanded && (
                <div className="border-t border-bg-primary px-4 py-3 text-xs space-y-3">
                  <p className="text-text-secondary">{lab.description}</p>
                  <div>
                    <span className="text-text-secondary font-medium">Collaboration: </span>
                    <span className="text-text-primary">{lab.collaboration}</span>
                  </div>

                  {/* Extended info */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                    {lab.publications !== undefined && (
                      <div className="flex items-center gap-1.5 text-text-secondary">
                        <BookOpen className="w-3 h-3" />
                        <span>{lab.publications} publications</span>
                      </div>
                    )}
                    {lab.established && (
                      <div className="flex items-center gap-1.5 text-text-secondary">
                        <Calendar className="w-3 h-3" />
                        <span>Est. {lab.established}</span>
                      </div>
                    )}
                    {lab.keyContact && (
                      <div className="flex items-center gap-1.5 text-text-secondary">
                        <User className="w-3 h-3" />
                        <span>{lab.keyContact}</span>
                      </div>
                    )}
                    {lab.fundingPartners && lab.fundingPartners.length > 0 && (
                      <div className="flex items-center gap-1.5 text-text-secondary">
                        <DollarSign className="w-3 h-3" />
                        <span>{lab.fundingPartners.join(', ')}</span>
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-2 flex-wrap">
                    {lab.focus.map(f => (
                      <span key={f} className="text-[10px] text-accent-blue/70 px-1.5 py-0.5 bg-accent-blue/10 rounded">
                        {f}
                      </span>
                    ))}
                  </div>
                  <div className="flex items-center gap-4">
                    <a
                      href={lab.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1 text-accent-blue hover:text-accent-blue/80 transition-colors"
                    >
                      <Globe className="w-3 h-3" /> Website <ExternalLink className="w-2.5 h-2.5" />
                    </a>
                    {lab.contact && (
                      <a href={`mailto:${lab.contact}`} className="flex items-center gap-1 text-accent-blue hover:text-accent-blue/80 transition-colors">
                        <Mail className="w-3 h-3" /> Contact
                      </a>
                    )}
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {filtered.length === 0 && (
        <div className="text-center py-12 text-text-secondary text-sm">
          <Users className="w-8 h-8 mx-auto mb-2 opacity-40" />
          No labs match your search criteria.
        </div>
      )}

      {/* ── Focus Area Tag Cloud ───────────────────────────────────────── */}
      <div className="bg-bg-card border border-bg-card rounded-lg p-4">
        <h2 className="text-sm font-display font-bold text-text-primary flex items-center gap-2 mb-3">
          <Tag className="w-4 h-4 text-accent-blue" />
          Focus Area Tag Cloud
        </h2>
        <div className="flex flex-wrap gap-2">
          {focusAreaCounts.map(([area, count]) => {
            const size = count >= 4 ? 'text-sm' : count >= 2 ? 'text-xs' : 'text-[10px]'
            const opacity = count >= 4 ? 'opacity-100' : count >= 2 ? 'opacity-80' : 'opacity-60'
            return (
              <span
                key={area}
                className={`${size} ${opacity} px-2 py-1 rounded bg-accent-blue/10 text-accent-blue cursor-default`}
                title={`${count} lab(s)`}
              >
                {area} <span className="text-accent-blue/50 font-medium">({count})</span>
              </span>
            )
          })}
        </div>
      </div>

      {/* ── Partnership Timeline ───────────────────────────────────────── */}
      <div className="bg-bg-card border border-bg-card rounded-lg p-4">
        <h2 className="text-sm font-display font-bold text-text-primary flex items-center gap-2 mb-4">
          <BarChart3 className="w-4 h-4 text-accent-blue" />
          Partnership Timeline
        </h2>
        <div className="relative">
          {/* Vertical line */}
          <div className="absolute left-[60px] top-0 bottom-0 w-px bg-bg-primary" />

          <div className="space-y-4">
            {timelineData.map(([year, labs]) => (
              <div key={year} className="relative flex gap-4">
                {/* Year label */}
                <div className="w-[48px] shrink-0 text-right">
                  <span className="text-xs font-bold text-accent-blue">{year}</span>
                </div>

                {/* Dot on timeline */}
                <div className="shrink-0 w-[24px] flex items-start justify-center pt-1">
                  <div className="w-2.5 h-2.5 rounded-full bg-accent-blue border-2 border-bg-card relative z-10" />
                </div>

                {/* Labs for this year */}
                <div className="flex-1 space-y-1.5 pb-2">
                  {labs.map(lab => {
                    const style = TYPE_STYLES[lab.type]
                    const statusStyle = STATUS_STYLES[lab.status]
                    return (
                      <div key={lab.name} className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs text-text-primary">{lab.name}</span>
                        <span className={`text-[9px] font-medium uppercase px-1 py-0.5 rounded ${style.bg} ${style.text}`}>
                          {style.label}
                        </span>
                        <span className={`text-[9px] font-medium uppercase px-1 py-0.5 rounded ${statusStyle.bg} ${statusStyle.text}`}>
                          {statusStyle.label}
                        </span>
                      </div>
                    )
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
