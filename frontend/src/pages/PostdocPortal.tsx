import { useState, useMemo } from 'react'
import {
  GraduationCap, Calendar, MapPin, ExternalLink, ChevronDown, ChevronRight,
  Briefcase, BookOpen, Globe, Clock, Star, Users, Award,
  Search, Tag, Lightbulb, AlertCircle, DollarSign,
} from 'lucide-react'

// ── Data types ───────────────────────────────────────────────────────────

type Position = {
  title: string
  institution: string
  department: string
  location: string
  type: 'postdoc' | 'fellowship' | 'research-scientist'
  topics: string[]
  deadline: string
  duration: string
  url: string
  description: string
  requirements: string[]
  funded: boolean
  salary: string
}

const POSITIONS: Position[] = [
  {
    title: 'Postdoctoral Researcher — AI for Network Security',
    institution: 'ETH Zurich',
    department: 'Dept. of Computer Science, Network Security Group',
    location: 'Zurich, Switzerland',
    type: 'postdoc',
    topics: ['intrusion detection', 'graph neural networks', 'adversarial ML'],
    deadline: '2026-06-15',
    duration: '2 years',
    url: 'https://ethz.ch/careers',
    description: 'Research on GNN-based network intrusion detection with focus on adversarial robustness and continual learning.',
    requirements: ['PhD in CS, ML, or Cybersecurity', 'Publications in top-tier venues (NeurIPS, CCS, NDSS)', 'Experience with PyTorch and network traffic analysis'],
    funded: true,
    salary: 'CHF 85,000/yr',
  },
  {
    title: 'Schmidt AI in Science Postdoctoral Fellowship',
    institution: 'University of Oxford',
    department: 'Cyber Security Centre',
    location: 'Oxford, UK',
    type: 'fellowship',
    topics: ['AI safety', 'uncertainty quantification', 'trustworthy AI'],
    deadline: '2026-05-01',
    duration: '2 years (renewable)',
    url: 'https://www.ox.ac.uk',
    description: 'Interdisciplinary fellowship applying AI methods to cybersecurity challenges, with emphasis on uncertainty-aware detection.',
    requirements: ['PhD in a relevant field', 'Strong publication record', 'Demonstrated interest in AI safety or trustworthy ML'],
    funded: true,
    salary: '£45,000–£55,000/yr',
  },
  {
    title: 'Research Scientist — Autonomous Cyber Defence',
    institution: 'DARPA / MITRE',
    department: 'Cyber Operations Division',
    location: 'McLean, VA, USA',
    type: 'research-scientist',
    topics: ['reinforcement learning', 'autonomous response', 'game theory', 'MITRE ATT&CK'],
    deadline: 'Rolling',
    duration: 'Permanent',
    url: 'https://www.mitre.org/careers',
    description: 'Research on RL-based autonomous cyber defence agents and game-theoretic threat modelling.',
    requirements: ['PhD or 5+ years research experience', 'US citizenship or clearance eligibility', 'Experience with RL frameworks and adversarial simulations'],
    funded: true,
    salary: '$120,000–$160,000/yr',
  },
  {
    title: 'Postdoctoral Fellow — Federated Threat Intelligence',
    institution: 'Max Planck Institute for Security and Privacy',
    department: 'Network and Distributed Systems Security',
    location: 'Bochum, Germany',
    type: 'postdoc',
    topics: ['federated learning', 'privacy-preserving ML', 'distributed IDS'],
    deadline: '2026-07-31',
    duration: '2–3 years',
    url: 'https://www.mpi-sp.org',
    description: 'Research on privacy-preserving federated learning for collaborative intrusion detection across organizations.',
    requirements: ['PhD in CS or related field', 'Publications on federated learning or privacy', 'Strong systems programming skills'],
    funded: true,
    salary: '€55,000–€65,000/yr',
  },
  {
    title: 'CSIRO Data61 Postdoctoral Scientist — IoT Security',
    institution: 'CSIRO Data61',
    department: 'Cybersecurity Research Programme',
    location: 'Sydney, Australia',
    type: 'postdoc',
    topics: ['IoT security', 'edge computing', 'anomaly detection', 'lightweight ML'],
    deadline: '2026-08-15',
    duration: '3 years',
    url: 'https://www.data61.csiro.au',
    description: 'Research on lightweight ML models for IoT intrusion detection at the network edge.',
    requirements: ['PhD in CS, EE, or Cybersecurity', 'Experience with embedded/edge ML', 'Familiarity with IoT protocols and datasets'],
    funded: true,
    salary: 'AUD 95,000–110,000/yr',
  },
  {
    title: 'Postdoctoral Researcher — LLM-Augmented Threat Hunting',
    institution: 'Tsinghua University',
    department: 'Institute for Network Sciences and Cyberspace',
    location: 'Beijing, China',
    type: 'postdoc',
    topics: ['large language models', 'threat hunting', 'log analysis', 'NLP for security'],
    deadline: '2026-09-01',
    duration: '2 years',
    url: 'https://www.tsinghua.edu.cn',
    description: 'Investigating the application of large language models for automated threat hunting in enterprise SIEM logs and alert triage.',
    requirements: ['PhD in CS, NLP, or Cybersecurity', 'Experience with LLMs and transformer architectures', 'Familiarity with SIEM systems and CTI frameworks'],
    funded: true,
    salary: '¥350,000–¥450,000/yr',
  },
  {
    title: 'Research Fellow — Adversarial Robustness in NIDS',
    institution: 'KAIST',
    department: 'School of Computing, Cyber Security Research Center',
    location: 'Daejeon, South Korea',
    type: 'fellowship',
    topics: ['adversarial ML', 'evasion attacks', 'certified defenses', 'intrusion detection'],
    deadline: '2026-06-30',
    duration: '2 years',
    url: 'https://www.kaist.ac.kr',
    description: 'Research on certified robustness guarantees for ML-based network intrusion detection systems against adversarial evasion.',
    requirements: ['PhD in CS or ML', 'Publications on adversarial ML (ICML, NeurIPS, CCS)', 'Strong mathematical background in optimization'],
    funded: true,
    salary: '₩55,000,000–₩70,000,000/yr',
  },
  {
    title: 'Postdoctoral Researcher — Cyber-Physical Systems Security',
    institution: 'Technion – Israel Institute of Technology',
    department: 'Faculty of Electrical and Computer Engineering',
    location: 'Haifa, Israel',
    type: 'postdoc',
    topics: ['CPS security', 'SCADA/ICS', 'anomaly detection', 'digital twins'],
    deadline: '2026-07-15',
    duration: '2 years',
    url: 'https://www.technion.ac.il',
    description: 'Research on ML-based anomaly detection for industrial control systems using digital twin simulations for training data generation.',
    requirements: ['PhD in CS, EE, or Control Systems', 'Experience with ICS/SCADA protocols', 'Familiarity with physics-informed ML'],
    funded: true,
    salary: '₪180,000–₪220,000/yr',
  },
  {
    title: 'Postdoctoral Fellow — AI-Driven Malware Analysis',
    institution: 'University of São Paulo (USP)',
    department: 'Institute of Mathematics and Computer Science',
    location: 'São Paulo, Brazil',
    type: 'postdoc',
    topics: ['malware analysis', 'binary analysis', 'deep learning', 'program analysis'],
    deadline: '2026-08-31',
    duration: '2 years',
    url: 'https://www.usp.br',
    description: 'Research on deep learning approaches for automated malware family classification and zero-day detection using binary analysis.',
    requirements: ['PhD in CS or Cybersecurity', 'Experience with reverse engineering tools', 'Publications in security or ML venues'],
    funded: true,
    salary: 'R$120,000–R$150,000/yr',
  },
  {
    title: 'Research Scientist — Explainable AI for Security Operations',
    institution: 'NTU Singapore',
    department: 'School of Computer Science and Engineering',
    location: 'Singapore',
    type: 'research-scientist',
    topics: ['explainable AI', 'SOC automation', 'alert triage', 'human-AI teaming'],
    deadline: '2026-05-31',
    duration: '3 years',
    url: 'https://www.ntu.edu.sg',
    description: 'Developing explainable AI methods that produce actionable justifications for security analysts in SOC environments.',
    requirements: ['PhD in CS, AI, or HCI', 'Experience with XAI methods (SHAP, LIME, attention)', 'Understanding of SOC workflows'],
    funded: true,
    salary: 'SGD 80,000–100,000/yr',
  },
  {
    title: 'Postdoctoral Fellow — Secure Federated Learning at Scale',
    institution: 'KAUST',
    department: 'Computer, Electrical and Mathematical Sciences Division',
    location: 'Thuwal, Saudi Arabia',
    type: 'postdoc',
    topics: ['federated learning', 'Byzantine robustness', 'secure aggregation', 'distributed systems'],
    deadline: '2026-10-01',
    duration: '2–3 years',
    url: 'https://www.kaust.edu.sa',
    description: 'Research on Byzantine-robust federated learning protocols for large-scale collaborative intrusion detection deployments.',
    requirements: ['PhD in CS or ML', 'Publications on federated/distributed learning', 'Experience with secure computation'],
    funded: true,
    salary: '$75,000–$90,000/yr (tax-free)',
  },
  {
    title: 'Postdoctoral Researcher — Network Traffic Intelligence',
    institution: 'University of Cape Town',
    department: 'Department of Computer Science, CAIR Lab',
    location: 'Cape Town, South Africa',
    type: 'postdoc',
    topics: ['traffic classification', 'encrypted traffic analysis', 'deep packet inspection', 'transfer learning'],
    deadline: '2026-09-15',
    duration: '2 years',
    url: 'https://www.uct.ac.za',
    description: 'Research on deep learning techniques for encrypted network traffic classification and cross-domain transfer learning for IDS.',
    requirements: ['PhD in CS or Network Engineering', 'Experience with traffic datasets (CIC, UNSW)', 'Strong Python and data science skills'],
    funded: true,
    salary: 'ZAR 550,000–700,000/yr',
  },
  {
    title: 'Research Scientist — Formal Verification of ML Security',
    institution: 'INRIA',
    department: 'INRIA Paris, PROSECCO Team',
    location: 'Paris, France',
    type: 'research-scientist',
    topics: ['formal verification', 'certified robustness', 'abstract interpretation', 'neural network verification'],
    deadline: '2026-06-01',
    duration: 'Permanent (subject to review)',
    url: 'https://www.inria.fr',
    description: 'Developing formal methods and abstract interpretation techniques to verify robustness properties of ML-based security systems.',
    requirements: ['PhD in CS or Formal Methods', 'Experience with verification tools (Marabou, ERAN)', 'Publications in CAV, PLDI, or security venues'],
    funded: true,
    salary: '€50,000–€62,000/yr',
  },
  {
    title: 'Postdoctoral Fellow — Privacy-Preserving Intrusion Detection',
    institution: 'TU Delft',
    department: 'Faculty of EEMCS, Cyber Security Group',
    location: 'Delft, Netherlands',
    type: 'postdoc',
    topics: ['differential privacy', 'homomorphic encryption', 'privacy-preserving ML', 'intrusion detection'],
    deadline: '2026-07-01',
    duration: '2 years',
    url: 'https://www.tudelft.nl',
    description: 'Investigating differential privacy and homomorphic encryption approaches for training IDS models on sensitive network data.',
    requirements: ['PhD in CS, Cryptography, or ML', 'Publications on privacy-preserving computation', 'Experience with HE libraries (SEAL, OpenFHE)'],
    funded: true,
    salary: '€55,000–€68,000/yr',
  },
  {
    title: 'Research Scientist — Foundation Models for Cybersecurity',
    institution: 'Carnegie Mellon University',
    department: 'CyLab Security and Privacy Institute',
    location: 'Pittsburgh, PA, USA',
    type: 'research-scientist',
    topics: ['foundation models', 'pre-training', 'zero-shot detection', 'security embeddings'],
    deadline: '2026-04-15',
    duration: '3 years',
    url: 'https://www.cylab.cmu.edu',
    description: 'Building foundation models pre-trained on diverse cybersecurity data for zero-shot and few-shot intrusion detection.',
    requirements: ['PhD in CS or ML', 'Experience training large-scale models', 'Publications in NeurIPS, ICML, or ACL'],
    funded: true,
    salary: '$90,000–$115,000/yr',
  },
  {
    title: 'Postdoctoral Fellowship — Adversarial Robustness Benchmarks',
    institution: 'Stanford University',
    department: 'Computer Science Department, Security Lab',
    location: 'Stanford, CA, USA',
    type: 'fellowship',
    topics: ['benchmarking', 'adversarial robustness', 'reproducibility', 'dataset curation'],
    deadline: '2026-05-15',
    duration: '2 years',
    url: 'https://security.stanford.edu',
    description: 'Developing rigorous benchmarks and evaluation methodologies for adversarial robustness in network intrusion detection systems.',
    requirements: ['PhD in CS or ML', 'Track record in empirical ML research', 'Experience with benchmark design and statistical methodology'],
    funded: true,
    salary: '$85,000–$100,000/yr',
  },
  {
    title: 'Postdoctoral Researcher — Graph-Based Threat Detection',
    institution: 'University of Tokyo',
    department: 'Information Technology Center, Security Division',
    location: 'Tokyo, Japan',
    type: 'postdoc',
    topics: ['graph neural networks', 'provenance graphs', 'APT detection', 'causal reasoning'],
    deadline: '2026-08-01',
    duration: '2 years',
    url: 'https://www.u-tokyo.ac.jp',
    description: 'Research on graph neural network methods for APT detection using system provenance graphs and causal reasoning.',
    requirements: ['PhD in CS or related field', 'Experience with GNNs (PyG, DGL)', 'Knowledge of system-level auditing and provenance'],
    funded: true,
    salary: '¥6,000,000–¥7,500,000/yr',
  },
]

const CONFERENCES = [
  { name: 'IEEE S&P (Oakland)', dates: 'May 18–22, 2026', submissionDeadline: 'Dec 5, 2025 (Cycle 3)', location: 'San Francisco, USA', url: 'https://sp2026.ieee-security.org' },
  { name: 'USENIX Security', dates: 'Aug 12–14, 2026', submissionDeadline: 'Feb 4, 2026 (Cycle 3)', location: 'Vancouver, Canada', url: 'https://www.usenix.org/conference/usenixsecurity26' },
  { name: 'ACM CCS', dates: 'Nov 9–13, 2026', submissionDeadline: 'May 2, 2026', location: 'Taipei, Taiwan', url: 'https://www.sigsac.org/ccs/CCS2026/' },
  { name: 'NDSS', dates: 'Feb 23–28, 2027', submissionDeadline: 'Jul 10, 2026', location: 'San Diego, USA', url: 'https://www.ndss-symposium.org/ndss2027/' },
  { name: 'NeurIPS', dates: 'Dec 7–13, 2026', submissionDeadline: 'May 22, 2026', location: 'Miami, USA', url: 'https://neurips.cc' },
  { name: 'ICML', dates: 'Jul 19–25, 2026', submissionDeadline: 'Jan 31, 2026', location: 'Honolulu, USA', url: 'https://icml.cc' },
  { name: 'ACSAC', dates: 'Dec 7–11, 2026', submissionDeadline: 'Jun 15, 2026', location: 'Austin, USA', url: 'https://www.acsac.org' },
  { name: 'RAID', dates: 'Oct 14–16, 2026', submissionDeadline: 'Apr 10, 2026', location: 'Berlin, Germany', url: 'https://raid2026.org' },
  { name: 'ESORICS', dates: 'Sep 22–26, 2026', submissionDeadline: 'Apr 24, 2026', location: 'Lisbon, Portugal', url: 'https://esorics2026.org' },
  { name: 'AISec (CCS Workshop)', dates: 'Nov 9, 2026', submissionDeadline: 'Jul 31, 2026', location: 'Taipei, Taiwan', url: 'https://aisec.cc' },
]

const APPLICATION_TIPS = [
  {
    title: 'Tailor Your Research Statement',
    content: 'Write a focused research statement (2–4 pages) that connects your PhD work to the specific position. Show how your expertise addresses the group\'s open problems and outline a concrete 2-year research plan.',
  },
  {
    title: 'Highlight Relevant Publications',
    content: 'Emphasize your publications that align with the position\'s topics. Include preprints and under-review papers if relevant. Mention impact metrics (citations, best paper awards) when applicable.',
  },
  {
    title: 'Prepare a Strong Coding Portfolio',
    content: 'Many positions in AI-for-security value practical skills. Maintain public GitHub repositories demonstrating your ML implementations, dataset curation, or tool development. Link to reproducible experiments.',
  },
  {
    title: 'Secure Strong Recommendation Letters',
    content: 'Request letters from advisors and collaborators who can speak to your research potential and technical skills. Give recommenders at least 4 weeks and share your tailored research statement with them.',
  },
  {
    title: 'Apply Broadly and Early',
    content: 'Postdoc searches can be competitive. Apply to 10–15 positions, including different countries and institution types. Many European positions have rolling deadlines — apply as soon as you see a fit.',
  },
  {
    title: 'Network at Conferences',
    content: 'Attend CCS, NDSS, NeurIPS, and USENIX Security. Introduce yourself to PIs whose work you admire. Many postdoc positions are filled through informal connections before they are formally advertised.',
  },
]

const TYPE_STYLES: Record<string, { bg: string; text: string; label: string }> = {
  postdoc:             { bg: 'bg-accent-blue/15',   text: 'text-accent-blue',  label: 'Postdoc' },
  fellowship:          { bg: 'bg-accent-amber/15',  text: 'text-accent-amber', label: 'Fellowship' },
  'research-scientist': { bg: 'bg-accent-green/15', text: 'text-accent-green', label: 'Research Scientist' },
}

function daysUntil(dateStr: string): number | null {
  if (dateStr === 'Rolling') return null
  const target = new Date(dateStr)
  const now = new Date()
  const diff = target.getTime() - now.getTime()
  return Math.ceil(diff / (1000 * 60 * 60 * 24))
}

function deadlineBadge(dateStr: string) {
  const days = daysUntil(dateStr)
  if (days === null) return <span className="text-text-secondary/50 text-[10px]">Rolling</span>
  if (days < 0) return <span className="text-red-400 text-[10px] font-medium">Closed</span>
  if (days <= 14) return <span className="text-red-400 text-[10px] font-medium">{days}d left</span>
  if (days <= 45) return <span className="text-accent-amber text-[10px] font-medium">{days}d left</span>
  return <span className="text-accent-green/70 text-[10px]">{days}d left</span>
}

// ── Component ────────────────────────────────────────────────────────────

export default function PostdocPortal() {
  const [expanded, setExpanded] = useState<string | null>(null)
  const [typeFilter, setTypeFilter] = useState<string>('')
  const [searchQuery, setSearchQuery] = useState('')
  const [topicFilter, setTopicFilter] = useState<string | null>(null)
  const [tipsExpanded, setTipsExpanded] = useState(false)
  const [expandedTip, setExpandedTip] = useState<number | null>(null)

  // Gather all unique topics
  const allTopics = useMemo(() => {
    const topics = new Map<string, number>()
    POSITIONS.forEach(p => p.topics.forEach(t => topics.set(t, (topics.get(t) || 0) + 1)))
    return Array.from(topics.entries()).sort((a, b) => b[1] - a[1])
  }, [])

  const filtered = useMemo(() => {
    const q = searchQuery.toLowerCase().trim()
    return POSITIONS.filter(p => {
      if (typeFilter && p.type !== typeFilter) return false
      if (topicFilter && !p.topics.includes(topicFilter)) return false
      if (q) {
        const haystack = [p.title, p.institution, p.location, ...p.topics].join(' ').toLowerCase()
        if (!haystack.includes(q)) return false
      }
      return true
    })
  }, [typeFilter, topicFilter, searchQuery])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-display font-bold text-text-primary flex items-center gap-2">
          <GraduationCap className="w-6 h-6 text-accent-blue" />
          Postdoc Portal
        </h1>
        <p className="text-sm text-text-secondary mt-1">
          Curated postdoctoral positions, fellowships, and research scientist roles in AI-driven cybersecurity.
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Open Positions', value: POSITIONS.length, icon: Briefcase, color: 'text-accent-blue' },
          { label: 'Countries', value: new Set(POSITIONS.map(p => p.location.split(', ').pop())).size, icon: Globe, color: 'text-accent-green' },
          { label: 'Funded', value: POSITIONS.filter(p => p.funded).length, icon: Award, color: 'text-accent-amber' },
          { label: 'Avg Duration', value: '2–3 yrs', icon: Clock, color: 'text-text-secondary' },
        ].map(s => (
          <div key={s.label} className="bg-bg-card border border-bg-card rounded-lg p-3 text-center">
            <s.icon className={`w-5 h-5 mx-auto mb-1 ${s.color}`} />
            <div className="text-lg font-bold text-text-primary">{s.value}</div>
            <div className="text-[10px] text-text-secondary uppercase tracking-wider">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Search bar */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-secondary/50" />
        <input
          type="text"
          placeholder="Search by title, institution, topic, or location..."
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          className="w-full bg-bg-card border border-bg-card rounded-lg pl-9 pr-3 py-2 text-sm text-text-primary placeholder:text-text-secondary/40 focus:outline-none focus:ring-1 focus:ring-accent-blue/40"
        />
      </div>

      {/* Type filter */}
      <div className="flex gap-1 flex-wrap">
        {['', 'postdoc', 'fellowship', 'research-scientist'].map(t => (
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

      {/* Topic tag cloud */}
      <div className="bg-bg-card border border-bg-card rounded-lg p-3">
        <div className="flex items-center gap-1.5 mb-2">
          <Tag className="w-3.5 h-3.5 text-text-secondary" />
          <span className="text-xs font-medium text-text-secondary">Topics</span>
          {topicFilter && (
            <button
              onClick={() => setTopicFilter(null)}
              className="text-[10px] text-accent-blue hover:text-accent-blue/80 ml-1"
            >
              clear filter
            </button>
          )}
        </div>
        <div className="flex flex-wrap gap-1.5">
          {allTopics.map(([topic, count]) => (
            <button
              key={topic}
              onClick={() => setTopicFilter(topicFilter === topic ? null : topic)}
              className={`text-[10px] px-1.5 py-0.5 rounded transition-colors ${
                topicFilter === topic
                  ? 'bg-accent-blue/25 text-accent-blue font-medium'
                  : 'bg-accent-blue/8 text-accent-blue/60 hover:bg-accent-blue/15 hover:text-accent-blue/80'
              }`}
            >
              {topic} <span className="opacity-50">({count})</span>
            </button>
          ))}
        </div>
      </div>

      {/* Positions list */}
      <div className="space-y-2">
        {filtered.map(pos => {
          const style = TYPE_STYLES[pos.type]
          const isExpanded = expanded === pos.title
          return (
            <div key={pos.title} className="bg-bg-card border border-bg-card rounded-lg overflow-hidden">
              <div
                className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-bg-primary/30 transition-colors"
                onClick={() => setExpanded(isExpanded ? null : pos.title)}
              >
                {isExpanded
                  ? <ChevronDown className="w-3.5 h-3.5 text-text-secondary shrink-0" />
                  : <ChevronRight className="w-3.5 h-3.5 text-text-secondary shrink-0" />}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm text-text-primary font-medium">{pos.title}</span>
                    <span className={`text-[10px] font-medium uppercase px-1.5 py-0.5 rounded ${style.bg} ${style.text}`}>
                      {style.label}
                    </span>
                    {pos.funded && (
                      <span className="text-[10px] font-medium uppercase px-1.5 py-0.5 rounded bg-accent-green/15 text-accent-green">
                        Funded
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-text-secondary mt-0.5 flex items-center gap-3 flex-wrap">
                    <span className="flex items-center gap-1"><Users className="w-3 h-3" /> {pos.institution}</span>
                    <span className="flex items-center gap-1"><MapPin className="w-3 h-3" /> {pos.location}</span>
                  </div>
                </div>
                <div className="hidden md:flex flex-col items-end text-xs gap-0.5">
                  <span className="flex items-center gap-1 text-text-secondary">
                    <Calendar className="w-3 h-3" /> {pos.deadline}
                  </span>
                  {deadlineBadge(pos.deadline)}
                  <span className="text-text-secondary/60">{pos.duration}</span>
                </div>
              </div>

              {isExpanded && (
                <div className="border-t border-bg-primary px-4 py-3 text-xs space-y-3">
                  <p className="text-text-secondary">{pos.description}</p>
                  <div className="text-text-secondary/60 text-[10px]">{pos.department}</div>
                  <div className="flex items-center gap-1.5 text-text-primary">
                    <DollarSign className="w-3 h-3 text-accent-green" />
                    <span className="font-medium">Salary:</span>
                    <span>{pos.salary}</span>
                  </div>
                  <div className="md:hidden flex items-center gap-2">
                    <Calendar className="w-3 h-3 text-text-secondary" />
                    <span className="text-text-secondary">{pos.deadline}</span>
                    {deadlineBadge(pos.deadline)}
                  </div>
                  <div>
                    <span className="text-text-secondary font-medium">Requirements:</span>
                    <ul className="list-disc list-inside mt-1 text-text-primary space-y-0.5">
                      {pos.requirements.map(r => <li key={r}>{r}</li>)}
                    </ul>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap">
                    {pos.topics.map(t => (
                      <button
                        key={t}
                        onClick={(e) => { e.stopPropagation(); setTopicFilter(t) }}
                        className="text-[10px] text-accent-blue/70 px-1.5 py-0.5 bg-accent-blue/10 rounded hover:bg-accent-blue/20 transition-colors cursor-pointer"
                      >
                        {t}
                      </button>
                    ))}
                  </div>
                  <a
                    href={pos.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-accent-blue hover:text-accent-blue/80 transition-colors"
                  >
                    <BookOpen className="w-3 h-3" /> Apply / Details <ExternalLink className="w-2.5 h-2.5" />
                  </a>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {filtered.length === 0 && (
        <div className="text-center py-12 text-text-secondary text-sm">
          <Star className="w-8 h-8 mx-auto mb-2 opacity-40" />
          No positions match the selected filters.
        </div>
      )}

      {/* Application Tips */}
      <div className="bg-bg-card border border-bg-card rounded-lg overflow-hidden">
        <button
          onClick={() => setTipsExpanded(!tipsExpanded)}
          className="w-full flex items-center gap-2 px-4 py-3 hover:bg-bg-primary/30 transition-colors"
        >
          {tipsExpanded
            ? <ChevronDown className="w-3.5 h-3.5 text-text-secondary" />
            : <ChevronRight className="w-3.5 h-3.5 text-text-secondary" />}
          <Lightbulb className="w-4 h-4 text-accent-amber" />
          <span className="text-sm font-medium text-text-primary">Application Tips for Postdoc Candidates</span>
        </button>
        {tipsExpanded && (
          <div className="border-t border-bg-primary px-4 py-3 space-y-1">
            {APPLICATION_TIPS.map((tip, i) => (
              <div key={i}>
                <button
                  onClick={() => setExpandedTip(expandedTip === i ? null : i)}
                  className="w-full flex items-center gap-2 py-1.5 text-left hover:bg-bg-primary/20 rounded px-1 transition-colors"
                >
                  {expandedTip === i
                    ? <ChevronDown className="w-3 h-3 text-text-secondary shrink-0" />
                    : <ChevronRight className="w-3 h-3 text-text-secondary shrink-0" />}
                  <span className="text-xs font-medium text-text-primary">{tip.title}</span>
                </button>
                {expandedTip === i && (
                  <p className="text-xs text-text-secondary ml-5 pb-2">{tip.content}</p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Conference Calendar */}
      <div className="bg-bg-card border border-bg-card rounded-lg p-4">
        <div className="flex items-center gap-2 mb-3">
          <Calendar className="w-4 h-4 text-accent-blue" />
          <h2 className="text-sm font-medium text-text-primary">Conference Calendar</h2>
          <span className="text-[10px] text-text-secondary">(Security &amp; ML)</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-text-secondary/60 text-[10px] uppercase tracking-wider border-b border-bg-primary">
                <th className="text-left py-1.5 pr-3 font-medium">Conference</th>
                <th className="text-left py-1.5 pr-3 font-medium">Dates</th>
                <th className="text-left py-1.5 pr-3 font-medium">Location</th>
                <th className="text-left py-1.5 font-medium">Submission Deadline</th>
              </tr>
            </thead>
            <tbody>
              {CONFERENCES.map(conf => (
                <tr key={conf.name} className="border-b border-bg-primary/50 last:border-0">
                  <td className="py-1.5 pr-3">
                    <a
                      href={conf.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-accent-blue hover:text-accent-blue/80 font-medium inline-flex items-center gap-1"
                    >
                      {conf.name} <ExternalLink className="w-2.5 h-2.5" />
                    </a>
                  </td>
                  <td className="py-1.5 pr-3 text-text-primary whitespace-nowrap">{conf.dates}</td>
                  <td className="py-1.5 pr-3 text-text-secondary whitespace-nowrap">{conf.location}</td>
                  <td className="py-1.5 text-text-secondary whitespace-nowrap flex items-center gap-1.5">
                    <AlertCircle className="w-3 h-3 text-accent-amber/50" />
                    {conf.submissionDeadline}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Footer note */}
      <div className="text-[10px] text-text-secondary/40 text-center pt-4">
        Positions are curated based on alignment with RobustIDPS.AI research areas. Contact us to list an opening.
      </div>
    </div>
  )
}
