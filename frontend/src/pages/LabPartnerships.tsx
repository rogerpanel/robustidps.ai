import { useState } from 'react'
import {
  Building2, ExternalLink, Globe, Mail, Users, MapPin,
  ChevronDown, ChevronRight, Search, Beaker, ShieldCheck,
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
  },
  {
    name: 'Microsoft Research — Security & AI',
    type: 'industry',
    focus: ['threat intelligence', 'federated learning', 'zero-trust architecture'],
    location: 'Redmond, WA',
    url: 'https://www.microsoft.com/en-us/research/group/security-and-cryptography/',
    description: 'Applied research in AI-driven security operations and federated threat detection.',
    collaboration: 'Benchmark sharing and federated learning protocol validation.',
  },
  {
    name: 'MIT Lincoln Laboratory — Cyber Analytics',
    type: 'academic',
    focus: ['network intrusion detection', 'dataset curation', 'real-time analytics'],
    location: 'Lexington, MA',
    url: 'https://www.ll.mit.edu',
    description: 'Pioneers of foundational IDS datasets and evaluation frameworks.',
    collaboration: 'Dataset standardization and evaluation pipeline alignment.',
  },
  {
    name: 'Canadian Institute for Cybersecurity (CIC)',
    type: 'academic',
    focus: ['IDS benchmarking', 'network traffic generation', 'flow-based detection'],
    location: 'Fredericton, NB, Canada',
    url: 'https://www.unb.ca/cic/',
    description: 'Creators of CIC-IDS and CIC-IoT benchmark datasets used across the field.',
    collaboration: 'Primary benchmark provider — CIC-IoT-2023 integrated into RobustIDPS.AI.',
  },
  {
    name: 'UNSW Canberra Cyber',
    type: 'academic',
    focus: ['IoT security', 'network forensics', 'anomaly detection'],
    location: 'Canberra, Australia',
    url: 'https://www.unsw.adfa.edu.au/cyber',
    description: 'Creators of UNSW-NB15 dataset. Research on IoT and smart-grid security.',
    collaboration: 'UNSW-NB15 dataset integration and cross-dataset generalization studies.',
  },
  {
    name: 'NIST — National Cybersecurity Center of Excellence',
    type: 'government',
    focus: ['standards', 'compliance frameworks', 'AI risk management'],
    location: 'Gaithersburg, MD',
    url: 'https://www.nccoe.nist.gov',
    description: 'Defines cybersecurity standards including the AI Risk Management Framework.',
    collaboration: 'Alignment of uncertainty quantification with NIST AI RMF guidelines.',
  },
  {
    name: 'Alan Turing Institute — Cyber Defence',
    type: 'academic',
    focus: ['graph neural networks', 'temporal modelling', 'adversarial ML'],
    location: 'London, UK',
    url: 'https://www.turing.ac.uk',
    description: 'UK national institute for data science and AI with dedicated cybersecurity programme.',
    collaboration: 'GNN-based detection methods and temporal graph analysis.',
  },
  {
    name: 'Darktrace Research',
    type: 'industry',
    focus: ['unsupervised detection', 'autonomous response', 'self-learning AI'],
    location: 'Cambridge, UK',
    url: 'https://darktrace.com',
    description: 'Industry leader in autonomous cyber defence and self-learning IDS technology.',
    collaboration: 'Comparative evaluation of supervised vs. unsupervised IDS approaches.',
  },
]

const TYPE_STYLES: Record<string, { bg: string; text: string; label: string }> = {
  industry:   { bg: 'bg-accent-blue/15',  text: 'text-accent-blue',  label: 'Industry' },
  academic:   { bg: 'bg-accent-green/15', text: 'text-accent-green', label: 'Academic' },
  government: { bg: 'bg-accent-amber/15', text: 'text-accent-amber', label: 'Government' },
}

// ── Component ────────────────────────────────────────────────────────────

export default function LabPartnerships() {
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('')
  const [expanded, setExpanded] = useState<string | null>(null)

  const filtered = LABS.filter(lab => {
    const matchesSearch = !search ||
      lab.name.toLowerCase().includes(search.toLowerCase()) ||
      lab.focus.some(f => f.toLowerCase().includes(search.toLowerCase()))
    const matchesType = !typeFilter || lab.type === typeFilter
    return matchesSearch && matchesType
  })

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

      {/* Filters */}
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
      </div>

      {/* Stats */}
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

      {/* Lab list */}
      <div className="space-y-2">
        {filtered.map(lab => {
          const style = TYPE_STYLES[lab.type]
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
    </div>
  )
}
