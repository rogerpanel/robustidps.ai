import { useState } from 'react'
import {
  GraduationCap, Calendar, MapPin, ExternalLink, ChevronDown, ChevronRight,
  Briefcase, BookOpen, Globe, Clock, Star, Users, Award,
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
  },
]

const TYPE_STYLES: Record<string, { bg: string; text: string; label: string }> = {
  postdoc:             { bg: 'bg-accent-blue/15',   text: 'text-accent-blue',  label: 'Postdoc' },
  fellowship:          { bg: 'bg-accent-amber/15',  text: 'text-accent-amber', label: 'Fellowship' },
  'research-scientist': { bg: 'bg-accent-green/15', text: 'text-accent-green', label: 'Research Scientist' },
}

// ── Component ────────────────────────────────────────────────────────────

export default function PostdocPortal() {
  const [expanded, setExpanded] = useState<string | null>(null)
  const [typeFilter, setTypeFilter] = useState<string>('')

  const filtered = POSITIONS.filter(p => !typeFilter || p.type === typeFilter)

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

      {/* Type filter */}
      <div className="flex gap-1">
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
                  <div className="text-xs text-text-secondary mt-0.5 flex items-center gap-3">
                    <span className="flex items-center gap-1"><Users className="w-3 h-3" /> {pos.institution}</span>
                    <span className="flex items-center gap-1"><MapPin className="w-3 h-3" /> {pos.location}</span>
                  </div>
                </div>
                <div className="hidden md:flex flex-col items-end text-xs">
                  <span className="flex items-center gap-1 text-text-secondary">
                    <Calendar className="w-3 h-3" /> {pos.deadline}
                  </span>
                  <span className="text-text-secondary/60">{pos.duration}</span>
                </div>
              </div>

              {isExpanded && (
                <div className="border-t border-bg-primary px-4 py-3 text-xs space-y-3">
                  <p className="text-text-secondary">{pos.description}</p>
                  <div className="text-text-secondary/60 text-[10px]">{pos.department}</div>
                  <div>
                    <span className="text-text-secondary font-medium">Requirements:</span>
                    <ul className="list-disc list-inside mt-1 text-text-primary space-y-0.5">
                      {pos.requirements.map(r => <li key={r}>{r}</li>)}
                    </ul>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap">
                    {pos.topics.map(t => (
                      <span key={t} className="text-[10px] text-accent-blue/70 px-1.5 py-0.5 bg-accent-blue/10 rounded">
                        {t}
                      </span>
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
          No positions match the selected filter.
        </div>
      )}

      {/* Footer note */}
      <div className="text-[10px] text-text-secondary/40 text-center pt-4">
        Positions are curated based on alignment with RobustIDPS.AI research areas. Contact us to list an opening.
      </div>
    </div>
  )
}
