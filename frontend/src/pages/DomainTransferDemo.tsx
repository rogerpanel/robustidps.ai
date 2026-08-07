import { useState } from 'react'
import { GitBranch, Building2, HeartPulse, Layers, ArrowRight, CheckCircle, Shield, Database, Paintbrush } from 'lucide-react'
import PageGuide from '../components/PageGuide'
import { cachePageResult } from '../utils/api'
import { registerSessionReset } from '../utils/sessionReset'

// Module-level store: survives component unmount on navigation
const _store = { tab: 'banking' as string }

registerSessionReset(() => {
  _store.tab = 'banking'
})

/* ── Guide ────────────────────────────────────────────────────────── */

const GUIDE_STEPS = [
  { title: 'Banking Fraud', desc: 'See how each IDS model maps to financial fraud detection equivalents.' },
  { title: 'Medical Security', desc: 'Explore model mappings for healthcare and regulatory compliance tables.' },
  { title: 'Architecture', desc: 'Understand the 3-step transfer process to adapt RobustIDPS for new domains.' },
]

/* ── Data: model mappings ─────────────────────────────────────────── */

const MODEL_MAP_BANKING = [
  { ids: 'CT-TGNN (Neural ODE)', banking: 'Temporal Transaction ODE', task: 'Real-time fraud trajectory detection across time-series payment flows' },
  { ids: 'TripleE-TGNN', banking: 'Multi-Scale Transaction GNN', task: 'Cross-account money laundering pattern detection at multiple time horizons' },
  { ids: 'FedLLM-API', banking: 'Federated Bank LLM', task: 'Zero-shot fraud classification across partner institutions without data sharing' },
  { ids: 'PQ-IDPS', banking: 'PQ-FraudShield', task: 'Quantum-resistant transaction signing and post-quantum secure fraud alerts' },
  { ids: 'MambaShield', banking: 'StreamFraud-SSM', task: 'High-throughput streaming fraud detection for payment processors' },
  { ids: 'Stochastic Transformer', banking: 'PAC-Bayes Fraud Scorer', task: 'Uncertainty-aware fraud scoring with calibrated confidence intervals' },
  { ids: 'Game-Theoretic Defence', banking: 'Nash Fraud Equilibrium', task: 'Adversarial robustness against adaptive fraud ring evasion tactics' },
]

const FRAUD_CLASSES = [
  'Card-Not-Present Fraud', 'Account Takeover', 'Synthetic Identity', 'First-Party Fraud',
  'Wire Transfer Fraud', 'ACH Fraud', 'Check Fraud', 'Money Laundering',
  'Insider Trading Signal', 'Phishing-Initiated Fraud', 'SIM Swap Fraud',
  'Authorized Push Payment', 'Bust-Out Fraud', 'Loyalty Point Fraud', 'Crypto Mixer Detection',
]

const TRANSACTION_FEATURES = [
  'transaction_amount', 'merchant_category', 'geo_distance_km', 'time_since_last_txn',
  'device_fingerprint_hash', 'velocity_1h', 'velocity_24h', 'avg_txn_amount_30d',
  'is_international', 'card_present_flag', 'ip_risk_score', 'session_duration_sec',
  'failed_auth_count', 'account_age_days', 'beneficiary_risk_tier',
]

/* ── Data: medical mappings ───────────────────────────────────────── */

const MODEL_MAP_MEDICAL = [
  { ids: 'CT-TGNN (Neural ODE)', medical: 'Patient Vitals ODE', task: 'Continuous-time ICU anomaly detection from irregular vital sign streams' },
  { ids: 'TripleE-TGNN', medical: 'Multi-Scale Clinical GNN', task: 'Hospital network infection propagation tracking across wards and visits' },
  { ids: 'FedLLM-API', medical: 'Federated Health LLM', task: 'Cross-hospital diagnostic anomaly detection without sharing PHI' },
  { ids: 'PQ-IDPS', medical: 'PQ-MedShield', task: 'Post-quantum encrypted EHR access anomaly detection' },
  { ids: 'MambaShield', medical: 'StreamMed-SSM', task: 'Real-time medical device telemetry anomaly detection (IoMT)' },
  { ids: 'Stochastic Transformer', medical: 'Clinical Uncertainty Scorer', task: 'Calibrated confidence in diagnostic anomaly alerts to reduce alarm fatigue' },
  { ids: 'Game-Theoretic Defence', medical: 'Adversarial Med Defence', task: 'Robustness against adversarial perturbations to medical image/signal inputs' },
]

const COMPLIANCE_TABLE = [
  { reg: 'HIPAA', scope: 'US healthcare data', requirement: 'PHI encryption, access audit logs, breach notification within 60 days', robustidps: 'Federated learning (no PHI sharing), PQ encryption, full audit trail' },
  { reg: 'FDA 21 CFR Part 11', scope: 'Electronic records', requirement: 'Validation, audit trails, electronic signatures, data integrity', robustidps: 'Model versioning, provenance chain, deterministic inference logs' },
  { reg: 'EU AI Act (High-Risk)', scope: 'Medical AI systems', requirement: 'Transparency, human oversight, accuracy metrics, bias testing', robustidps: 'XAI studio, uncertainty quantification, adversarial robustness reports' },
  { reg: 'EU MDR', scope: 'Medical devices', requirement: 'Clinical evaluation, post-market surveillance, risk management', robustidps: 'Continual learning with drift detection, benchmark tracking' },
  { reg: 'SOC 2 Type II', scope: 'Service security', requirement: 'Security, availability, processing integrity, confidentiality', robustidps: 'Zero-trust governance, supply chain security, PQ cryptography' },
]

/* ── Transfer steps ───────────────────────────────────────────────── */

const TRANSFER_STEPS = [
  {
    step: 1, title: 'Replace Feature Pipeline',
    icon: Database,
    desc: 'Swap the network flow feature extractor for domain-specific features (transaction vectors, vital signs, etc.).',
    details: [
      'Map 46 CIC-IoT features to domain equivalents',
      'Retrain feature normalization layers',
      'Validate input distribution alignment',
      'Update preprocessing pipeline configs',
    ],
  },
  {
    step: 2, title: 'Retrain & Fine-Tune',
    icon: Layers,
    desc: 'Fine-tune all 7 surrogate branches on domain data using transfer learning from network IDS weights.',
    details: [
      'Freeze lower layers, retrain classification heads',
      'Apply domain-specific label taxonomy',
      'Run ablation to verify branch contributions',
      'Calibrate uncertainty thresholds for new domain',
    ],
  },
  {
    step: 3, title: 'Customize UI & Alerts',
    icon: Paintbrush,
    desc: 'Adapt the dashboard, alerting, and compliance modules for the target industry.',
    details: [
      'Relabel severity tiers for domain context',
      'Configure industry-specific compliance checks',
      'Customize executive dashboard KPIs',
      'Integrate domain alerting channels (SIEM, EHR, etc.)',
    ],
  },
]

/* ── Component ────────────────────────────────────────────────────── */

type Tab = 'banking' | 'medical' | 'architecture'

export default function DomainTransferDemo() {
  const [tab, _setTab] = useState<Tab>(_store.tab as Tab)
  const setTab = (t: Tab) => { _store.tab = t; _setTab(t) }

  // Cache on mount (informational page)
  useState(() => { cachePageResult('domain_transfer', {}).catch(() => {}) })

  const tabs: { key: Tab; label: string; icon: typeof Building2 }[] = [
    { key: 'banking', label: 'Banking Fraud', icon: Building2 },
    { key: 'medical', label: 'Medical', icon: HeartPulse },
    { key: 'architecture', label: 'Architecture', icon: Layers },
  ]

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-accent-purple/10 flex items-center justify-center">
          <GitBranch className="w-5 h-5 text-accent-purple" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Domain Transfer Demo</h1>
          <p className="text-sm text-text-secondary">How RobustIDPS.ai transfers to banking and medical domains</p>
        </div>
      </div>

      <PageGuide title="Domain Transfer Overview" steps={GUIDE_STEPS} tip="This is an informational page. No file upload needed." />

      {/* Tabs */}
      <div className="flex gap-1 bg-bg-secondary rounded-xl p-1 border border-bg-card">
        {tabs.map(t => (
          <button key={t.key} onClick={() => setTab(t.key)}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors flex-1 justify-center ${
              tab === t.key ? 'bg-accent-purple/15 text-accent-purple' : 'text-text-secondary hover:text-text-primary hover:bg-bg-card/50'
            }`}>
            <t.icon className="w-4 h-4" /> {t.label}
          </button>
        ))}
      </div>

      {/* ── Banking Tab ─────────────────────────────────────────────── */}
      {tab === 'banking' && (
        <div className="space-y-6">
          {/* Model mapping table */}
          <div className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
            <div className="px-5 py-4 border-b border-bg-card">
              <h2 className="text-lg font-semibold text-text-primary flex items-center gap-2">
                <Building2 className="w-5 h-5 text-accent-amber" /> IDS to Banking Model Mapping
              </h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-bg-card text-text-secondary">
                    <th className="text-left px-4 py-3 font-semibold">IDS Model</th>
                    <th className="text-left px-4 py-3 font-semibold">Banking Equivalent</th>
                    <th className="text-left px-4 py-3 font-semibold">Financial Task</th>
                  </tr>
                </thead>
                <tbody>
                  {MODEL_MAP_BANKING.map((row, i) => (
                    <tr key={i} className="border-b border-bg-card/50 hover:bg-bg-card/30 transition-colors">
                      <td className="px-4 py-3 font-mono text-accent-blue">{row.ids}</td>
                      <td className="px-4 py-3 font-semibold text-accent-amber">{row.banking}</td>
                      <td className="px-4 py-3 text-text-secondary">{row.task}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Fraud classes + features */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="bg-bg-secondary rounded-xl border border-bg-card p-5">
              <h3 className="text-sm font-semibold text-text-primary mb-3">15 Fraud Classification Labels</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                {FRAUD_CLASSES.map((cls, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    <span className="w-1.5 h-1.5 rounded-full bg-accent-red shrink-0" />
                    <span className="text-text-secondary">{cls}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl border border-bg-card p-5">
              <h3 className="text-sm font-semibold text-text-primary mb-3">15 Transaction Features</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                {TRANSACTION_FEATURES.map((feat, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    <span className="font-mono text-accent-blue">{feat}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Medical Tab ─────────────────────────────────────────────── */}
      {tab === 'medical' && (
        <div className="space-y-6">
          {/* Model mapping table */}
          <div className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
            <div className="px-5 py-4 border-b border-bg-card">
              <h2 className="text-lg font-semibold text-text-primary flex items-center gap-2">
                <HeartPulse className="w-5 h-5 text-accent-green" /> IDS to Medical Model Mapping
              </h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-bg-card text-text-secondary">
                    <th className="text-left px-4 py-3 font-semibold">IDS Model</th>
                    <th className="text-left px-4 py-3 font-semibold">Medical Equivalent</th>
                    <th className="text-left px-4 py-3 font-semibold">Healthcare Task</th>
                  </tr>
                </thead>
                <tbody>
                  {MODEL_MAP_MEDICAL.map((row, i) => (
                    <tr key={i} className="border-b border-bg-card/50 hover:bg-bg-card/30 transition-colors">
                      <td className="px-4 py-3 font-mono text-accent-blue">{row.ids}</td>
                      <td className="px-4 py-3 font-semibold text-accent-green">{row.medical}</td>
                      <td className="px-4 py-3 text-text-secondary">{row.task}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Compliance table */}
          <div className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
            <div className="px-5 py-4 border-b border-bg-card">
              <h2 className="text-lg font-semibold text-text-primary flex items-center gap-2">
                <Shield className="w-5 h-5 text-accent-purple" /> Regulatory Compliance Mapping
              </h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-bg-card text-text-secondary">
                    <th className="text-left px-4 py-3 font-semibold w-28">Regulation</th>
                    <th className="text-left px-4 py-3 font-semibold w-28">Scope</th>
                    <th className="text-left px-4 py-3 font-semibold">Key Requirements</th>
                    <th className="text-left px-4 py-3 font-semibold">RobustIDPS Coverage</th>
                  </tr>
                </thead>
                <tbody>
                  {COMPLIANCE_TABLE.map((row, i) => (
                    <tr key={i} className="border-b border-bg-card/50 hover:bg-bg-card/30 transition-colors">
                      <td className="px-4 py-3 font-semibold text-accent-purple">{row.reg}</td>
                      <td className="px-4 py-3 text-text-secondary">{row.scope}</td>
                      <td className="px-4 py-3 text-text-secondary">{row.requirement}</td>
                      <td className="px-4 py-3 text-accent-green">{row.robustidps}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── Architecture Tab ────────────────────────────────────────── */}
      {tab === 'architecture' && (
        <div className="space-y-6">
          <div className="bg-bg-secondary rounded-xl border border-bg-card p-6">
            <h2 className="text-lg font-semibold text-text-primary mb-2">3-Step Domain Transfer Process</h2>
            <p className="text-xs text-text-secondary mb-6">Transfer learning from network IDS to any anomaly-detection domain</p>

            {/* Visual flow diagram */}
            <div className="flex flex-col lg:flex-row items-stretch gap-4 mb-8">
              {TRANSFER_STEPS.map((step, i) => (
                <div key={step.step} className="flex-1 flex flex-col">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="w-10 h-10 rounded-xl bg-accent-purple/15 flex items-center justify-center shrink-0">
                      <step.icon className="w-5 h-5 text-accent-purple" />
                    </div>
                    <div>
                      <div className="text-[10px] text-accent-purple font-semibold uppercase tracking-wider">Step {step.step}</div>
                      <div className="text-sm font-semibold text-text-primary">{step.title}</div>
                    </div>
                  </div>
                  <div className="bg-bg-card rounded-xl p-4 flex-1 border border-bg-card">
                    <p className="text-xs text-text-secondary mb-3">{step.desc}</p>
                    <div className="space-y-1.5">
                      {step.details.map((d, j) => (
                        <div key={j} className="flex items-start gap-2 text-xs">
                          <CheckCircle className="w-3.5 h-3.5 text-accent-green shrink-0 mt-0.5" />
                          <span className="text-text-secondary">{d}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  {i < TRANSFER_STEPS.length - 1 && (
                    <div className="hidden lg:flex justify-center py-2">
                      <ArrowRight className="w-5 h-5 text-accent-purple/40 rotate-0 lg:rotate-0" />
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Flow diagram summary */}
            <div className="bg-bg-card rounded-xl p-5 border border-bg-card">
              <h3 className="text-sm font-semibold text-text-primary mb-3">Transfer Architecture Flow</h3>
              <div className="flex flex-wrap items-center justify-center gap-2 text-xs">
                {[
                  { label: 'Network IDS Weights', color: 'bg-accent-blue/15 text-accent-blue border-accent-blue/30' },
                  { label: null, color: '' },
                  { label: 'Domain Feature Adapter', color: 'bg-accent-amber/15 text-accent-amber border-accent-amber/30' },
                  { label: null, color: '' },
                  { label: '7-Branch Ensemble', color: 'bg-accent-purple/15 text-accent-purple border-accent-purple/30' },
                  { label: null, color: '' },
                  { label: 'Domain Classification Head', color: 'bg-accent-green/15 text-accent-green border-accent-green/30' },
                  { label: null, color: '' },
                  { label: 'Industry Dashboard', color: 'bg-accent-red/15 text-accent-red border-accent-red/30' },
                ].map((item, i) =>
                  item.label ? (
                    <span key={i} className={`px-3 py-2 rounded-lg border font-medium ${item.color}`}>{item.label}</span>
                  ) : (
                    <ArrowRight key={i} className="w-4 h-4 text-text-secondary/40" />
                  )
                )}
              </div>
            </div>
          </div>

          {/* Key advantages */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[
              { title: 'Minimal Retraining', desc: 'Lower layers (feature extractors) transfer directly. Only classification heads and normalization layers need retraining.', color: 'text-accent-blue' },
              { title: 'Preserved Robustness', desc: 'Adversarial defences and uncertainty calibration transfer across domains via the shared ensemble architecture.', color: 'text-accent-green' },
              { title: 'Compliance Ready', desc: 'Zero-trust governance, audit trails, and XAI modules work identically regardless of the target domain.', color: 'text-accent-purple' },
            ].map((adv, i) => (
              <div key={i} className="bg-bg-secondary rounded-xl border border-bg-card p-5">
                <h3 className={`text-sm font-semibold ${adv.color} mb-2`}>{adv.title}</h3>
                <p className="text-xs text-text-secondary">{adv.desc}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="text-[10px] text-text-secondary/60 text-center">
        Domain transfer is a proof-of-concept demonstration. Production deployments require domain-specific data and validation.
      </div>
    </div>
  )
}
