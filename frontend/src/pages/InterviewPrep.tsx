import { useState } from 'react'
import {
  ClipboardCheck, ChevronDown, ChevronRight, BookOpen, Code, Brain,
  MessageSquare, Target, Lightbulb, Award, CheckCircle2,
} from 'lucide-react'

// ── Interview topic data ─────────────────────────────────────────────────

type InterviewTopic = {
  category: string
  icon: typeof Brain
  color: string
  questions: {
    question: string
    keyPoints: string[]
    depth: 'fundamental' | 'intermediate' | 'advanced'
    relevance: string
  }[]
}

const TOPICS: InterviewTopic[] = [
  {
    category: 'ML for Network Security',
    icon: Brain,
    color: 'text-accent-blue',
    questions: [
      {
        question: 'How would you design an intrusion detection system that handles concept drift in network traffic?',
        keyPoints: [
          'Continual learning with experience replay (CT-TGNN approach)',
          'Elastic Weight Consolidation to prevent catastrophic forgetting',
          'Drift detection via statistical tests on feature distributions',
          'Online model updating vs periodic retraining trade-offs',
        ],
        depth: 'advanced',
        relevance: 'Directly addresses RobustIDPS.AI\'s Continual Learning module',
      },
      {
        question: 'What are the trade-offs between flow-based and packet-based intrusion detection?',
        keyPoints: [
          'Flow-based: aggregated features (duration, byte counts), lower compute, misses payload attacks',
          'Packet-based: deep packet inspection, higher fidelity, computationally expensive',
          'Hybrid approaches: flow-level detection + packet inspection for flagged flows',
          'Real-world constraint: encrypted traffic makes DPI less effective',
        ],
        depth: 'fundamental',
        relevance: 'Core to understanding the feature extraction pipeline',
      },
      {
        question: 'Explain how uncertainty quantification improves IDS reliability.',
        keyPoints: [
          'MC Dropout: multiple stochastic forward passes yield prediction variance',
          'Epistemic vs aleatoric uncertainty decomposition',
          'High uncertainty → flag for human review instead of auto-blocking',
          'Calibration via temperature scaling (ECE optimisation)',
          'Reduces false positive impact in production SOCs',
        ],
        depth: 'advanced',
        relevance: 'Implemented in RobustIDPS.AI Calibration Layer + Uncertainty Estimator',
      },
      {
        question: 'How do Graph Neural Networks capture lateral movement in enterprise networks?',
        keyPoints: [
          'Model hosts as nodes and flows as edges in a temporal interaction graph',
          'Message-passing aggregates neighbour behaviour to detect anomalous paths',
          'Temporal attention weights recent edges higher to catch fast-spreading campaigns',
          'Heterogeneous graph types: host-to-host, host-to-service, user-to-resource',
          'Scalability via GraphSAGE sampling on billion-edge enterprise telemetry',
          'Provenance graph enrichment from EDR logs (Sysmon, auditd) improves recall',
        ],
        depth: 'advanced',
        relevance: 'CT-TGNN module and provenance-aware detection pipeline',
      },
      {
        question: 'How would you apply foundation models and LLMs to network intrusion detection?',
        keyPoints: [
          'Pre-train on large unlabelled NetFlow corpora with masked-flow modelling objectives',
          'Fine-tune on labelled attack datasets with parameter-efficient methods (LoRA, QLoRA)',
          'LLM-as-judge: use GPT-4/Claude to label ambiguous traffic samples for active learning',
          'Embedding-based zero-shot: encode flow metadata as natural language for cross-domain transfer',
          'Retrieval-Augmented Generation for SOC alert triage and contextual explanation',
          'Cost-performance trade-off: distil large models into lightweight student networks for edge',
        ],
        depth: 'advanced',
        relevance: 'FedLLM-API integration and LLM-based ensemble member',
      },
      {
        question: 'What is the role of self-supervised learning in building IDS with limited labels?',
        keyPoints: [
          'Contrastive learning (SimCLR-style) on augmented flow representations',
          'Flow augmentations: jittering timing features, masking optional fields, sub-flow sampling',
          'Pre-text tasks: predict next flow in session, reconstruct masked features',
          'Reduces labelling cost — often <5% labelled data matches fully-supervised performance',
          'Transfer from simulation (GAN-generated traffic) to real-world deployment',
        ],
        depth: 'intermediate',
        relevance: 'Data-efficient training strategies in the continual learning pipeline',
      },
      {
        question: 'Explain how state-space models (Mamba/S4) compare to transformers for sequence-based IDS.',
        keyPoints: [
          'SSMs achieve linear-time sequence processing vs quadratic attention in transformers',
          'Selective state spaces (Mamba) dynamically filter irrelevant flow tokens',
          'Critical for long session modelling: thousands of flows per connection',
          'Hardware-efficient: leverages parallel scan on GPU for real-time inference',
          'Hybrid SSM-attention architectures balance global context with local precision',
          'Benchmark: 2-4x throughput gains on CIC-IoT-2023 with comparable macro-F1',
        ],
        depth: 'advanced',
        relevance: 'State-space ensemble member in SurrogateIDS architecture',
      },
      {
        question: 'How do you detect encrypted malicious traffic without decryption?',
        keyPoints: [
          'TLS/JA3/JA4 fingerprinting: hash of cipher suites, extensions, and curves',
          'Encrypted traffic classification via packet-size distributions and inter-arrival times',
          'Certificate transparency log analysis for C2 infrastructure detection',
          'ESNI/ECH challenges: domain info no longer visible in ClientHello',
          'ML on metadata: flow duration, byte ratios, TLS record sizes, session resumption patterns',
          'Industry standard: Cisco ETA, Palo Alto App-ID use similar feature sets',
        ],
        depth: 'intermediate',
        relevance: 'Feature extraction pipeline for encrypted traffic analysis',
      },
    ],
  },
  {
    category: 'Adversarial Robustness',
    icon: Target,
    color: 'text-accent-red',
    questions: [
      {
        question: 'How do adversarial attacks differ in the network traffic domain vs computer vision?',
        keyPoints: [
          'Feature constraints: network features have physical semantics (can\'t have negative packet counts)',
          'Realizability: perturbations must map to real network behaviour',
          'Feature interdependencies: changing flow duration affects rate-based features',
          'Attack surface: adversary controls traffic generation, not the feature extractor',
        ],
        depth: 'intermediate',
        relevance: 'Key to adversarial evaluation methodology',
      },
      {
        question: 'Describe a Stackelberg game-theoretic approach to IDS robustness.',
        keyPoints: [
          'Defender (leader) commits to detection strategy first',
          'Attacker (follower) observes and best-responds',
          'Minimax optimisation over adversarial perturbation budgets',
          'Robust certificates via certified radius bounds',
          'Practical application: optimal threshold selection under attack',
        ],
        depth: 'advanced',
        relevance: 'Implemented in Game-Theoretic Defence module',
      },
      {
        question: 'How do you generate realizable adversarial examples for network traffic?',
        keyPoints: [
          'Constraint-aware PGD: project gradients onto feasible feature space after each step',
          'Traffic mutation operators: packet padding, timing delays, dummy flow injection',
          'GAN-based traffic generation: train generator to produce evasive but functional flows',
          'Semantic constraints: preserve application-layer functionality (HTTP validity, DNS resolution)',
          'Inverse feature mapping: translate feature-space perturbations back to raw packets',
          'Evaluation: replay generated pcaps in testbed to confirm attack success end-to-end',
        ],
        depth: 'advanced',
        relevance: 'Adversarial evaluation framework and constraint-aware attack generation',
      },
      {
        question: 'What certified defence methods apply to ML-based intrusion detection?',
        keyPoints: [
          'Randomised smoothing: provable L2 robustness radius for flow classifiers',
          'Interval bound propagation (IBP) for network-feature constrained inputs',
          'Certified radius vs empirical robustness: when formal guarantees matter',
          'Scalability challenges: certification cost grows with input dimension and model depth',
          'Hybrid approach: certify critical attack classes, use empirical defences for the rest',
          'Industry adoption gap: most SOC tools lack certified robustness benchmarks',
        ],
        depth: 'advanced',
        relevance: 'Certified robustness module in game-theoretic defence pipeline',
      },
      {
        question: 'How would you defend an IDS against model extraction and membership inference attacks?',
        keyPoints: [
          'Model extraction: attacker queries IDS API to train a surrogate and craft transferable attacks',
          'Defence: output confidence discretisation — return class label only, not probabilities',
          'Query rate limiting and anomaly detection on API usage patterns',
          'Differential privacy in training: DP-SGD bounds membership inference leakage',
          'Watermarking model predictions to detect stolen copies downstream',
          'Trade-off: privacy-preserving outputs reduce utility for legitimate SOC analysts',
        ],
        depth: 'advanced',
        relevance: 'Privacy-preserving deployment and API security design',
      },
      {
        question: 'Explain adversarial training strategies tailored for imbalanced IDS datasets.',
        keyPoints: [
          'Standard AT overwrites rare-class decision boundaries — need class-aware perturbation budgets',
          'TRADES loss adapted with per-class weights to balance robustness across attack types',
          'Curriculum AT: start with clean samples, gradually increase perturbation on minority classes',
          'Synthetic oversampling (SMOTE) in adversarial feature space for rare attacks',
          'Evaluation: report robust accuracy per attack category, not just aggregate',
          'Industry relevance: zero-day attacks are inherently rare and need robust detection',
        ],
        depth: 'advanced',
        relevance: 'Adversarial training pipeline with class-balanced robust optimisation',
      },
      {
        question: 'What is the role of evasion-aware feature engineering in hardening IDS models?',
        keyPoints: [
          'Identify features attackers can vs cannot manipulate (threat model scoping)',
          'Immutable features: TCP handshake flags, IP TTL artefacts, TLS version negotiation',
          'Mutable features: inter-packet timing, payload size padding, optional header fields',
          'Feature resilience scoring: rank features by cost-of-manipulation for the attacker',
          'Robust feature selection: prefer low-mutability features for decision boundaries',
          'Adaptive defence: dynamically weight features based on detected attack campaign type',
        ],
        depth: 'intermediate',
        relevance: 'Feature extraction hardening in the preprocessing pipeline',
      },
    ],
  },
  {
    category: 'System Design & Architecture',
    icon: Code,
    color: 'text-accent-green',
    questions: [
      {
        question: 'How would you scale an ML-based IDS to process 2TB of traffic per day?',
        keyPoints: [
          'Streaming architecture: Kafka → GPU inference workers → results DB',
          'Batch inference with dynamic batching (1024–4096 flows)',
          'Mixed-precision (FP16) inference on A100/RTX 4090',
          'Horizontal scaling: Kubernetes GPU node pools',
          'Data pipeline: chunked Polars/Dask instead of in-memory pandas',
          'TimescaleDB for time-series storage, ClickHouse for analytics',
        ],
        depth: 'advanced',
        relevance: 'Directly maps to SCALING_AND_DESKTOP_ANALYSIS.md roadmap',
      },
      {
        question: 'Explain the benefits of a 7-method ensemble for intrusion detection.',
        keyPoints: [
          'Diversity: GNN, RNN, transformer, state-space, LLM approaches capture different patterns',
          'Attention fusion: learned combination weights per flow',
          'Uncertainty from ensemble disagreement',
          'Graceful degradation: system works with subset of methods',
          'Trade-off: latency vs accuracy — prunable at deployment time',
        ],
        depth: 'intermediate',
        relevance: 'Core SurrogateIDS architecture',
      },
      {
        question: 'How do you design an MLOps pipeline for continuous IDS model deployment?',
        keyPoints: [
          'CI/CD for ML: automated retraining triggered by drift detection alerts',
          'Model registry (MLflow/Weights & Biases) with versioning and lineage tracking',
          'Shadow deployment: new model runs in parallel, compare metrics before promotion',
          'Canary rollout: route 5% of traffic to new model, monitor FPR/latency deltas',
          'Feature store (Feast/Tecton) ensures training-serving feature consistency',
          'Automated rollback: if macro-F1 drops >2% or p99 latency exceeds SLA, revert',
          'Compliance: model cards and audit logs for SOC 2 / ISO 27001 requirements',
        ],
        depth: 'advanced',
        relevance: 'Production deployment pipeline and model lifecycle management',
      },
      {
        question: 'Design a real-time threat intelligence integration layer for ML-based IDS.',
        keyPoints: [
          'STIX/TAXII feeds ingested into streaming enrichment pipeline',
          'IoC matching (IP, domain, hash) as pre-filter before ML inference',
          'MITRE ATT&CK mapping: label predicted attacks with technique IDs (T1071, T1048)',
          'Threat intel confidence scores as additional features to the ML model',
          'Feedback loop: ML detections generate new IoCs pushed back to TI platform',
          'Latency budget: enrichment must complete within 10ms to maintain line-rate',
        ],
        depth: 'advanced',
        relevance: 'Integration with SOC toolchain and MITRE ATT&CK taxonomy',
      },
      {
        question: 'How would you deploy IDS inference at the network edge with constrained hardware?',
        keyPoints: [
          'Model compression: knowledge distillation from ensemble to single compact model',
          'Quantisation: INT8/INT4 via TensorRT or ONNX Runtime on Jetson/Intel NUC',
          'Pruning: structured channel pruning to reduce FLOPs by 60-80% with <1% F1 loss',
          'Split inference: lightweight pre-filter at edge, full model in cloud for flagged flows',
          'FPGA/SmartNIC offload: P4-programmable switches for wire-speed feature extraction',
          'Energy/thermal constraints: dynamic model selection based on device temperature',
          'Target: <5ms p99 latency for 10Gbps link on NVIDIA Orin or Intel Tofino',
        ],
        depth: 'advanced',
        relevance: 'Edge deployment strategy and model compression pipeline',
      },
      {
        question: 'Explain how federated learning applies to multi-organisation IDS deployment.',
        keyPoints: [
          'Horizontal FL: each organisation trains on local traffic, shares gradients not data',
          'Privacy guarantees: secure aggregation + differential privacy (DP-FedAvg)',
          'Non-IID challenge: each org sees different traffic distributions and attack profiles',
          'Personalised FL: local fine-tuning layers on top of shared global backbone',
          'Communication efficiency: gradient compression, federated distillation',
          'Trust model: Byzantine-robust aggregation to handle compromised participants',
          'Industry use case: ISAC (Information Sharing and Analysis Centre) collaboration',
        ],
        depth: 'advanced',
        relevance: 'FedLLM-API federated learning architecture',
      },
      {
        question: 'How do you architect an IDS observability and monitoring stack?',
        keyPoints: [
          'Model metrics: real-time macro-F1, per-class precision/recall, confidence distribution',
          'System metrics: inference latency (p50/p95/p99), GPU utilisation, queue depth',
          'Data quality monitoring: feature distribution shifts, missing value rates, schema violations',
          'Alerting: PagerDuty integration for model degradation and infrastructure failures',
          'Dashboarding: Grafana with Prometheus for system, custom panels for ML health',
          'Log aggregation: structured JSON logs → ELK stack for incident forensics',
        ],
        depth: 'intermediate',
        relevance: 'Production monitoring and SRE integration for deployed models',
      },
    ],
  },
  {
    category: 'Research Methodology',
    icon: BookOpen,
    color: 'text-accent-amber',
    questions: [
      {
        question: 'What evaluation metrics matter most for IDS research, and why?',
        keyPoints: [
          'Macro F1: class-balanced performance across 34 attack categories',
          'False Positive Rate: critical for SOC analyst workload',
          'Detection latency: time from first malicious flow to alert',
          'Per-class recall: identify which attack types are missed',
          'ECE (Expected Calibration Error): reliability of confidence scores',
          'Robustness under adversarial perturbation budgets',
        ],
        depth: 'fundamental',
        relevance: 'Evaluation framework used across all RobustIDPS.AI experiments',
      },
      {
        question: 'How do you ensure cross-dataset generalisability in IDS research?',
        keyPoints: [
          'Train on CIC-IoT-2023, test on UNSW-NB15 and vice versa',
          'Feature alignment across datasets with different schemas',
          'Domain adaptation techniques for distribution shift',
          'Zero-shot classification via LLM embeddings (FedLLM-API)',
          'Report per-dataset performance separately, not just aggregate',
        ],
        depth: 'advanced',
        relevance: 'Multi-dataset support in RobustIDPS.AI loader system',
      },
      {
        question: 'How do you design reproducible ML experiments for IDS research publications?',
        keyPoints: [
          'Seed management: fix random seeds for PyTorch, NumPy, CUDA, and data shuffling',
          'Containerised environments: Docker/Singularity with pinned dependency versions',
          'Experiment tracking: W&B/MLflow with hyperparameter, metric, and artefact logging',
          'Dataset versioning: DVC or Git LFS with SHA-256 checksums for exact reproduction',
          'Statistical rigour: report mean ± std over 5+ runs with different seeds',
          'Ablation protocol: systematic one-component-out analysis with controlled baselines',
          'Open science: release code, configs, and pre-trained weights with the paper',
        ],
        depth: 'fundamental',
        relevance: 'Reproducibility framework across all RobustIDPS.AI experiments',
      },
      {
        question: 'What are the key pitfalls in benchmarking IDS models on public datasets?',
        keyPoints: [
          'Data leakage: temporal overlap between train/test splits violates real deployment order',
          'Label noise: CIC datasets have known mislabelling issues (up to 5% error rate)',
          'Feature leakage: including ground-truth-correlated features (e.g., attack tool signatures)',
          'Class imbalance artefacts: high accuracy driven by dominant benign class',
          'Synthetic traffic bias: generated datasets lack real-world network complexity',
          'Overfitting to dataset-specific artefacts rather than learning attack semantics',
          'Mitigation: time-ordered splits, label audit, hold-out on unseen attack variants',
        ],
        depth: 'intermediate',
        relevance: 'Dataset preprocessing and evaluation integrity protocols',
      },
      {
        question: 'How would you structure an ablation study for a multi-component IDS?',
        keyPoints: [
          'Component isolation: test each ensemble member, fusion layer, and defence module independently',
          'Factorial design: evaluate all meaningful component combinations systematically',
          'Computational budget: use Bayesian hyperparameter search to reduce ablation runs',
          'Reporting: heatmap of component contributions to macro-F1 and robustness metrics',
          'Negative results: document what didn\'t work — essential for research community',
          'Statistical testing: paired t-test or Wilcoxon signed-rank for component significance',
        ],
        depth: 'intermediate',
        relevance: 'Ablation methodology for RobustIDPS.AI publication-ready experiments',
      },
      {
        question: 'How do you handle responsible disclosure and ethical considerations in IDS adversarial research?',
        keyPoints: [
          'Dual-use risk: adversarial evasion techniques can be weaponised by attackers',
          'Responsible disclosure timeline: share findings with vendors before public release',
          'Ethical review: IRB/ethics board approval for experiments involving real network data',
          'Data anonymisation: strip PII from pcap captures, mask internal IP addresses',
          'Coordinated vulnerability disclosure (CVD) with CERT/CC for discovered weaknesses',
          'Publication guidelines: withhold attack code until defences are deployed; reference USENIX/IEEE policies',
        ],
        depth: 'fundamental',
        relevance: 'Ethics framework for adversarial robustness research and publications',
      },
      {
        question: 'Compare Bayesian optimisation vs multi-fidelity methods for IDS hyperparameter tuning.',
        keyPoints: [
          'Bayesian optimisation (BO): Gaussian process surrogate models the objective surface',
          'Acquisition functions: EI, UCB, and knowledge-gradient for explore-exploit trade-off',
          'Multi-fidelity (Hyperband/BOHB): early-stop poor configs using successive halving',
          'Cost-aware: BOHB combines BO with Hyperband for sample-efficient search on GPU clusters',
          'IDS-specific: tune detection threshold jointly with model hyperparameters for FPR targets',
          'Distributed HPO: Optuna with Kubernetes jobs for parallel trial evaluation',
          'Warm-starting: transfer search history from related datasets to accelerate tuning',
        ],
        depth: 'advanced',
        relevance: 'Hyperparameter optimisation in the training pipeline',
      },
    ],
  },
]

const DEPTH_STYLES: Record<string, { bg: string; text: string }> = {
  fundamental:  { bg: 'bg-accent-green/15', text: 'text-accent-green' },
  intermediate: { bg: 'bg-accent-amber/15', text: 'text-accent-amber' },
  advanced:     { bg: 'bg-accent-red/15',   text: 'text-accent-red' },
}

// ── Component ────────────────────────────────────────────────────────────

export default function InterviewPrep() {
  const [expandedCategory, setExpandedCategory] = useState<string | null>(TOPICS[0].category)
  const [expandedQuestion, setExpandedQuestion] = useState<string | null>(null)
  const [checkedQuestions, setCheckedQuestions] = useState<Set<string>>(new Set())

  const toggleChecked = (q: string) => {
    setCheckedQuestions(prev => {
      const next = new Set(prev)
      next.has(q) ? next.delete(q) : next.add(q)
      return next
    })
  }

  const totalQuestions = TOPICS.reduce((sum, t) => sum + t.questions.length, 0)
  const completedCount = checkedQuestions.size

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-display font-bold text-text-primary flex items-center gap-2">
          <ClipboardCheck className="w-6 h-6 text-accent-blue" />
          Interview Prep
        </h1>
        <p className="text-sm text-text-secondary mt-1">
          Structured interview questions for postdoc positions and industry research roles in AI-driven cybersecurity.
        </p>
      </div>

      {/* Progress */}
      <div className="bg-bg-card border border-bg-card rounded-lg p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-text-secondary font-medium">Preparation Progress</span>
          <span className="text-xs text-text-primary font-medium">{completedCount}/{totalQuestions} reviewed</span>
        </div>
        <div className="h-2 bg-bg-primary rounded-full overflow-hidden">
          <div
            className="h-full bg-accent-blue rounded-full transition-all duration-500"
            style={{ width: `${totalQuestions > 0 ? (completedCount / totalQuestions) * 100 : 0}%` }}
          />
        </div>
      </div>

      {/* Topic sections */}
      {TOPICS.map(topic => {
        const isExpanded = expandedCategory === topic.category
        const Icon = topic.icon
        const categoryDone = topic.questions.every(q => checkedQuestions.has(q.question))
        return (
          <div key={topic.category} className="bg-bg-card border border-bg-card rounded-lg overflow-hidden">
            <button
              onClick={() => setExpandedCategory(isExpanded ? null : topic.category)}
              className="w-full flex items-center gap-3 px-4 py-3 hover:bg-bg-primary/30 transition-colors"
            >
              {isExpanded
                ? <ChevronDown className="w-4 h-4 text-text-secondary shrink-0" />
                : <ChevronRight className="w-4 h-4 text-text-secondary shrink-0" />}
              <Icon className={`w-5 h-5 ${topic.color} shrink-0`} />
              <span className="text-sm text-text-primary font-semibold flex-1 text-left">{topic.category}</span>
              <span className="text-xs text-text-secondary">{topic.questions.length} questions</span>
              {categoryDone && <CheckCircle2 className="w-4 h-4 text-accent-green" />}
            </button>

            {isExpanded && (
              <div className="border-t border-bg-primary">
                {topic.questions.map(q => {
                  const isQExpanded = expandedQuestion === q.question
                  const isChecked = checkedQuestions.has(q.question)
                  const depthStyle = DEPTH_STYLES[q.depth]
                  return (
                    <div key={q.question} className="border-b border-bg-primary/50 last:border-b-0">
                      <div className="flex items-start gap-3 px-4 py-3">
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={() => toggleChecked(q.question)}
                          className="w-3.5 h-3.5 rounded border-text-secondary/30 bg-bg-primary accent-[#3b82f6] cursor-pointer mt-0.5 shrink-0"
                        />
                        <div
                          className="flex-1 min-w-0 cursor-pointer"
                          onClick={() => setExpandedQuestion(isQExpanded ? null : q.question)}
                        >
                          <div className="flex items-center gap-2 flex-wrap">
                            <MessageSquare className="w-3.5 h-3.5 text-text-secondary/50 shrink-0" />
                            <span className={`text-sm font-medium ${isChecked ? 'text-text-secondary line-through' : 'text-text-primary'}`}>
                              {q.question}
                            </span>
                            <span className={`text-[10px] font-medium uppercase px-1.5 py-0.5 rounded ${depthStyle.bg} ${depthStyle.text}`}>
                              {q.depth}
                            </span>
                          </div>
                        </div>
                        {isQExpanded
                          ? <ChevronDown className="w-3.5 h-3.5 text-text-secondary shrink-0 mt-0.5" />
                          : <ChevronRight className="w-3.5 h-3.5 text-text-secondary shrink-0 mt-0.5" />}
                      </div>

                      {isQExpanded && (
                        <div className="px-4 pb-3 pl-10 space-y-2">
                          <div className="space-y-1">
                            <span className="text-xs text-text-secondary font-medium flex items-center gap-1">
                              <Lightbulb className="w-3 h-3 text-accent-amber" /> Key Points:
                            </span>
                            <ul className="space-y-1">
                              {q.keyPoints.map(kp => (
                                <li key={kp} className="text-xs text-text-primary flex items-start gap-2">
                                  <span className="text-accent-blue mt-1">•</span>
                                  {kp}
                                </li>
                              ))}
                            </ul>
                          </div>
                          <div className="flex items-center gap-1 text-[10px] text-text-secondary/60">
                            <Award className="w-3 h-3" />
                            Relevance: {q.relevance}
                          </div>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
