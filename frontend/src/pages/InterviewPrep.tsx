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
