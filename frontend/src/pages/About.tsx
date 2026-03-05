import MethodCard from '../components/MethodCard'

const METHODS = [
  {
    name: 'CT-TGNN (Neural ODE)',
    description:
      'Continuous-time temporal graph neural network using Neural ODEs for modelling non-stationary attack dynamics.',
    formalism: 'dx/dt = f_theta(x, t); solved via adjoint sensitivity',
    gap: 'Existing IDS treat time as discrete snapshots, missing continuous attack evolution.',
  },
  {
    name: 'TripleE-TGNN (Multi-scale)',
    description:
      'Multi-granularity temporal graph network capturing attack patterns at packet, flow, and session levels.',
    formalism: 'H_l = AGG(h_packet, h_flow, h_session)',
    gap: 'Single-granularity models miss cross-level correlations in attack campaigns.',
  },
  {
    name: 'FedLLM-API (Zero-shot)',
    description:
      'Federated zero-shot detection leveraging LLM embeddings for novel attack recognition without labelled data.',
    formalism: 'p(y|x) = softmax(sim(LLM(x), LLM(y_desc)))',
    gap: 'Zero-day attacks have no training labels; LLM semantic understanding bridges this gap.',
  },
  {
    name: 'PQ-IDPS (Post-quantum)',
    description:
      'Post-quantum cryptographic framework for securing IDS communications against quantum adversaries.',
    formalism: 'CRYSTALS-Kyber KEM + lattice-based signatures',
    gap: 'Current IDS rely on RSA/ECDH vulnerable to Shor\'s algorithm on quantum computers.',
  },
  {
    name: 'MambaShield (State-space)',
    description:
      'Selective state-space model for linear-time sequence processing of high-throughput network traffic.',
    formalism: 'x_k = A x_{k-1} + B u_k; y_k = C x_k (selective scan)',
    gap: 'Transformers have O(n^2) complexity, impractical for real-time 10Gbps traffic.',
  },
  {
    name: 'Stochastic Transformer',
    description:
      'Bayesian transformer with MC Dropout for calibrated uncertainty quantification on every prediction.',
    formalism: 'Var[y] = E[Var[y|w]] + Var[E[y|w]] (aleatoric + epistemic)',
    gap: 'Standard IDS give point predictions with no confidence measure for SOC analysts.',
  },
  {
    name: 'Game-Theoretic Defence',
    description:
      'Stackelberg game formulation where the defender leads and the attacker best-responds, yielding robustness certificates.',
    formalism: 'max_d min_a U_d(d, BR_a(d)) s.t. Lipschitz(f) <= K',
    gap: 'Adversarial ML attacks can evade IDS; game theory provides provable robustness bounds.',
  },
]

export default function About() {
  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-2xl font-display font-bold">About RobustIDPS.ai</h1>
        <p className="text-sm text-text-secondary mt-2 max-w-3xl">
          This web application demonstrates 7 novel machine learning methods for adversarially
          robust network intrusion detection, developed as part of a PhD dissertation at MEPhI.
          Each method addresses a specific gap in existing intrusion detection systems.
        </p>
      </div>

      <div>
        <h2 className="text-lg font-display font-semibold mb-4">The 7 Dissertation Methods</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {METHODS.map((m, i) => (
            <MethodCard
              key={i}
              index={i}
              name={m.name}
              description={m.description}
              formalism={m.formalism}
              gap={m.gap}
            />
          ))}
        </div>
      </div>

      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold mb-3">Architecture</h2>
        <div className="font-mono text-xs text-text-secondary space-y-1 leading-relaxed">
          <p>Input: CIC-IoT-2023 / CICIDS2018 / UNSW-NB15 / PCAP (83 flow features)</p>
          <p>&nbsp;&nbsp;&darr;</p>
          <p>Feature Extraction &amp; StandardScaler normalisation</p>
          <p>&nbsp;&nbsp;&darr;</p>
          <p>SurrogateIDS (7-branch MLP simulating unified ensemble)</p>
          <p>&nbsp;&nbsp;|-- Branch 0: CT-TGNN (Neural ODE)</p>
          <p>&nbsp;&nbsp;|-- Branch 1: TripleE-TGNN (Multi-scale)</p>
          <p>&nbsp;&nbsp;|-- Branch 2: FedLLM-API (Zero-shot)</p>
          <p>&nbsp;&nbsp;|-- Branch 3: PQ-IDPS (Post-quantum)</p>
          <p>&nbsp;&nbsp;|-- Branch 4: MambaShield (State-space)</p>
          <p>&nbsp;&nbsp;|-- Branch 5: Stochastic Transformer</p>
          <p>&nbsp;&nbsp;|-- Branch 6: Game-Theoretic Defence</p>
          <p>&nbsp;&nbsp;&darr;</p>
          <p>Fusion Layer &rarr; 34-class classification</p>
          <p>&nbsp;&nbsp;&darr;</p>
          <p>MC Dropout (20 passes) &rarr; Epistemic + Aleatoric uncertainty</p>
          <p>&nbsp;&nbsp;&darr;</p>
          <p>Ablation: disable any branch &rarr; measure accuracy drop</p>
        </div>
      </div>

      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold mb-3">Dissertation &rarr; Web App Mapping</h2>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-text-secondary text-xs">
              <th className="px-3 py-2 text-left">#</th>
              <th className="px-3 py-2 text-left">Method</th>
              <th className="px-3 py-2 text-left">Model Class</th>
              <th className="px-3 py-2 text-left">Web App Feature</th>
            </tr>
          </thead>
          <tbody>
            {[
              ['M1', 'CT-TGNN', 'TemporalAdaptiveNeuralODE', 'Branch 0; ablation toggle'],
              ['M2', 'TripleE-TGNN', '(fused in surrogate)', 'Branch 1; multi-granularity'],
              ['M3', 'FedLLM-API', 'LLMZeroShotDetector', 'Branch 2; zero-shot labels'],
              ['M4', 'PQ-IDPS', '(surrogate branch)', 'Branch 3; crypto badge'],
              ['M5', 'MambaShield', '(surrogate branch)', 'Branch 4; streaming'],
              ['M6', 'Stochastic TF', 'BayesianUncertaintyNet', 'Branch 5; MC Dropout'],
              ['M7', 'Game-Theoretic', '(surrogate branch)', 'Branch 6; robustness'],
            ].map(([id, method, cls, feature]) => (
              <tr key={id} className="border-t border-bg-card/50">
                <td className="px-3 py-2 font-mono text-accent-blue">{id}</td>
                <td className="px-3 py-2">{method}</td>
                <td className="px-3 py-2 font-mono text-xs text-text-secondary">{cls}</td>
                <td className="px-3 py-2 text-xs text-text-secondary">{feature}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold mb-3">Alternative Standalone Models</h2>
        <p className="text-sm text-text-secondary mb-3">
          In addition to the 7-branch SurrogateIDS, the following research models are available as
          standalone alternatives via the Models page.
        </p>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-text-secondary text-xs">
              <th className="px-3 py-2 text-left">Model</th>
              <th className="px-3 py-2 text-left">Paper</th>
              <th className="px-3 py-2 text-left">Approach</th>
            </tr>
          </thead>
          <tbody>
            {[
              ['Neural ODE (TA-BN-ODE)', 'Temporal Adaptive Neural ODEs', 'Continuous-time ODE + Hawkes point process'],
              ['Optimal Transport (PPFOT-IDS)', 'DP Optimal Transport for Multi-Cloud IDS', 'Wasserstein domain adaptation + DP'],
              ['FedGTD', 'Federated Graph Temporal Dynamics', 'Byzantine-resilient federated graph learning'],
              ['SDE-TGNN', 'SDE Temporal Graph Neural Networks', 'Stochastic DE + temporal graph attention'],
              ['CyberSecLLM', 'Cybersecurity Foundation Model (IEEE TNNLS)', 'Mamba SSM + cross-attention KB + MoE'],
            ].map(([name, paper, approach]) => (
              <tr key={name} className="border-t border-bg-card/50">
                <td className="px-3 py-2 font-medium text-accent-purple">{name}</td>
                <td className="px-3 py-2 text-xs text-text-secondary">{paper}</td>
                <td className="px-3 py-2 text-xs text-text-secondary">{approach}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* ── Dissertation & Author Info ──────────────────────────────────── */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-semibold mb-4">Dissertation Information</h2>
        <div className="space-y-3">
          <div>
            <p className="text-sm font-medium text-text-primary">
              Adversarially Robust AI-based Hybrid Intrusion Detection and Prevention Systems
            </p>
            <p className="text-xs text-text-secondary mt-1">PhD Dissertation Application</p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-bg-card">
            <div>
              <p className="text-xs text-text-secondary uppercase tracking-wider mb-1">Author</p>
              <p className="text-sm font-medium text-text-primary">Roger Nick Anaedevha</p>
              <p className="text-xs text-text-secondary">ICIS, MEPhI, Moscow</p>
            </div>
            <div>
              <p className="text-xs text-text-secondary uppercase tracking-wider mb-1">Supervisor</p>
              <p className="text-sm font-medium text-text-primary">Alexander Gennadievich Trofimov</p>
              <p className="text-xs text-text-secondary">ICIS, MEPhI, Moscow</p>
            </div>
          </div>
          <div className="pt-2 border-t border-bg-card">
            <p className="text-xs text-text-secondary">
              National Research Nuclear University MEPhI (Moscow Engineering Physics Institute)
              &mdash; Institute of Cyber Intelligence Systems (ICIS)
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
