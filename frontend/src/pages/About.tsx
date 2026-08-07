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
          AI/ML-powered intrusion detection &amp; prevention with 12+ neural network models, LLM security testing, continual learning, and autonomous response.
          Developed as part of a PhD dissertation at MEPhI — each method addresses a specific gap in existing intrusion detection systems.
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
              ['CL-RL Unified', 'Continual Learning + Reinforcement Learning', 'FIM regularisation + PPO-based adaptive response'],
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

      {/* Who Is This For? */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h2 className="text-lg font-display font-bold text-text-primary mb-4">Who Is This For?</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          <div className="bg-bg-primary rounded-lg p-4 border border-bg-card">
            <div className="text-2xl mb-2">🛡️</div>
            <h3 className="text-sm font-semibold text-accent-blue mb-1">SOC Analysts & Security Engineers</h3>
            <p className="text-xs text-text-secondary">Upload your network traffic, get AI-powered threat detection with uncertainty scores. Auto-generate Suricata/Snort rules and incident reports. The SOC Copilot answers questions about your data in plain English.</p>
          </div>
          <div className="bg-bg-primary rounded-lg p-4 border border-bg-card">
            <div className="text-2xl mb-2">🎓</div>
            <h3 className="text-sm font-semibold text-accent-purple mb-1">Researchers & PhD Students</h3>
            <p className="text-xs text-text-secondary">Benchmark your models against 13+ neural networks on 6 datasets. Interactive ablation studies, adversarial robustness testing, and publication-ready LaTeX exports. All models are open-source with Zenodo DOI.</p>
          </div>
          <div className="bg-bg-primary rounded-lg p-4 border border-bg-card">
            <div className="text-2xl mb-2">🏢</div>
            <h3 className="text-sm font-semibold text-accent-orange mb-1">Enterprise Security Teams</h3>
            <p className="text-xs text-text-secondary">MITRE ATT&CK mapping, OWASP LLM Top 10 compliance, NIST AI RMF dashboard, and CVE vulnerability tracking. Multi-user with admin controls, audit logging, and role-based access.</p>
          </div>
          <div className="bg-bg-primary rounded-lg p-4 border border-bg-card">
            <div className="text-2xl mb-2">🔐</div>
            <h3 className="text-sm font-semibold text-accent-green mb-1">LLM Security Practitioners</h3>
            <p className="text-xs text-text-secondary">Test prompt injection, jailbreak, RAG poisoning, and multi-agent chain attacks against real LLM providers (Claude, GPT-4o, Gemini, DeepSeek). Measure defense effectiveness with quantified metrics.</p>
          </div>
          <div className="bg-bg-primary rounded-lg p-4 border border-bg-card">
            <div className="text-2xl mb-2">🔬</div>
            <h3 className="text-sm font-semibold text-accent-red mb-1">Penetration Testers</h3>
            <p className="text-xs text-text-secondary">Red Team Arena with 6 adversarial attack methods, attack chain prediction, and auto-generated remediation recommendations. Test how models degrade under FGSM, PGD, C&W, and DeepFool attacks.</p>
          </div>
          <div className="bg-bg-primary rounded-lg p-4 border border-bg-card">
            <div className="text-2xl mb-2">📊</div>
            <h3 className="text-sm font-semibold text-accent-amber mb-1">Anyone with Network Data</h3>
            <p className="text-xs text-text-secondary">Upload any CSV or PCAP file and get instant threat analysis. No ML expertise needed — the platform explains results in plain language through the SOC Copilot. Try the demo with sample data to see it in action.</p>
          </div>
        </div>
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
              <a href="mailto:roger@robustidps.ai" className="text-xs text-accent-blue hover:underline">roger@robustidps.ai</a>
            </div>
            <div>
              <p className="text-xs text-text-secondary uppercase tracking-wider mb-1">Supervisor</p>
              <p className="text-sm font-medium text-text-primary">Alexander Gennadievich Trofimov</p>
              <p className="text-xs text-text-secondary">ICIS, MEPhI, Moscow</p>
              <a href="mailto:agtrofimov@robustidps.ai" className="text-xs text-accent-blue hover:underline">agtrofimov@robustidps.ai</a>
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

      {/* Citation & DOI */}
      <div className="bg-accent-blue/5 border border-accent-blue/20 rounded-xl p-5 mt-8">
        <h2 className="text-lg font-display font-bold text-text-primary mb-3">Cite This Work</h2>
        <div className="bg-bg-primary rounded-lg p-4 font-mono text-xs text-text-primary/90 leading-relaxed mb-3">
          Anaedevha, R. N. and Trofimov A. G. (2026). RobustIDPS.ai: Advanced AI-powered intrusion detection &amp; prevention system (Version 1.1.0) [Computer software]. Zenodo. <a href="https://doi.org/10.5281/zenodo.19129512" target="_blank" rel="noopener noreferrer" className="text-accent-blue hover:underline">https://doi.org/10.5281/zenodo.19129512</a>
        </div>
        <div className="flex flex-wrap gap-3">
          <button
            onClick={() => navigator.clipboard.writeText('Anaedevha, R. N. and Trofimov A. G. (2026). RobustIDPS.ai: Advanced AI-powered intrusion detection & prevention system (Version 1.1.0) [Computer software]. Zenodo. https://doi.org/10.5281/zenodo.19129512')}
            className="text-xs text-accent-blue hover:text-accent-blue/80 flex items-center gap-1.5 px-3 py-1.5 bg-accent-blue/10 rounded-lg"
          >
            Copy APA Citation
          </button>
          <button
            onClick={() => navigator.clipboard.writeText('@software{anaedevha2026robustidps,\n  author = {Anaedevha, Roger Nick and Trofimov, Alexander G.},\n  title = {RobustIDPS.ai: Advanced AI-powered intrusion detection \\& prevention system},\n  year = {2026},\n  version = {1.1.0},\n  publisher = {Zenodo},\n  doi = {10.5281/zenodo.19129512},\n  url = {https://doi.org/10.5281/zenodo.19129512}\n}')}
            className="text-xs text-accent-blue hover:text-accent-blue/80 flex items-center gap-1.5 px-3 py-1.5 bg-accent-blue/10 rounded-lg"
          >
            Copy BibTeX
          </button>
          <a
            href="https://doi.org/10.5281/zenodo.19129512"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-accent-green hover:text-accent-green/80 flex items-center gap-1.5 px-3 py-1.5 bg-accent-green/10 rounded-lg"
          >
            View on Zenodo
          </a>
        </div>
        <p className="text-[10px] text-text-secondary mt-3">
          Roger Nick Anaedevha — <a href="mailto:roger@robustidps.ai" className="text-accent-blue hover:underline">roger@robustidps.ai</a><br/>
          Alexander Gennadievich Trofimov — <a href="mailto:agtrofimov@robustidps.ai" className="text-accent-blue hover:underline">agtrofimov@robustidps.ai</a><br/>
          General inquiries — <a href="mailto:support@robustidps.ai" className="text-accent-blue hover:underline">support@robustidps.ai</a>
        </p>
      </div>
    </div>
  )
}
